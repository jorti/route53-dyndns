#!/usr/bin/python3

# Copyright 2023 Juan Orti Alcaine <jortialc@redhat.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import shutil
import sys
import argparse
import yaml
import os
import boto3
from ipaddress import IPv4Address, IPv6Address, IPv6Network, ip_address, ip_network
import netifaces
from subprocess import check_output, SubprocessError
from signal import signal, SIGINT, SIGTERM
import logging
from typing import Optional
from datetime import datetime


def get_ipv4_address(source: dict) -> Optional[IPv4Address]:
    if source["type"] == "interface":
        addresses = netifaces.ifaddresses(source["interface"])[
            netifaces.AF_INET]
        return ip_address(addresses[0]["addr"])
    elif source["type"] == "file":
        try:
            with open(source["file"], "r") as f:
                content = f.readline().rstrip()
            return ip_address(content)
        except OSError as exception:
            print(f"Error reading IPv4 address from file {source['file']}: {exception}")
    elif source["type"] == "url":
        curl_cmd = [shutil.which('curl'), '--ipv4',
                    '--silent', '--max-time', '10', source["url"]]
        try:
            logging.debug(f"Running command {curl_cmd}")
            output = check_output(curl_cmd)
            return ip_address(output.decode('utf-8').strip())
        except SubprocessError as exception:
            print("Error getting IPv4 address using curl:")
            print(curl_cmd)
            print(exception)
    else:
        print("Unknown IPv4 source type'{}'".format(source["type"]))
        raise ValueError


def get_ipv6_prefix(source: dict) -> Optional[IPv6Network]:
    """ Returns a discovered IPv6 prefix or None"""
    if source["type"] == "interface":
        addresses = netifaces.ifaddresses(source["interface"])[
            netifaces.AF_INET6]
        for address in addresses:
            if "prefixlen" in source.keys():
                prefix = str(source["prefixlen"])
            else:
                prefix = address["netmask"].split('/')[1]
            ipv6_network = ip_network(
                address["addr"] + '/' + prefix, strict=False)
            if ipv6_network.is_global and ipv6_network.prefixlen <= 64:
                return ipv6_network
        print(f"Error reading IPv6 prefix from network interface {source['interface']}")
    elif source["type"] == "file":
        try:
            with open(source["file"], "r") as f:
                content = f.readline().rstrip()
            return ip_network(content)
        except OSError as exception:
            print(f"Error reading IPv6 prefix from file {source['file']}: {exception}")
    elif source["type"] == "url":
        if "prefixlen" not in source.keys():
            print("You need to specify 'prefixlen' for the IPv6 URL method")
            sys.exit(1)
        curl_cmd = [shutil.which('curl'), '--ipv6',
                    '--silent', '--max-time', '10', source["url"]]
        try:
            logging.debug(f"Running command {curl_cmd}")
            output = check_output(curl_cmd).decode('utf-8')
            return ip_network(output.strip() + '/' + str(source["prefixlen"]), strict=False)
        except SubprocessError as exception:
            print("Error getting IPv6 prefix using curl:")
            print(curl_cmd)
            print(exception)
    else:
        print("Unknown IPv6 source type '{}'".format(source["type"]))
        raise ValueError


def calculate_ipv6_address(prefix: IPv6Network, dns_record_conf: dict) -> Optional[IPv6Address]:
    if "ipv6_subnet_interface" in dns_record_conf.keys():
        target_subnet = get_ipv6_prefix(
            {"type": "interface", "interface": dns_record_conf["ipv6_subnet_interface"]})
        if not target_subnet:
            print(f"Cannot calculate IPv6 address using interface {dns_record_conf['ipv6_subnet_interface']}")
            return
        return target_subnet[int(str(dns_record_conf["ipv6_host_addr"]), 16)]
    elif "ipv6_subnet_hint" in dns_record_conf.keys():
        if prefix.prefixlen < 64:
            subnets = list(prefix.subnets(new_prefix=64))
            target_subnet = subnets[int(
                str(dns_record_conf["ipv6_subnet_hint"]), 16)]
        else:
            print("IPv6 Prefix length is {}, ignoring ipv6_subnet_hint".format(prefix.prefixlen))
            target_subnet = prefix
        return target_subnet[int(str(dns_record_conf["ipv6_host_addr"]), 16)]
    else:
        print(f"Cannot calculate IPv6 address with dns_record_conf={dns_record_conf}")


def finish(_signo, _stack_frame):
    print("Goodbye")
    sys.exit(0)


def get_base_domain(fqdn: str) -> str:
    return '.'.join(fqdn.split('.')[-2:])


def needs_update(desired: dict, current: list) -> (bool, bool):
    """Checks if a desired record exists in the list of retrieved records and if needs to be updated.

    Returns a tuple of booleans: (exists, updated)"""
    exists = False
    updated = False
    for record in current:
        decoded_name = record['Name'].encode('utf-8').decode('unicode_escape')
        if decoded_name == desired['Name'] and \
                record['Type'] == desired['Type']:
            exists = True
            if record['TTL'] == desired['TTL'] and \
                    record['ResourceRecords'][0]['Value'] == desired['ResourceRecords'][0]['Value']:
                updated = True
            break
    return exists, updated


def create_route53_change(action: str, record: dict) -> dict:
    return {'Action': action,
            'ResourceRecordSet': {
                'Name': record['Name'],
                'Type': record['Type'],
                'TTL': record['TTL'],
                'ResourceRecords': [
                    {'Value': record['ResourceRecords'][0]['Value']}
                ]
            }}


def create_route53_change_batch(changed_records: list) -> dict:
    """Create a Route 53 change batch from a list of changed records"""
    return {'Comment': "Change created by route53-dyndns.py",
            'Changes': changed_records}


def get_route53_domain_records(domain_id: str, **kwargs) -> list:
    if 'StartRecordName' in kwargs and 'StartRecordType' in kwargs and 'StartRecordIdentifier' not in kwargs:
        resource_record_sets = route53.list_resource_record_sets(HostedZoneId=domain_id,
                                                                 StartRecordName=kwargs['StartRecordName'],
                                                                 StartRecordType=kwargs['StartRecordType'])
    elif 'StartRecordName' in kwargs and 'StartRecordType' in kwargs and 'StartRecordIdentifier' in kwargs:
        resource_record_sets = route53.list_resource_record_sets(HostedZoneId=domain_id,
                                                                 StartRecordName=kwargs['StartRecordName'],
                                                                 StartRecordType=kwargs['StartRecordType'],
                                                                 StartRecordIdentifier=kwargs['StartRecordIdentifier'])
    else:
        resource_record_sets = route53.list_resource_record_sets(HostedZoneId=domain_id)
    records = resource_record_sets['ResourceRecordSets']
    if resource_record_sets['IsTruncated']:
        next_query_args = {'StartRecordName': resource_record_sets['NextRecordName'],
                           'StartRecordType': resource_record_sets['NextRecordType']}
        if 'StartRecordIdentifier' in resource_record_sets:
            next_query_args['StartRecordIdentifier'] = resource_record_sets['NextRecordIdentifier']
        records = records + get_route53_domain_records(domain_id=domain_id, **next_query_args)
    return records


def find_record_in_list(record_list: list, wanted_name: str, wanted_type: str) -> Optional[dict]:
    """Find a specific record in a list of records"""
    for record in record_list:
        if record['Name'] == wanted_name and record['Type'] == wanted_type:
            return record


def get_all_base_domains() -> dict:
    """Get all the base domains and their Route 53 IDs from the list of configured records"""
    all_domains = []
    domain_ids = {}
    for record in conf['dns_records']:
        domain = get_base_domain(record['hostname'])
        if domain not in all_domains:
            all_domains.append(domain)
    for domain in all_domains:
        hosted_zones = route53.list_hosted_zones_by_name(DNSName=domain)
        domain_ids[domain] = {'Id': hosted_zones['HostedZones'][0]['Id'],
                              'Name': domain
                              }
    return domain_ids


def discover_ips() -> dict:
    """Discover IPv4 address and IPv6 prefix"""
    print(f"{datetime.now()} Starting IP discovery...")
    if "ipv4" in conf["sources"]:
        print("Trying to discover IPv4 address...")
        ipv4_address = get_ipv4_address(conf["sources"]["ipv4"])
        if ipv4_address:
            print(f"Discovered IPv4 address: {ipv4_address}")
    else:
        ipv4_address = None
    if "ipv6" in conf["sources"]:
        print("Trying to discover IPv6 prefix...")
        ipv6_prefix = get_ipv6_prefix(conf["sources"]["ipv6"])
        if ipv6_prefix:
            print(f"Discovered IPv6 prefix: {ipv6_prefix}")
    else:
        ipv6_prefix = None
    return {'ipv4': ipv4_address,
            'ipv6': ipv6_prefix
            }


def generate_desired_records() -> dict:
    """Generate list of desired records grouped by domain"""
    records = {}
    # Create domain keys
    for record in conf['dns_records']:
        domain = get_base_domain(record["hostname"])
        if domain not in records:
            records[domain] = []
    # Add record to dictionary
    for record in conf['dns_records']:
        if record["ipv4"] and 'ipv4' in current_ips:
            domain = get_base_domain(record["hostname"])
            records[domain].append({"Name": record["hostname"] + '.',
                                    "ResourceRecords": [{"Value": str(current_ips['ipv4'])}],
                                    "Type": "A",
                                    "TTL": args.ttl
                                    })
        if record["ipv6"] and 'ipv6' in current_ips:
            ipv6_address = calculate_ipv6_address(current_ips['ipv6'], record)
            if ipv6_address:
                domain = get_base_domain(record["hostname"])
                records[domain].append({"Name": record["hostname"] + '.',
                                        "ResourceRecords": [{"Value": str(ipv6_address)}],
                                        "Type": "AAAA",
                                        "TTL": args.ttl
                                        })
    return records


def get_current_records() -> dict:
    """Get the current values of the configured records"""
    records = {}
    for domain in domains:
        records[domain] = get_route53_domain_records(domain_id=domains[domain]['Id'])
    return records


def print_record_change(modification_flag: str, record: dict):
    print("%s %26s %6s %4s %s" % (modification_flag, record['Name'], record['TTL'],
                                  record['Type'], record['ResourceRecords'][0]['Value']))


def generate_changes() -> dict:
    """Generate lists of changes grouped by domain"""
    record_changes = {}
    print("Generating change batch:")
    for domain in domains:
        record_changes[domain] = []
        for desired_record in desired_records[domain]:
            exists, updated = needs_update(
                desired_record, current_records[domain])
            logging.debug(
                f"{desired_record['Type']} Record '{desired_record['Name']}' checked with results: exists={exists} updated={updated}")
            if exists and updated:
                print_record_change("  ", desired_record)
            elif not exists:
                print_record_change("++", desired_record)
                change = create_route53_change('CREATE', desired_record)
                record_changes[domain].append(change)
            elif not updated:
                current_record = find_record_in_list(current_records[domain], desired_record['Name'],
                                                     desired_record['Type'])
                print_record_change("--", current_record)
                print_record_change("++", desired_record)
                change = create_route53_change('UPSERT', desired_record)
                record_changes[domain].append(change)
    return record_changes


def apply_changes():
    """Submit changes to Route 53"""
    for domain in domains:
        if domain in changes and len(changes[domain]) > 0:
            print(f"Submitting changes to domain {domain}...")
            change_batch = create_route53_change_batch(changes[domain])
            route53.change_resource_record_sets(HostedZoneId=domains[domain]['Id'], ChangeBatch=change_batch)


parser = argparse.ArgumentParser(description='Route 53 DynDNS')
parser.add_argument("--conf-file", "-c",
                    default="/etc/route53-dyndns/route53-dyndns.yml", help="Configuration file")
parser.add_argument("--aws-conf-file", help="AWS configuration file")
parser.add_argument("--ttl", default=60, type=int,
                    help="TTL for DNS records (default: 60 seconds)")
parser.add_argument("--log-level", default="INFO", help="Log level",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
args = parser.parse_args()
log_numeric_level = getattr(logging, args.log_level.upper(), None)
logging.basicConfig(level=log_numeric_level)
signal(SIGTERM, finish)
signal(SIGINT, finish)

try:
    with open(args.conf_file, 'r') as conf_file:
        conf = yaml.load(conf_file, Loader=yaml.SafeLoader)
except OSError as e:
    print(f"Error opening configuration file '{args.conf_file}': {e}")
    sys.exit(1)

# Config file validations
if 'sources' not in conf:
    print("'sources' is not defined in the configuration file")
    sys.exit(1)
if 'dns_records' not in conf:
    print("'dns_records' is not defined in the configuration file")
    sys.exit(1)
if 'ipv4' not in conf['sources'] and 'ipv6' not in conf['sources']:
    print("Either 'ipv4' or 'ipv6' sources have to be configured")
    sys.exit(1)

if args.aws_conf_file:
    os.environ['AWS_CONFIG_FILE'] = args.aws_conf_file
route53 = boto3.client('route53')

domains = get_all_base_domains()
current_ips = discover_ips()
desired_records = generate_desired_records()
current_records = get_current_records()
changes = generate_changes()
apply_changes()

print("Goodbye.")
