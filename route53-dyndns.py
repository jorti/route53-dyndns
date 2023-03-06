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
from time import sleep
from signal import signal, SIGINT, SIGTERM
import logging
from typing import Optional


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
        except OSError as e:
            logging.error(
                f"Error reading IPv4 address from file {source['file']}: {e}")
    elif source["type"] == "url":
        curl_cmd = [shutil.which('curl'), '--ipv4',
                    '--silent', '--max-time', '10', source["url"]]
        try:
            logging.debug(f"Running command {curl_cmd}")
            output = check_output(curl_cmd)
            return ip_address(output.decode('utf-8'))
        except SubprocessError as e:
            logging.error("Error getting IPv4 address using curl:")
            logging.error(curl_cmd)
            logging.error(e)
    else:
        logging.error("Unknown IPv4 source type'{}'".format(source["type"]))
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
        logging.error(
            f"Error reading IPv6 prefix from network interface {source['interface']}")
    elif source["type"] == "file":
        try:
            with open(source["file"], "r") as f:
                content = f.readline().rstrip()
            return ip_network(content)
        except OSError as e:
            logging.error(
                f"Error reading IPv6 prefix from file {source['file']}: {e}")
    elif source["type"] == "url":
        if "prefixlen" not in source.keys():
            logging.error(
                "You need to specify 'prefixlen' for the IPv6 URL method")
            sys.exit(1)
        curl_cmd = [shutil.which('curl'), '--ipv6',
                    '--silent', '--max-time', '10', source["url"]]
        try:
            logging.debug(f"Running command {curl_cmd}")
            output = check_output(curl_cmd).decode('utf-8')
            return ip_network(output + '/' + str(source["prefixlen"]), strict=False)
        except SubprocessError as e:
            logging.error("Error getting IPv6 prefix using curl:")
            logging.error(curl_cmd)
            logging.error(e)
    else:
        logging.error("Unknown IPv6 source type '{}'".format(source["type"]))
        raise ValueError


def calculate_ipv6_address(prefix: IPv6Network, dns_record_conf: dict) -> Optional[IPv6Address]:
    if "ipv6_subnet_interface" in dns_record_conf.keys():
        target_subnet = get_ipv6_prefix(
            {"type": "interface", "interface": dns_record_conf["ipv6_subnet_interface"]})
        if not target_subnet:
            logging.error(
                f"Cannot calculate IPv6 address using interface {dns_record_conf['ipv6_subnet_interface']}")
            return
        return target_subnet[int(str(dns_record_conf["ipv6_host_addr"]), 16)]
    elif "ipv6_subnet_hint" in dns_record_conf.keys():
        if prefix.prefixlen < 64:
            subnets = list(prefix.subnets(new_prefix=64))
            target_subnet = subnets[int(
                str(dns_record_conf["ipv6_subnet_hint"]), 16)]
        else:
            logging.warning(
                "IPv6 Prefix length is {}, ignoring ipv6_subnet_hint".format(prefix.prefixlen))
            target_subnet = prefix
        return target_subnet[int(str(dns_record_conf["ipv6_host_addr"]), 16)]
    else:
        logging.error(
            f"Cannot calculate IPv6 address with dns_record_conf={dns_record_conf}")


def finish(_signo, _stack_frame):
    logging.info("Goodbye")
    sys.exit(0)


def get_base_domain(fqdn):
    return '.'.join(fqdn.split('.')[-2:])


def needs_update(desired_record, current_records):
    """Checks if a desired record exists in the list of retrieved records and if needs to be updated.

    Returns a tuple of booleans: (exists, updated)"""
    exists = False
    updated = False
    for record in current_records:
        decoded_name = record['Name'].encode('utf-8').decode('unicode_escape')
        if decoded_name == desired_record['name'] and \
                record['Type'] == desired_record['type']:
            exists = True
            if record['TTL'] == desired_record['ttl'] and \
                    record['ResourceRecords'][0]['Value'] == desired_record['value']:
                updated = True
            break
    return exists, updated


def create_route53_change(action, record):
    return {'Action': action,
            'ResourceRecordSet': {
                'Name': record['name'],
                'Type': record['type'],
                'TTL': record['ttl'],
                'ResourceRecords': [
                    {'Value': record['value']}
                ]
            }}


def create_route53_change_batch(changes):
    return {'Comment': "Change created by route53-dyndns.py",
            'Changes': changes}


def get_route53_domain_records(domain_id, **kwargs):
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


parser = argparse.ArgumentParser(description='Route 53 DynDNS')
parser.add_argument("--conf-file", "-c",
                    default="route53-dyndns.yml", help="Configuration file")
parser.add_argument("--aws-conf-file", help="AWS configuration file")
parser.add_argument("--ttl", default=60, type=int,
                    help="TTL for DNS records (default: 60 seconds)")
parser.add_argument("--log-level", default="INFO", help="Log level",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
parser.add_argument("--delay", "-d", default=300, type=int,
                    help="Delay between runs (in seconds)")
args = parser.parse_args()
log_numeric_level = getattr(logging, args.log_level.upper(), None)
logging.basicConfig(level=log_numeric_level)
signal(SIGTERM, finish)
signal(SIGINT, finish)

try:
    with open(args.conf_file, 'r') as conf_file:
        conf = yaml.load(conf_file, Loader=yaml.SafeLoader)
except OSError as e:
    logging.critical(
        f"Error opening configuration file '{args.conf_file}': {e}")
    sys.exit(1)

# Config file validations
if 'sources' not in conf:
    logging.critical("'sources' is not defined in the configuration file")
    sys.exit(1)
if 'dns_records' not in conf:
    logging.critical("'dns_records' is not defined in the configuration file")
    sys.exit(1)
if 'ipv4' not in conf['sources'] and 'ipv6' not in conf['sources']:
    logging.critical("Either 'ipv4' or 'ipv6' sources have to be configured")
    sys.exit(1)

if args.aws_conf_file:
    os.environ['AWS_CONFIG_FILE'] = args.aws_conf_file
route53 = boto3.client('route53')

# Get all the domain IDs
domains = []
domain_ids = {}
for record in conf["dns_records"]:
    domain = get_base_domain(record['hostname'])
    if domain not in domains:
        domains.append(domain)
for domain in domains:
    hosted_zones = route53.list_hosted_zones_by_name(DNSName=domain)
    domain_ids[domain] = hosted_zones['HostedZones'][0]['Id']

# main loop
while True:
    # Discover IPv4 and IPv6 addresses
    if "ipv4" in conf["sources"]:
        logging.debug("Trying to discover IPv4 address...")
        ipv4_address = get_ipv4_address(conf["sources"]["ipv4"])
        if ipv4_address:
            logging.info(f"Discovered IPv4 address: {ipv4_address}")
    else:
        ipv4_address = None
    if "ipv6" in conf["sources"]:
        logging.debug("Trying to discover IPv6 prefix...")
        ipv6_prefix = get_ipv6_prefix(conf["sources"]["ipv6"])
        if ipv6_prefix:
            logging.info(f"Discovered IPv6 prefix: {ipv6_prefix}")
    else:
        ipv6_prefix = None

    # Create desired state
    desired_records = {}
    for domain in domain_ids:
        desired_records[domain] = []
    for record in conf["dns_records"]:
        if record["ipv4"] and ipv4_address:
            domain = get_base_domain(record["hostname"])
            desired_records[domain].append({"name": record["hostname"] + '.',
                                            "value": str(ipv4_address),
                                            "type": "A",
                                            "ttl": args.ttl
                                            })
        if record["ipv6"] and ipv6_prefix:
            ipv6_address = calculate_ipv6_address(ipv6_prefix, record)
            if ipv6_address:
                domain = get_base_domain(record["hostname"])
                desired_records[domain].append({"name": record["hostname"] + '.',
                                                "value": str(ipv6_address),
                                                "type": "AAAA",
                                                "ttl": args.ttl
                                                })
    # Get current state
    current_records = {}
    for domain in domain_ids:
        current_records[domain] = get_route53_domain_records(domain_id=domain_ids[domain])

    # Prepare changes
    record_changes = {}
    for domain in domain_ids:
        record_changes[domain] = []
        for desired_record in desired_records[domain]:
            exists, updated = needs_update(
                desired_record, current_records[domain])
            logging.debug(
                f"{desired_record['type']} Record '{desired_record['name']}' checked with results: exists={exists} updated={updated}")
            if exists and updated:
                logging.info("OK: %26s %6s %4s %s" % (desired_record['name'], desired_record['ttl'],
                                                      desired_record['type'], desired_record['value']))
                continue
            if not exists:
                logging.info("Adding: %26s %6s %4s %s" % (desired_record['name'], desired_record['ttl'],
                                                          desired_record['type'], desired_record['value']))
                change = create_route53_change('CREATE', desired_record)
                record_changes[domain].append(change)
            if not updated:
                logging.info("Changing: %26s %6s %4s %s" % (desired_record['name'], desired_record['ttl'],
                                                            desired_record['type'], desired_record['value']))
                change = create_route53_change('UPSERT', desired_record)
                record_changes[domain].append(change)

    # Apply changes
    for domain in domain_ids:
        if record_changes[domain]:
            logging.info(f"Applying changes for domain {domain} ...")
            change_batch = create_route53_change_batch(record_changes[domain])
            result = route53.change_resource_record_sets(
                HostedZoneId=domain_ids[domain], ChangeBatch=change_batch)

    logging.info(f"Sleeping for {args.delay} seconds...")
    sleep(args.delay)
