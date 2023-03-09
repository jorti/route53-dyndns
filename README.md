Route 53 DynDNS
===============

route53-dyndns is a Python script to update DNS records in AWS Route 53. It can
get the IP address from a network interface, URL or a file and keeps the
configured registries up to date.

It supports a single IPv4 address and an IPv6 delegated prefix.

## Usage

The script depends on several python packages, see the `requirements.txt` file.

Create a yaml configuration file using `route53-dyndns.yml.example` as a
reference of the different supported options. You can indicate the location of
the configuration file with the `--conf-file` options.

The AWS credentials are located by default in `~/.aws/config`, but you can use
an alternate location using the `--aws-conf-file` option.

The needed AWS permissions are:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "route53:ChangeResourceRecordSets",
                "route53:ListResourceRecordSets"
            ],
            "Resource": "arn:aws:route53:::hostedzone/YOUR_HOSTEDZONE_ID"
        },
        {
            "Effect": "Allow",
            "Action": "route53:ListHostedZonesByName",
            "Resource": "*"
        }
    ]
}
```
