#!/usr/bin/env python3

import ipaddress
from typing import Iterable

import pyasn

import parse_rir_file
import update_files
from trie import trie_uniq_v6


def nibble_split(ip_net: ipaddress.IPv6Network) -> Iterable[ipaddress.IPv6Network]:
    return ip_net.subnets(-ip_net.prefixlen % 4)


def main() -> None:
    update_files.update_all()

    asndb = pyasn.pyasn('v6.db')
    filter_f = lambda record: record.get('cc') == 'EE' and record['type'] != 'ipv4'
    rir_data = parse_rir_file.parse_file(filter_f=filter_f)

    cc_asns = (record['asn'] for record in rir_data['records']['asn'])
    cc_asn_subnets = (ipaddress.IPv6Network(subnet) for asn in cc_asns for subnet in (asndb.get_as_prefixes(asn) or []) if ':' in subnet)
    cc_subnets = {ipaddress.IPv6Network(record['subnet']) for record in rir_data['records']['ipv6']}
    cc_subnets.update(cc_asn_subnets)

    nibble_match_v6_nets = (nib_net for subnet, _ in trie_uniq_v6(cc_subnets) for nib_net in nibble_split(subnet))

    for net in nibble_match_v6_nets:
        print(net)


if __name__ == '__main__':
    main()
