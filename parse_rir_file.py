#!/usr/bin/env python3

import ipaddress
import json
import math

import trie

from functools import partial
from typing import TextIO, Optional, Callable, Any, Iterable, Generator

from frozendict import frozendict


def _line_field_map(fields: list[Optional[str]], fd: TextIO) -> dict[str, str]:
    return dict(
        (field_name, field_data)
        for field_name, field_data in zip(fields, _line_data(fd, len(fields)))
        if field_name and field_data
    )


def _line_data(fd: TextIO, num_rows: int = 0) -> list[str]:
    line = ''
    while not line or line.startswith('#'):
        line = fd.readline()
        if not line:
            raise ValueError('unexpected EOF')

        line = line.rstrip()

    return line.split('|', maxsplit=num_rows-1)


def get_host_max_len(ip: ipaddress.IPv4Address) -> int:
    '''Get maximum possible subnet size for the given IPv4 address'''
    res = 0
    ip_bits = int(ip)
    while not ip_bits & 1:
        ip_bits >>= 1
        res += 1

    return res


def ipv4_range_to_subnets(start: str, num: int) -> Generator[str, None, None]:
    '''
    Given a start IPv4 address and a number of hosts starting from that address,
    generate the minimal set of subnets to exactly cover only those hosts
    '''
    current_start = ipaddress.IPv4Address(start)
    while num:
        subnet_bits = min(
            int(math.log2(num)),
            get_host_max_len(current_start)
        )
        yield f'{current_start}/{32 - subnet_bits}'

        current_subnet_hosts = 1 << subnet_bits
        num -= current_subnet_hosts
        current_start += current_subnet_hosts


def record_changes(record: dict[str, Any], ignored_fields: Iterable[str] = ('registry', 'extensions', 'date')) -> Iterable[dict[str, Any]]:
    for ignored_field in ignored_fields:
        record.pop(ignored_field, None)

    start = record.pop('start')
    value = int(record.pop('value'))

    r_type = record['type']  # removed in parse_file

    if r_type == 'ipv6':
        yield record | {'subnet': f'{start}/{value}'}

    elif r_type == 'asn':
        start_i = int(start)
        yield from (
            record | {'asn': asn}
            for asn in range(start_i, start_i + value)
        )

    elif r_type == 'ipv4':
        yield from (
            record | {'subnet': subnet}
            for subnet in ipv4_range_to_subnets(start, value)
        )

    else:
        raise ValueError(f'unknown {r_type=}')


parse_header = partial(_line_field_map, ['version', 'registry', 'serial', 'records', 'startdate', 'enddate', 'utc_offset'])
parse_summary = partial(_line_field_map, ['registry', None, 'type', None, 'count', 'summary'])
parse_record = partial(_line_field_map, ['registry', 'cc', 'type', 'start', 'value', 'date', 'status', 'extensions'])


def eof_check(fd: TextIO) -> None:
    # hacky EOF check
    extra_line = fd.readline()
    if not extra_line:
        return

    if len(extra_line) > 100:
        extra_line = repr(extra_line[:100]) + '[...] (over 100 chars)'
    else:
        extra_line = repr(extra_line)

    raise ValueError(f'data left over: {extra_line}')


def parse_file(filename: str = 'delegated-ripencc-extended-latest', filter_f: Callable[[dict[str, str]], bool] = lambda record: True) -> dict[str, Any]:
    data: dict[str, Any] = {}
    with open(filename) as fd:
        data['header'] = parse_header(fd)
        data['summaries'] = {summary['type']: summary for summary in (parse_summary(fd) for _ in range(3))}
        data['records'] = {record_type: [] for record_type in data['summaries']}

        num_records = 0

        for summary in data['summaries'].values():
            count = int(summary['count'])
            summary['count'] = count
            num_records += count

        tries = {t: trie.Trie() for t in trie.IPVersion}
        record_cache: dict[int, frozendict[str, Any]] = {}

        for record in (
            updated_record
            for record in (
                parse_record(fd)
                for _ in range(num_records)
            )
            if filter_f(record)
            for updated_record in record_changes(record)
        ):
            record_type = record.pop('type')
            if record_type == 'asn':
                data['records']['asn'].append(record)
            else:
                family = trie.IPVersion(int(record_type[-1]))
                subnet = ipaddress.ip_network(record.pop('subnet'))
                frozen_record = frozendict(record)
                record_hash = hash(frozen_record)
                record_cache.setdefault(record_hash, frozen_record)
                tries[family].insert(family, trie.ip_to_bools(subnet), record_hash)

        eof_check(fd)

        for family in trie.IPVersion:
            family_s = str(int(family))
            family_trie = tries[family]
            family_trie._merge_entries(family)
            data['records'][f'ipv{family_s}'] = list(record_cache[record_hash] | {'subnet': str(ip)} for ip, record_hash in family_trie._get_entries(family))

    return data


def main() -> None:
    import sys
    import json
#    print(json.dumps(parse_file(filter_f = lambda record: record.get('cc') == 'EE')))
    print(json.dumps(parse_file(sys.argv[1])))
#    print(list(ipv4_range_to_subnets('127.245.1.5', 256)))


if __name__ == '__main__':
    main()
