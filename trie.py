#!/usr/bin/env python3

import ipaddress
import itertools
import functools

import enum

from typing import Optional, Iterable, Generator, Union, Any

_shifts = list(range(7, -1, -1))
_masks = [1 << i for i in _shifts]


class IPVersion(enum.IntEnum):
    v4 = 4
    v6 = 6


def ip_to_bools(ip_net: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]) -> Iterable[bool]:
    return itertools.islice(
        (
            bool(byte & mask)
            for byte, mask in itertools.product(
                ip_net.network_address.packed,
                _masks
            )
        ),
        ip_net.prefixlen
    )


def _bools_to_ip(addr_type: IPVersion, bools: Iterable[bool]) -> Any:
    addr_bytes = 4 if addr_type == IPVersion.v4 else 16
    max_prefix_len = addr_bytes * 8

    bools = iter(bools)
    packed = bytearray()
    prefixlen = 0
    while prefixlen <= max_prefix_len:
        partial = list(itertools.islice(bools, 8))
        if not partial:
            break

        prefixlen += len(partial)
        packed.append(sum(bit << shift for bit, shift in zip(partial, _shifts)))
    else:
        raise ValueError(f'prefix length over {max_prefix_len} bits')

    packed += bytes(addr_bytes - len(packed))

    ip = ipaddress.ip_address(bytes(packed))
    return ipaddress.ip_network(f'{ip}/{prefixlen}')


def bools_to_ipv4(bools: Iterable[bool]) -> ipaddress.IPv4Network:
    return _bools_to_ip(IPVersion.v4, bools)


def bools_to_ipv6(bools: Iterable[bool]) -> ipaddress.IPv6Network:
    return _bools_to_ip(IPVersion.v6, bools)


class Node(object):
    def __init__(self, left: Optional['Node'] = None, right: Optional['Node'] = None, value: Any = False) -> None:
        self.left = left
        self.right = right
        self.value = value

    def __str__(self) -> str:
        sections = ', '.join(f'{key}={value}' for key, value in {k: getattr(self, k) for k in ('value', 'left', 'right')}.items() if value)
        return f'Node({sections})'

    def _get_entries(self, addr_type: IPVersion, prev_bits: tuple[bool, ...] = ()) -> Generator[tuple[tuple[bool, ...], Any], None, None]:
        max_prefix_len = 32 if addr_type == IPVersion.v4 else 128
        if len(prev_bits) > max_prefix_len:
            raise ValueError(f'prefix over {max_prefix_len} bits')

        if self.value:
            yield (prev_bits, self.value)
        else:
            for i, child in enumerate(getattr(self, direction) for direction in ('left', 'right')):
                if child:
                    yield from child._get_entries(addr_type, prev_bits + (bool(i),))

    def _merge_entries(self, n_type: IPVersion, cur_len: int) -> None:
        max_len = 32 if n_type == IPVersion.v4 else 128
        if cur_len > max_len:
            raise ValueError('Too deep in trie')

        num_children = 0
        for direction in ('left', 'right'):
            child = getattr(self, direction, None)
            if child:
                child._merge_entries(n_type, cur_len + 1)
                num_children += 1

        if num_children == 2:
            assert self.left and self.right
            l_value = self.left.value
            if l_value and l_value == self.right.value:
                self.left = None
                self.right = None
                self.value = l_value


# insert-only, no delete
class Trie(object):
    def __init__(self, tree: Optional[Node] = None) -> None:
        self.tree = tree or Node()

    def insert(self, addr_type: IPVersion, it: Iterable[bool], value: Any = True, error_on_conflict: bool = False) -> None:
        current = self.tree

        if error_on_conflict:
            it = list(it)

        max_prefix_len = 32 if addr_type == IPVersion.v4 else 128
        for prefix_len, bit in enumerate(it):
            if prefix_len > max_prefix_len:
                raise ValueError(f'prefix over {max_prefix_len} bits')

            if current.value:  # entry with shorter prefixlen already exists
                if error_on_conflict:
                    raise ValueError(f'conflict inserting {_bools_to_ip(addr_type, it)}')
                return

            direction = 'right' if bit else 'left'

            if not getattr(current, direction):
                setattr(current, direction, Node())
            current = getattr(current, direction)

        current.left = None
        current.right = None
        current.value = value

    def get_entries_v4(self) -> Iterable[tuple[ipaddress.IPv4Network, Any]]:
        return self._get_entries(IPVersion.v4)

    def get_entries_v6(self) -> Iterable[tuple[ipaddress.IPv6Network, Any]]:
        return self._get_entries(IPVersion.v6)

    def _get_entries(self, n_type: IPVersion) -> Iterable[tuple[Any, Any]]:
        return ((_bools_to_ip(n_type, entry), value) for entry, value in self.tree._get_entries(n_type))

    def merge_entries_v4(self) -> None:
        self._merge_entries(IPVersion.v4)

    def merge_entries_v6(self) -> None:
        self._merge_entries(IPVersion.v6)

    def _merge_entries(self, addr_type: IPVersion) -> None:
        self.tree._merge_entries(addr_type, 0)

    def __str__(self) -> str:
        return f'Trie(tree={self.tree})'


def trie_uniq_v4(nets: Iterable[ipaddress.IPv4Network], merge: bool = True) -> Iterable[tuple[ipaddress.IPv4Network, Any]]:
    return _trie_uniq(IPVersion.v4, nets, merge)


def trie_uniq_v6(nets: Iterable[ipaddress.IPv6Network], merge: bool = True) -> Iterable[tuple[ipaddress.IPv6Network, Any]]:
    return _trie_uniq(IPVersion.v6, nets, merge)


def _trie_uniq(n_type: IPVersion, nets: Iterable[Any], merge: bool) -> Iterable[tuple[Any, Any]]:
    t = Trie()
    for net in nets:
        t.insert(n_type, ip_to_bools(net))

    if merge:
        t._merge_entries(n_type)

    return t._get_entries(n_type)


if __name__ == '__main__':
    nets = {ipaddress.IPv6Network(net_s) for net_s in ('2001:1530::/32', '2001:1548:206::/48', '2001:1b28:405::/48', '2001:1b28::/32', '2001:1bf0::/29', '2001:418:1::/48', '2001:418:3807::/48', '2001:418:8006::/48', '2001:678:5e0::/48', '2001:678:6d8::/48', '2001:678:94::/48', '2001:678:a54::/48', '2001:67c:23d4::/48', '2001:67c:2618::/48', '2001:67c:32c::/48', '2001:67c:3c8::/48', '2001:67c:bc::/48', '2001:7d0::/32', '2001:7f8:15::/48', '2001:7f8:50::/48', '2001:bb8::/32', '2001:df7:5380::/48', '2001:df7:5381::/48', '2a00:16e0::/32', '2a00:6a00::/29', '2a00:6a00::/32', '2a00:6cc0::/32', '2a00:9b40::/32', '2a00:9ec0::/32', '2a00:b9e0::/32', '2a00:c3a0::/32', '2a00:c700::/32', '2a00:d800::/32', '2a01:158::/32', '2a01:1b8:5::/48', '2a01:6da0::/32', '2a01:8020::/32', '2a01:82a0::/32', '2a01:97a0::/32', '2a01:a3e0::/32', '2a02:29e8::/29', '2a02:29e8::/32', '2a02:29ea:14::/48', '2a02:29ea:1e::/48', '2a02:68a0::/32', '2a02:7980:105::/48', '2a02:7980::/32', '2a02:88::/32', '2a02:e80::/32', '2a03:29c0:1000::/36', '2a03:29c0:2000::/36', '2a03:29c0:8000::/33', '2a03:29c0::/32', '2a03:29c0:a000::/35', '2a03:42e0::/32', '2a03:42e0::/48', '2a03:4360::/32', '2a03:5820::/32', '2a03:5880:104::/48', '2a03:5880::/32', '2a03:7c60::/32', '2a03:95c0::/32', '2a03:c840::/32', '2a03:e980::/32', '2a03:f480:1::/48', '2a03:f480:2::/48', '2a03:f480:3::/48', '2a03:f480::/32', '2a04:3340::/29', '2a04:6f00::/29', '2a04:7e80::/29', '2a04:80c0::/29', '2a04:b040::/29', '2a04:c280::/29', '2a04:d400::/29', '2a05:1cc0::/29', '2a05:4080::/29', '2a05:4280::/29', '2a05:c680::/29', '2a06:22c0::/29', '2a06:a980::/29', '2a07:1180::/29', '2a07:1280::/32', '2a07:44c0::/29', '2a07:8800::/29', '2a07:9000::/29', '2a07:9280::/29', '2a07:9900::/29', '2a09:1f40::/29', '2a09:5840::/29', '2a09:6940::/29', '2a09:7:2005::/48', '2a09:8240::/32', '2a09:a400::/29', '2a09:ae80::/29', '2a09:c500::/29', '2a09:c840::/29', '2a09:d480::/29', '2a09:d9c0::/32', '2a09:f540::/29', '2a09:f540::/32', '2a0a:acc0::/29', '2a0a:d040::/29', '2a0b:2540::/29', '2a0b:40::/29', '2a0b:4440::/29', '2a0b:6140::/29', '2a0b:6c00::/29', '2a0b:8400::/29', '2a0b:a0c0::/29', '2a0b:ac40::/29', '2a0b:b240::/29', '2a0b:b2c0::/29', '2a0b:b2c0::/48', '2a0b:b87:ffd7::/48', '2a0b:f740::/29', '2a0c:1180::/29', '2a0c:36c0::/29', '2a0c:36c7::/32', '2a0c:3e40::/29', '2a0c:4880::/29', '2a0c:4bc0::/29', '2a0c:7d80::/29', '2a0c:9d40::/29', '2a0c:e240::/32', '2a0c:e6c0::/29', '2a0c:f940::/29', '2a0d:4ec0::/29', '2a0d:6b00::/29', '2a0d:8f00::/29', '2a0d:94c0::/29', '2a0d:9e80::/29', '2a0d:a180::/32', '2a0d:c0::/29', '2a0d:cfc0::/29', '2a0d:dbc0::/29', '2a0d:e000::/29', '2a0e:4440::/29', '2a0e:4c00::/29', '2a0e:5800::/29', '2a0e:7c80::/29', '2a0e:7d80::/29', '2a0e:8680::/29', '2a0e:8680::/48', '2a0e:8a80::/29', '2a0e:8a80::/32', '2a0e:92c0::/29', '2a0e:9a40::/29', '2a0e:a840::/32', '2a0e:a840::/48', '2a0e:d040::/29', '2a0e:e740::/29', '2a0e:e740::/30', '2a0e:e744::/30', '2a0f:4980::/29', '2a0f:aac0::/29', '2a0f:bb80::/29', '2a10:1fc0::/29', '2a10:46c0::/29', '2a10:46c0::/32', '2a10:6340::/29', '2a10:b000::/29', '2a10:f040::/32', '2a10:f340::/29', '2a11:2600::/29', '2a11:3b80::/29', '2a11:6a00::/29')}
    new_nets = set(ip for ip, _ in trie_uniq_v6(nets))

    print(f'{nets - new_nets=}')
    print(f'{new_nets - nets=}')
