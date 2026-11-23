"""Address, path and decoding helpers."""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
from datetime import datetime
from typing import Iterable

def _ts(dt: datetime) -> float:
    return dt.timestamp()


def _nets(cidrs: Iterable[str]):
    return [ipaddress.ip_network(c, strict=False) for c in cidrs]


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _in_nets(ip: str, nets) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr.version == n.version and addr in n for n in nets)


def _track_key(ip: str) -> str:
    """IPv4 by address; IPv6 by /64, since one host owns the whole prefix."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


def _norm_path(path: str) -> str:
    p = urllib.parse.unquote(path or "/")
    p = re.sub(r"/{2,}", "/", p)
    return p if p.startswith("/") else "/" + p


def _decode(text: str) -> str:
    """Undo up to two layers of URL encoding so %2527-style double encoding
    does not hide a payload."""
    for _ in range(2):
        nxt = urllib.parse.unquote_plus(text)
        if nxt == text:
            break
        text = nxt
    return text
