"""Address, path and decoding helpers."""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
from datetime import datetime
from typing import Iterable, Optional

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


def _usable_ip(value: str) -> bool:
    """An address that can stand for one client: parseable and not 0.0.0.0 / ::."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return not addr.is_unspecified


def _hop_ip(hop: str) -> Optional[str]:
    """The address in one X-Forwarded-For entry, or None. Some proxies append
    the source port: `203.0.113.7:44321`, `[2001:db8::7]:443`."""
    h = hop.strip().strip('"')
    if h.startswith("["):
        end = h.find("]")
        if end > 0:
            h = h[1:end]
    elif h.count(":") == 1:
        h = h.split(":", 1)[0]
    return h if _valid_ip(h) else None


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


def _url_text(path: str, query: str) -> str:
    """What the client sent in the URL, for payload matching: the decoded path,
    then each decoded query name and value, separated by NUL. The `?`, `&` and
    `=` that hold a query string together are left out, so `page=2&id=5` is
    read as four words and not as text containing `&id`. A `&` or `=` the
    client encoded is data and stays in."""
    parts = [_decode(path)]
    for pair in query.split("&"):
        if pair:
            name, _, value = pair.partition("=")
            parts.append(_decode(name))
            parts.append(_decode(value))
    return "\x00".join(parts)
