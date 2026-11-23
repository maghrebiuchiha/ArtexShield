"""Address, path and decoding helpers."""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
from datetime import datetime
from typing import Dict, Iterable, List, Optional

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


def _prefixes(entries: Iterable[str], field: str) -> List[str]:
    """Validate a list of path prefixes and drop trailing slashes. An entry
    must name something below the root: "" or "/" would cover every request."""
    if isinstance(entries, str):
        raise ValueError(f"{field} must be a list of paths, not one string")
    out = []
    for entry in entries:
        if not isinstance(entry, str) or not entry.startswith("/") or not entry.strip("/"):
            raise ValueError(f"{field}: {entry!r} must start with '/' and name a path below it")
        out.append(re.sub(r"/{2,}", "/", entry).rstrip("/"))
    return out


def _under(path: str, prefixes: List[str]) -> bool:
    """True when `path` is one of `prefixes` or lies below one: whole segments
    only, so "/static" covers "/static/app.js" and not "/static-admin". `path`
    is taken as the app will route it, without decoding it further, and a path
    that climbs with ".." at any depth of encoding is under nothing."""
    if not prefixes:
        return False
    p = re.sub(r"/{2,}", "/", path or "/")
    if ".." in _decode(p).replace("\\", "/").split("/"):
        return False
    return any(p == prefix or p.startswith(prefix + "/") for prefix in prefixes)


def _extension(path: str) -> str:
    """Lower-case extension of the last path segment, without the dot."""
    name = path.rsplit("/", 1)[-1]
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _induced(h: Dict[str, str]) -> bool:
    """Did a web page, not the person, make the browser send this request?

    Browsers say so themselves in the Sec-Fetch-* headers. Induced: anything
    started from another site (`cross-site`, `same-site`), and anything a
    page of this site embeds (an image, a frame, a stylesheet). Not induced:
    an address typed or bookmarked (`none`), a navigation inside the site, and
    the site's own scripts (`same-origin` with dest `document` or `empty`).
    Browsers too old to send these, and plain-HTTP sites, fall back to the
    Referer: one from another host means another site started the request.
    A client that sends neither is taken to be acting for itself."""
    site = h.get("sec-fetch-site", "").strip().lower()
    if site in ("cross-site", "same-site"):
        return True
    if site == "same-origin":
        return h.get("sec-fetch-dest", "").strip().lower() not in ("", "document", "empty")
    if site:
        return False
    referer, host = h.get("referer", ""), h.get("host", "").strip().lower()
    if not referer or not host:
        return False
    try:
        origin = urllib.parse.urlsplit(referer.strip()).netloc
    except ValueError:
        return False
    origin = origin.rsplit("@", 1)[-1].lower()
    return bool(origin) and origin != host


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
