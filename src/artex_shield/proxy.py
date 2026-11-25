"""artex-shield-proxy: artex-shield in front of any website.

A reverse proxy on asyncio, standard library only. It listens on a port,
puts every request through the shield, and forwards the ones it allows to
one backend URL; the backend can be anything that speaks HTTP (WordPress, a
Node or PHP app, a static site). Responses stream back, and their status is
fed to the shield the way the Python adapters do.

    artex-shield-proxy --backend http://127.0.0.1:8000 --listen 0.0.0.0:8080
    artex-shield-proxy --config /etc/artex-shield.toml

HTTP/1.1, strictly: requests whose framing is ambiguous (Content-Length and
Transfer-Encoding together, conflicting lengths, folded headers, bad chunk
sizes) are refused rather than guessed at, so the proxy cannot be used to
smuggle a second request past it. A request's body is read whole before the
backend is asked (in memory, then in a temporary file), so a visitor that
sends slowly holds none of the site's connections; one that sends too slowly
or too much is cut off, and past max_connections new visitors are answered
503. Responses stream back without being held. Keep-alive is kept with clients
and backend connections are reused. WebSocket handshakes are checked like any
request, then tunnelled; one with a body is refused, and the backend
connection of one the backend turns down is closed, never reused. With
honeytokens set, the first part of each request body is read before the
request is decided on, and the optional client check's script and endpoint are
answered by the proxy itself.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import signal
import ssl
import sys
import tempfile
import time
import urllib.parse
from collections import deque
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Awaitable, Callable, Deque, Dict, List, Mapping, Optional, Tuple

from .client_check import tag as client_check_tag
from .core import Config, Engagement, Shield
from .decoys import (Honeytokens, honeytoken_html, honeytoken_js, html_trap, js_trap, make_canaries, make_honeytokens,
                     robots_txt_block)
from .middleware import _reply
from .util import _in_nets

log = logging.getLogger("artex_shield.proxy")

# Headers that describe one connection, not the message: never forwarded.
HOP_BY_HOP = frozenset({"connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding",
                        "upgrade", "proxy-authorization", "proxy-authenticate"})
IDEMPOTENT = frozenset({"GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"})
_TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_TARGET = re.compile(rb"[\x21-\x7e]+")
_CHUNK_SIZE = re.compile(rb"[0-9A-Fa-f]{1,16}")
_READ = 65536
_REASONS = {400: "Bad Request", 408: "Request Timeout", 405: "Method Not Allowed", 413: "Content Too Large",
            431: "Request Header Fields Too Large", 503: "Service Unavailable",
            501: "Not Implemented", 502: "Bad Gateway", 504: "Gateway Timeout", 505: "HTTP Version Not Supported"}


class ClientError(Exception):
    """The client sent something the proxy will not forward."""

    def __init__(self, status: int, why: str):
        super().__init__(why)
        self.status = status


class BackendError(Exception):
    """The backend could not be reached or answered badly."""


# ---- settings ------------------------------------------------------------------
@dataclass
class Settings:
    backend: str = ""                     # http://host:port or https://host:port
    listen: str = "0.0.0.0:8080"          # host:port, [ipv6]:port, or a bare port
    backend_host_header: str = "preserve"  # "preserve" the client's Host, or "backend" to send the backend's
    backend_tls_verify: bool = True
    connect_timeout: float = 10.0
    read_timeout: float = 60.0            # waiting on the backend, and on a client mid-request
    idle_timeout: float = 75.0            # a client's keep-alive connection between requests
    max_header_bytes: int = 65536
    max_idle_backend: int = 32            # pooled backend connections kept open
    buffer_requests: bool = True          # read a request's whole body before the backend is asked
    body_buffer_bytes: int = 1048576      # a body is held in memory up to this, past it in a temporary file
    max_body_bytes: int = 104857600       # larger request bodies are answered 413; 0 for no limit
    min_body_rate: int = 500              # bytes a second a visitor must average while sending a body; 0: no minimum
    max_connections: int = 0              # visitors' connections at once, then 503; 0 works it out from the open-file limit
    backend_idle_timeout: float = 4.0     # reuse a pooled connection only this long: under the backend's keep-alive
    access_log: bool = False
    shield: Config = field(default_factory=Config)

    def __post_init__(self):
        u = urllib.parse.urlsplit(self.backend)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError(f"backend must be an http:// or https:// URL, not {self.backend!r}")
        if u.path not in ("", "/") or u.query or u.fragment:
            raise ValueError("backend must be a bare origin, like http://127.0.0.1:8000, with no path")
        if self.backend_host_header not in ("preserve", "backend"):
            raise ValueError("backend_host_header must be 'preserve' or 'backend'")
        self.listen_host, self.listen_port = _host_port(self.listen)
        for name in ("connect_timeout", "read_timeout", "idle_timeout", "backend_idle_timeout"):
            if not getattr(self, name) > 0:
                raise ValueError(f"{name} must be positive")
        if self.max_header_bytes < 1024:
            raise ValueError("max_header_bytes must be at least 1024")
        for name in ("body_buffer_bytes", "max_body_bytes", "min_body_rate", "max_connections"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} must not be negative")


def _host_port(text: str) -> Tuple[str, int]:
    text = str(text).strip()
    if text.isascii() and text.isdigit():
        return "0.0.0.0", int(text)
    m = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\]:(\d+)|([^:\[\]]*):(\d+)", text)
    if not m:
        raise ValueError(f"listen must be host:port, [ipv6]:port or a port, not {text!r}")
    host, port = (m.group(1), m.group(2)) if m.group(1) else (m.group(3) or "0.0.0.0", m.group(4))
    if not 0 <= int(port) < 65536:
        raise ValueError(f"listen port out of range: {port}")
    return host, int(port)


_PROXY_KEYS = {f.name for f in fields(Settings)} - {"shield"}
_SHIELD_SKIP = {"logger", "on_event", "engagements"}
_SHIELD_KEYS = {f.name for f in fields(Config)} - _SHIELD_SKIP


def _when(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc)
    text = str(value).strip().replace("Z", "+00:00")
    when = datetime.fromisoformat(text)
    if when.tzinfo is None:
        raise ValueError(f"engagement times need a timezone: {value!r}")
    return when


_DERIVED = {"canary_secret": str, "canary_count": int, "honeytoken_secret": str, "honeytoken_count": int}


def _shield_config(values: Mapping[str, Any]) -> Tuple[Config, Optional[Honeytokens]]:
    """The shield's Config, and the honeytokens made from honeytoken_secret
    (kept whole, so --print-decoys can plant them)."""
    kw = dict(values)
    unknown = set(kw) - _SHIELD_KEYS - {"engagements"} - set(_DERIVED)
    if unknown:
        raise ValueError(f"unknown [shield] settings: {sorted(unknown)}")
    secret = kw.pop("canary_secret", None)
    count = int(kw.pop("canary_count", 3))
    if secret and "canary_paths" not in kw:
        kw["canary_paths"] = make_canaries(str(secret), count)
    secret = kw.pop("honeytoken_secret", None)
    count = int(kw.pop("honeytoken_count", 2))
    tokens = make_honeytokens(str(secret), count) if secret else None
    if tokens is not None:
        kw["honeytokens"] = list(kw.get("honeytokens", [])) + list(tokens)
    if "engagements" in kw:
        engagements = []
        for e in kw["engagements"]:
            if not isinstance(e, dict) or set(e) != {"reference", "cidrs", "start", "end"}:
                raise ValueError("each engagement needs exactly reference, cidrs, start and end")
            engagements.append(Engagement(str(e["reference"]), list(e["cidrs"]), _when(e["start"]), _when(e["end"])))
        kw["engagements"] = engagements
    return Config(**kw), tokens


def _kind(annotation: str) -> type:
    """What an ARTEX_SHIELD_* value is parsed as, from the field's annotation."""
    for word, kind in (("List", list), ("Iterable", list), ("bool", bool), ("float", float), ("int", int)):
        if word in str(annotation):
            return kind
    return str


_KINDS = {f.name: _kind(f.type) for f in fields(Config)}
_KINDS.update({f.name: _kind(f.type) for f in fields(Settings) if f.name != "shield"})


def _from_env(env: Mapping[str, str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """ARTEX_SHIELD_<NAME> for every proxy and shield setting. Lists are
    comma-separated; ARTEX_SHIELD_ENGAGEMENTS is a JSON list."""
    proxy: Dict[str, Any] = {}
    shield: Dict[str, Any] = {}
    for key, raw in env.items():
        if not key.startswith("ARTEX_SHIELD_") or key in ("ARTEX_SHIELD_CONFIG", "ARTEX_SHIELD_LOG_LEVEL"):
            continue
        name = key[len("ARTEX_SHIELD_"):].lower()
        if name in _PROXY_KEYS:
            proxy[name] = _parse_env(raw, _KINDS[name], key)
        elif name == "engagements":
            try:
                shield[name] = json.loads(raw)
            except ValueError as e:
                raise ValueError(f"{key} must be a JSON list: {e}") from None
        elif name in _DERIVED:
            shield[name] = _parse_env(raw, _DERIVED[name], key)
        elif name in _SHIELD_KEYS:
            shield[name] = _parse_env(raw, _KINDS[name], key)
        else:
            raise ValueError(f"unknown setting {key}")
    return proxy, shield


def _parse_env(raw: str, kind: type, key: str) -> Any:
    raw = raw.strip()
    try:
        if kind is bool:
            if raw.lower() not in ("1", "0", "true", "false", "yes", "no", "on", "off"):
                raise ValueError(raw)
            return raw.lower() in ("1", "true", "yes", "on")
        if kind is list:
            return [item.strip() for item in raw.split(",") if item.strip()]
        return kind(raw)
    except ValueError:
        raise ValueError(f"{key}: cannot read {raw!r}") from None


def load_settings(path: Optional[str] = None, env: Optional[Mapping[str, str]] = None,
                  overrides: Optional[Mapping[str, Any]] = None) -> Settings:
    """Defaults, then the TOML file, then ARTEX_SHIELD_* variables, then
    `overrides` (the command line). TOML needs Python 3.11 or newer."""
    env = os.environ if env is None else env
    path = path or env.get("ARTEX_SHIELD_CONFIG")
    proxy: Dict[str, Any] = {}
    shield: Dict[str, Any] = {}
    if path:
        try:
            import tomllib
        except ImportError:
            raise SystemExit("reading a TOML config needs Python 3.11 or newer; use ARTEX_SHIELD_* variables instead") from None
        with open(path, "rb") as f:
            data = tomllib.load(f)
        unknown = set(data) - {"proxy", "shield"}
        if unknown:
            raise ValueError(f"unknown sections in {path}: {sorted(unknown)}")
        proxy.update(data.get("proxy", {}))
        shield.update(data.get("shield", {}))
    env_proxy, env_shield = _from_env(env)
    proxy.update(env_proxy)
    shield.update(env_shield)
    for k, v in (overrides or {}).items():
        if v is None:
            continue
        (shield if k == "mode" else proxy)[k] = v
    unknown = set(proxy) - _PROXY_KEYS
    if unknown:
        raise ValueError(f"unknown [proxy] settings: {sorted(unknown)}")
    config, tokens = _shield_config(shield)
    settings = Settings(shield=config, **proxy)
    settings.honeytoken_set = tokens
    return settings


# ---- reading HTTP ----------------------------------------------------------------
class Head:
    """A parsed request or response head. Header names keep their case in
    `headers`; get() and tokens() take a lower-case name."""
    __slots__ = ("first", "headers", "index")

    def __init__(self, first: Tuple[str, str, str], headers: List[Tuple[str, str]]):
        self.first, self.headers = first, headers
        self.index: Dict[str, List[str]] = {}
        for k, v in headers:
            self.index.setdefault(k.lower(), []).append(v)

    def get(self, name: str) -> List[str]:
        return self.index.get(name, [])

    def tokens(self, name: str) -> List[str]:
        return [t.strip().lower() for v in self.index.get(name, ()) for t in v.split(",") if t.strip()]


# Every header line at once: a token, a colon, then tab, visible ASCII or
# obs-text. No folding, no control characters, no bare CR or LF.
_HEADER_LINES = re.compile(rb"(?:[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\t\x20-\x7e\x80-\xff]*\r\n)*")


def _parse_head(data: bytes, request: bool) -> Head:
    """`data` ends with the blank line."""
    cut = data.index(b"\r\n")
    parts = data[:cut].split(b" ", 2)
    if len(parts) != 3:
        raise ClientError(400, "malformed request line") if request else BackendError("malformed status line")
    if request:
        method, target, version = parts
        if not _TOKEN.fullmatch(method) or not _TARGET.fullmatch(target):
            raise ClientError(400, "malformed request line")
        if version not in (b"HTTP/1.1", b"HTTP/1.0"):
            raise ClientError(505 if version.startswith(b"HTTP/") else 400, "unsupported HTTP version")
        first = (method.decode("ascii"), target.decode("ascii"), version.decode("ascii"))
    else:
        version, status, reason = parts
        if version not in (b"HTTP/1.1", b"HTTP/1.0") or not re.fullmatch(rb"[1-5]\d\d", status):
            raise BackendError("malformed status line")
        first = (version.decode("ascii"), status.decode("ascii"), reason.decode("latin-1"))
    block = data[cut + 2:-2]
    if not _HEADER_LINES.fullmatch(block):
        raise ClientError(400, "malformed header") if request else BackendError("malformed header")
    lines = block.decode("latin-1").split("\r\n")[:-1]
    if len(lines) > 256:
        raise ClientError(431, "too many headers") if request else BackendError("too many headers")
    headers = []
    for line in lines:
        name, _, value = line.partition(":")
        headers.append((name, value.strip(" \t")))
    return Head(first, headers)


def _framing(head: Head, http10: bool, request: bool) -> Tuple[Optional[int], bool]:
    """(Content-Length, chunked?) of a message, refusing anything ambiguous.
    A request with neither has no body; a response with neither runs to EOF (None)."""
    err = (lambda why: ClientError(400, why)) if request else BackendError
    te, cl = head.tokens("transfer-encoding"), head.get("content-length")
    if te:
        if cl:
            raise err("both Content-Length and Transfer-Encoding")
        if http10 and request:
            raise err("Transfer-Encoding on HTTP/1.0")
        if te != ["chunked"]:
            raise ClientError(501, "unsupported Transfer-Encoding") if request else BackendError("unsupported coding")
        return None, True
    if cl:
        values = {v.strip() for raw in cl for v in raw.split(",")}
        value = values.pop() if len(values) == 1 else ""
        if not re.fullmatch(r"\d{1,18}", value):
            raise err("invalid or conflicting Content-Length")
        return int(value), False
    return (0 if request else None), False


class _Pace:
    """How long a visitor may take over a request body. Each read may wait
    read_timeout; all of them together, read_timeout plus a second for every
    min_rate bytes received (the rule of Apache's mod_reqtimeout), so a body
    cannot be dripped in to hold a connection open. Only time spent waiting
    on the visitor counts, not time the backend takes over what was sent."""

    def __init__(self, timeout: float, min_rate: int):
        self.timeout, self.min_rate, self.waited, self.got = timeout, min_rate, 0.0, 0

    async def read(self, start: Callable[[], Awaitable[bytes]]) -> bytes:
        budget = self.timeout
        if self.min_rate:
            budget = min(budget, self.timeout + self.got / self.min_rate - self.waited)
        if budget <= 0:
            raise asyncio.TimeoutError
        began = time.monotonic()
        try:
            data = await asyncio.wait_for(start(), budget)
        finally:
            self.waited += time.monotonic() - began
        self.got += len(data)
        return data


def _waiter(timeout: float, pace: Optional[_Pace]):
    """Await a read: within `pace` for a visitor's body, else within `timeout`."""
    if pace is not None:
        return pace.read
    return lambda start: asyncio.wait_for(start(), timeout)


async def _fixed(reader: asyncio.StreamReader, n: int, timeout: float,
                 pace: Optional[_Pace] = None) -> AsyncIterator[bytes]:
    wait = _waiter(timeout, pace)
    while n > 0:
        k = min(n, _READ)
        data = await wait(lambda: reader.read(k))
        if not data:
            raise ConnectionError("connection closed mid-body")
        n -= len(data)
        yield data


async def _until_eof(reader: asyncio.StreamReader, timeout: float) -> AsyncIterator[bytes]:
    while True:
        data = await asyncio.wait_for(reader.read(_READ), timeout)
        if not data:
            return
        yield data


async def _chunked(reader: asyncio.StreamReader, timeout: float, request: bool,
                   pace: Optional[_Pace] = None) -> AsyncIterator[bytes]:
    """The data of a chunked body. Trailers are read and dropped."""
    err = (lambda why: ClientError(400, why)) if request else BackendError
    wait = _waiter(timeout, pace)
    while True:
        try:
            line = await wait(lambda: reader.readuntil(b"\r\n"))
        except (asyncio.LimitOverrunError, asyncio.IncompleteReadError):
            raise err("malformed chunk") from None
        size = line[:-2].split(b";", 1)[0].strip(b" \t")
        if not _CHUNK_SIZE.fullmatch(size):
            raise err("malformed chunk size")
        remaining = int(size, 16)
        if remaining == 0:
            while True:
                try:
                    trailer = await wait(lambda: reader.readuntil(b"\r\n"))
                except (asyncio.LimitOverrunError, asyncio.IncompleteReadError):
                    raise err("malformed trailer") from None
                if trailer == b"\r\n":
                    return
        while remaining:
            k = min(remaining, _READ)
            data = await wait(lambda: reader.read(k))
            if not data:
                raise ConnectionError("connection closed mid-chunk")
            remaining -= len(data)
            yield data
        if await wait(lambda: reader.readexactly(2)) != b"\r\n":
            raise err("chunk not followed by CRLF")


async def _from_client(body: AsyncIterator[bytes], limit: int) -> AsyncIterator[bytes]:
    """A visitor's request body, at most `limit` bytes (0: no limit)."""
    size = 0
    try:
        async for data in body:
            size += len(data)
            if limit and size > limit:
                raise ClientError(413, f"a request body over max_body_bytes ({limit})")
            yield data
    except asyncio.TimeoutError:
        raise ClientError(408, "request body too slow") from None


async def _spooled(spool) -> AsyncIterator[bytes]:
    while True:
        data = spool.read(_READ)
        if not data:
            return
        yield data


async def _prefetch(body: AsyncIterator[bytes], limit: int) -> Tuple[List[bytes], bool]:
    """Read from `body` until `limit` bytes or its end: (what was read, ended?)."""
    chunks, size = [], 0
    async for data in body:
        chunks.append(data)
        size += len(data)
        if size >= limit:
            return chunks, False
    return chunks, True


async def _chain(first: List[bytes], rest: Optional[AsyncIterator[bytes]]) -> AsyncIterator[bytes]:
    for data in first:
        yield data
    if rest is not None:
        async for data in rest:
            yield data


async def _send(writer: asyncio.StreamWriter, body: Optional[AsyncIterator[bytes]], chunked: bool) -> None:
    if body is not None:
        async for data in body:
            writer.write(b"%x\r\n%s\r\n" % (len(data), data) if chunked else data)
            await writer.drain()
    if chunked:
        writer.write(b"0\r\n\r\n")
    await writer.drain()


def _close(writer: Optional[asyncio.StreamWriter]) -> None:
    if writer is not None and not writer.is_closing():
        writer.close()


# ---- the backend ---------------------------------------------------------------------
class Backend:
    def __init__(self, settings: Settings):
        u = urllib.parse.urlsplit(settings.backend)
        self.settings = settings
        self.host = u.hostname
        self.port = u.port or (443 if u.scheme == "https" else 80)
        self.netloc = u.netloc
        self.ssl: Optional[ssl.SSLContext] = None
        if u.scheme == "https":
            self.ssl = ssl.create_default_context()
            if not settings.backend_tls_verify:
                self.ssl.check_hostname = False
                self.ssl.verify_mode = ssl.CERT_NONE
        self.idle: Deque[Tuple[asyncio.StreamReader, asyncio.StreamWriter, float]] = deque()
        self.opened = 0                                  # connections made, for tests and the benchmark

    async def connect(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port, ssl=self.ssl, limit=self.settings.max_header_bytes,
                                        server_hostname=self.host if self.ssl else None),
                self.settings.connect_timeout)
        except (OSError, asyncio.TimeoutError) as e:
            raise BackendError(f"cannot connect to {self.netloc}: {e or type(e).__name__}") from None
        self.opened += 1
        return reader, writer

    async def acquire(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter, bool]:
        now = time.monotonic()
        while self.idle:
            reader, writer, since = self.idle.pop()
            if writer.is_closing() or reader.at_eof() or now - since > self.settings.backend_idle_timeout:
                _close(writer)
                continue
            return reader, writer, True
        reader, writer = await self.connect()
        return reader, writer, False

    def release(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if len(self.idle) < self.settings.max_idle_backend and not writer.is_closing() and not reader.at_eof():
            self.idle.append((reader, writer, time.monotonic()))
        else:
            _close(writer)

    def close_all(self) -> None:
        while self.idle:
            _close(self.idle.pop()[1])

    async def read_head(self, reader: asyncio.StreamReader) -> Head:
        try:
            data = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self.settings.read_timeout)
        except asyncio.IncompleteReadError as e:
            raise ConnectionResetError("backend closed the connection") if not e.partial else BackendError(
                "backend closed mid-head") from None
        except asyncio.LimitOverrunError:
            raise BackendError("backend response head too large") from None
        return _parse_head(data, request=False)


# ---- the proxy ---------------------------------------------------------------------
def _connection_cap(settings: Settings) -> int:
    """max_connections, or when that is 0 what the open-file limit allows: a
    visitor's connection can hold one to the backend as well, and the pool and
    the process need some files of their own."""
    if settings.max_connections:
        return settings.max_connections
    try:
        import resource
        soft = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    except (ImportError, OSError, ValueError):
        return 512
    if soft == resource.RLIM_INFINITY:
        return 10000
    return max(16, min(10000, (soft - 64 - settings.max_idle_backend) // 2))


class Proxy:
    def __init__(self, settings: Settings, shield: Optional[Shield] = None):
        self.settings = settings
        self.shield = shield or Shield(settings.shield)
        self.backend = Backend(settings)
        self.server: Optional[asyncio.AbstractServer] = None
        self.connections: set = set()
        self.waiting: Dict[asyncio.Task, asyncio.StreamWriter] = {}     # connections between requests
        self.linger: set = set()                                            # writers to close gently
        self.stopping = False
        self.max_connections = _connection_cap(settings)
        self._busy_logged = float("-inf")

    async def start(self, host: Optional[str] = None, port: Optional[int] = None) -> asyncio.AbstractServer:
        self.server = await asyncio.start_server(
            self._connection, host if host is not None else self.settings.listen_host,
            port if port is not None else self.settings.listen_port, limit=self.settings.max_header_bytes)
        return self.server

    @property
    def port(self) -> int:
        return self.server.sockets[0].getsockname()[1]

    async def stop(self, grace: float = 10.0) -> None:
        self.stopping = True
        if self.server is not None:
            self.server.close()
        for writer in list(self.waiting.values()):
            _close(writer)
        if self.connections:
            done, pending = await asyncio.wait(list(self.connections), timeout=grace)
            for task in pending:
                task.cancel()
        self.backend.close_all()

    # -- one client connection: requests one after another ---------------------------------
    async def _connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if len(self.connections) >= self.max_connections:
            return await self._busy(writer)
        task = asyncio.current_task()
        self.connections.add(task)
        peer = (writer.get_extra_info("peername") or ("",))[0] or ""
        trusted = _in_nets(peer, self.shield._trusted)        # may it speak for the client in X-Forwarded-*?
        try:
            while not self.stopping:
                self.waiting[task] = writer
                try:
                    data = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self.settings.idle_timeout)
                except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
                    return
                except asyncio.LimitOverrunError:
                    await self._error(writer, 431, "request head too large")
                    return
                finally:
                    self.waiting.pop(task, None)
                try:
                    head = _parse_head(data, request=True)
                    keep = await self._request(head, reader, writer, peer, trusted)
                except ClientError as e:
                    await self._error(writer, e.status, str(e))
                    return
                if not keep or self.stopping:
                    return
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            return
        except asyncio.CancelledError:
            raise
        except Exception:                                  # a bug must cost one connection, not the proxy
            log.exception("proxy connection failed")
        finally:
            if writer in self.linger:
                self.linger.discard(writer)
                if not writer.is_closing():
                    await self._linger(reader, writer)
            _close(writer)
            self.connections.discard(task)

    async def _busy(self, writer: asyncio.StreamWriter) -> None:
        """Past max_connections: a 503, and the connection closed, unread."""
        now = time.monotonic()
        if now - self._busy_logged >= 60:
            self._busy_logged = now
            log.warning("max_connections (%d) reached: new connections are answered 503", self.max_connections)
        body = b"503 Service Unavailable\n"
        try:
            writer.write(b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\nContent-Type: text/plain; charset=utf-8\r\n"
                         b"Content-Length: %d\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n%s" % (len(body), body))
            await asyncio.wait_for(writer.drain(), 5)
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            _close(writer)

    async def _error(self, writer: asyncio.StreamWriter, status: int, why: str) -> None:
        """Answer and mark the connection for closing; _connection lingers before it closes.
        A 4xx says what was wrong with the request. A 5xx gives its status only:
        what went wrong with the backend (its address, the error) is for the
        log, not for whoever sent the request."""
        reason = _REASONS.get(status, "Error")
        if status >= 500:
            log.warning("%d %s: %s", status, reason, why)
            body = f"{status} {reason}\n".encode()
        else:
            body = f"{status} {reason}: {why}\n".encode()
        writer.write(f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n"
                     f"Content-Length: {len(body)}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n".encode()
                     + body)
        self.linger.add(writer)
        try:
            await writer.drain()
        except ConnectionError:
            pass

    async def _linger(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Close after an answer the client may still be sending into. A socket
        closed with unread input resets the connection, and the client's
        kernel can then throw away the answer before it is read, so: stop
        writing, read and drop what is still coming for a moment, then close."""
        try:
            if writer.can_write_eof():
                writer.write_eof()
            deadline, total = time.monotonic() + 2.0, 0
            while total < 1 << 20 and time.monotonic() < deadline:
                data = await asyncio.wait_for(reader.read(_READ), deadline - time.monotonic())
                if not data:
                    break
                total += len(data)
        except (OSError, asyncio.TimeoutError):
            pass

    async def _request(self, head: Head, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, peer: str,
                       trusted: bool) -> bool:
        """Handle one request. True to keep the client connection for the next."""
        s, shield = self.settings, self.shield
        method, target, version = head.first
        http10 = version == "HTTP/1.0"
        length, chunked = _framing(head, http10, request=True)
        has_body = chunked or bool(length)
        if s.max_body_bytes and length and length > s.max_body_bytes:
            raise ClientError(413, f"a request body over max_body_bytes ({s.max_body_bytes})")
        conn = head.tokens("connection")
        keep = ("keep-alive" in conn) if http10 else ("close" not in conn)
        upgrade = "upgrade" in conn and any(t == "websocket" for t in head.tokens("upgrade")) and method == "GET"
        if upgrade and has_body:
            # A handshake has no body. Forwarded, its Content-Length would leave a
            # backend that turns the upgrade down waiting for bytes the tunnel
            # never sends, and it would read the next request as them.
            raise ClientError(400, "a WebSocket handshake with a body")

        if len(head.get("host")) > 1:
            raise ClientError(400, "more than one Host header")
        h = {k: ("; " if k == "cookie" else ", ").join(v) for k, v in head.index.items()}
        if target.startswith("/"):
            raw_path, _, query = target.partition("?")
        elif target == "*" and method == "OPTIONS":
            raw_path, query = "*", ""
        elif re.match(r"https?://", target, re.I):
            u = urllib.parse.urlsplit(target)                  # the URL's host replaces the Host header
            raw_path, query, h["host"] = u.path or "/", u.query, u.netloc
            target = raw_path + ("?" + query if query else "")
        else:
            raise ClientError(400, "unsupported request target")
        path = urllib.parse.unquote(raw_path, errors="replace")

        ip = shield.client_ip(peer, h.get("x-forwarded-for"))
        started = time.perf_counter()
        pace = _Pace(s.read_timeout, s.min_body_rate)
        upload = _from_client(_chunked(reader, s.read_timeout, True, pace) if chunked else
                              _fixed(reader, length, s.read_timeout, pace), s.max_body_bytes) if has_body else None
        continued = "100-continue" in head.tokens("expect") and has_body and not http10
        prefix, limit = None, shield.cfg.honeytoken_body_limit
        if upload is not None and shield.cfg.honeytokens and limit:
            # Honeytokens: the shield reads the start of the body before it decides.
            if continued:
                writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                await writer.drain()
                continued = False
            chunks, ended = await _prefetch(upload, limit)
            prefix = b"".join(chunks)[:limit]
            upload = _chain(chunks, None if ended else upload)
        d = shield.check(ip, method, path, query, h, prefix)

        if d.stop:
            _, status, hdrs, body = _reply(d)
            keep = keep and not has_body           # an unread body would be taken for the next request
            if not keep:
                self.linger.add(writer)
            out = "".join(f"{k}: {v}\r\n" for k, v in hdrs)
            writer.write(f"HTTP/1.1 {status}\r\n{out}Connection: {'keep-alive' if keep else 'close'}\r\n\r\n".encode()
                         + (b"" if method == "HEAD" else body))
            await writer.drain()
            self._access(peer, ip, method, target, status.split()[0], d, started)
            return keep
        route = shield.client_check_route(path)
        if route:
            return await self._client_check(route, writer, method, query, h, ip, trusted, keep and not has_body,
                                            peer, target, d, started)
        if method == "CONNECT":
            await self._error(writer, 405, "this is a reverse proxy")
            return False

        if continued:
            writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")      # the backend is not asked: the shield said yes
            await writer.drain()

        spool = None
        try:
            if upload is not None and s.buffer_requests:
                # The whole body first, then the backend: a visitor that sends
                # slowly holds a connection of the proxy's, never one of the site's.
                spool, length = await self._buffer(upload)
                upload, chunked = _spooled(spool), False
            forward = self._forward_head(head, method, target, peer, trusted, h, length, chunked, upgrade)
            if upgrade:
                return await self._tunnel(forward, reader, writer, peer, ip, path, d, method, target, started)

            retry = method in IDEMPOTENT and not has_body
            for attempt in (1, 2):
                bw, reused = None, False
                try:
                    br, bw, reused = await self.backend.acquire()
                    bw.write(forward)
                    await _send(bw, upload, chunked)
                    response = await self.backend.read_head(br)
                    break
                except ConnectionError as e:
                    _close(bw)
                    if reused and retry and attempt == 1:
                        continue                                    # a pooled connection the backend had closed
                    await self._error(writer, 502, str(e) or "backend closed the connection")
                    return False
                except asyncio.TimeoutError:                       # before OSError: from 3.11 it is one
                    _close(bw)
                    await self._error(writer, 504, "backend did not answer in time")
                    return False
                except (BackendError, OSError) as e:
                    _close(bw)
                    await self._error(writer, 502, str(e) or "backend error")
                    return False
                except ClientError:
                    _close(bw)
                    raise
            while response.first[1].startswith("1") and response.first[1] != "101":   # interim responses
                if response.first[1] != "100" and not http10:
                    writer.write(self._head_bytes(response, []))
                    await writer.drain()
                try:
                    response = await self.backend.read_head(br)
                except (BackendError, ConnectionError, asyncio.TimeoutError):
                    _close(bw)
                    await self._error(writer, 502, "backend failed after an interim response")
                    return False
            if response.first[1] == "101":
                _close(bw)
                await self._error(writer, 502, "backend switched protocols unasked")
                return False
            return await self._respond(response, br, bw, writer, method, version, keep, peer, ip, target, path, d,
                                       started)
        finally:
            if spool is not None:
                spool.close()

    async def _buffer(self, upload: AsyncIterator[bytes]) -> Tuple[Any, int]:
        """A request's whole body and its size: in memory up to body_buffer_bytes,
        past that in a temporary file (deleted when closed)."""
        spool = tempfile.SpooledTemporaryFile(max_size=max(1, self.settings.body_buffer_bytes))
        size = 0
        try:
            async for data in upload:
                spool.write(data)
                size += len(data)
            spool.seek(0)
        except BaseException:
            spool.close()
            raise
        return spool, size

    async def _client_check(self, route, writer, method, query, h, ip, trusted, keep, peer, target, d,
                            started) -> bool:
        """The client check's script and endpoint, answered here, not by the site."""
        shield = self.shield
        if route == "script":
            code, hdrs, payload = shield.client_check_asset()
        else:
            proto = h.get("x-forwarded-proto", "").split(",")[0].strip().lower()
            code, hdrs, payload = shield.client_check_reply(ip, query, h, secure=trusted and proto == "https")
        if not keep:
            self.linger.add(writer)                        # a body came with it, unread
        out = "".join(f"{k}: {v}\r\n" for k, v in hdrs)
        writer.write(f"HTTP/1.1 {code} {'OK' if code == 200 else 'No Content'}\r\n{out}"
                     f"Connection: {'keep-alive' if keep else 'close'}\r\n\r\n".encode()
                     + (b"" if method == "HEAD" else payload))
        await writer.drain()
        self._access(peer, ip, method, target, str(code), d, started)
        return keep

    def _forward_head(self, head: Head, method: str, target: str, peer: str, trusted: bool, h: Dict[str, str],
                      length: Optional[int], chunked: bool, upgrade: bool) -> bytes:
        listed = set(head.tokens("connection"))
        lines = [f"{method} {target} HTTP/1.1"]
        for name, value in head.headers:
            low = name.lower()
            if (low in HOP_BY_HOP or low in listed or low in ("content-length", "expect", "host")
                    or low.startswith("x-forwarded-") or low == "forwarded"):
                continue
            lines.append(f"{name}: {value}")
        host = h.get("host", "")
        lines.insert(1, f"Host: {self.backend.netloc if self.settings.backend_host_header == 'backend' or not host else host}")
        xff = h.get("x-forwarded-for", "") if trusted else ""
        lines.append(f"X-Forwarded-For: {xff + ', ' + peer if xff else peer}")
        proto = h.get("x-forwarded-proto", "").split(",")[0].strip().lower() if trusted else ""
        lines.append(f"X-Forwarded-Proto: {proto if proto in ('http', 'https') else 'http'}")
        fwd_host = h.get("x-forwarded-host", "") if trusted else ""
        if fwd_host or host:
            lines.append(f"X-Forwarded-Host: {fwd_host or host}")
        if chunked:
            lines.append("Transfer-Encoding: chunked")
        elif length:
            lines.append(f"Content-Length: {length}")
        elif method in ("POST", "PUT", "PATCH"):
            lines.append("Content-Length: 0")
        if upgrade:
            lines += [f"Upgrade: {', '.join(head.get('upgrade'))}", "Connection: Upgrade"]
        else:
            lines.append("Connection: keep-alive")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")

    def _head_bytes(self, response: Head, extra: List[Tuple[str, str]], drop: frozenset = HOP_BY_HOP) -> bytes:
        version, status, reason = response.first
        listed = set(response.tokens("connection")) - {"upgrade"} if status == "101" else set(response.tokens("connection"))
        out = [f"HTTP/1.1 {status} {reason}"]
        out += [f"{k}: {v}" for k, v in response.headers if k.lower() not in drop and k.lower() not in listed]
        out += [f"{k}: {v}" for k, v in extra]
        return ("\r\n".join(out) + "\r\n\r\n").encode("latin-1")

    async def _respond(self, response: Head, br, bw, writer, method, version, keep, peer, ip, target, path, d,
                       started, reuse: bool = True) -> bool:
        s = self.settings
        status = int(response.first[1])
        try:
            self.shield.observe(ip, path, status, d.induced, (response.get("content-type") or [""])[0])
        except Exception:
            log.exception("observe failed")
        no_body = method == "HEAD" or status in (204, 304)
        try:
            length, chunked = _framing(response, response.first[0] == "HTTP/1.0", request=False)
        except BackendError as e:
            _close(bw)
            await self._error(writer, 502, str(e))
            return False
        backend_keep = (response.first[0] == "HTTP/1.1" and "close" not in response.tokens("connection")
                        and (no_body or chunked or length is not None))
        extra: List[Tuple[str, str]] = []
        small = b""
        if no_body:
            body = None
            to_client_chunked = False
        elif chunked or length is None:
            body = _chunked(br, s.read_timeout, False) if chunked else _until_eof(br, s.read_timeout)
            to_client_chunked = version == "HTTP/1.1"
            if to_client_chunked:
                extra.append(("Transfer-Encoding", "chunked"))
            else:
                keep = False                                  # an HTTP/1.0 client reads to the close
        elif length and length <= _READ:
            try:                                              # small and sized: send it with its head, in one write
                body = None
                small = await asyncio.wait_for(br.readexactly(length), s.read_timeout)
            except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError):
                _close(bw)
                await self._error(writer, 502, "backend closed mid-answer")
                return False
            to_client_chunked = False
        else:
            body = _fixed(br, length, s.read_timeout) if length else None
            to_client_chunked = False
        extra.append(("Connection", "keep-alive" if keep else "close"))
        writer.write(self._head_bytes(response, extra) + small)
        try:
            await _send(writer, body, to_client_chunked)
        except (BackendError, ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            _close(bw)                                        # nothing sensible to tell the client mid-body
            self._access(peer, ip, method, target, str(status), d, started)
            return False
        if backend_keep and reuse:
            self.backend.release(br, bw)
        else:
            _close(bw)
        self._access(peer, ip, method, target, str(status), d, started)
        return keep

    async def _tunnel(self, forward, reader, writer, peer, ip, path, d, method, target, started) -> bool:
        """A WebSocket upgrade: its own backend connection, then bytes both ways."""
        bw = None
        try:
            br, bw = await self.backend.connect()
            bw.write(forward)
            await bw.drain()
            response = await self.backend.read_head(br)
        except asyncio.TimeoutError:
            _close(bw)
            await self._error(writer, 504, "backend did not answer in time")
            return False
        except (BackendError, OSError) as e:
            _close(bw)
            await self._error(writer, 502, str(e) or "backend error")
            return False
        if response.first[1] != "101":
            # Turned down. The connection was asked to switch protocols, so it is
            # not one to hand the next request: close it, whatever it says.
            return await self._respond(response, br, bw, writer, method, "HTTP/1.1", False, peer, ip, target, path,
                                       d, started, reuse=False)
        try:
            self.shield.observe(ip, path, 101, d.induced)
        except Exception:
            log.exception("observe failed")
        writer.write(self._head_bytes(response, [], drop=frozenset({"keep-alive", "proxy-connection", "te",
                                                                     "trailer", "transfer-encoding"})))
        await writer.drain()
        self._access(peer, ip, method, target, "101", d, started)

        async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while True:
                    data = await src.read(_READ)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                if dst.can_write_eof() and not dst.is_closing():
                    try:
                        dst.write_eof()
                    except OSError:
                        pass

        ups = [asyncio.ensure_future(pump(reader, bw)), asyncio.ensure_future(pump(br, writer))]
        try:
            done, pending = await asyncio.wait(ups, return_when=asyncio.FIRST_COMPLETED)
            if pending:
                await asyncio.wait(pending, timeout=5.0)
        finally:
            for task in ups:
                task.cancel()
            _close(bw)
        return False

    def _access(self, peer, ip, method, target, status, d, started) -> None:
        if self.settings.access_log:
            log.info("%s %s %s %s -> %s [%s] %.1f ms", peer, ip, method, target[:200], status, d.action,
                     (time.perf_counter() - started) * 1000)


# ---- command line ---------------------------------------------------------------------
def decoys(settings: Settings) -> str:
    """What to plant on the site for the decoys these settings watch for. A
    site behind the proxy may not be Python, so it cannot call the helpers."""
    cfg, tokens, out = settings.shield, getattr(settings, "honeytoken_set", None), []
    canaries = list(cfg.canary_paths)
    if canaries:
        out += ["# robots.txt: add these lines", robots_txt_block(canaries),
                "# HTML: a link no visitor sees, for your page template", html_trap(canaries[0]), "",
                "# JavaScript: a dead constant, for your bundle", js_trap(canaries[-1]), ""]
    if tokens is not None:
        out += ["# JavaScript: fake credentials, for your bundle", honeytoken_js(tokens, 0), "",
                "# HTML: a comment with fake credentials, for your page template", honeytoken_html(tokens, 1), ""]
    if cfg.client_check:
        out += ["# HTML: the client check, on every page", client_check_tag(cfg.client_check_path.rstrip("/")), ""]
    if not out:
        return ("# Nothing to plant. Set canary_secret, honeytoken_secret or client_check "
                "(ARTEX_SHIELD_CANARY_SECRET, ARTEX_SHIELD_HONEYTOKEN_SECRET, ARTEX_SHIELD_CLIENT_CHECK).")
    return "\n".join(out).rstrip()



async def serve(settings: Settings) -> None:
    proxy = Proxy(settings)
    await proxy.start()
    for sock in proxy.server.sockets:
        host, port = sock.getsockname()[:2]
        log.warning("artex-shield-proxy listening on %s:%s, forwarding to %s, mode %s, up to %d connections",
                    f"[{host}]" if ":" in host else host, port, settings.backend, settings.shield.mode,
                    proxy.max_connections)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            pass
    await stop.wait()
    log.warning("artex-shield-proxy stopping")
    await proxy.stop()


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="artex-shield-proxy", description="Run artex-shield in front of any website.")
    ap.add_argument("--config", help="TOML file (Python 3.11+); also ARTEX_SHIELD_CONFIG")
    ap.add_argument("--backend", help="where allowed requests go, e.g. http://127.0.0.1:8000")
    ap.add_argument("--listen", help="host:port to listen on (default 0.0.0.0:8080)")
    ap.add_argument("--mode", choices=("monitor", "enforce"))
    ap.add_argument("--check-config", action="store_true", help="print the settings in effect and exit")
    ap.add_argument("--print-decoys", action="store_true",
                    help="print what to plant on your site (canaries, honeytokens, client check) and exit")
    args = ap.parse_args(argv)
    logging.basicConfig(level=os.environ.get("ARTEX_SHIELD_LOG_LEVEL", "INFO").upper(), format="%(message)s",
                        stream=sys.stderr)
    try:
        settings = load_settings(args.config, overrides={"backend": args.backend, "listen": args.listen,
                                                         "mode": args.mode})
    except (ValueError, OSError, KeyError, TypeError) as e:
        print(f"artex-shield-proxy: {e}", file=sys.stderr)
        return 2
    if args.check_config:
        shown = {f.name: getattr(settings, f.name) for f in fields(Settings) if f.name != "shield"}
        shown["shield"] = {f.name: getattr(settings.shield, f.name) for f in fields(Config)
                           if f.name not in ("on_event", "engagements")}
        shown["shield"]["engagements"] = [e.reference for e in settings.shield.engagements]
        print(json.dumps(shown, indent=2, default=str))
        return 0
    if args.print_decoys:
        print(decoys(settings))
        return 0
    try:
        asyncio.run(serve(settings))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
