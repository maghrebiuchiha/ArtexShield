"""WSGI and ASGI adapters."""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .core import Decision, Shield
from .util import _in_nets


def _https(shield: Shield, scheme: str, peer: str, headers: Dict[str, str]) -> bool:
    """Did the visitor use HTTPS? Behind your own proxy, believe its X-Forwarded-Proto."""
    if scheme == "https":
        return True
    proto = headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return proto == "https" and _in_nets(peer, shield._trusted)


def _content_type(hdrs) -> str:
    for k, v in hdrs or ():
        name = k.decode("latin-1") if isinstance(k, bytes) else k
        if name.lower() == "content-type":
            return v.decode("latin-1") if isinstance(v, bytes) else v
    return ""


def _reply(d: Decision) -> Tuple[int, str, List[Tuple[str, str]], bytes]:
    if d.action in ("block", "refuse"):
        word = "blocked" if d.action == "block" else "refused"
        body = f"Request {word}. Reference: {d.ref}\n".encode()
        return 403, "403 Forbidden", [("Content-Type", "text/plain; charset=utf-8"),
                                      ("Content-Length", str(len(body))), ("Cache-Control", "no-store")], body
    body = f"Too many requests. Reference: {d.ref}\n".encode()
    return 429, "429 Too Many Requests", [("Content-Type", "text/plain; charset=utf-8"),
                                          ("Content-Length", str(len(body))),
                                          ("Retry-After", str(d.retry_after)), ("Cache-Control", "no-store")], body


class _Replay:
    """wsgi.input for the app after the shield has read the start of the body:
    those bytes first, then the rest of the original stream."""

    def __init__(self, head: bytes, rest, remaining: Optional[int]):
        self._head, self._rest, self._remaining = head, rest, remaining
        self._pos = 0

    def _more(self, size: int) -> bytes:
        if self._remaining is not None:
            size = self._remaining if size < 0 else min(size, self._remaining)
            if size <= 0:
                return b""
        data = self._rest.read(size) if size >= 0 else self._rest.read()
        if self._remaining is not None:
            self._remaining -= len(data)
        return data

    def read(self, size: Optional[int] = -1) -> bytes:
        size = -1 if size is None else size
        if size < 0:
            data, self._pos = self._head[self._pos:], len(self._head)
            return data + self._more(-1)
        data = self._head[self._pos:self._pos + size]
        self._pos += len(data)
        return data + (self._more(size - len(data)) if len(data) < size else b"")

    def readline(self, size: Optional[int] = -1) -> bytes:
        size = -1 if size is None else size
        end = self._head.find(b"\n", self._pos)
        stop = len(self._head) if end < 0 else end + 1
        if size >= 0:
            stop = min(stop, self._pos + size)
        line, self._pos = self._head[self._pos:stop], stop
        if line.endswith(b"\n") or (size >= 0 and len(line) >= size) or self._pos < len(self._head):
            return line
        rest_size = -1 if size < 0 else size - len(line)
        if self._remaining is not None:
            rest_size = self._remaining if rest_size < 0 else min(rest_size, self._remaining)
            if rest_size <= 0:
                return line
        more = self._rest.readline(rest_size) if rest_size >= 0 else self._rest.readline()
        if self._remaining is not None:
            self._remaining -= len(more)
        return line + more

    def readlines(self, hint: int = -1) -> List[bytes]:
        lines, total = [], 0
        while True:
            line = self.readline()
            if not line:
                return lines
            lines.append(line)
            total += len(line)
            if 0 < hint <= total:
                return lines

    def __iter__(self):
        return iter(self.readline, b"")


def _wsgi_body(environ, limit: int) -> bytes:
    """Read the start of the request body for the honeytoken check and leave
    the whole body in place for the app. Never reads a body of unknown length
    from a server that does not mark its end: that read could block."""
    stream = environ.get("wsgi.input")
    if not limit or stream is None:
        return b""
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    if length > 0:
        head = stream.read(min(length, limit))
        environ["wsgi.input"] = _Replay(head, stream, length - len(head))
    elif environ.get("wsgi.input_terminated"):
        head = stream.read(limit)
        environ["wsgi.input"] = _Replay(head, stream, None)
    else:
        return b""
    return head


class ShieldWSGI:
    """Flask:   app.wsgi_app = ShieldWSGI(app.wsgi_app, shield)
    Django:  application = ShieldWSGI(get_wsgi_application(), shield)"""

    def __init__(self, app, shield: Shield):
        self.app, self.shield = app, shield

    def __call__(self, environ, start_response):
        s = self.shield
        ip = s.client_ip(environ.get("REMOTE_ADDR", ""), environ.get("HTTP_X_FORWARDED_FOR"))
        headers = {k[5:].replace("_", "-"): v for k, v in environ.items() if k.startswith("HTTP_")}
        path = environ.get("PATH_INFO", "/")
        body = _wsgi_body(environ, s.cfg.honeytoken_body_limit) if s.cfg.honeytokens else None
        d = s.check(ip, environ.get("REQUEST_METHOD", "GET"), path, environ.get("QUERY_STRING", ""), headers, body)
        if d.stop:
            _, status, hdrs, body = _reply(d)
            start_response(status, hdrs)
            return [body]
        route = s.client_check_route(path)
        if route:
            lower = {k.lower(): v for k, v in headers.items()}
            code, hdrs, body = (s.client_check_asset() if route == "script" else
                                s.client_check_reply(ip, environ.get("QUERY_STRING", ""), lower,
                                                     _https(s, environ.get("wsgi.url_scheme", ""),
                                                            environ.get("REMOTE_ADDR", ""), lower)))
            start_response({200: "200 OK", 204: "204 No Content"}[code], hdrs)
            return [body]

        def watching(status, hdrs, exc_info=None):
            try:
                s.observe(ip, path, int(status.split(" ", 1)[0]), d.induced, _content_type(hdrs))
            except Exception:
                s.log.exception("observe failed")
            return start_response(status, hdrs, exc_info) if exc_info else start_response(status, hdrs)

        return self.app(environ, watching)


async def _asgi_body(receive, limit: int):
    """Read the start of the request body for the honeytoken check; return it
    and a receive that hands the app every message again, then the rest."""
    held, size = [], 0
    while size < limit:
        message = await receive()
        held.append(message)
        if message.get("type") != "http.request":
            break
        size += len(message.get("body", b""))
        if not message.get("more_body"):
            break
    body = b"".join(m.get("body", b"") for m in held if m.get("type") == "http.request")[:limit]

    async def replay():
        return held.pop(0) if held else await receive()

    return body, replay


class ShieldASGI:
    """FastAPI / Starlette:  app.add_middleware(ShieldASGI, shield=shield)"""

    def __init__(self, app, shield: Shield):
        self.app, self.shield = app, shield

    async def __call__(self, scope, receive, send):
        kind = scope.get("type")
        if kind not in ("http", "websocket"):       # lifespan and the like
            return await self.app(scope, receive, send)
        s = self.shield
        headers: Dict[str, str] = {}
        for k, v in scope.get("headers") or []:
            name = k.decode("latin-1").lower()
            val = v.decode("latin-1")
            headers[name] = f"{headers[name]}, {val}" if name in headers else val
        peer = (scope.get("client") or ("", 0))[0]
        ip = s.client_ip(peer, headers.get("x-forwarded-for"))
        path = scope.get("path", "/")
        body = None
        if kind == "http" and s.cfg.honeytokens and s.cfg.honeytoken_body_limit and (
                headers.get("content-length", "0").strip() not in ("", "0") or "transfer-encoding" in headers):
            body, receive = await _asgi_body(receive, s.cfg.honeytoken_body_limit)
        d = s.check(ip, scope.get("method", "GET"), path,
                    (scope.get("query_string") or b"").decode("latin-1"), headers, body)
        if kind == "websocket":
            # The handshake is a GET like any other, checked before the socket
            # opens. Closing before accepting makes the server answer it 403.
            if d.stop:
                await receive()                     # websocket.connect
                return await send({"type": "websocket.close", "code": 1008})
            return await self.app(scope, receive, send)     # no status code to observe afterwards
        if d.stop:
            code, _, hdrs, body = _reply(d)
            await send({"type": "http.response.start", "status": code,
                        "headers": [(k.lower().encode(), v.encode()) for k, v in hdrs]})
            return await send({"type": "http.response.body", "body": body})
        route = s.client_check_route(path)
        if route:
            code, hdrs, body = (s.client_check_asset() if route == "script" else
                                s.client_check_reply(ip, (scope.get("query_string") or b"").decode("latin-1"), headers,
                                                     _https(s, scope.get("scheme", ""), peer, headers)))
            await send({"type": "http.response.start", "status": code,
                        "headers": [(k.lower().encode(), v.encode()) for k, v in hdrs]})
            return await send({"type": "http.response.body", "body": body})

        async def watching(message):
            if message.get("type") == "http.response.start":
                try:
                    s.observe(ip, path, int(message.get("status", 200)), d.induced,
                              _content_type(message.get("headers")))
                except Exception:
                    s.log.exception("observe failed")
            await send(message)

        await self.app(scope, receive, watching)
