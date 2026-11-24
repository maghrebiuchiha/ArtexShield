"""WSGI and ASGI adapters."""
from __future__ import annotations

from typing import Dict, List, Tuple

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
        d = s.check(ip, environ.get("REQUEST_METHOD", "GET"), path, environ.get("QUERY_STRING", ""), headers)
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
        d = s.check(ip, scope.get("method", "GET"), path,
                    (scope.get("query_string") or b"").decode("latin-1"), headers)
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
