"""Decoy kit: canary paths and credential honeytokens, planted where only a
harvester, a crawler or someone reading your source looks."""
from __future__ import annotations

import hashlib
import hmac
import json
import string
from dataclasses import dataclass
from typing import Iterable, Iterator, List, Tuple


def make_canaries(secret: str, count: int = 3) -> List[str]:
    """Stable, unguessable decoy paths derived from a secret you keep.

    The shapes are chosen for what ARTEX's harvester keeps: it pulls quoted
    strings that start with /api, /admin, /v1 ... out of JS bundles and drops
    anything ending in an asset extension (skills/api-recon/scripts/harvest_static.py).
    """
    shapes = ["/api/v1/internal/audit-{}", "/admin/legacy-{}/export", "/api/v2/debug/session-{}",
              "/backend/ops-{}/config", "/api/v1/staff/reports-{}"]
    out = []
    for i in range(count):
        tag = hmac.new(secret.encode(), f"canary-{i}".encode(), hashlib.sha256).hexdigest()[:10]
        out.append(shapes[i % len(shapes)].format(tag))
    return out


def robots_txt_block(canaries: Iterable[str]) -> str:
    """Disallow lines for robots.txt. Polite crawlers stay out; anything that
    reads robots.txt as a to-do list walks into the decoys."""
    return "User-agent: *\n" + "".join(f"Disallow: {p}\n" for p in canaries)


def html_trap(canary: str) -> str:
    """A link no person can see or reach by keyboard. Also list the path in robots.txt."""
    return (f'<a href="{canary}" rel="nofollow" tabindex="-1" aria-hidden="true" '
            f'style="position:absolute;left:-9999px">.</a>')


def js_trap(canary: str, name: str = "__legacyApi") -> str:
    """A dead constant for your JS bundle. Your code never calls it; a static
    endpoint harvester extracts it and then requests it."""
    return f'var {name} = "{canary}";'


# ---- credential honeytokens -------------------------------------------------
_BASE62 = string.digits + string.ascii_uppercase + string.ascii_lowercase
# Names for the fake accounts. They are decoration: a username is not secret
# and could be someone's real one, so presenting it alone triggers nothing.
_USERS = ("svc-deploy", "admin-legacy", "ops-backup", "staging-admin")


def _base62(data: bytes, length: int) -> str:
    n, out = int.from_bytes(data, "big"), []
    for _ in range(length):
        n, r = divmod(n, 62)
        out.append(_BASE62[r])
    return "".join(out)


@dataclass(frozen=True)
class Honeytokens:
    """Fake credentials derived from a secret. Iterating gives the values the
    shield watches for (the API keys and passwords), so an instance can be
    passed straight to Config(honeytokens=...)."""
    api_keys: Tuple[str, ...]
    users: Tuple[str, ...]
    passwords: Tuple[str, ...]

    def __iter__(self) -> Iterator[str]:
        return iter(self.api_keys + self.passwords)


def make_honeytokens(secret: str, count: int = 2) -> Honeytokens:
    """Stable fake API keys and passwords derived from a secret you keep (the
    canary secret will do: different derivations, so nothing repeats).

    They look like credentials someone forgot to remove, and they open
    nothing: there is no account behind them, so the only way a request
    carries one is that someone harvested it from where you planted it.
    The key format deliberately matches no real provider's (no sk_live_,
    AKIA, ghp_, AIza...), so planting them sets off no secret scanner and
    sends no false leak report to a provider."""
    if count < 1:
        raise ValueError("count must be at least 1")

    def derive(label: str) -> bytes:
        return hmac.new(secret.encode(), f"honeytoken-{label}".encode(), hashlib.sha256).digest()

    keys, passwords = [], []
    for i in range(count):
        keys.append("api_live_" + _base62(derive(f"key-{i}"), 32))
        d = derive(f"password-{i}")
        body, at = _base62(d, 14), d[1] % 14
        passwords.append(body[:at] + "!@#$*"[d[0] % 5] + body[at:] + str(d[2] % 10))
    users = tuple(_USERS[i % len(_USERS)] for i in range(count))
    return Honeytokens(tuple(keys), users, tuple(passwords))


def honeytoken_js(tokens: Honeytokens, index: int = 0, name: str = "__stagingConfig") -> str:
    """A dead config object for your JS bundle, in the shape a forgotten
    staging setup leaves behind. Your code never reads it; whoever reads
    the bundle finds a key and a login."""
    i = index % len(tokens.api_keys)
    config = {"apiBase": "/api/v1", "apiKey": tokens.api_keys[i], "adminUser": tokens.users[i],
              "adminPassword": tokens.passwords[i]}
    return f"var {name} = {json.dumps(config)};"


def honeytoken_html(tokens: Honeytokens, index: int = 1) -> str:
    """An HTML comment for your base template: credentials someone meant to
    remove before release. Plant a different index here than in the bundle,
    and the log says which one was harvested."""
    i = index % len(tokens.api_keys)
    return (f"<!-- TODO(ops): remove before release. Staging admin login {tokens.users[i]} / {tokens.passwords[i]} "
            f"; reporting API key {tokens.api_keys[i]} -->")
