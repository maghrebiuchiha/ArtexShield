"""Decoy kit: canary paths planted where only a harvester or crawler looks."""
from __future__ import annotations

import hashlib
import hmac
from typing import Iterable, List


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
