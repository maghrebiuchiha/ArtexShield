"""Configuration, tracking, sensors and fire control."""
from __future__ import annotations

import base64
import binascii
import json
import logging
import math
import re
import secrets
import statistics
import threading
import time
from collections import OrderedDict, deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from . import client_check as _cc
from .signatures import (ASSESSMENT_UA, BROWSER_UA, CRAWLER_UA, HARD_UA, MISSING_SENSITIVE, ODD_METHODS,
                         OOB, PAYLOADS, RECON_PATHS, SENSITIVE_PATHS, SOFT_METHODS, SOFT_UA)
from .util import (_decode, _extension, _file_lock, _hop_ip, _in_nets, _induced, _is_network, _nets, _norm_path,
                   _prefixes, _read_state, _strip_sql_comments, _track_key, _ts, _under, _url_text, _usable_ip,
                   _wider, _write_atomic)

_Hit = Tuple[str, float, bool]       # label, points, soft?
_MISSING_MEMORY = 128                # missing paths remembered per client, so repeats are not recounted


@dataclass
class Engagement:
    """An authorised assessment. ARTEX's own docs say a matching User-Agent
    alone must never justify an allowlist entry, so all three facts must hold:
    the reference, the source range, and the time window."""
    reference: str
    cidrs: List[str]
    start: datetime
    end: datetime

    def covers(self, ref: str, ip: str, now: float) -> bool:
        if ref != self.reference:
            return False
        if not (_ts(self.start) <= now < _ts(self.end)):
            return False
        return _in_nets(ip, _nets(self.cidrs))


@dataclass
class Config:
    mode: str = "monitor"            # "monitor" logs what it would do; "enforce" does it
    throttle_score: float = 50.0
    block_score: float = 100.0
    half_life: float = 600.0         # seconds for a score to halve
    block_ttl: float = 3600.0        # first block; doubles per repeat offence
    max_block_ttl: float = 86400.0
    # Minimum Retry-After. ARTEX's governor gives up on a request when Retry-After
    # exceeds its profile's MaxDelay (10 s / 30 s / 60 s in egress/egress.go).
    retry_after: int = 120
    ignored_throttle_points: float = 5.0
    trusted_proxies: List[str] = field(default_factory=list)   # CIDRs allowed to set X-Forwarded-For
    allow_cidrs: List[str] = field(default_factory=list)       # never scored (monitors, partners)
    exempt_paths: List[str] = field(default_factory=list)      # these paths and what is under them: never scored
    engagements: List[Engagement] = field(default_factory=list)
    canary_paths: List[str] = field(default_factory=list)      # see make_canaries()
    enum_404_threshold: int = 15     # different paths answered 404 inside enum_window
    enum_window: float = 60.0
    rate_limit: int = 240            # requests inside rate_window
    rate_window: float = 60.0
    cadence_samples: int = 30        # evenly spaced requests = machine pacing
    cadence_min_mean: float = 0.15   # faster than this is the flood sensor's job
    cadence_max_mean: float = 2.0
    cadence_max_cv: float = 0.35
    tls_header: Optional[str] = None           # e.g. "X-JA4", set by your edge proxy
    tls_denylist: Iterable[str] = ()           # fingerprints you captured yourself
    max_tracks: int = 50000
    blocklist_export_path: Optional[str] = None
    blocklist_export_format: str = "nginx"     # "nginx" or "plain"
    logger: str = "artex_shield"
    on_event: Optional[Callable[[dict], None]] = None
    # Most that soft signals (scored once per half-life) can hold between them.
    # Kept below throttle_score so they cannot stop a request without hard
    # evidence beside them. None means 80% of throttle_score.
    soft_cap: Optional[float] = None
    # 404s that never count as path enumeration: under these paths (routes that
    # answer 404 for "no such item"), or with these extensions (a page asking
    # for assets that are gone is not guessing). Recon and dump names still score.
    enum_ignore_prefixes: List[str] = field(default_factory=list)
    enum_ignore_extensions: Iterable[str] = ("js", "mjs", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "webp",
                                             "avif", "ico", "woff", "woff2", "ttf", "otf", "eot", "mp3", "mp4", "webm")
    # False: a request that a web page made the visitor's browser send (see
    # util._induced) is never held against the visitor; if it trips a hard
    # signal that one request is refused. True: score it like any other, which
    # lets anyone who can show your visitors an image tag get them blocked.
    score_induced: bool = False
    max_blocks: int = 100000         # most blocks held; past it the ones nearest expiry go first
    # IPv6 block widening, off by default. One host can own a /56 or a /48 and
    # move to a fresh /64 for every request. Set this to N (8 is a reasonable
    # start) and when N /64s inside one /56 are blocked at once the /56 is
    # blocked, and the same again from /56 to /48. Off, because a /56 or /48
    # can also be a provider's pool shared by hundreds of customers, who would
    # all be blocked together. 0 is off; 1 is refused.
    v6_escalate_after: int = 0
    # Guessing below enum_404_threshold a minute used to cost nothing for ever.
    # A client gets this many newly missing paths per slow_enum_window; each one
    # past that scores slow_enum_points. 0 switches it off.
    slow_enum_budget: int = 60
    slow_enum_window: float = 3600.0
    slow_enum_points: float = 10.0
    # Optional client-side check, off by default; see client_check.py. Put
    # client_check_tag(config) on every HTML page first. API requests (under
    # client_check_api_prefixes) that a page's script made then score, softly,
    # when the client loaded pages but never completed the check
    # ("client:no-check"), or when it reported browser automation
    # ("client:automation-reported"). Navigations and image loads are never
    # scored, so visitors without JavaScript are not affected.
    client_check: bool = False
    # Signs the cookie. Give every worker the same secret; None makes a random
    # one per process, which a client's cookie only matches on the worker that set it.
    client_check_secret: Optional[str] = None
    client_check_path: str = "/_artex/check"          # the script is served at this path + ".js"
    client_check_cookie: str = "artex_check"
    client_check_api_prefixes: List[str] = field(default_factory=lambda: ["/api"])
    client_check_grace: float = 30.0   # after a client's first page, how long its API calls may run unchecked
    client_check_ttl: float = 86400.0  # how long a check cookie is good for
    client_check_points: float = 20.0
    # Credential honeytokens (see make_honeytokens): fake API keys and
    # passwords you planted. A request presenting one, in any header (Basic
    # auth included), a cookie, the query, the path or the body, is blocked
    # on the spot. Bodies are read up to honeytoken_body_limit bytes, and
    # only when honeytokens are set.
    honeytokens: Iterable[str] = ()
    honeytoken_body_limit: int = 65536

    def __post_init__(self):
        if self.mode not in ("monitor", "enforce"):
            raise ValueError("mode must be 'monitor' or 'enforce'")
        for name, least in (("rate_limit", 1), ("cadence_samples", 2), ("enum_404_threshold", 1), ("max_tracks", 1),
                            ("max_blocks", 1), ("v6_escalate_after", 0), ("slow_enum_budget", 0)):
            if getattr(self, name) < least:
                raise ValueError(f"{name} must be at least {least}")
        if self.v6_escalate_after == 1:
            raise ValueError("v6_escalate_after must be 0 (off) or at least 2")
        for name in ("half_life", "rate_window", "enum_window", "slow_enum_window", "block_ttl"):
            if not getattr(self, name) > 0:
                raise ValueError(f"{name} must be positive")
        _prefixes(self.exempt_paths, "exempt_paths")
        _prefixes(self.enum_ignore_prefixes, "enum_ignore_prefixes")
        if isinstance(self.honeytokens, str):
            raise ValueError("honeytokens must be a list of values (or make_honeytokens(...)), not one string")
        self.honeytokens = tuple(dict.fromkeys(str(t) for t in self.honeytokens))
        for token in self.honeytokens:
            if len(token) < 12 or any(c.isspace() for c in token):
                raise ValueError(f"honeytoken {token[:4]}... must be at least 12 characters with no whitespace: "
                                 "anything shorter could turn up in ordinary requests")
        if self.honeytoken_body_limit < 0:
            raise ValueError("honeytoken_body_limit must not be negative")
        _prefixes(self.client_check_api_prefixes, "client_check_api_prefixes")
        _prefixes([self.client_check_path], "client_check_path")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.client_check_cookie):
            raise ValueError("client_check_cookie must be 1 to 64 letters, digits, - or _")
        for name in ("client_check_ttl", "client_check_points"):
            if not getattr(self, name) > 0:
                raise ValueError(f"{name} must be positive")
        if self.client_check_grace < 0:
            raise ValueError("client_check_grace must not be negative")
        if not 0 < self.throttle_score <= self.block_score:
            raise ValueError("need 0 < throttle_score <= block_score")
        if self.soft_cap is None:
            self.soft_cap = 0.8 * self.throttle_score
        if not 0 <= self.soft_cap < self.throttle_score:
            raise ValueError("need 0 <= soft_cap < throttle_score")
        for e in self.engagements:
            if e.start.tzinfo is None or e.end.tzinfo is None:
                raise ValueError("engagement start/end must be timezone-aware")


@dataclass
class Decision:
    # "pass" | "throttle" (429, the client may retry later) | "block" (403, the address is blocked)
    # | "refuse" (403 for this one request; nothing is held against the address)
    action: str
    enforced: bool                   # False in monitor mode
    score: float
    hits: List[str]
    ref: str                         # incident reference shown to the client
    ip: str
    retry_after: int = 0
    friendly: bool = False
    induced: bool = False            # a web page, not the person, made the browser send it; pass on to observe()

    @property
    def stop(self) -> bool:
        return self.enforced and self.action != "pass"


class _Track:
    __slots__ = ("hard", "soft_points", "updated", "times", "not_found", "slow", "missing", "soft", "strikes",
                 "throttled_until", "page_at", "checked_at", "automation_at")

    def __init__(self, now: float, history: int = 512, slow_budget: int = 0):
        self.hard = 0.0              # points from signals that repeat on every hit
        self.soft_points = 0.0       # points from once-per-half-life signals, capped at Config.soft_cap
        self.updated = now
        self.times: deque = deque(maxlen=history)       # sized so that the flood limit can be reached
        self.not_found: deque = deque(maxlen=512)       # when each newly missing path was first asked for
        self.slow: deque = deque(maxlen=max(slow_budget, 1))        # the same, kept for the hourly allowance
        self.missing: "OrderedDict[int, float]" = OrderedDict()     # missing paths already counted -> last asked
        self.soft: Dict[str, float] = {}
        self.strikes = 0
        self.throttled_until = 0.0
        self.page_at: Optional[float] = None         # first HTML page served to this client (client check)
        self.checked_at: Optional[float] = None      # last time it completed the client check
        self.automation_at: Optional[float] = None   # last time that check reported automation

    @property
    def score(self) -> float:
        return self.hard + self.soft_points


class Shield:
    def __init__(self, config: Optional[Config] = None, clock: Callable[[], float] = time.time):
        self.cfg = config or Config()
        self.clock = clock
        self.log = logging.getLogger(self.cfg.logger)
        self._lock = threading.RLock()
        self._local = threading.local()             # what this thread queued under the lock: see _state()
        self._tracks: "OrderedDict[str, _Track]" = OrderedDict()
        self._history = max(self.cfg.rate_limit, self.cfg.cadence_samples)
        self._blocks: Dict[str, float] = {}         # network -> expiry
        self._members: Dict[str, Set[str]] = {}     # wider IPv6 prefix -> blocked networks inside it
        self._wide = 0                              # blocks wider than a /64 now held
        self._pruned = self.clock()
        self._export_lock = threading.Lock()        # one writer of the block file per process
        self._export_due: Optional[float] = None    # when the earliest entry in that file expires
        self._timer: Optional[threading.Timer] = None
        self._trusted = _nets(self.cfg.trusted_proxies)
        self._allowed = _nets(self.cfg.allow_cidrs)
        self._exempt = _prefixes(self.cfg.exempt_paths, "exempt_paths")
        self._enum_skip = _prefixes(self.cfg.enum_ignore_prefixes, "enum_ignore_prefixes")
        self._enum_skip_ext = {str(e).lower().lstrip(".") for e in self.cfg.enum_ignore_extensions}
        self._canaries = {_norm_path(p) for p in self.cfg.canary_paths}
        self._tls_deny = {str(v).lower() for v in self.cfg.tls_denylist}
        secret = self.cfg.client_check_secret
        self._check_key = secret.encode() if secret else secrets.token_bytes(32)
        self._check_path = _prefixes([self.cfg.client_check_path], "client_check_path")[0]
        self._check_api = _prefixes(self.cfg.client_check_api_prefixes, "client_check_api_prefixes")
        self.stats = {"requests": 0, "throttled": 0, "blocked": 0, "friendly": 0, "unidentified": 0, "refused": 0}
        self._unidentified_warned: Optional[float] = None

    # ---- lock and delivery ----------------------------------------------
    @contextmanager
    def _state(self):
        """Hold the lock for bookkeeping. Events and block-file writes asked for
        inside are queued and carried out once it is released: a slow log
        handler, callback or disk must not make every other request wait."""
        local = self._local
        with self._lock:
            local.depth = getattr(local, "depth", 0) + 1
            try:
                yield
            finally:
                local.depth -= 1
        if not local.depth:
            self._deliver()

    def _deliver(self) -> None:
        local = self._local
        events, local.events = getattr(local, "events", None), None
        forget, local.export = getattr(local, "export", None), None
        for event in events or ():
            self.log.warning(json.dumps(event, separators=(",", ":")))
            if self.cfg.on_event:
                try:
                    self.cfg.on_event(event)
                except Exception:                   # a broken hook must not take the site down
                    self.log.exception("on_event callback failed")
        if forget is not None:
            self._export_safely(forget)

    def _want_export(self, forget: Iterable[str] = ()) -> None:
        """Rewrite the block file once the lock is released, leaving out `forget`."""
        if self.cfg.blocklist_export_path:
            local = self._local
            local.export = (getattr(local, "export", None) or set()) | set(forget)

    # ---- client address -------------------------------------------------
    def client_ip(self, remote_addr: str, forwarded_for: Optional[str] = None) -> str:
        """X-Forwarded-For is believed only when the direct peer is one of your
        own proxies; otherwise anyone could get a stranger blocked by forging it.

        When the header names no client, the peer is returned: a proxy's own
        address, or 0.0.0.0 when there is none (a unix socket). check() does
        not score those, because every visitor would arrive under them. To take
        X-Forwarded-For from a unix-socket peer, trust "0.0.0.0/32"."""
        remote = (remote_addr or "").strip() or "0.0.0.0"
        if forwarded_for and _in_nets(remote, self._trusted):
            for hop in reversed([h.strip() for h in forwarded_for.split(",") if h.strip()]):
                addr = _hop_ip(hop)
                if addr is None:
                    break
                if not _in_nets(addr, self._trusted):
                    return addr
        return remote

    def _identified(self, ip: str) -> bool:
        """False when `ip` cannot stand for one client: missing, unparseable,
        or one of the operator's own proxies."""
        return _usable_ip(ip) and not _in_nets(ip, self._trusted)

    # ---- before the app runs --------------------------------------------
    def check(self, ip: str, method: str, path: str, query: str = "",
              headers: Optional[Dict[str, str]] = None, body: Optional[bytes] = None) -> Decision:
        """Decide on one request before the app sees it. `body` is only looked
        at for honeytokens: pass its first Config.honeytoken_body_limit bytes
        (the adapters do)."""
        cfg, now = self.cfg, self.clock()
        h = {k.lower(): v for k, v in (headers or {}).items()}
        ua = h.get("user-agent", "")
        key = _track_key(ip)
        ref = secrets.token_hex(4)
        enforce = cfg.mode == "enforce"
        npath = _norm_path(path)
        allowed = _in_nets(ip, self._allowed)
        exempt = not allowed and _under(path, self._exempt)
        induced = not cfg.score_induced and _induced(h)
        m = ASSESSMENT_UA.search(ua)
        hits: List[_Hit] = []

        with self._state():
            self.stats["requests"] += 1
            if self._export_due is not None and now >= self._export_due:
                self._export_due = None             # an entry in the block file has expired: one rewrite, not one per request
                self._want_export()

            # IFF 1: operator allowlists. An allowlisted address is never scored.
            # Nor is a request for an exempt path, but a client blocked for what
            # it did elsewhere stays blocked there too.
            if allowed:
                return Decision("pass", enforce, 0.0, [], ref, ip)
            if exempt:
                if self._blocked(key, now):
                    return Decision("block", enforce, cfg.block_score, ["blocklist"], ref, ip)
                return Decision("pass", enforce, 0.0, [], ref, ip)

            # No address that stands for this client alone: scoring it would
            # score everyone behind the same proxy or socket. Let it through
            # and tell the operator, once per half-life.
            if not self._identified(ip):
                self.stats["unidentified"] += 1
                labels = ["config:unidentified-client"]
                if self._unidentified_warned is None or now - self._unidentified_warned >= cfg.half_life:
                    self._unidentified_warned = now
                    self._emit("unidentified", ip, 0.0, labels, method, path, ua, ref, enforce)
                return Decision("pass", enforce, 0.0, labels, ref, ip)

            # IFF 2: self-declared ARTEX assessment. Verified -> friend. Unverified -> foe.
            if m:
                eref = m.group(1) or ""
                if any(e.covers(eref, ip, now) for e in cfg.engagements):
                    self.stats["friendly"] += 1
                    t = self._track(key, now)
                    if self._soft_due(t, "friendly", now):
                        self._emit("friendly", ip, 0.0, [f"iff:engagement={eref}"], method, path, ua, ref, enforce)
                    return Decision("pass", enforce, 0.0, [f"iff:engagement={eref}"], ref, ip, friendly=True)
                hits.append(("artex:unverified-assessment-label", 100.0, False))

            # Already blocked: no need to look further. (Monitor mode did not
            # stop the client, so there it keeps looking: see below.)
            if enforce and self._blocked(key, now):
                return Decision("block", enforce, cfg.block_score, ["blocklist"], ref, ip)

        # Reading the request needs no shared state, so it is done without the
        # lock: a large request must not make every other one wait.
        seen = self._scan(method, npath, query, h, ua)
        if cfg.honeytokens:
            where = self._honeytoken(npath, query, h, body)
            if where:                                # worth a block on its own, whatever block_score is
                seen.append((f"decoy:honeytoken-{where}", max(100.0, cfg.block_score), False))
        checked = self._client_request(path, h, now)

        with self._state():
            if self._blocked(key, now):
                if enforce:                         # blocked by another request in the meantime
                    return Decision("block", enforce, cfg.block_score, ["blocklist"], ref, ip)
                # Monitor mode: enforce would be refusing this address, so its
                # score stays frozen, but what it goes on to do is the evidence
                # the operator needs. Report requests that carry a hard signal,
                # and the rest once per half-life.
                labels = ["blocklist"] + [l for l, _, _ in hits + seen]
                loud = any(not soft for _, _, soft in hits + seen)
                if loud or self._soft_due(self._track(key, now), "blocked", now):
                    self._emit("blocked", ip, cfg.block_score, labels, method, path, ua, ref, enforce)
                return Decision("block", enforce, cfg.block_score, labels, ref, ip)

            # A page made the browser send this, so it says nothing about the
            # visitor: no score, no track. If it carries a hard signal it is
            # refused, which also means a tool gains nothing by posing as one.
            if induced:
                labels = [l for l, _, soft in hits + seen if not soft]
                if not labels:
                    return Decision("pass", enforce, 0.0, [], ref, ip, induced=True)
                self.stats["refused"] += 1
                self._emit("refuse", ip, 0.0, labels, method, path, ua, ref, enforce)
                return Decision("refuse", enforce, 0.0, labels, ref, ip, induced=True)

            t = self._track(key, now)
            self._decay(t, now)
            hits += self._radar(t, now, seen)
            hits += self._client_hits(t, now, checked)
            t.times.append(now)

            # A throttled client that keeps coming inside Retry-After is not backing off.
            # Only if it was told: in monitor mode nobody sent it a Retry-After.
            if enforce and t.throttled_until > now:
                hits.append(("behavior:ignored-retry-after", cfg.ignored_throttle_points, False))

            self._add(t, hits)
            return self._engage(t, key, ip, now, [l for l, _, _ in hits], method, path, ua, ref, enforce)

    # ---- after the app answered -------------------------------------------
    def observe(self, ip: str, path: str, status: int, induced: bool = False, content_type: str = "") -> None:
        """Feed the app's status code back in. 404s drive the enumeration,
        recon and missing-dump sensors, so what your site really serves never
        counts against anyone. Pass `induced` from the Decision check() gave:
        a 404 for a request some page forced is not the visitor's guess. Pass
        the response's Content-Type for the client check: it needs to know
        which clients have been served HTML pages."""
        if (self.cfg.client_check and not induced and 200 <= status < 300
                and content_type.split(";", 1)[0].strip().lower() in ("text/html", "application/xhtml+xml")):
            self._client_page(ip)
        if status != 404 or induced:
            return
        cfg, now = self.cfg, self.clock()
        npath = _norm_path(path)
        if _under(path, self._exempt) or _in_nets(ip, self._allowed):
            return
        key = _track_key(ip)
        hits: List[_Hit] = []
        if RECON_PATHS.search(npath):
            hits.append(("recon:probe-404", 25.0, False))
        if MISSING_SENSITIVE.search(npath) and not SENSITIVE_PATHS.search(npath):   # not twice for /.env.bak
            hits.append(("decoy:sensitive-file-probe", 60.0, False))
        guess = not _under(path, self._enum_skip) and _extension(npath) not in self._enum_skip_ext
        with self._state():
            t = self._tracks.get(key)
            if t is None or self._blocked(key, now):
                return
            self._decay(t, now)
            # Enumeration is many different missing paths. Asking again for one
            # already counted (polling, a reload, the same dead link on every
            # page) adds nothing, however often it happens.
            if guess and self._newly_missing(t, npath, now):
                t.not_found.append(now)
                # The allowance for the longer window: full, and its oldest
                # entry still inside the window, means this one is past it.
                if cfg.slow_enum_budget:
                    if len(t.slow) == t.slow.maxlen and now - t.slow[0] <= cfg.slow_enum_window:
                        hits.append(("behavior:slow-enumeration", cfg.slow_enum_points, False))
                    t.slow.append(now)
            while t.not_found and now - t.not_found[0] > cfg.enum_window:
                t.not_found.popleft()
            if len(t.not_found) >= cfg.enum_404_threshold:
                hits.append(("behavior:path-enumeration", 40.0, False))
                t.not_found.clear()
            if not hits:
                return
            self._add(t, hits)
            labels = [l for l, _, _ in hits]
            score = t.score
            if score >= cfg.block_score:
                self._block(t, key, now)
                self._emit("block", ip, score, labels, "-", path, "", "-", cfg.mode == "enforce")
            else:
                self._emit("score", ip, t.score, labels, "-", path, "", "-", cfg.mode == "enforce")

    def _newly_missing(self, t: _Track, npath: str, now: float) -> bool:
        """True the first time this client is told `npath` does not exist, and
        again only after a half-life without asking for it."""
        k = hash(npath)
        last = t.missing.get(k)
        t.missing[k] = now
        t.missing.move_to_end(k)
        while len(t.missing) > _MISSING_MEMORY:
            t.missing.popitem(last=False)
        return last is None or now - last > self.cfg.half_life

    # ---- honeytokens ----------------------------------------------------------
    def _honeytoken(self, npath: str, query: str, h: Dict[str, str], body: Optional[bytes]) -> Optional[str]:
        """Where a planted credential turns up in this request, or None. Each
        place is searched as sent and URL-decoded; Basic auth is unpacked.
        The Referer is skipped: it is the browser repeating an address."""
        tokens = self.cfg.honeytokens

        def has(text: str) -> bool:
            if not text:
                return False
            if any(t in text for t in tokens):
                return True
            decoded = _decode(text)
            return decoded != text and any(t in decoded for t in tokens)

        for name, value in h.items():
            if name == "referer":
                continue
            value = value[:16384]
            if has(value):
                return "cookie" if name == "cookie" else "header"
            if name in ("authorization", "proxy-authorization"):
                m = re.match(r"\s*basic\s+([A-Za-z0-9+/_=-]{4,8192})", value, re.I)
                if m:
                    try:
                        raw = base64.b64decode(m.group(1) + "===", altchars=b"-_" if "-" in m.group(1) or "_" in m.group(1) else None)
                    except (ValueError, binascii.Error):
                        raw = b""
                    if has(raw.decode("latin-1")):
                        return "header"
        if has(query[:65536]):
            return "query"
        if has(npath):
            return "path"
        if body and self.cfg.honeytoken_body_limit and has(body[:self.cfg.honeytoken_body_limit].decode("latin-1")):
            return "body"
        return None

    # ---- client check (optional) --------------------------------------------
    def client_check_reply(self, ip: str, query: str, headers: Optional[Dict[str, str]] = None,
                           secure: bool = False) -> Tuple[int, List[Tuple[str, str]], bytes]:
        """Answer the check script's call: record what it reported and set the
        signed cookie. Returns (status, headers, body); the adapters call this
        for requests to Config.client_check_path."""
        now = self.clock()
        params = dict(p.partition("=")[::2] for p in query.split("&") if p)
        flags = int(params["f"]) & _cc.FLAGS if params.get("f", "").isdigit() and len(params["f"]) < 6 else 0
        if self._identified(ip):
            with self._state():
                t = self._track(_track_key(ip), now)
                t.checked_at = now
                if flags:
                    t.automation_at = now
        value = _cc.sign(self._check_key, int(now), flags)
        attrs = f"Path=/; Max-Age={int(self.cfg.client_check_ttl)}; HttpOnly; SameSite=Lax"
        hdrs = [("Set-Cookie", f"{self.cfg.client_check_cookie}={value}; {attrs}" + ("; Secure" if secure else "")),
                ("Cache-Control", "no-store"), ("Content-Length", "0")]
        return 204, hdrs, b""

    def client_check_asset(self) -> Tuple[int, List[Tuple[str, str]], bytes]:
        """The check script itself, served at Config.client_check_path + ".js"."""
        body = _cc.script(self._check_path).encode()
        return 200, [("Content-Type", "text/javascript; charset=utf-8"), ("Content-Length", str(len(body))),
                     ("Cache-Control", "public, max-age=3600"), ("X-Content-Type-Options", "nosniff")], body

    def client_check_route(self, path: str) -> Optional[str]:
        """"check" or "script" when `path` is one of the client check's own
        endpoints and the check is on; None otherwise."""
        if not self.cfg.client_check:
            return None
        npath = _norm_path(path)
        return "check" if npath == self._check_path else "script" if npath == self._check_path + ".js" else None

    def _client_page(self, ip: str) -> None:
        if not self._identified(ip):
            return
        now = self.clock()
        with self._state():
            t = self._tracks.get(_track_key(ip))
            if t is not None and t.page_at is None:
                t.page_at = now

    def _client_request(self, path: str, h: Dict[str, str], now: float) -> Optional[Tuple[bool, int]]:
        """For an API request a page's script made, with the check on:
        (cookie valid?, flags it reports). None when the check does not apply."""
        if not self.cfg.client_check or not _under(path, self._check_api) or not _cc.script_made(h):
            return None
        value = _cc.cookie(h.get("cookie", ""), self.cfg.client_check_cookie)
        flags = _cc.verify(self._check_key, value, now, self.cfg.client_check_ttl)
        return (flags is not None, flags or 0)

    def _client_hits(self, t: _Track, now: float, checked: Optional[Tuple[bool, int]]) -> List[_Hit]:
        """Soft signals from the client check, at most once per half-life each."""
        if checked is None:
            return []
        cfg, (valid, flags), hits = self.cfg, checked, []
        reported = flags or (t.automation_at is not None and now - t.automation_at < cfg.client_check_ttl)
        if reported and self._soft_due(t, "client:automation-reported", now):
            hits.append(("client:automation-reported", cfg.client_check_points, True))
        # Never completed the check: loaded pages (and has had time to run
        # their script) but no check from this client has ever come back.
        if (not valid and t.checked_at is None and t.page_at is not None and now - t.page_at >= cfg.client_check_grace
                and self._soft_due(t, "client:no-check", now)):
            hits.append(("client:no-check", cfg.client_check_points, True))
        return hits

    # ---- sensors ----------------------------------------------------------
    def _scan(self, method: str, npath: str, query: str, h: Dict[str, str], ua: str) -> List[_Hit]:
        """Signals that depend on this request alone. Called without the lock."""
        cfg = self.cfg
        hits: List[_Hit] = []

        # Decoys: a canary path has no legitimate visitor at all.
        if npath in self._canaries:
            hits.append(("decoy:canary-path", 100.0, False))
        elif SENSITIVE_PATHS.search(npath):
            hits.append(("decoy:sensitive-file-probe", 60.0, False))

        # Signatures.
        hard = next(((l, p) for rx, p, l in HARD_UA if rx.search(ua)), None)
        if hard:
            hits.append((hard[0], float(hard[1]), False))
        else:
            for rx, pts, label in SOFT_UA:
                if rx.search(ua):
                    hits.append((label, float(pts), True))
            if not ua.strip():
                hits.append(("ua:empty", 20.0, True))
            # A "browser" that sends no Accept-Language is a client library
            # wearing a browser User-Agent (rotating-UA scanners do this).
            if BROWSER_UA.search(ua) and not CRAWLER_UA.search(ua) and not h.get("accept-language"):
                hits.append(("shape:browser-ua-without-browser-headers", 20.0, True))

        verb = method.upper()
        if verb in ODD_METHODS or verb in SOFT_METHODS:
            hits.append((f"method:{verb}", 30.0, verb in SOFT_METHODS))

        # Payloads in the URL; out-of-band markers in headers as well.
        target = _url_text(npath, query)
        plain = _strip_sql_comments(target)         # UNION/**/SELECT reads as UNION SELECT
        found = [label for rx, label in PAYLOADS + OOB
                 if rx.search(target) or (plain is not target and rx.search(plain))]
        head_blob = _decode(" ".join(h.values()))   # every header, whole, cookies included
        found += [label for rx, label in OOB if label not in found and rx.search(head_blob)]
        hits += [(label, 50.0, False) for label in found]

        # TLS fingerprint handed down by the edge (optional).
        if cfg.tls_header and self._tls_deny:
            fp = h.get(cfg.tls_header.lower(), "").lower()
            if fp and fp in self._tls_deny:
                hits.append(("tls:denylisted-fingerprint", 40.0, True))
        return hits

    def _radar(self, t: _Track, now: float, seen: List[_Hit]) -> List[_Hit]:
        """What counts against this client now: the request's own signals, with
        soft ones limited to once per half-life, plus volume and cadence."""
        cfg = self.cfg
        hits = [hit for hit in seen if not hit[2] or self._soft_due(t, hit[0], now)]

        # Volume.
        recent = [x for x in t.times if now - x <= cfg.rate_window]
        if len(recent) + 1 > cfg.rate_limit:
            hits.append(("behavior:request-flood", 30.0, False))
            t.times.clear()
        # Cadence: ARTEX's noise profiles and paced scanners (-rate N) space
        # requests evenly. People and browsers arrive in bursts and pauses.
        elif len(t.times) >= cfg.cadence_samples:
            seq = list(t.times)[-cfg.cadence_samples:] + [now]
            gaps = [b - a for a, b in zip(seq, seq[1:])]
            mean = statistics.fmean(gaps)
            if cfg.cadence_min_mean <= mean <= cfg.cadence_max_mean:
                cv = statistics.pstdev(gaps) / mean
                if cv <= cfg.cadence_max_cv and self._soft_due(t, "behavior:metronomic-cadence", now):
                    hits.append(("behavior:metronomic-cadence", 20.0, True))
        return hits

    def _add(self, t: _Track, hits: List[_Hit]) -> None:
        """Soft points fill a capped bucket; everything else adds without limit."""
        for _, points, soft in hits:
            if soft:
                t.soft_points = min(self.cfg.soft_cap, t.soft_points + points)
            else:
                t.hard += points

    # ---- fire control ----------------------------------------------------
    def _engage(self, t, key, ip, now, labels, method, path, ua, ref, enforce) -> Decision:
        cfg = self.cfg
        score = t.score
        if score >= cfg.block_score:
            self._block(t, key, now)
            self._emit("block", ip, score, labels, method, path, ua, ref, enforce)
            return Decision("block", enforce, score, labels, ref, ip)
        if score >= cfg.throttle_score:
            # Tell the truth: wait at least as long as the score needs to decay.
            decay = cfg.half_life * math.log2(score / cfg.throttle_score)
            wait = max(cfg.retry_after, math.ceil(decay) + 1)
            t.throttled_until = now + wait
            self.stats["throttled"] += 1
            self._emit("throttle", ip, score, labels, method, path, ua, ref, enforce)
            return Decision("throttle", enforce, score, labels, ref, ip, retry_after=wait)
        t.throttled_until = 0.0
        if labels:
            self._emit("score", ip, t.score, labels, method, path, ua, ref, enforce)
        return Decision("pass", enforce, t.score, labels, ref, ip)

    def _block(self, t: _Track, key: str, now: float) -> None:
        t.strikes += 1
        self.stats["blocked"] += 1
        ttl = min(self.cfg.block_ttl * (2 ** (t.strikes - 1)), self.cfg.max_block_ttl)
        if now - self._pruned >= 60 or len(self._blocks) >= self.cfg.max_blocks:
            self._prune_blocks(now)
        self._set_block(key, now + ttl)
        t.hard = t.soft_points = 0.0     # served its sentence when the block expires
        t.throttled_until = 0.0
        t.not_found.clear()
        self._want_export(self._escalate(key, now))

    def _escalate(self, key: str, now: float) -> List[str]:
        """Enough blocked networks inside one wider IPv6 prefix: block the prefix
        and let that one entry stand for them. Returns the entries it replaced."""
        replaced: List[str] = []
        need, parent = self.cfg.v6_escalate_after, _wider(key)
        while need and parent and len(self._members.get(parent, ())) >= need:
            for inside in list(self._members[parent]):
                self._drop_block(inside)
                replaced.append(inside)
            self._set_block(parent, now + self.cfg.block_ttl)
            self._emit("block", parent, self.cfg.block_score, ["behavior:network-rotation"], "-", "-", "", "-",
                       self.cfg.mode == "enforce")
            parent = _wider(parent)
        return replaced

    def _set_block(self, key: str, until: float) -> None:
        if key not in self._blocks:
            parent = _wider(key)
            if parent:
                self._members.setdefault(parent, set()).add(key)
            self._wide += not key.endswith("/64") and ":" in key
        self._blocks[key] = until

    def _drop_block(self, key: str) -> bool:
        if self._blocks.pop(key, None) is None:
            return False
        parent = _wider(key)
        inside = self._members.get(parent) if parent else None
        if inside is not None:
            inside.discard(key)
            if not inside:
                del self._members[parent]
        self._wide -= not key.endswith("/64") and ":" in key
        return True

    def _prune_blocks(self, now: float) -> None:
        """Drop expired blocks, and when the table is full make room by dropping
        the tenth nearest to expiry: they have served most of their time."""
        self._pruned = now
        for key in [k for k, until in self._blocks.items() if until <= now]:
            self._drop_block(key)
        over = len(self._blocks) - self.cfg.max_blocks + 1
        if over > 0:
            nearest = sorted(self._blocks.items(), key=lambda kv: kv[1])
            for key, _ in nearest[:max(over, self.cfg.max_blocks // 10)]:
                self._drop_block(key)

    # ---- command post ------------------------------------------------------
    def blocklist(self) -> Dict[str, float]:
        """Active blocks: network -> expiry (unix time)."""
        now = self.clock()
        with self._lock:
            for key in [k for k, until in self._blocks.items() if until <= now]:
                self._drop_block(key)
            return dict(self._blocks)

    def unblock(self, ip: str) -> bool:
        """Lift the block on `ip`, including a wider IPv6 prefix that covers it."""
        with self._state():
            key = _track_key(ip)
            self._tracks.pop(key, None)
            dropped = [k for k in self._covering(key, wide=True) if self._drop_block(k)]
            if dropped:
                self._want_export(dropped)
            return bool(dropped)

    def export_blocklist(self, path: str, fmt: str = "nginx") -> int:
        """Write active blocks for the edge to enforce (nginx: `include` the file
        inside http/server and reload). Returns the number of entries written.

        Every worker process writes the same file, so each one merges: entries
        other workers wrote stay until they expire. Expiry times are kept next
        to it in `<path>.state`, and writers take turns on `<path>.lock`. Both
        files are replaced atomically."""
        return self._export(path, fmt, ())

    def _export(self, path: str, fmt: str, forget: Iterable[str]) -> int:
        mine, now, forget = self.blocklist(), self.clock(), set(forget)
        with self._export_lock, _file_lock(path + ".lock"):
            merged = {k: until for k, until in _read_state(path + ".state").items()
                      if until > now and k not in forget}
            for key, until in mine.items():
                if _is_network(key):
                    merged[key] = max(until, merged.get(key, 0.0))
            _write_atomic(path + ".state", json.dumps(merged, sort_keys=True))
            lines = [f"deny {key};" if fmt == "nginx" else key for key in sorted(merged)]
            _write_atomic(path, "\n".join(lines) + ("\n" if lines else ""))
            if path == self.cfg.blocklist_export_path:
                self._export_due = min(merged.values(), default=None)
                self._arm_timer()
        return len(merged)

    def _export_safely(self, forget: Iterable[str] = ()) -> None:
        try:
            self._export(self.cfg.blocklist_export_path, self.cfg.blocklist_export_format, forget)
        except OSError as e:
            self.log.error("blocklist export failed: %s", e)
            self._export_due = self.clock() + 60    # try again in a minute, not on every request

    def _arm_timer(self) -> None:
        """Rewrite the file when its earliest entry expires, even if no request
        arrives to notice. Needs a real clock; with an injected one the check
        at the top of check() does the same on the next request."""
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        if self._export_due is None or self.clock is not time.time:
            return
        self._timer = threading.Timer(max(self._export_due - time.time(), 0.0) + 0.05, self._export_safely)
        self._timer.daemon = True
        self._timer.start()

    def _emit(self, action, ip, score, labels, method, path, ua, ref, enforced) -> None:
        event = {"ts": datetime.fromtimestamp(self.clock(), timezone.utc).isoformat(timespec="seconds"),
                 "action": action, "enforced": enforced, "ip": ip, "score": round(score, 1),
                 "hits": labels, "method": method, "path": path[:512], "ua": ua[:256], "ref": ref}
        local = self._local
        if getattr(local, "events", None) is None:
            local.events = []
        local.events.append(event)
        if not getattr(local, "depth", 0):          # not under the lock: nothing to wait for
            self._deliver()

    # ---- tracking ------------------------------------------------------------
    def _track(self, key: str, now: float) -> _Track:
        t = self._tracks.get(key)
        if t is None:
            t = self._tracks[key] = _Track(now, self._history, self.cfg.slow_enum_budget)
            while len(self._tracks) > self.cfg.max_tracks:
                self._tracks.popitem(last=False)
        else:
            self._tracks.move_to_end(key)
        return t

    def _covering(self, key: str, wide: bool = False) -> List[str]:
        """`key` and, for IPv6, the wider prefixes a block on it could sit under.
        Those cost two address computations, so they are skipped while no wide
        block exists unless `wide` asks for them."""
        keys = [key]
        if ":" in key and (wide or self._wide):
            while keys[-1]:
                keys.append(_wider(keys[-1]))
            keys.pop()
        return keys

    def _blocked(self, key: str, now: float) -> bool:
        for k in self._covering(key):
            until = self._blocks.get(k)
            if until is None:
                continue
            if until > now:
                return True
            self._drop_block(k)
        return False

    def _decay(self, t: _Track, now: float) -> None:
        dt = now - t.updated
        if dt > 0:
            factor = 0.5 ** (dt / self.cfg.half_life)
            t.hard *= factor
            t.soft_points *= factor
            if t.score < 0.5:
                t.hard = t.soft_points = 0.0
        t.updated = now

    def _soft_due(self, t: _Track, label: str, now: float) -> bool:
        """Soft signals count once per half-life, so a legitimate script or
        monitor cannot talk itself into a block just by existing."""
        last = t.soft.get(label)
        if last is not None and now - last < self.cfg.half_life:
            return False
        t.soft[label] = now
        return True
