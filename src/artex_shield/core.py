"""Configuration, tracking, sensors and fire control."""
from __future__ import annotations

import json
import logging
import math
import os
import secrets
import statistics
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from .signatures import (ASSESSMENT_UA, BROWSER_UA, CRAWLER_UA, HARD_UA, ODD_METHODS, OOB,
                         PAYLOADS, RECON_PATHS, SENSITIVE_PATHS, SOFT_UA)
from .util import (_decode, _hop_ip, _in_nets, _nets, _norm_path, _track_key, _ts, _url_text,
                   _usable_ip)

_Hit = Tuple[str, float, bool]       # label, points, soft?


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
    exempt_paths: List[str] = field(default_factory=list)      # path prefixes never scored
    engagements: List[Engagement] = field(default_factory=list)
    canary_paths: List[str] = field(default_factory=list)      # see make_canaries()
    enum_404_threshold: int = 15     # 404s inside enum_window
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

    def __post_init__(self):
        if self.mode not in ("monitor", "enforce"):
            raise ValueError("mode must be 'monitor' or 'enforce'")
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
    action: str                      # "pass" | "throttle" | "block"
    enforced: bool                   # False in monitor mode
    score: float
    hits: List[str]
    ref: str                         # incident reference shown to the client
    ip: str
    retry_after: int = 0
    friendly: bool = False

    @property
    def stop(self) -> bool:
        return self.enforced and self.action != "pass"


class _Track:
    __slots__ = ("hard", "soft_points", "updated", "times", "not_found", "soft", "strikes", "throttled_until")

    def __init__(self, now: float):
        self.hard = 0.0              # points from signals that repeat on every hit
        self.soft_points = 0.0       # points from once-per-half-life signals, capped at Config.soft_cap
        self.updated = now
        self.times: deque = deque(maxlen=512)
        self.not_found: deque = deque(maxlen=512)
        self.soft: Dict[str, float] = {}
        self.strikes = 0
        self.throttled_until = 0.0

    @property
    def score(self) -> float:
        return self.hard + self.soft_points


class Shield:
    def __init__(self, config: Optional[Config] = None, clock: Callable[[], float] = time.time):
        self.cfg = config or Config()
        self.clock = clock
        self.log = logging.getLogger(self.cfg.logger)
        self._lock = threading.RLock()
        self._tracks: "OrderedDict[str, _Track]" = OrderedDict()
        self._blocks: Dict[str, float] = {}
        self._trusted = _nets(self.cfg.trusted_proxies)
        self._allowed = _nets(self.cfg.allow_cidrs)
        self._canaries = {_norm_path(p) for p in self.cfg.canary_paths}
        self._tls_deny = {str(v).lower() for v in self.cfg.tls_denylist}
        self.stats = {"requests": 0, "throttled": 0, "blocked": 0, "friendly": 0, "unidentified": 0}
        self._unidentified_warned: Optional[float] = None

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
              headers: Optional[Dict[str, str]] = None) -> Decision:
        cfg, now = self.cfg, self.clock()
        h = {k.lower(): v for k, v in (headers or {}).items()}
        ua = h.get("user-agent", "")
        key = _track_key(ip)
        ref = secrets.token_hex(4)
        enforce = cfg.mode == "enforce"
        npath = _norm_path(path)
        exempt = any(npath.startswith(p) for p in cfg.exempt_paths) or _in_nets(ip, self._allowed)
        m = ASSESSMENT_UA.search(ua)
        hits: List[_Hit] = []

        with self._lock:
            self.stats["requests"] += 1

            # IFF 1: operator allowlists.
            if exempt:
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

            # Already blocked: no need to look further.
            if self._blocked(key, now):
                return Decision("block", enforce, cfg.block_score, ["blocklist"], ref, ip)

        # Reading the request needs no shared state, so it is done without the
        # lock: a large request must not make every other one wait.
        seen = self._scan(method, npath, query, h, ua)

        with self._lock:
            if self._blocked(key, now):             # blocked by another request in the meantime
                return Decision("block", enforce, cfg.block_score, ["blocklist"], ref, ip)

            t = self._track(key, now)
            self._decay(t, now)
            hits += self._radar(t, now, seen)
            t.times.append(now)

            # A throttled client that keeps coming inside Retry-After is not backing off.
            if t.throttled_until > now:
                hits.append(("behavior:ignored-retry-after", cfg.ignored_throttle_points, False))

            self._add(t, hits)
            return self._engage(t, key, ip, now, [l for l, _, _ in hits], method, path, ua, ref, enforce)

    # ---- after the app answered -------------------------------------------
    def observe(self, ip: str, path: str, status: int) -> None:
        """Feed the app's status code back in. 404s drive the enumeration and
        recon sensors, so real routes on your site never count against anyone."""
        if status != 404:
            return
        cfg, now = self.cfg, self.clock()
        npath = _norm_path(path)
        if any(npath.startswith(p) for p in cfg.exempt_paths) or _in_nets(ip, self._allowed):
            return
        key = _track_key(ip)
        with self._lock:
            t = self._tracks.get(key)
            if t is None or key in self._blocks:
                return
            self._decay(t, now)
            hits: List[_Hit] = []
            if RECON_PATHS.match(npath):
                hits.append(("recon:probe-404", 25.0, False))
            t.not_found.append(now)
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

        if method.upper() in ODD_METHODS:
            hits.append((f"method:{method.upper()}", 30.0, False))

        # Payloads in the URL; out-of-band markers in headers as well.
        target = _url_text(npath, query)
        found = [label for rx, label in PAYLOADS + OOB if rx.search(target)]
        head_blob = _decode(" ".join(v[:2048] for k, v in h.items() if k != "cookie"))
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
        self._blocks[key] = now + ttl
        t.hard = t.soft_points = 0.0     # served its sentence when the block expires
        t.throttled_until = 0.0
        t.not_found.clear()
        if self.cfg.blocklist_export_path:
            try:
                self.export_blocklist(self.cfg.blocklist_export_path, self.cfg.blocklist_export_format)
            except OSError as e:
                self.log.error("blocklist export failed: %s", e)

    # ---- command post ------------------------------------------------------
    def blocklist(self) -> Dict[str, float]:
        """Active blocks: network -> expiry (unix time)."""
        now = self.clock()
        with self._lock:
            self._blocks = {k: v for k, v in self._blocks.items() if v > now}
            return dict(self._blocks)

    def unblock(self, ip: str) -> bool:
        with self._lock:
            self._tracks.pop(_track_key(ip), None)
            return self._blocks.pop(_track_key(ip), None) is not None

    def export_blocklist(self, path: str, fmt: str = "nginx") -> int:
        """Write active blocks for the edge to enforce (nginx: `include` the file
        inside http/server and reload). Written atomically."""
        entries = sorted(self.blocklist())
        lines = [f"deny {e};" if fmt == "nginx" else e for e in entries]
        tmp = f"{path}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + ("\n" if lines else ""))
        os.replace(tmp, path)
        return len(entries)

    def _emit(self, action, ip, score, labels, method, path, ua, ref, enforced) -> None:
        event = {"ts": datetime.fromtimestamp(self.clock(), timezone.utc).isoformat(timespec="seconds"),
                 "action": action, "enforced": enforced, "ip": ip, "score": round(score, 1),
                 "hits": labels, "method": method, "path": path[:512], "ua": ua[:256], "ref": ref}
        self.log.warning(json.dumps(event, separators=(",", ":")))
        if self.cfg.on_event:
            try:
                self.cfg.on_event(event)
            except Exception:                       # a broken hook must not take the site down
                self.log.exception("on_event callback failed")

    # ---- tracking ------------------------------------------------------------
    def _track(self, key: str, now: float) -> _Track:
        t = self._tracks.get(key)
        if t is None:
            t = self._tracks[key] = _Track(now)
            while len(self._tracks) > self.cfg.max_tracks:
                self._tracks.popitem(last=False)
        else:
            self._tracks.move_to_end(key)
        return t

    def _blocked(self, key: str, now: float) -> bool:
        until = self._blocks.get(key)
        if until is None:
            return False
        if until > now:
            return True
        del self._blocks[key]
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
