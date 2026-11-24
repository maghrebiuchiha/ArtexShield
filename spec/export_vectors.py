"""Write spec/vectors.json from the Python test suite.

Runs the detection tests (tests/test_shield.py, test_client_check.py and
test_honeytokens.py) with Shield instrumented, and records every decision they
make: each test's shield becomes one case (its config, then every request,
status fed back, client check call, unblock and blocklist check, in order,
with the outcome). The canary and honeytoken derivations and the client check
script are written out too. Long runs of near-identical requests
are folded into repeat blocks, and the result is checked by replaying it
through the Python shield (tests/test_vectors.py) before it is written.

The expectations are therefore what the reference implementation does under
the tests that already assert the intended behaviour. Regenerate only after a
deliberate change of behaviour, and review the diff of vectors.json: it is the
contract every port is held to.

It also writes spec/patterns.json, the signature patterns in Python `re`
syntax, so that ports translate one source instead of copying them by hand.

    python spec/export_vectors.py           # rewrite spec/vectors.json and spec/patterns.json
    python spec/export_vectors.py --check   # exit 1 if either would change
"""
from __future__ import annotations

import argparse
import base64
import dataclasses
import json
import os
import re
import sys
import time
import unittest
from typing import Any, Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "tests")]

from artex_shield import Config, Shield, make_canaries, make_honeytokens  # noqa: E402
from artex_shield import client_check, signatures  # noqa: E402

T0 = 1_800_000_000.0
OUT = os.path.join(ROOT, "spec", "vectors.json")
PATTERNS = os.path.join(ROOT, "spec", "patterns.json")

# Tests of Python plumbing, not of decisions: adapters, the block file, the
# lock, the block table's memory bound, and timing.
MODULES = ("test_shield", "test_client_check", "test_honeytokens")
SKIP_CLASSES = {"Adapters", "Export", "Delivery", "Cost", "WebSockets", "Making"}
SKIP_TESTS = {"test_blocklist_export", "test_track_table_is_bounded", "test_block_table_is_capped",
              "test_expired_blocks_are_dropped_without_being_asked_for", "test_asgi_passes_the_context_through",
              "test_canaries_match_what_artex_harvests", "test_helpers", "test_parsing_a_huge_cookie_header_is_quick",
              "test_checking_a_large_request_is_quick", "test_tag"}
# Config fields that are wiring, not behaviour.
NOT_SPEC = {"logger", "on_event", "blocklist_export_path", "blocklist_export_format", "max_tracks", "max_blocks"}

state: Dict[str, Any] = {"test": None, "cases": [], "client_ip": [], "config_errors": [], "routes": []}
_orig = {name: getattr(Shield, name) for name in ("__init__", "check", "observe", "client_ip", "blocklist", "unblock",
                                                  "client_check_reply", "client_check_route")}
_orig_post_init = Config.__post_init__


def _number(v: float) -> Any:
    return int(v) if float(v).is_integer() else round(v, 9)


def _config(cfg: Config) -> Dict[str, Any]:
    default, out = Config(), {}
    for f in dataclasses.fields(Config):
        if f.name in NOT_SPEC:
            continue
        value, base = getattr(cfg, f.name), getattr(default, f.name)
        if f.name == "soft_cap":
            base = 0.8 * cfg.throttle_score
        if f.name == "engagements":
            value = [{"reference": e.reference, "cidrs": list(e.cidrs), "start": _time(e.start.timestamp()),
                      "end": _time(e.end.timestamp())} for e in value]
            base = []
        if isinstance(value, (tuple, set, frozenset)):
            value = sorted(value) if isinstance(value, (set, frozenset)) else list(value)
            base = list(base) if isinstance(base, (tuple, list)) else base
        if value != base:
            out[f.name] = value
    return out


def _decision(d) -> Dict[str, Any]:
    out = {"action": d.action, "hits": sorted(d.hits), "score": _number(d.score)}
    if d.action == "throttle":
        out["retry_after"] = d.retry_after
    return out


def _recording(self) -> Optional[Dict[str, Any]]:
    return getattr(self, "_vector", None)


def _init(self, config=None, clock=time.time):
    _orig["__init__"](self, config, clock)
    if state["test"] and clock is not time.time:
        self._vector = {"id": None, "test": state["test"], "config": _config(self.cfg), "steps": []}
        state["cases"].append(self._vector)


def _time(t: float) -> Any:
    """Seconds after T0, exactly: T0 + this gives back t bit for bit."""
    at = t - T0
    return int(at) if at.is_integer() else at


def _at(self) -> Any:
    return _time(self.clock())


def _body(body: bytes) -> Dict[str, str]:
    """A body as text when it is UTF-8, else base64."""
    try:
        return {"body": body.decode("utf-8")}
    except UnicodeDecodeError:
        return {"body_base64": base64.b64encode(body).decode()}


def _check(self, ip, method, path, query="", headers=None, body=None):
    rec, at = _recording(self), self.clock()
    d = _orig["check"](self, ip, method, path, query, headers, body)
    if rec is not None:
        request = {"ip": ip, "method": method, "path": path}
        if query:
            request["query"] = query
        if headers:
            request["headers"] = dict(headers)
        if body:
            request.update(_body(body))
        rec["steps"].append({"at": _time(at), "request": request, "expect": _decision(d)})
    return d


def _observe(self, ip, path, status, induced=False, content_type=""):
    rec = _recording(self)
    if rec is not None:
        step = {"at": _at(self), "observe": {"ip": ip, "path": path, "status": status}}
        if induced:
            step["observe"]["induced"] = True
        if content_type:
            step["observe"]["content_type"] = content_type
        rec["steps"].append(step)
    return _orig["observe"](self, ip, path, status, induced, content_type)


def _client_check_reply(self, ip, query, headers=None, secure=False):
    rec, at = _recording(self), self.clock()
    status, hdrs, body = _orig["client_check_reply"](self, ip, query, headers, secure)
    if rec is not None:
        call = {"ip": ip, "query": query}
        if headers:
            call["headers"] = dict(headers)
        if secure:
            call["secure"] = True
        rec["steps"].append({"at": _time(at), "client_check": call,
                             "expect": {"status": status, "headers": [list(h) for h in hdrs]}})
    return status, hdrs, body


def _client_check_route(self, path):
    """Which client check endpoint a path is: config and path alone decide, so
    each distinct question is kept once, apart from the cases."""
    out = _orig["client_check_route"](self, path)
    if state["test"]:
        item = {"config": {k: v for k, v in _config(self.cfg).items() if k.startswith("client_check")},
                "path": path, "expect": out}
        if item not in state["routes"]:
            state["routes"].append(item)
    return out


def _client_ip(self, remote_addr, forwarded_for=None):
    out = _orig["client_ip"](self, remote_addr, forwarded_for)
    if state["test"]:
        item = {"trusted_proxies": list(self.cfg.trusted_proxies), "remote": remote_addr or "",
                "forwarded_for": forwarded_for, "expect": out}
        if item not in state["client_ip"]:
            state["client_ip"].append(item)
    return out


def _blocklist(self):
    out = _orig["blocklist"](self)
    rec = _recording(self)
    if rec is not None:
        rec["steps"].append({"at": _at(self), "expect_blocklist": sorted(out)})
    return out


def _unblock(self, ip):
    out = _orig["unblock"](self, ip)
    rec = _recording(self)
    if rec is not None:
        rec["steps"].append({"at": _at(self), "unblock": ip, "expect": out})
    return out


def _post_init(self):
    try:
        _orig_post_init(self)
    except ValueError as e:
        if state["test"]:
            fields = {f.name: getattr(self, f.name) for f in dataclasses.fields(Config)}
            default = {f.name: getattr(Config(), f.name) for f in dataclasses.fields(Config)}
            given = {k: (list(v) if isinstance(v, tuple) else v) for k, v in fields.items()
                     if k not in NOT_SPEC and v != default[k] and not (k == "soft_cap" and v is None)}
            entry = {"config": given, "error": str(e)}
            if entry not in state["config_errors"]:
                state["config_errors"].append(entry)
        raise


# ---- folding loops into repeat blocks ----------------------------------------------
_TOKEN = re.compile(r"\d+")


def _shape(step: Dict[str, Any]) -> str:
    """The step with its time removed and every number replaced, for grouping.
    Only requests and observes fold; anything else gets a shape of its own."""
    if "request" not in step and "observe" not in step:
        return f"#{id(step)}"
    body = {k: v for k, v in step.items() if k not in ("at", "expect")}
    return _TOKEN.sub("#", json.dumps(body, sort_keys=True))


def _template(steps: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """If the request/observe parts of `steps` differ only by one number that
    counts up by one per step, the template with {i} in its place and the
    first value; else None."""
    texts = [json.dumps({k: v for k, v in s.items() if k not in ("at", "expect")}, sort_keys=True) for s in steps]
    if all(t == texts[0] for t in texts):
        return {"template": json.loads(texts[0]), "first": None}
    parts = [_TOKEN.split(t) for t in texts]
    nums = [_TOKEN.findall(t) for t in texts]
    if any(p != parts[0] for p in parts) or any(len(n) != len(nums[0]) for n in nums):
        return None
    varying = [j for j in range(len(nums[0])) if any(n[j] != nums[0][j] for n in nums)]
    if len(varying) != 1:
        return None
    j = varying[0]
    first = int(nums[0][j])
    if any(int(n[j]) != first + k for k, n in enumerate(nums)) or nums[0][j] != str(first):
        return None
    pieces = []
    for k, piece in enumerate(parts[0]):
        pieces.append(piece)
        if k < len(nums[0]):
            pieces.append("{i}" if k == j else nums[0][k])
    text = "".join(pieces)
    if text.count("{i}") != 1 or any("{i}" in t for t in texts):
        return None
    try:
        template = json.loads(text)               # the counter must sit inside a string value
    except ValueError:
        return None
    return {"template": template, "first": first}


def _fold(steps: List[Dict[str, Any]], min_run: int = 12, widths=(1, 2, 3, 4)) -> List[Dict[str, Any]]:
    """Fold runs of groups of 1 to 4 requests and observes into repeat blocks.
    A run qualifies when its groups differ only by one number counting up by
    one, and each step's absolute time is the previous step's plus a time step
    that depends only on its place in the group (`dt`), so a runner that
    accumulates time the same way reproduces every instant exactly."""
    count = len(steps)
    shapes = [_shape(s) for s in steps]
    instants = [T0 + s["at"] if "at" in s else None for s in steps]
    run = {}                                            # groups of identical shapes starting here
    for w in widths:
        run[w] = [1] * count
        for k in range(count - 2 * w, -1, -1):
            if shapes[k:k + w] == shapes[k + w:k + 2 * w]:
                run[w][k] = run[w][k + w] + 1
    out, i = [], 0
    while i < count:
        done = False
        for width in widths:
            n = run[width][i]
            if n < min_run:
                continue
            # dt[j]: the time from the step before to step j of a group (dt[0]
            # spans from one group's last step to the next group's first).
            dt = [instants[i + width] - instants[i + width - 1]] + \
                 [instants[i + j] - instants[i + j - 1] for j in range(1, width)]
            t, m, p = instants[i], 1, i + 1
            while p < i + n * width:
                nxt = t + dt[(p - i) % width]
                if dt[(p - i) % width] < 0 or nxt != instants[p]:
                    break
                t, p = nxt, p + 1
                if (p - i) % width == 0:
                    m = (p - i) // width
            if (p - i) % width == 0:
                m = (p - i) // width
            if m < min_run:
                continue
            groups = [steps[i + g * width:i + (g + 1) * width] for g in range(m)]
            templates = [_template([g[k] for g in groups]) for k in range(width)]
            firsts = {tp["first"] for tp in templates if tp is not None and tp["first"] is not None}
            if any(tp is None for tp in templates) or len(firsts) > 1:
                continue                                # same shape, but not one counter: try another width
            block = {"repeat": m, "at": steps[i]["at"], "dt": [_number_exact(x) for x in dt],
                     "i_from": firsts.pop() if firsts else 0, "steps": [tp["template"] for tp in templates],
                     "expect": []}
            for g in groups:
                full = [st.get("expect") for st in g]
                outcome = [None if e is None else {"action": e["action"], "hits": e["hits"]} for e in full]
                if block["expect"] and block["expect"][-1]["each"] == outcome:
                    block["expect"][-1]["times"] += 1
                    block["expect"][-1]["last"] = full
                else:
                    block["expect"].append({"times": 1, "each": outcome, "last": full})
            out.append(block)
            i += m * width
            done = True
            break
        if not done:
            out.append(steps[i])
            i += 1
    return out


def _number_exact(v: float) -> Any:
    return int(v) if float(v).is_integer() else v


class _Recorder(unittest.TextTestResult):
    def startTest(self, test):
        state["test"] = test.id().split(".", 1)[1]
        super().startTest(test)

    def stopTest(self, test):
        super().stopTest(test)
        state["test"] = None


def _selected(suite) -> List[unittest.TestCase]:
    out = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            out += _selected(item)
        elif type(item).__name__ not in SKIP_CLASSES and item._testMethodName not in SKIP_TESTS:
            out.append(item)
    return out


def patterns() -> Dict[str, Any]:
    """signatures.py as data. Every pattern is compiled with re.IGNORECASE
    (and, being str patterns, Unicode matching); SPEC.md says how to port them."""
    def src(rx):
        if rx.flags != re.IGNORECASE | re.UNICODE:
            raise SystemExit(f"pattern with unexpected flags {rx.flags}: {rx.pattern[:40]}")
        return rx.pattern
    sig = signatures
    return {
        "about": "Generated from src/artex_shield/signatures.py by spec/export_vectors.py. Python re syntax, "
                 "all case-insensitive with Unicode classes; see spec/SPEC.md, Porting notes.",
        "hard_ua": [[src(rx), pts, label] for rx, pts, label in sig.HARD_UA],
        "soft_ua": [[src(rx), pts, label] for rx, pts, label in sig.SOFT_UA],
        "assessment_ua": src(sig.ASSESSMENT_UA),
        "browser_ua": src(sig.BROWSER_UA),
        "crawler_ua": src(sig.CRAWLER_UA),
        "sensitive_paths": src(sig.SENSITIVE_PATHS),
        "missing_sensitive": src(sig.MISSING_SENSITIVE),
        "recon_paths": src(sig.RECON_PATHS),
        "payloads": [[src(rx), label] for rx, label in sig.PAYLOADS],
        "oob": [[src(rx), label] for rx, label in sig.OOB],
        "odd_methods": sorted(sig.ODD_METHODS),
        "soft_methods": sorted(sig.SOFT_METHODS),
    }


# Short texts on which regex dialects disagree: line ends, word boundaries and
# digits in other scripts, case folding, what "." takes. Every pattern's
# verdict on each is in the vectors, so a port's translation is checked
# where it is most likely to be wrong.
PROBES = [
    "/id_rsa", "/id_rsa\n", "/id_rsa\n\n", "/id_rsa\r", "/id_rsa\u2028", "/web.config\n", "/backup.sql\n",
    "/db.zip\nx", "/notes.old\n", "/admin", "/admin\n", "/admin/x", "/console\n", "/wp-login.php\n",
    "/swagger.json\n", "/actuator\n", "/.env", "/.envé", "/.env.local", "/.env_x", "/.env٣", "/.gitß", "/.ENV",
    "/.ſsh", "/.SSH", "/İD_RSA", "/mydb.sql", "/db_2026.zip", "/handbook.zip", "/feedback.zip", "/dbé.sql",
    "SQLMAP/1", "ſqlmap", "Nucleı", "Mozilla/5.0 (X11) Chrome/131.0", "Mozilla/5.0\rChrome/1", "Mozilla/5.0\nChrome/1",
    "Mozilla/5.0\u2028Chrome/1", "mozilla/5.0 mozilla/5.0 firefox/1", "1 union select null",
    "1\u00a0union\u00a0select\u00a0null", "1\u2003union select 1,2", "٣ union select null", "' or 1=1--",
    "'\u00a0or\u00a01=1--", "x' and '1'='1", "sleep(5)", "x.sleep(5)", "ésleep(5)", "sleep(٥)",
    "benchmark(1000000,md5(1))", "pg_sleep (3)", "waitfor delay '0:0:5'", "into outfile", "éinto outfile",
    "xinto outfile", "<script>alert(1)</script>", "<SCRIPT SRC=//x>", "<script>\n\n</script>", "javascript:alert(1)",
    "javascript:void(0)", "javascript:void(0)\n", "\" onmouseover=alert(1)", "x.onload=f()", "éonload=x()",
    "<img onerror=alert(1)>", "<iframe src=x>", "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    "../../config.yml", "../../utils.js", "/proc/self/environ", ";cat /etc/passwd", "|id", "|id -u", "\nwhoami",
    "&& curl x", "$(whoami)", "`id`", "{{7*7}}", "{{ ７*７ }}", "${7*7}", "{{config.items()}}", "{{ config.site_name }}",
    "#{7*7}", "169.254.169.254", "metadata.google.internal", "${jndi:ldap://x/a}", "${${lower:j}ndi:x}", "${ env:HOME}",
    "abc.oast.fun", ".oast.fun", "É.oast.fun", "ß.interact.sh", "x-.burpcollaborator.net", "python-requests/2.32",
    "curl/8.5", " curl/8.5", "Wget/1.21", "HeadlessChrome/131", "Go-http-client/1.1", "node-fetch/1.0",
    "ARTEX-Assessment/1.0 (engagement=ENG-1)", "artex-assessment/2", "Googlebot/2.1", "facebookexternalhit/1.1",
    "", " ", "\u00a0", "1\x1cunion\x1cselect\x1cnull", "' or\x1f1=1--", "1\x85union select null",
    "\x1d<script>alert(1)</script>", "x\x1ewhoami",
]


def pattern_probes() -> Dict[str, Any]:
    sig, matches = signatures, {}
    named = [(f"hard_ua:{label}", rx) for rx, _, label in sig.HARD_UA]
    named += [(f"soft_ua:{label}", rx) for rx, _, label in sig.SOFT_UA]
    named += [(name, getattr(sig, name.upper())) for name in ("assessment_ua", "browser_ua", "crawler_ua",
                                                              "sensitive_paths", "missing_sensitive", "recon_paths")]
    named += [(f"payloads:{label}", rx) for rx, label in sig.PAYLOADS]
    named += [(f"oob:{label}", rx) for rx, label in sig.OOB]
    for name, rx in named:
        matches[name] = "".join("1" if rx.search(text) else "0" for text in PROBES)
    return {"texts": PROBES, "matches": matches}


def derivations() -> Dict[str, Any]:
    """What make_canaries and make_honeytokens give for a few secrets: a port
    that takes a secret in its settings must derive the same values."""
    canaries = [{"secret": secret, "count": count, "paths": make_canaries(secret, count)}
                for secret, count in (("a-long-random-secret-you-keep", 3), ("s", 5), ("Grüße 🔑", 7))]
    honeytokens = []
    for secret, count in (("site-secret", 2), ("s", 5), ("Grüße 🔑", 3)):
        t = make_honeytokens(secret, count)
        honeytokens.append({"secret": secret, "count": count, "api_keys": list(t.api_keys), "users": list(t.users),
                            "passwords": list(t.passwords)})
    return {"canaries": canaries, "honeytokens": honeytokens}


def record() -> Dict[str, Any]:
    Shield.__init__, Shield.check, Shield.observe = _init, _check, _observe
    Shield.client_ip, Shield.blocklist, Shield.unblock = _client_ip, _blocklist, _unblock
    Shield.client_check_reply, Shield.client_check_route = _client_check_reply, _client_check_route
    Config.__post_init__ = _post_init
    try:
        tests = []
        for name in MODULES:
            tests += _selected(unittest.defaultTestLoader.loadTestsFromModule(__import__(name)))
        with open(os.devnull, "w") as devnull:
            result = unittest.TextTestRunner(resultclass=_Recorder, verbosity=0, stream=devnull).run(
                unittest.TestSuite(tests))
        if not result.wasSuccessful():
            raise SystemExit(f"the test suite fails; fix it before exporting: {result.failures + result.errors}")
    finally:
        for name, fn in _orig.items():
            setattr(Shield, name, fn)
        Config.__post_init__ = _orig_post_init

    cases, counts = [], {}
    for case in state["cases"]:
        if not case["steps"]:
            continue
        name = case["test"].replace(".", "/")
        counts[name] = counts.get(name, 0) + 1
        case["id"] = f"{name}#{counts[name]}"
        case["steps"] = _fold(case["steps"])
        cases.append({k: case[k] for k in ("id", "config", "steps") if case[k] or k != "config"})
    return {
        "spec": "artex-shield detection vectors",
        "version": 2,
        "t0": T0,
        "about": "Generated by spec/export_vectors.py from the Python test suite; see spec/SPEC.md for the format.",
        "client_check_script": client_check._SCRIPT,
        "pattern_probes": pattern_probes(),
        **derivations(),
        "client_ip": state["client_ip"],
        "client_check_routes": state["routes"],
        "config_errors": state["config_errors"],
        "cases": cases,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="exit 1 if vectors.json would change")
    args = ap.parse_args()
    data = record()
    text = json.dumps(data, indent=1, ensure_ascii=False, sort_keys=False) + "\n"
    pattern_text = json.dumps(patterns(), indent=1, ensure_ascii=False) + "\n"
    stale = []
    for path, new in ((OUT, text), (PATTERNS, pattern_text)):
        old = ""
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                old = f.read()
        if old != new:
            stale.append(os.path.relpath(path, ROOT))
    if args.check:
        print(f"{', '.join(stale)} would change" if stale else "spec/vectors.json and spec/patterns.json are up to date")
        return 1 if stale else 0
    for path, new in ((OUT, text), (PATTERNS, pattern_text)):
        with open(path, "w", encoding="utf-8") as f:
            f.write(new)
    steps = sum(len(c["steps"]) for c in data["cases"])
    print(f"wrote {OUT}: {len(data['cases'])} cases, {steps} top-level steps, "
          f"{len(data['client_ip'])} client_ip cases, {len(data['config_errors'])} config errors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
