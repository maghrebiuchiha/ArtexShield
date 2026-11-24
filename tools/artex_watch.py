"""Check that ARTEX still behaves the way artex-shield relies on.

artex-shield is built from a reading of ARTEX's source: its User-Agents, its
pacing limits, how its static harvester picks endpoints out of JavaScript,
the scanners it ships, and how its browser presents itself. This tool reads
a checkout of ARTEX as text (it never runs ARTEX code), extracts those facts,
and compares them with tools/artex_baseline.json. It also checks that the
shield, as it is in this repository, still covers what it finds.

    python tools/artex_watch.py check --artex PATH [--report r.md] [--findings f.json]
        exit 0: nothing changed; 1: changes or gaps found (report written); 2: the check failed
    python tools/artex_watch.py baseline --artex PATH
        record what PATH contains as the new baseline
    python tools/artex_watch.py sync-issue --findings f.json --report r.md
        open, update or close the GitHub issue (needs GITHUB_TOKEN, GITHUB_REPOSITORY)

Standard library only.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
BASELINE = os.path.join(HERE, "artex_baseline.json")
ARTEX_URL = "https://github.com/BaaRai/ARTEX"
LABEL = "artex-drift"
MARKER = "artex-watch fingerprint:"

HARVEST = "skills/api-recon/scripts/harvest_static.py"
SPIDER = "skills/api-recon/scripts/spider_mpa.py"
RUNTIME = "skills/api-recon/scripts/runtime_harvest.js"
UPDATE = "server/update_check.go"
LABELS = "config/task_user_agents.go"
EGRESS = "egress/egress.go"
DOCKERFILE = "Dockerfile"

# Code that would hide a browser's automation from the page (and so from a
# client-side check): stealth plugins, a patched navigator.webdriver, the
# Chrome switch that removes it.
HIDING = re.compile(r"puppeteer-extra-plugin-stealth|playwright-extra|playwright-stealth|undetected[-_]chromedriver"
                    r"|AutomationControlled|navigator\.webdriver|['\"]webdriver['\"]\s*[,:]|stealth\.min\.js", re.I)
HIDING_EXTENSIONS = (".js", ".mjs", ".cjs", ".ts", ".py", ".go", ".sh", ".json", ".yml", ".yaml")


class Missing:
    """A fact that could not be read, and why."""

    def __init__(self, why: str):
        self.why = why

    def __eq__(self, other):
        return isinstance(other, Missing)

    def __repr__(self):
        return f"Missing({self.why!r})"


# ---- reading ARTEX ----------------------------------------------------------
def _read(root: str, rel: str) -> Optional[str]:
    try:
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def _go_duration(expr: str) -> Optional[float]:
    """Seconds in a Go duration expression such as `30 * time.Second`."""
    m = re.fullmatch(r"\s*(?:(\d+(?:\.\d+)?)\s*\*\s*)?time\.(Hour|Minute|Second|Millisecond)\s*", expr)
    if not m:
        return None
    unit = {"Hour": 3600.0, "Minute": 60.0, "Second": 1.0, "Millisecond": 0.001}[m.group(2)]
    return round(float(m.group(1) or 1) * unit, 6)


def _go_func(text: str, signature: str) -> Optional[str]:
    """The source of a Go function, from its signature to the closing brace at column 0."""
    start = text.find(signature)
    if start < 0:
        return None
    end = text.find("\n}\n", start)
    return text[start:end + 2] if end >= 0 else None


def _digest(source: Optional[str]) -> Any:
    if source is None:
        return None
    normal = "\n".join(line.rstrip() for line in source.strip().splitlines())
    return "sha256:" + hashlib.sha256(normal.encode()).hexdigest()[:16]


def _py_module(text: Optional[str]) -> Optional[ast.Module]:
    if text is None:
        return None
    try:
        return ast.parse(text)
    except SyntaxError:
        return None


def _py_assign(tree: Optional[ast.Module], name: str) -> Optional[ast.expr]:
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return node.value
    return None


def _py_string(node: Optional[ast.expr]) -> Optional[str]:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _py_regex(node: Optional[ast.expr]) -> Optional[Dict[str, Any]]:
    """{"pattern": ..., "ignorecase": ...} for `re.compile("...", re.I)`."""
    if not (isinstance(node, ast.Call) and node.args and _py_string(node.args[0]) is not None):
        return None
    flags = ast.dump(node.args[1]) if len(node.args) > 1 else ""
    flags += "".join(ast.dump(k.value) for k in node.keywords if k.arg == "flags")
    return {"pattern": node.args[0].value, "ignorecase": "'I'" in flags or "IGNORECASE" in flags}


def _py_function(tree: Optional[ast.Module], text: str, name: str) -> Optional[ast.FunctionDef]:
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _first_findall(func: Optional[ast.FunctionDef]) -> Optional[str]:
    for node in ast.walk(func) if func else ():
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "findall"
                and node.args and _py_string(node.args[0]) is not None):
            return node.args[0].value
    return None


def _dockerfile_tools(text: str) -> Dict[str, List[str]]:
    joined = re.sub(r"\\\n", " ", text)                     # follow line continuations
    release = re.findall(r"(?:\$gh|github\.com)/([\w.-]+/[\w.-]+)/releases/download", joined)
    clones = re.findall(r"git clone [^;&|]*?https://github\.com/([\w.-]+/[\w.-]+?)(?:\.git)?(?=[\s;\"']|$)", joined)
    pip = []
    for args in re.findall(r"pip install ([^;&|]+)", joined):
        pip += [m for m in re.findall(r"\"?([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?==", args)]
    npm = []
    for args in re.findall(r"npm install -g ([^;&|]+)", joined):
        npm += re.findall(r"\"?((?:@[\w.-]+/)?[\w.-]+)@", args)
    apt = []
    for args in re.findall(r"apt-get install ((?:[^;&|])+)", joined):
        apt += [w for w in args.split() if not w.startswith("-") and re.fullmatch(r"[a-z0-9][a-z0-9.+-]+", w)]
    return {name: sorted(set(values)) for name, values in
            (("release_binaries", release), ("git_clones", clones), ("pip", pip), ("npm", npm), ("apt", apt))}


def _automation_hiding(root: str) -> List[str]:
    found = set()
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "vendor", "dist", "build")]
        for name in files:
            if not name.endswith(HIDING_EXTENSIONS) or name == "package-lock.json":
                continue
            path = os.path.join(base, name)
            try:
                if os.path.getsize(path) > 2_000_000:
                    continue
                with open(path, encoding="utf-8", errors="replace") as f:
                    for m in HIDING.finditer(f.read()):
                        found.add(f"{os.path.relpath(path, root)}: {m.group(0)}")
            except OSError:
                continue
    return sorted(found)


def extract(root: str) -> Dict[str, Dict[str, Any]]:
    """Every fact artex-shield relies on, as {fact id: {"file": ..., "value": ...}}.
    A fact that cannot be read has a Missing value saying why."""
    facts: Dict[str, Dict[str, Any]] = {}

    def put(fact: str, rel: str, value: Any, why: str = "not found") -> None:
        text_missing = _read(root, rel) is None
        if value is None:
            value = Missing(f"{rel} does not exist" if text_missing else f"{why} in {rel}")
        facts[fact] = {"file": rel, "value": value}

    harvest_text = _read(root, HARVEST)
    harvest = _py_module(harvest_text)
    spider = _py_module(_read(root, SPIDER))
    put("ua.harvester", HARVEST, _py_string(_py_assign(harvest, "UA")), "UA = \"...\"")
    put("ua.spider", SPIDER, _py_string(_py_assign(spider, "UA")), "UA = \"...\"")

    update = _read(root, UPDATE) or ""
    m = re.search(r'Header\.Set\(\s*"User-Agent"\s*,\s*"([^"]+)"\s*\)', update)
    put("ua.update_check", UPDATE, m and m.group(1), 'Header.Set("User-Agent", "...")')

    labels = _read(root, LABELS) or ""
    m = re.search(r'assessmentUserAgent\s*=\s*"([^"]+)"', labels)
    put("ua.assessment", LABELS, m and m.group(1), "const assessmentUserAgent")
    m = re.search(r"assessmentReference\s*=\s*regexp\.MustCompile\(\s*`([^`]+)`", labels)
    put("ua.assessment_reference", LABELS, m and m.group(1), "assessmentReference = regexp.MustCompile(...)")
    m = re.search(r'ua\s*\+=\s*"([^"]*)"\s*\+\s*\*?\w+\s*\+\s*"([^"]*)"', labels)
    put("ua.assessment_format", LABELS, m and f"{m.group(1)}REF{m.group(2)}", 'ua += "..." + ref + "..."')

    egress = _read(root, EGRESS) or ""
    profiles = {}
    for name, body in re.findall(r'"(\w+)"\s*:\s*\{(Name:[^{}]*)\}', egress):
        rps = re.search(r"\bRPS:\s*([\d.]+)", body)
        jitter = re.search(r"\bJitter:\s*([\d.]+)", body)
        burst = re.search(r"\bBurst:\s*(\d+)", body)
        delay = re.search(r"\bMaxDelay:\s*([^,}]+)", body)
        profiles[name] = {"rps": rps and float(rps.group(1)), "burst": burst and int(burst.group(1)),
                          "jitter": jitter and float(jitter.group(1)),
                          "max_delay_s": delay and _go_duration(delay.group(1))}
    put("pacing.profiles", EGRESS, profiles or None, "var Profiles = map[string]Profile{...}")
    m = re.search(r"const\s+MaxJitter\s*=\s*([^\n]+)", egress)
    put("pacing.max_jitter_s", EGRESS, m and _go_duration(m.group(1)), "const MaxJitter")
    put("pacing.retry_after_read", EGRESS, True if 'Get("Retry-After")' in egress else None,
        'h.Get("Retry-After")')
    put("pacing.backoff_source", EGRESS, _digest(_go_func(egress, "func (g *Governor) backoff(")),
        "func (g *Governor) backoff")
    put("pacing.jitter_source", EGRESS, _digest(_go_func(egress, "func (g *Governor) jitterBound(")),
        "func (g *Governor) jitterBound")

    put("harvest.api_hint", HARVEST, _py_regex(_py_assign(harvest, "API_HINT")), "API_HINT = re.compile(...)")
    put("harvest.asset_ext", HARVEST, _py_regex(_py_assign(harvest, "ASSET_EXT")), "ASSET_EXT = re.compile(...)")
    func = _py_function(harvest, harvest_text or "", "extract_endpoints")
    put("harvest.endpoint_pattern", HARVEST, _first_findall(func), "re.findall(...) in extract_endpoints")
    put("harvest.extract_endpoints_source", HARVEST,
        _digest(ast.get_source_segment(harvest_text, func)) if func and harvest_text else None, "def extract_endpoints")

    docker = _read(root, DOCKERFILE)
    tools = _dockerfile_tools(docker) if docker is not None else {}
    for name in ("release_binaries", "git_clones", "pip", "npm", "apt"):
        put(f"tools.{name}", DOCKERFILE, tools.get(name), name)

    runtime = _read(root, RUNTIME) or ""
    put("browser.runtime_headless_default", RUNTIME,
        True if re.search(r"headless\s*=\s*\w+\.headless\s*!==\s*false", runtime) else
        (False if runtime else None), "the headless default")
    facts["browser.automation_hiding"] = {"file": "(whole repository)", "value": _automation_hiding(root)}
    return facts


# ---- what the shield needs from those facts ------------------------------------
def coverage(facts: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Gaps between what ARTEX does and what artex-shield, as checked out here, catches."""
    from artex_shield import Config, js_trap, make_canaries
    from artex_shield.signatures import ASSESSMENT_UA, HARD_UA

    gaps = []

    def gap(category: str, fact: str, file: str, now: str) -> None:
        gaps.append({"kind": "gap", "category": category, "fact": fact, "file": file, "was": None, "now": now})

    def value(fact: str) -> Any:
        v = facts.get(fact, {}).get("value")
        return None if isinstance(v, Missing) else v

    for fact in ("ua.harvester", "ua.spider", "ua.update_check"):
        ua = value(fact)
        if ua and not any(rx.search(ua) for rx, _, _ in HARD_UA):
            gap("User-Agents", fact, facts[fact]["file"], f"`{ua}` matches no signature in signatures.HARD_UA")
    base, fmt = value("ua.assessment"), value("ua.assessment_format")
    if base:
        for ref in ("FS-17", "a" * 64, "x.y_z-1"):
            label = base + (fmt.replace("REF", ref) if fmt else "")
            m = ASSESSMENT_UA.search(label)
            if not m or (fmt and m.group(1) != ref):
                gap("User-Agents", "ua.assessment", facts["ua.assessment"]["file"],
                    f"signatures.ASSESSMENT_UA does not read the engagement reference out of `{label}`")
                break
        if not ASSESSMENT_UA.search(base):
            gap("User-Agents", "ua.assessment", facts["ua.assessment"]["file"],
                f"signatures.ASSESSMENT_UA does not match the bare label `{base}`")

    cfg = Config()
    profiles = value("pacing.profiles") or {}
    max_jitter = value("pacing.max_jitter_s")
    for name, p in sorted(profiles.items()):
        rps, jitter, delay = p.get("rps"), p.get("jitter"), p.get("max_delay_s")
        if not rps:
            continue
        bound = min((jitter or 0) / rps, max_jitter if max_jitter is not None else math.inf)
        mean = 1 / rps + bound / 2
        cv = (bound / math.sqrt(12)) / mean
        flood = rps * cfg.rate_window > cfg.rate_limit
        cadence = cfg.cadence_min_mean <= mean <= cfg.cadence_max_mean and cv <= cfg.cadence_max_cv
        if not (flood or cadence):
            gap("Pacing", f"pacing.profiles.{name}", EGRESS,
                f"{rps:g} req/s with up to {bound * 1000:.0f} ms jitter (mean gap {mean:.2f} s, variation {cv:.2f}) "
                f"is under the flood limit ({cfg.rate_limit} per {cfg.rate_window:g} s) and outside the cadence "
                f"sensor's window ({cfg.cadence_min_mean}-{cfg.cadence_max_mean} s, variation <= {cfg.cadence_max_cv})")
        if delay is not None and delay >= cfg.retry_after:
            gap("Pacing", f"pacing.profiles.{name}", EGRESS,
                f"waits out a Retry-After of up to {delay:g} s, so the shield's {cfg.retry_after} s "
                f"Retry-After no longer makes it give up")

    hint, asset, endpoint = value("harvest.api_hint"), value("harvest.asset_ext"), value("harvest.endpoint_pattern")
    if hint and asset and endpoint:
        flags = lambda r: re.I if r.get("ignorecase") else 0
        try:
            hint_rx = re.compile(hint["pattern"], flags(hint))
            asset_rx = re.compile(asset["pattern"], flags(asset))
            endpoint_rx = re.compile(endpoint)
        except re.error as e:
            gap("Harvest", "harvest", HARVEST, f"a harvest pattern no longer compiles in Python: {e}")
        else:
            for canary in make_canaries("artex-watch", 5):
                found = canary in endpoint_rx.findall(js_trap(canary))
                if not found:
                    why = "the endpoint pattern no longer picks it out of a JS bundle"
                elif asset_rx.search(canary):
                    why = "ASSET_EXT now discards it as an asset"
                elif not hint_rx.search(canary):
                    why = "API_HINT no longer counts it as an API path"
                else:
                    continue
                gap("Harvest", "harvest", HARVEST, f"canary shape `{canary}` would not be harvested: {why}")
    return gaps


# ---- comparing ------------------------------------------------------------------
CATEGORY = {"ua": "User-Agents", "pacing": "Pacing", "harvest": "Harvest", "tools": "Tools ARTEX installs",
            "browser": "Browser automation"}


def compare(baseline: Dict[str, Dict[str, Any]], current: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []

    def add(kind, fact, file, was, now):
        findings.append({"kind": kind, "category": CATEGORY.get(fact.split(".")[0], "Other"), "fact": fact,
                         "file": file, "was": was, "now": now})

    for fact in sorted(set(baseline) | set(current)):
        old = baseline.get(fact, {}).get("value")
        new_entry = current.get(fact, {"file": baseline.get(fact, {}).get("file"), "value": None})
        new, file = new_entry["value"], new_entry["file"]
        if isinstance(new, Missing):
            add("missing", fact, file, old, new.why)
        elif fact not in baseline:
            add("added", fact, file, None, new)
        elif isinstance(old, list) and isinstance(new, list):
            for item in sorted(set(new) - set(old)):
                add("added", fact, file, None, item)
            for item in sorted(set(old) - set(new)):
                add("removed", fact, file, item, None)
        elif fact == "pacing.profiles" and isinstance(old, dict) and isinstance(new, dict):
            for name in sorted(set(old) | set(new)):
                sub = f"pacing.profiles.{name}"
                if name not in old:
                    add("added", sub, file, None, new[name])
                elif name not in new:
                    add("removed", sub, file, old[name], None)
                elif old[name] != new[name]:
                    add("changed", sub, file, old[name], new[name])
        elif old != new:
            add("changed", fact, file, old, new)
    return findings


def fingerprint(findings: List[Dict[str, Any]]) -> str:
    keyed = sorted(json.dumps([f["kind"], f["fact"], f["was"], f["now"]], sort_keys=True, default=str)
                   for f in findings)
    return hashlib.sha256("\n".join(keyed).encode()).hexdigest()[:16]


def _show(v: Any) -> str:
    if v is None:
        return "nothing"
    if isinstance(v, dict) and set(v) == {"pattern", "ignorecase"}:
        return f"`{v['pattern']}`" + (" (case-insensitive)" if v["ignorecase"] else "")
    if isinstance(v, dict):
        return ", ".join(f"{k} {v[k]:g}" if isinstance(v[k], (int, float)) else f"{k} {v[k]}"
                         for k in sorted(v) if v[k] is not None)
    if isinstance(v, bool):
        return "yes" if v else "no"
    return f"`{v}`"


def report(findings: List[Dict[str, Any]], artex_commit: str, baseline_commit: str) -> str:
    if not findings:
        return (f"ARTEX at `{artex_commit[:12]}` still matches what artex-shield relies on "
                f"(baseline recorded at `{baseline_commit[:12]}`).\n")
    lines = ["## ARTEX changed in ways artex-shield relies on", "",
             f"Checked [{ARTEX_URL.split('github.com/')[1]}]({ARTEX_URL}) at `{artex_commit[:12]}` against the "
             f"baseline recorded at `{baseline_commit[:12]}`."]
    if baseline_commit != "unknown" and artex_commit != "unknown":
        lines.append(f"Everything that changed upstream: {ARTEX_URL}/compare/{baseline_commit[:12]}...{artex_commit[:12]}")
    order = ["User-Agents", "Pacing", "Harvest", "Tools ARTEX installs", "Browser automation", "Other"]
    for category in order:
        items = [f for f in findings if f["category"] == category]
        if not items:
            continue
        lines += ["", f"### {category}", ""]
        for f in items:
            where = f"`{f['file']}`" if f.get("file") else ""
            if f["kind"] == "changed":
                text = f"**Changed:** `{f['fact']}` in {where} was {_show(f['was'])}, now {_show(f['now'])}."
                was, now = f["was"], f["now"]
                if isinstance(was, dict) and isinstance(now, dict) and "pattern" not in was:
                    parts = [f"{k} {_show({k: was.get(k)})[len(k) + 1:] or 'unset'} → "
                             f"{_show({k: now.get(k)})[len(k) + 1:] or 'unset'}"
                             for k in sorted(set(was) | set(now)) if was.get(k) != now.get(k)]
                    text = f"**Changed:** `{f['fact']}` in {where}: {', '.join(parts)}."
                if f["fact"].endswith("_source"):
                    text = f"**Changed:** the code behind `{f['fact']}` in {where} is different from the baseline."
            elif f["kind"] == "added":
                text = f"**Added:** `{f['fact']}` in {where}: {_show(f['now'])}."
            elif f["kind"] == "removed":
                text = f"**Removed:** `{f['fact']}` in {where}: {_show(f['was'])}."
            elif f["kind"] == "missing":
                text = f"**Not found:** `{f['fact']}` (was {_show(f['was'])}): {f['now']}."
            else:
                text = f"**Not covered by artex-shield:** `{f['fact']}`: {f['now']}."
            lines.append(f"- {text}")
    lines += ["", "### What to do", "",
              "1. Check each item above against the shield: signatures in `src/artex_shield/signatures.py`, pacing "
              "limits in `Config`, canary shapes in `src/artex_shield/decoys.py`.",
              "2. Change the shield where it no longer covers ARTEX, with a test, and check that "
              "`python examples/simulate.py` still reports 0 legitimate requests stopped.",
              "3. Record the new state: `git clone --depth 1 " + ARTEX_URL + " /tmp/artex && "
              "python tools/artex_watch.py baseline --artex /tmp/artex`, and commit `tools/artex_baseline.json`.",
              "", "This issue is updated when the findings change and closed when none are left."]
    return "\n".join(lines) + "\n"


def _commit(root: str) -> str:
    try:
        out = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=30)
        return out.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _jsonable(facts: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {k: {"file": v["file"], "value": None if isinstance(v["value"], Missing) else v["value"]}
            for k, v in facts.items()}


def check(artex: str, baseline_path: str = BASELINE) -> Tuple[List[Dict[str, Any]], str, str]:
    with open(baseline_path, encoding="utf-8") as f:
        baseline = json.load(f)
    base_commit = baseline.get("artex_commit", "unknown")
    if not os.path.isdir(artex) or not os.listdir(artex):
        return ([{"kind": "missing", "category": "Other", "fact": "repository", "file": None,
                  "was": ARTEX_URL, "now": f"{ARTEX_URL} could not be cloned (deleted, renamed, made private, or down)"}],
                "unknown", base_commit)
    current = extract(artex)
    findings = compare(baseline["facts"], current) + coverage(current)
    return findings, _commit(artex), base_commit


def write_baseline(artex: str, baseline_path: str = BASELINE) -> Dict[str, Any]:
    facts = extract(artex)
    missing = [k for k, v in facts.items() if isinstance(v["value"], Missing)]
    if missing:
        raise SystemExit(f"refusing to record a baseline with facts that could not be read: {missing}")
    data = {"artex_repository": ARTEX_URL, "artex_commit": _commit(artex), "facts": _jsonable(facts)}
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    return data


# ---- the GitHub issue ---------------------------------------------------------------
Api = Callable[[str, str, Optional[Dict[str, Any]]], Tuple[int, Any]]


def github_api(token: str, repo: str, base: str = "https://api.github.com") -> Api:
    def call(method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
        req = urllib.request.Request(f"{base}/repos/{repo}{path}", method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {token}", "User-Agent": "artex-shield-watch",
                                              "Accept": "application/vnd.github+json",
                                              "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                return r.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw) if raw else None
            except ValueError:
                return e.code, raw.decode(errors="replace")
    return call


def sync_issue(findings: List[Dict[str, Any]], body: str, api: Api, run_url: str = "") -> str:
    """Open, update or close the one drift issue. Returns what it did."""
    status, issues = api("GET", f"/issues?state=open&labels={LABEL}&per_page=20", None)
    if status != 200:
        raise RuntimeError(f"listing issues failed: HTTP {status}: {issues}")
    issues = [i for i in issues if "pull_request" not in i]
    issue = min(issues, key=lambda i: i["number"]) if issues else None
    stamp = f"\n<!-- {MARKER} {fingerprint(findings)} -->\n"
    if run_url:
        body += f"\nFound by [this run]({run_url}).\n"
    if not findings:
        if not issue:
            return "nothing to do"
        api("POST", f"/issues/{issue['number']}/comments", {"body": body.strip() + "\n\nClosing: nothing is left to fix."})
        api("PATCH", f"/issues/{issue['number']}", {"state": "closed", "state_reason": "completed"})
        return f"closed #{issue['number']}"
    title = f"ARTEX changed: {len(findings)} thing{'s' if len(findings) != 1 else ''} artex-shield relies on"
    if issue is None:
        api("POST", "/labels", {"name": LABEL, "color": "d93f0b",
                                "description": "ARTEX changed in a way artex-shield relies on"})
        status, created = api("POST", "/issues", {"title": title, "body": body + stamp, "labels": [LABEL]})
        if status != 201:
            raise RuntimeError(f"opening the issue failed: HTTP {status}: {created}")
        return f"opened #{created['number']}"
    if stamp.strip() in (issue.get("body") or ""):
        return f"already reported in #{issue['number']}"
    api("PATCH", f"/issues/{issue['number']}", {"title": title, "body": body + stamp})
    api("POST", f"/issues/{issue['number']}/comments",
        {"body": "The findings changed. The description above now lists the current ones."})
    return f"updated #{issue['number']}"


# ---- command line ---------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)
    c = sub.add_parser("check")
    c.add_argument("--artex", required=True)
    c.add_argument("--baseline", default=BASELINE)
    c.add_argument("--report")
    c.add_argument("--findings")
    b = sub.add_parser("baseline")
    b.add_argument("--artex", required=True)
    b.add_argument("--baseline", default=BASELINE)
    s = sub.add_parser("sync-issue")
    s.add_argument("--findings", required=True)
    s.add_argument("--report", required=True)
    args = ap.parse_args(argv)

    if args.command == "baseline":
        data = write_baseline(args.artex, args.baseline)
        print(f"recorded {len(data['facts'])} facts from ARTEX {data['artex_commit'][:12]} in {args.baseline}")
        return 0
    if args.command == "check":
        findings, commit, base_commit = check(args.artex, args.baseline)
        text = report(findings, commit, base_commit)
        if args.report:
            with open(args.report, "w", encoding="utf-8") as f:
                f.write(text)
        if args.findings:
            with open(args.findings, "w", encoding="utf-8") as f:
                json.dump(findings, f, indent=1, default=str)
        print(text)
        return 1 if findings else 0
    with open(args.findings, encoding="utf-8") as f:
        findings = json.load(f)
    with open(args.report, encoding="utf-8") as f:
        body = f.read()
    repo, token = os.environ.get("GITHUB_REPOSITORY"), os.environ.get("GITHUB_TOKEN")
    if not repo or not token:
        print("GITHUB_REPOSITORY and GITHUB_TOKEN are required", file=sys.stderr)
        return 2
    run_url = ""
    if os.environ.get("GITHUB_RUN_ID"):
        run_url = f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{repo}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
    api = github_api(token, repo, os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    print(sync_issue(findings, body, api, run_url))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:                               # the check itself broke: exit 2, not "drift"
        print(f"artex_watch failed: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(2)
