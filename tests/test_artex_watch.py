"""tools/artex_watch.py on a small stand-in for an ARTEX checkout. No network."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import artex_watch as watch  # noqa: E402

# Written for these tests in the shape of the ARTEX files the watcher reads.
FILES = {
    "skills/api-recon/scripts/harvest_static.py": '''import re
UA = "Mozilla/5.0 (spa-api-recon)"
API_HINT = re.compile(r'/(?:api|rest|service|services|gateway|graphql|v\\d|web|admin|backend|open)\\b', re.I)
ASSET_EXT = re.compile(r'\\.(js|css|png|jpe?g|svg|gif|woff2?|ttf|ico|map|json|mp4|webp)(\\?|$)', re.I)

def extract_endpoints(js_text):
    found = set(re.findall(r\'\'\'["'`](/[A-Za-z0-9_\\-./{}$:]+)["'`]\'\'\', js_text))
    return {p for p in found if not ASSET_EXT.search(p) and API_HINT.search(p)}
''',
    "skills/api-recon/scripts/spider_mpa.py": 'UA = "Mozilla/5.0 (spa-api-recon spider)"\n',
    "skills/api-recon/scripts/runtime_harvest.js":
        "function cfg(c) {\n  c.headless = c.headless !== false;\n  return c;\n}\n",
    "server/update_check.go": 'func check() {\n\treq.Header.Set("User-Agent", "artex-update-check")\n}\n',
    "config/task_user_agents.go": '''package config
const assessmentUserAgent = "ARTEX-Assessment/1.0"
var assessmentReference = regexp.MustCompile(`^[A-Za-z0-9._-]{0,64}$`)
func label(ref *string) string {
	ua := assessmentUserAgent
	ua += " (engagement=" + *ref + ")"
	return ua
}
''',
    "egress/egress.go": '''package egress
const MaxJitter = 250 * time.Millisecond
var Profiles = map[string]Profile{
	"quiet":      {Name: "quiet", RPS: 2, Burst: 4, Jitter: 0.5, MaxDelay: time.Minute},
	"balanced":   {Name: "balanced", RPS: 5, Burst: 10, Jitter: 0.2, MaxDelay: 30 * time.Second},
	"aggressive": {Name: "aggressive", RPS: 20, Burst: 40, Jitter: 0.1, MaxDelay: 10 * time.Second},
}
func (g *Governor) jitterBound() time.Duration {
	return min(time.Duration(g.p.Jitter/g.p.RPS*float64(time.Second)), MaxJitter)
}
func (g *Governor) backoff(h http.Header) (time.Duration, bool) {
	v := h.Get("Retry-After")
	return parse(v, g.p.MaxDelay)
}
''',
    "Dockerfile": '''FROM debian AS tools
RUN fetch "$gh/projectdiscovery/nuclei/releases/download/$V" "nuclei.zip" "$S" nuclei; \\
    fetch "$gh/ffuf/ffuf/releases/download/$V" "ffuf.tgz" "$S" ffuf; \\
    git clone --quiet --depth 1 --branch "$V" https://github.com/sqlmapproject/sqlmap /opt/sqlmap
FROM python
RUN apt-get update && apt-get install -y --no-install-recommends \\
      curl nmap hydra \\
    && rm -rf /var/lib/apt/lists/*
RUN npm install -g "playwright@${PLAYWRIGHT_VERSION}"
RUN python -m venv /opt/bbot; /opt/bbot/bin/pip install --no-cache-dir "bbot==${BBOT_VERSION}"
''',
}


def make_artex(root, changes=None, drop=()):
    for rel, text in FILES.items():
        if rel in drop:
            continue
        for old, new in (changes or {}).get(rel, []):
            assert old in text, (rel, old)
            text = text.replace(old, new)
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
    return root


class Watch(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.baseline = os.path.join(self.tmp, "baseline.json")
        watch.write_baseline(make_artex(os.path.join(self.tmp, "recorded")), self.baseline)

    def check(self, changes=None, drop=()):
        root = make_artex(os.path.join(self.tmp, "now"), changes, drop)
        findings, _, _ = watch.check(root, self.baseline)
        return findings

    def by_fact(self, findings):
        return {(f["kind"], f["fact"]): f for f in findings}

    def test_every_fact_is_read_from_the_stand_in(self):
        facts = watch.extract(os.path.join(self.tmp, "recorded"))
        self.assertEqual([k for k, v in facts.items() if isinstance(v["value"], watch.Missing)], [])
        self.assertEqual(facts["pacing.profiles"]["value"]["quiet"],
                         {"rps": 2.0, "burst": 4, "jitter": 0.5, "max_delay_s": 60.0})
        self.assertEqual(facts["tools.release_binaries"]["value"], ["ffuf/ffuf", "projectdiscovery/nuclei"])
        self.assertEqual(facts["tools.apt"]["value"], ["curl", "hydra", "nmap"])
        self.assertEqual(facts["ua.assessment_format"]["value"], " (engagement=REF)")

    def test_an_unchanged_checkout_reports_nothing(self):
        self.assertEqual(self.check(), [])
        root = os.path.join(self.tmp, "now")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(watch.main(["check", "--artex", root, "--baseline", self.baseline]), 0)

    def test_each_change_is_reported_exactly(self):
        harvest, egress, docker = ("skills/api-recon/scripts/harvest_static.py", "egress/egress.go", "Dockerfile")
        findings = self.check(changes={
            harvest: [('UA = "Mozilla/5.0 (spa-api-recon)"', 'UA = "Mozilla/5.0 (api-harvest)"')],
            egress: [('"quiet":      {Name: "quiet", RPS: 2,', '"quiet":      {Name: "quiet", RPS: 3,'),
                     ('"aggressive": {', '"slow": {Name: "slow", RPS: 1, Burst: 1, Jitter: 0.1, '
                                         'MaxDelay: time.Minute},\n\t"aggressive": {')],
            docker: [('    fetch "$gh/ffuf/ffuf/releases/download/$V" "ffuf.tgz" "$S" ffuf; \\\n', ''),
                     ("curl nmap hydra", "curl nmap hydra masscan")],
            "skills/api-recon/scripts/runtime_harvest.js": [("function cfg", "const s = require('puppeteer-extra-plugin-stealth');\nfunction cfg")],
        }, drop=("server/update_check.go",))
        got = self.by_fact(findings)
        self.assertEqual((got[("changed", "ua.harvester")]["was"], got[("changed", "ua.harvester")]["now"]),
                         ("Mozilla/5.0 (spa-api-recon)", "Mozilla/5.0 (api-harvest)"))
        self.assertEqual(got[("changed", "pacing.profiles.quiet")]["now"]["rps"], 3.0)
        self.assertEqual(got[("added", "pacing.profiles.slow")]["now"]["rps"], 1.0)
        self.assertEqual(got[("removed", "tools.release_binaries")]["was"], "ffuf/ffuf")
        self.assertEqual(got[("added", "tools.apt")]["now"], "masscan")
        self.assertIn("puppeteer-extra-plugin-stealth", got[("added", "browser.automation_hiding")]["now"])
        self.assertEqual(got[("missing", "ua.update_check")]["now"], "server/update_check.go does not exist")
        self.assertEqual(got[("missing", "ua.update_check")]["was"], "artex-update-check")
        # Nothing else is reported as changed.
        self.assertEqual({k for k in got if k[0] != "gap"},
                         {("changed", "ua.harvester"), ("changed", "pacing.profiles.quiet"),
                          ("added", "pacing.profiles.slow"), ("removed", "tools.release_binaries"),
                          ("added", "tools.apt"), ("added", "browser.automation_hiding"),
                          ("missing", "ua.update_check")})
        report = watch.report(findings, "c" * 40, "b" * 40)
        for f in findings:
            self.assertIn(f["fact"], report)
        self.assertIn("compare/bbbbbbbbbbbb...cccccccccccc", report)

    def test_a_fact_that_moved_inside_its_file_is_reported_as_not_found(self):
        findings = self.check(changes={"config/task_user_agents.go": [
            ('const assessmentUserAgent = "ARTEX-Assessment/1.0"', 'const assessmentLabel = "ARTEX-Assessment/1.0"')]})
        got = self.by_fact(findings)
        self.assertEqual(got[("missing", "ua.assessment")]["now"],
                         "const assessmentUserAgent in config/task_user_agents.go")

    def test_gaps_in_what_the_shield_covers(self):
        findings = self.check(changes={
            "skills/api-recon/scripts/harvest_static.py": [
                ('UA = "Mozilla/5.0 (spa-api-recon)"', 'UA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0"'),
                ("|v\\d|web|admin|backend|open)", "|web|backend|open)")],
            "egress/egress.go": [('Jitter: 0.5, MaxDelay: time.Minute}', 'Jitter: 0.5, MaxDelay: 3 * time.Minute}'),
                                 ('"aggressive": {', '"stealth": {Name: "stealth", RPS: 0.2, Burst: 1, Jitter: 0.5, '
                                                     'MaxDelay: time.Minute},\n\t"aggressive": {')],
            "config/task_user_agents.go": [('" (engagement=" + *ref + ")"', '" [ref:" + *ref + "]"')],
        })
        gaps = [f["now"] for f in findings if f["kind"] == "gap"]
        self.assertTrue(any("matches no signature" in g and "Chrome/131.0" in g for g in gaps), gaps)
        self.assertTrue(any("0.2 req/s" in g and "outside the cadence" in g for g in gaps), gaps)
        self.assertTrue(any("Retry-After of up to 180 s" in g for g in gaps), gaps)
        self.assertTrue(any("/admin/legacy-" in g and "API_HINT" in g for g in gaps), gaps)
        self.assertTrue(any("engagement reference" in g for g in gaps), gaps)

    def test_the_recorded_baseline_is_covered_by_the_shield(self):
        # Guards the other direction: a change to the shield that stops covering
        # what ARTEX does today fails here, in the ordinary test run.
        with open(watch.BASELINE) as f:
            recorded = json.load(f)
        self.assertEqual(watch.coverage(recorded["facts"]), [])
        self.assertEqual(len(recorded["artex_commit"]), 40)

    def test_an_unreachable_repository_is_a_finding(self):
        findings, commit, _ = watch.check(os.path.join(self.tmp, "nothing-here"), self.baseline)
        self.assertEqual(commit, "unknown")
        self.assertEqual([(f["kind"], f["fact"]) for f in findings], [("missing", "repository")])
        self.assertIn("could not be cloned", watch.report(findings, commit, "b" * 40))

    def test_a_baseline_is_not_recorded_from_an_incomplete_checkout(self):
        root = make_artex(os.path.join(self.tmp, "partial"), drop=("egress/egress.go",))
        with self.assertRaises(SystemExit):
            watch.write_baseline(root, os.path.join(self.tmp, "partial.json"))

    def test_artex_code_is_read_never_run(self):
        marker = os.path.join(self.tmp, "ran")
        bomb = f"open({marker!r}, 'w').write('ran')\nraise SystemExit('executed')\n"
        harvest = "skills/api-recon/scripts/harvest_static.py"
        findings = self.check(changes={harvest: [("import re\n", "import re\n" + bomb)]})
        self.assertFalse(os.path.exists(marker))
        self.assertEqual([f for f in findings if f["kind"] != "gap"], [])

    def test_fingerprint_ignores_order_and_commit(self):
        a = [{"kind": "added", "fact": "x", "was": None, "now": 1}, {"kind": "changed", "fact": "y", "was": 1, "now": 2}]
        self.assertEqual(watch.fingerprint(a), watch.fingerprint(list(reversed(a))))
        self.assertNotEqual(watch.fingerprint(a), watch.fingerprint(a[:1]))


class FakeGitHub:
    def __init__(self, issues=()):
        self.issues = {i["number"]: dict(i) for i in issues}
        self.calls = []

    def __call__(self, method, path, body):
        self.calls.append((method, path, body))
        if method == "GET" and path.startswith("/issues?"):
            return 200, [i for i in self.issues.values() if i.get("state", "open") == "open"]
        if method == "POST" and path == "/labels":
            return 422, {"message": "already_exists"}
        if method == "POST" and path == "/issues":
            n = max(self.issues, default=0) + 1
            self.issues[n] = dict(body, number=n, state="open")
            return 201, self.issues[n]
        if method == "PATCH" and path.startswith("/issues/"):
            self.issues[int(path.split("/")[2])].update(body)
            return 200, {}
        if method == "POST" and path.endswith("/comments"):
            return 201, {}
        raise AssertionError((method, path))


class Issue(unittest.TestCase):
    FINDINGS = [{"kind": "changed", "category": "User-Agents", "fact": "ua.harvester", "file": "h.py",
                 "was": "a", "now": "b"}]

    def test_opens_an_issue_when_there_is_none(self):
        gh = FakeGitHub()
        self.assertEqual(watch.sync_issue(self.FINDINGS, "report", gh, "https://run"), "opened #1")
        issue = gh.issues[1]
        self.assertEqual(issue["labels"], [watch.LABEL])
        self.assertIn("report", issue["body"])
        self.assertIn("https://run", issue["body"])
        self.assertIn(watch.fingerprint(self.FINDINGS), issue["body"])
        self.assertEqual(issue["title"], "ARTEX changed: 1 thing artex-shield relies on")

    def test_the_same_findings_next_week_change_nothing(self):
        gh = FakeGitHub()
        watch.sync_issue(self.FINDINGS, "report", gh)
        gh.calls.clear()
        self.assertEqual(watch.sync_issue(self.FINDINGS, "report, new run", gh), "already reported in #1")
        self.assertEqual([c[0] for c in gh.calls], ["GET"])

    def test_different_findings_update_the_open_issue(self):
        gh = FakeGitHub()
        watch.sync_issue(self.FINDINGS, "report", gh)
        more = self.FINDINGS + [dict(self.FINDINGS[0], fact="ua.spider")]
        self.assertEqual(watch.sync_issue(more, "new report", gh), "updated #1")
        self.assertEqual(len(gh.issues), 1)
        self.assertIn("new report", gh.issues[1]["body"])
        self.assertIn(watch.fingerprint(more), gh.issues[1]["body"])
        self.assertTrue(any(c[1] == "/issues/1/comments" for c in gh.calls))

    def test_the_issue_is_closed_when_nothing_is_left(self):
        gh = FakeGitHub()
        watch.sync_issue(self.FINDINGS, "report", gh)
        self.assertEqual(watch.sync_issue([], "all clear", gh), "closed #1")
        self.assertEqual((gh.issues[1]["state"], gh.issues[1]["state_reason"]), ("closed", "completed"))
        self.assertEqual(watch.sync_issue([], "all clear", gh), "nothing to do")

    def test_pull_requests_with_the_label_are_ignored(self):
        gh = FakeGitHub([{"number": 7, "state": "open", "body": "", "pull_request": {}}])
        self.assertEqual(watch.sync_issue(self.FINDINGS, "report", gh), "opened #8")

    def test_a_failed_listing_is_an_error_not_silence(self):
        with self.assertRaises(RuntimeError):
            watch.sync_issue(self.FINDINGS, "report", lambda m, p, b: (403, {"message": "forbidden"}))


class Workflow(unittest.TestCase):
    def test_the_workflow_runs_weekly_and_only_files_issues_off_pull_requests(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            ".github", "workflows", "artex-watch.yml")
        with open(path) as f:
            text = f.read()
        self.assertRegex(text, r"schedule:\s*\n\s*- cron: \"\d+ \d+ \* \* \d\"")
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("issues: write", text)
        self.assertIn("https://github.com/BaaRai/ARTEX", text)
        self.assertRegex(text, r"if: github.event_name != 'pull_request'\s*\n\s*env:[\s\S]*sync-issue")


if __name__ == "__main__":
    unittest.main()
