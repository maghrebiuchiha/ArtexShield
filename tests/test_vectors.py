"""The Python shield against spec/vectors.json, the cases every port must pass.
See spec/SPEC.md for the format; this file is also a reference runner."""
import base64
import json
import logging
import os
import unittest
from datetime import datetime, timezone

from artex_shield import Config, Engagement, Shield, client_check, make_canaries, make_honeytokens

SPEC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "spec", "vectors.json")
logging.getLogger("artex_shield").disabled = True
SCORE_TOLERANCE = 1e-6


def load():
    with open(SPEC, encoding="utf-8") as f:
        return json.load(f)


def make_config(spec, t0):
    kw = dict(spec)
    if "engagements" in kw:
        kw["engagements"] = [Engagement(e["reference"], e["cidrs"], datetime.fromtimestamp(t0 + e["start"], timezone.utc),
                                        datetime.fromtimestamp(t0 + e["end"], timezone.utc)) for e in kw["engagements"]]
    return Config(**kw)


def body(request):
    """A request's body as bytes, or None."""
    if "body_base64" in request:
        return base64.b64decode(request["body_base64"])
    return request["body"].encode("utf-8") if "body" in request else None


def fill(template, i):
    """A repeat block's step with {i} replaced by the iteration's number."""
    if isinstance(template, str):
        return template.replace("{i}", str(i))
    if isinstance(template, dict):
        return {k: fill(v, i) for k, v in template.items()}
    if isinstance(template, list):
        return [fill(v, i) for v in template]
    return template


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


class Runner:
    """Replays one case. Each failure is a string naming the step."""

    def __init__(self, case, t0):
        self.case, self.t0, self.failures = case, t0, []
        self.clock = Clock(t0)
        self.shield = Shield(make_config(case.get("config", {}), t0), clock=self.clock)

    def fail(self, where, message):
        self.failures.append(f"{self.case['id']} step {where}: {message}")

    def compare(self, where, got, want, full=True):
        if got.action != want["action"]:
            self.fail(where, f"action {got.action!r}, expected {want['action']!r} (hits {sorted(got.hits)})")
        if sorted(got.hits) != want["hits"]:
            self.fail(where, f"hits {sorted(got.hits)}, expected {want['hits']}")
        if full and abs(got.score - want["score"]) > SCORE_TOLERANCE:
            self.fail(where, f"score {got.score}, expected {want['score']}")
        if full and "retry_after" in want and got.retry_after != want["retry_after"]:
            self.fail(where, f"retry_after {got.retry_after}, expected {want['retry_after']}")

    def step(self, where, step, expect=None, full=True):
        s = self.shield
        if "request" in step:
            r = step["request"]
            d = s.check(r["ip"], r.get("method", "GET"), r["path"], r.get("query", ""), r.get("headers", {}), body(r))
            if expect is not None:
                self.compare(where, d, expect, full)
        elif "observe" in step:
            o = step["observe"]
            s.observe(o["ip"], o["path"], o["status"], o.get("induced", False), o.get("content_type", ""))
        elif "client_check" in step:
            c = step["client_check"]
            status, headers, _ = s.client_check_reply(c["ip"], c["query"], c.get("headers", {}), c.get("secure", False))
            got = {"status": status, "headers": [list(h) for h in headers]}
            if got != step["expect"]:
                self.fail(where, f"client check answered {got}, expected {step['expect']}")

        elif "unblock" in step:
            got = s.unblock(step["unblock"])
            if got != step["expect"]:
                self.fail(where, f"unblock returned {got}, expected {step['expect']}")
        elif "expect_blocklist" in step:
            got = sorted(s.blocklist())
            if got != step["expect_blocklist"]:
                self.fail(where, f"blocklist {got}, expected {step['expect_blocklist']}")
        else:
            self.fail(where, f"unknown step {sorted(step)}")

    def run(self):
        for n, step in enumerate(self.case["steps"]):
            if "repeat" in step:
                t, started = self.t0 + step["at"], False
                outcomes = [(run["times"], run["each"], run["last"]) for run in step["expect"]]
                iteration = 0
                for times, each, last in outcomes:
                    for k in range(times):
                        final = k == times - 1
                        for j, template in enumerate(step["steps"]):
                            if started:
                                t += step["dt"][j]          # accumulated, never at + k * dt
                            started = True
                            self.clock.t = t
                            want = (last if final else each)[j]
                            self.step(f"{n} (repeat {iteration}, part {j})", fill(template, step["i_from"] + iteration),
                                      want, full=final)
                        iteration += 1
                if iteration != step["repeat"]:
                    self.fail(n, f"repeat block expects {iteration} iterations, declares {step['repeat']}")
            else:
                self.clock.t = self.t0 + step["at"]
                self.step(n, step, step.get("expect"))
        return self.failures


class Vectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = load()

    def test_the_file_is_the_version_this_runner_reads(self):
        self.assertEqual((self.data["version"], self.data["t0"]), (2, 1_800_000_000.0))
        self.assertGreater(len(self.data["cases"]), 400)

    def test_cases(self):
        failures = []
        for case in self.data["cases"]:
            with self.subTest(case=case["id"]):
                got = Runner(case, self.data["t0"]).run()
                failures += got
                self.assertEqual(got, [])

    def test_client_ip(self):
        for item in self.data["client_ip"]:
            with self.subTest(item=item):
                s = Shield(Config(trusted_proxies=item["trusted_proxies"]))
                self.assertEqual(s.client_ip(item["remote"], item["forwarded_for"]), item["expect"])

    def test_client_check_routes(self):
        for item in self.data["client_check_routes"]:
            with self.subTest(item=item):
                s = Shield(make_config(item["config"], self.data["t0"]))
                self.assertEqual(s.client_check_route(item["path"]), item["expect"])

    def test_derivations(self):
        for item in self.data["canaries"]:
            self.assertEqual(make_canaries(item["secret"], item["count"]), item["paths"])
        for item in self.data["honeytokens"]:
            t = make_honeytokens(item["secret"], item["count"])
            self.assertEqual((list(t.api_keys), list(t.users), list(t.passwords)),
                             (item["api_keys"], item["users"], item["passwords"]))

    def test_pattern_probes(self):
        from artex_shield import signatures as sig
        probes = self.data["pattern_probes"]
        table = {f"hard_ua:{label}": rx for rx, _, label in sig.HARD_UA}
        table.update({f"soft_ua:{label}": rx for rx, _, label in sig.SOFT_UA})
        table.update({f"payloads:{label}": rx for rx, label in sig.PAYLOADS})
        table.update({f"oob:{label}": rx for rx, label in sig.OOB})
        for name, want in probes["matches"].items():
            rx = table.get(name) or getattr(sig, name.upper())
            got = "".join("1" if rx.search(text) else "0" for text in probes["texts"])
            self.assertEqual(got, want, name)

    def test_client_check_script(self):
        self.assertEqual(self.data["client_check_script"].replace("PATH", json.dumps("/_artex/check")),
                         client_check.script("/_artex/check"))

    def test_config_errors(self):
        for item in self.data["config_errors"]:
            with self.subTest(config=item["config"]):
                with self.assertRaises(ValueError):
                    make_config(item["config"], self.data["t0"])


if __name__ == "__main__":
    unittest.main()
