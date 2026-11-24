"""The Python shield against spec/vectors.json, the cases every port must pass.
See spec/SPEC.md for the format; this file is also a reference runner."""
import json
import logging
import os
import unittest
from datetime import datetime, timezone

from artex_shield import Config, Engagement, Shield

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
            d = s.check(r["ip"], r.get("method", "GET"), r["path"], r.get("query", ""), r.get("headers", {}))
            if expect is not None:
                self.compare(where, d, expect, full)
        elif "observe" in step:
            o = step["observe"]
            s.observe(o["ip"], o["path"], o["status"], o.get("induced", False))
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
                t = self.t0 + step["at"]
                outcomes = [(run["times"], run["each"], run["last"]) for run in step["expect"]]
                iteration = 0
                for times, each, last in outcomes:
                    for k in range(times):
                        self.clock.t = t
                        final = k == times - 1
                        for j, template in enumerate(step["steps"]):
                            want = (last if final else each)[j]
                            self.step(f"{n} (repeat {iteration}, part {j})", fill(template, step["i_from"] + iteration),
                                      want, full=final)
                        t += step["every"]
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
        self.assertEqual((self.data["version"], self.data["t0"]), (1, 1_800_000_000.0))
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

    def test_config_errors(self):
        for item in self.data["config_errors"]:
            with self.subTest(config=item["config"]):
                with self.assertRaises(ValueError):
                    make_config(item["config"], self.data["t0"])


if __name__ == "__main__":
    unittest.main()
