"""The setup steps in the READMEs point at things that exist: every relative
link, every file a step names, and every CI job "How each one is tested"
names. A step that names a renamed file fails here, not on a reader."""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
READMES = ["README.md", "ports/node/README.md", "ports/php/README.md", "ports/openresty/README.md"]


def read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return f.read()


def section(text, heading):
    """The text under a "## heading", up to the next "## "."""
    start = text.index("## " + heading + "\n")
    end = text.find("\n## ", start + 3)
    return text[start:end if end >= 0 else len(text)]


class Links(unittest.TestCase):
    def test_every_relative_link_resolves(self):
        for readme in READMES:
            for target in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", read(readme)):
                if re.match(r"[a-z]+://", target):
                    continue
                with self.subTest(readme=readme, link=target):
                    self.assertTrue(os.path.exists(os.path.join(ROOT, os.path.dirname(readme), target)))


class SetupSteps(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = section(read("README.md"), "Which one fits your site")

    def test_every_repository_path_a_step_names_exists(self):
        named = set(re.findall(r"`((?:ports|examples|spec|tests)/[^`\s]+)`", self.text))
        named |= set(re.findall(r'"\$PWD/((?:ports|examples)/[^":]+)', self.text))
        self.assertGreater(len(named), 10)
        for path in sorted(named):
            with self.subTest(path=path):
                self.assertTrue(os.path.exists(os.path.join(ROOT, path)), path)

    def test_every_kind_of_site_has_its_steps(self):
        for kind in ("A Python app", "WordPress", "A Node app", "Any other PHP site", "A static site",
                     "Anything behind nginx", "Anything else"):
            with self.subTest(kind=kind):
                self.assertIn(f"| {kind}", self.text)
                self.assertIn(f"**{kind}", self.text.replace("**A Python app** (", "**A Python app (")
                              .replace("**A Node app** (", "**A Node app ("))

    def test_the_ci_jobs_it_names_are_the_workflow_s(self):
        jobs = set(re.findall(r"^  ([a-z][a-z0-9_-]*):\s*$", read(".github/workflows/tests.yml"), re.M))
        table = self.text[self.text.index("### How each one is tested"):]
        named = set(re.findall(r"^\| `([a-z][a-z0-9_-]*)`", table, re.M))
        self.assertEqual(named, jobs)


if __name__ == "__main__":
    unittest.main()
