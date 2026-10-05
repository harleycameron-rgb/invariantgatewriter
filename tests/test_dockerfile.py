"""Static checks on the container recipe (no Docker daemon needed)."""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def instructions():
    text = (ROOT / "Dockerfile").read_text().replace("\\\n", " ")
    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


class DockerfileTests(unittest.TestCase):
    def test_installs_pinned_ed25519_requirements_from_wheels_before_dropping_root(self):
        lines = instructions()
        copy = next(i for i, l in enumerate(lines) if l.startswith("COPY") and "requirements-ed25519.txt" in l)
        run = next(i for i, l in enumerate(lines) if l.startswith("RUN") and "-r requirements-ed25519.txt" in l)
        user = next(i for i, l in enumerate(lines) if l.startswith("USER"))
        self.assertLess(copy, run)
        self.assertLess(run, user)
        self.assertIn("--only-binary=:all:", lines[run])
        self.assertIn("ed25519", lines[run].split("&&", 1)[1])

    def test_requirement_is_exactly_pinned(self):
        reqs = [l.strip() for l in (ROOT / "requirements-ed25519.txt").read_text().splitlines()
                if l.strip() and not l.startswith("#")]
        self.assertEqual(len(reqs), 1)
        self.assertRegex(reqs[0], r"^cryptography==\d+\.\d+\.\d+$")
        self.assertGreaterEqual(int(reqs[0].split("==")[1].split(".")[0]), 42)

    def test_runs_non_root_and_ships_only_the_package(self):
        lines = instructions()
        self.assertEqual([l for l in lines if l.startswith("USER")], ["USER 65532:65532"])
        copies = [l for l in lines if l.startswith("COPY")]
        self.assertEqual(len(copies), 2)
        self.assertTrue(any("invariantgatewriter/ ./invariantgatewriter/" in l for l in copies))
        self.assertEqual(lines[-1], 'CMD ["python", "-m", "invariantgatewriter.public_node"]')
        self.assertIn("PIP_NO_CACHE_DIR=1", " ".join(lines))

    def test_dockerignore_keeps_requirements_and_drops_tests(self):
        ignored = (ROOT / ".dockerignore").read_text().split()
        self.assertIn("tests", ignored)
        self.assertFalse(any(re.fullmatch(p.replace("*", ".*"), "requirements-ed25519.txt") for p in ignored))


if __name__ == "__main__":
    unittest.main()
