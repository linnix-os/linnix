#!/usr/bin/env python3
"""Regression tests for full-test-suite pipeline status handling."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


FULL_SUITE = Path(__file__).resolve().with_name("full_test_suite.sh")


class FullTestSuiteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp_dir.name)
        self.fake_bin = self.repo / "fake-bin"
        self.fake_bin.mkdir()
        (self.repo / "scripts").mkdir()
        (self.repo / "cognitod" / "src").mkdir(parents=True)

        suite = self.repo / "scripts" / "full_test_suite.sh"
        shutil.copy2(FULL_SUITE, suite)
        self._write_executable(
            self.fake_bin / "cargo",
            """#!/bin/bash
set -u

if [ -n "${FAKE_CARGO_FAIL_MATCH:-}" ] && [[ "$*" == *"$FAKE_CARGO_FAIL_MATCH"* ]]; then
    echo "simulated cargo failure: $*" >&2
    exit 23
fi
exit 0
""",
        )
        (self.repo / "scripts" / "validate_docs.py").write_text(
            "raise SystemExit(0)\n", encoding="utf-8"
        )
        (self.repo / "cognitod" / "src" / "api" / "mod.rs").parent.mkdir(
            parents=True, exist_ok=True
        )
        (self.repo / "cognitod" / "src" / "api" / "mod.rs").write_text(
            '.route("/healthz")\n', encoding="utf-8"
        )
        (self.repo / "cognitod" / "src" / "config.rs").write_text(
            "pub struct ApiConfig {}\n", encoding="utf-8"
        )

        self.suite = suite
        self.env = os.environ.copy()
        self.env["PATH"] = f"{self.fake_bin}:/usr/bin:/bin"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    @staticmethod
    def _write_executable(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

    def _run_suite(self, failure_match: str | None = None) -> subprocess.CompletedProcess[str]:
        env = self.env.copy()
        if failure_match is not None:
            env["FAKE_CARGO_FAIL_MATCH"] = failure_match
        return subprocess.run(
            [str(self.suite)],
            cwd=self.repo,
            env=env,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def test_successful_commands_pass_the_suite(self) -> None:
        result = self._run_suite()

        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("All tests passed", result.stdout)

    def test_piped_cargo_failures_fail_the_suite(self) -> None:
        commands = (
            "nextest run --workspace --profile default",
            "nextest run --workspace --profile e2e",
            "clippy --all-targets --all-features",
            "deny check",
            "build --release",
            "xtask build-ebpf",
        )

        for command in commands:
            with self.subTest(command=command):
                result = self._run_suite(command)

                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("Some tests failed", result.stdout)


if __name__ == "__main__":
    unittest.main()
