#!/usr/bin/env python3
"""Regression tests for the generated pre-commit hook."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


INSTALLER = Path(__file__).resolve().with_name("install-git-hooks.sh")


class PreCommitHookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp_dir.name)
        self.fake_bin = self.repo / "fake-bin"
        (self.repo / ".git" / "hooks").mkdir(parents=True)
        (self.repo / "scripts").mkdir()
        self.fake_bin.mkdir()
        (self.repo / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")

        installer = self.repo / "scripts" / "install-git-hooks.sh"
        shutil.copy2(INSTALLER, installer)
        self._write_executable(
            self.fake_bin / "cargo",
            """#!/bin/bash
set -u

case "${1:-}" in
    fmt)
        status="${FAKE_FMT_STATUS:-0}"
        ;;
    clippy)
        status="${FAKE_CLIPPY_STATUS:-0}"
        ;;
    nextest)
        status="${FAKE_NEXTEST_STATUS:-0}"
        ;;
    deny)
        status="${FAKE_DENY_STATUS:-0}"
        ;;
    *)
        echo "unexpected cargo command: ${1:-}" >&2
        exit 64
        ;;
esac

if [ "$status" -ne 0 ]; then
    echo "simulated ${1:-} failure" >&2
fi
exit "$status"
""",
        )
        self.env = os.environ.copy()
        self.env["PATH"] = f"{self.fake_bin}:/usr/bin:/bin"
        subprocess.run(
            [str(installer)],
            cwd=self.repo,
            env=self.env,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    @staticmethod
    def _write_executable(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

    def _run_hook(self, **statuses: str) -> subprocess.CompletedProcess[str]:
        env = self.env.copy()
        env.update(statuses)
        return subprocess.run(
            [str(self.repo / ".git" / "hooks" / "pre-commit")],
            cwd=self.repo,
            env=env,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def test_successful_checks_allow_commit(self) -> None:
        result = self._run_hook()

        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("All pre-commit checks passed", result.stdout)

    def test_cargo_failures_are_not_masked_by_output_filters(self) -> None:
        cases = (
            ("FAKE_FMT_STATUS", "Format check failed"),
            ("FAKE_CLIPPY_STATUS", "Clippy failed"),
            ("FAKE_NEXTEST_STATUS", "Tests failed"),
        )

        for variable, expected_message in cases:
            with self.subTest(command=variable):
                result = self._run_hook(**{variable: "23"})

                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(expected_message, result.stdout)
                self.assertNotIn("All pre-commit checks passed", result.stdout)

    def test_cargo_deny_failure_is_not_masked_by_tail(self) -> None:
        self._write_executable(self.fake_bin / "cargo-deny", "#!/bin/sh\nexit 0\n")

        result = self._run_hook(FAKE_DENY_STATUS="23")

        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("Cargo deny failed", result.stdout)
        self.assertNotIn("All pre-commit checks passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
