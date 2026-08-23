#!/usr/bin/env python3
"""Tests for package asset validation."""

from __future__ import annotations

import importlib.util
import textwrap
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


MODULE_PATH = Path(__file__).with_name("validate_package_assets.py")
SPEC = importlib.util.spec_from_file_location("validate_package_assets", MODULE_PATH)
assert SPEC is not None
validate_package_assets = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(validate_package_assets)


def package_metadata() -> dict:
    return {
        "deb": {
            "assets": [
                ["target/release/cognitod", "usr/bin/", "755"],
                [
                    "target/bpfel-unknown-none/release/linnix-ai-ebpf-ebpf",
                    "usr/local/share/linnix/",
                    "644",
                ],
                [
                    "target/bpfel-unknown-none/release/rss_trace",
                    "usr/local/share/linnix/",
                    "644",
                ],
                ["../configs/linnix.toml", "etc/linnix/", "644"],
                ["../configs/rules.yaml", "etc/linnix/", "644"],
                ["../configs/systemd/linnix-cognitod.service", "lib/systemd/system/cognitod.service", "644"],
            ],
            "conf-files": [
                "/etc/linnix/linnix.toml",
                "/etc/linnix/rules.yaml",
            ],
        },
        "generate-rpm": {
            "assets": [
                {"source": "target/release/cognitod", "dest": "/usr/bin/cognitod", "mode": "755"},
                {
                    "source": "target/bpfel-unknown-none/release/linnix-ai-ebpf-ebpf",
                    "dest": "/usr/local/share/linnix/linnix-ai-ebpf-ebpf",
                    "mode": "644",
                },
                {
                    "source": "target/bpfel-unknown-none/release/rss_trace",
                    "dest": "/usr/local/share/linnix/rss_trace",
                    "mode": "644",
                },
                {
                    "source": "../configs/linnix.toml",
                    "dest": "/etc/linnix/linnix.toml",
                    "mode": "644",
                    "config": True,
                },
                {
                    "source": "../configs/rules.yaml",
                    "dest": "/etc/linnix/rules.yaml",
                    "mode": "644",
                    "config": True,
                },
                {
                    "source": "../configs/systemd/linnix-cognitod.service",
                    "dest": "/usr/lib/systemd/system/cognitod.service",
                    "mode": "644",
                },
            ],
        },
    }


class PackageAssetValidationTests(unittest.TestCase):
    def validate_unit(self, execstart: str, environments: list[str] | None = None) -> list[str]:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            crate_dir = root / "cognitod"
            unit_path = root / "configs" / "systemd" / "linnix-cognitod.service"
            crate_dir.mkdir()
            unit_path.parent.mkdir(parents=True)
            env_lines = "\n".join(f"Environment={env}" for env in environments or [])
            unit_path.write_text(
                textwrap.dedent(
                    f"""\
                    [Service]
                    ExecStart={execstart}
                    {env_lines}
                    """
                ),
                encoding="utf-8",
            )

            errors: list[str] = []
            validate_package_assets.validate_systemd_execstart_references(
                crate_dir,
                package_metadata(),
                errors,
            )
            return errors

    def test_execstart_paths_match_package_assets(self) -> None:
        errors = self.validate_unit(
            "/usr/bin/cognitod --config /etc/linnix/linnix.toml --handler rules:/etc/linnix/rules.yaml"
        )

        self.assertEqual(errors, [])

    def test_execstart_paths_reject_stale_binary_and_rules_file(self) -> None:
        errors = self.validate_unit(
            "/usr/local/bin/cognitod --config /etc/linnix/linnix.toml --handler rules:/etc/linnix/rules.toml"
        )

        self.assertTrue(any("/usr/local/bin/cognitod" in error for error in errors), errors)
        self.assertTrue(any("/etc/linnix/rules.toml" in error for error in errors), errors)

    def test_systemd_bpf_environment_paths_match_package_assets(self) -> None:
        errors = self.validate_unit(
            "/usr/bin/cognitod --config /etc/linnix/linnix.toml --handler rules:/etc/linnix/rules.yaml",
            [
                "LINNIX_BPF_PATH=/usr/local/share/linnix/linnix-ai-ebpf-ebpf",
                "LINNIX_RSS_TRACE_BPF_PATH=/usr/local/share/linnix/rss_trace",
            ],
        )

        self.assertEqual(errors, [])

    def test_systemd_bpf_environment_paths_reject_unshipped_objects(self) -> None:
        errors = self.validate_unit(
            "/usr/bin/cognitod --config /etc/linnix/linnix.toml --handler rules:/etc/linnix/rules.yaml",
            [
                "LINNIX_BPF_PATH=/usr/local/share/linnix/linnix-ai-ebpf-ebpf",
                "LINNIX_RSS_TRACE_BPF_PATH=/usr/local/share/linnix/rss_trace.o",
            ],
        )

        self.assertTrue(any("/usr/local/share/linnix/rss_trace.o" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
