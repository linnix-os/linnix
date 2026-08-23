#!/usr/bin/env python3
"""Validate package metadata asset sources that should exist before builds."""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path


def is_build_output(source: str) -> bool:
    return source == "target" or source.startswith("target/")


def require_file(path: Path, label: str, errors: list[str]) -> None:
    if not path.is_file():
        errors.append(f"{label} does not exist: {path}")


def validate_deb_assets(crate_dir: Path, metadata: dict, errors: list[str]) -> None:
    deb = metadata.get("deb", {})

    license_file = deb.get("license-file")
    if isinstance(license_file, list) and license_file:
        require_file((crate_dir / license_file[0]).resolve(), "deb license-file", errors)

    maintainer_scripts = deb.get("maintainer-scripts")
    if isinstance(maintainer_scripts, str):
        scripts_dir = (crate_dir / maintainer_scripts).resolve()
        if not scripts_dir.is_dir():
            errors.append(f"deb maintainer-scripts directory does not exist: {scripts_dir}")

    for index, asset in enumerate(deb.get("assets", []), start=1):
        if not isinstance(asset, list) or not asset:
            errors.append(f"deb asset #{index} is malformed: {asset!r}")
            continue

        source = asset[0]
        if isinstance(source, str) and not is_build_output(source):
            require_file((crate_dir / source).resolve(), f"deb asset #{index}", errors)


def validate_rpm_assets(crate_dir: Path, metadata: dict, errors: list[str]) -> None:
    rpm = metadata.get("generate-rpm", {})

    for index, asset in enumerate(rpm.get("assets", []), start=1):
        source = asset.get("source") if isinstance(asset, dict) else None
        if isinstance(source, str) and not is_build_output(source):
            require_file((crate_dir / source).resolve(), f"rpm asset #{index}", errors)
        elif source is None:
            errors.append(f"rpm asset #{index} is missing source: {asset!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest-path",
        default="cognitod/Cargo.toml",
        help="Path to the crate Cargo.toml containing package metadata",
    )
    args = parser.parse_args()

    manifest = Path(args.manifest_path).resolve()
    crate_dir = manifest.parent

    with manifest.open("rb") as manifest_file:
        cargo_toml = tomllib.load(manifest_file)

    metadata = cargo_toml.get("package", {}).get("metadata", {})
    errors: list[str] = []

    validate_deb_assets(crate_dir, metadata, errors)
    validate_rpm_assets(crate_dir, metadata, errors)

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print(f"Package asset metadata is valid: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
