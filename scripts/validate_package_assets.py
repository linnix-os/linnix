#!/usr/bin/env python3
"""Validate package metadata asset sources that should exist before builds."""

from __future__ import annotations

import argparse
import re
import shlex
import sys
import tomllib
from pathlib import Path, PurePosixPath


LOCAL_SCHEME_PATH_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:(/[^/].*)$")
PACKAGE_OWNED_SYSTEMD_ENV_PATHS = {
    "LINNIX_BPF_PATH",
    "LINNIX_RSS_TRACE_BPF_PATH",
}


def is_build_output(source: str) -> bool:
    return source == "target" or source.startswith("target/")


def require_file(path: Path, label: str, errors: list[str]) -> None:
    if not path.is_file():
        errors.append(f"{label} does not exist: {path}")


def normalize_package_dest(dest: str, source: str) -> str:
    package_path = dest if dest.startswith("/") else f"/{dest}"
    if package_path.endswith("/"):
        package_path = f"{package_path}{Path(source).name}"
    return PurePosixPath(package_path).as_posix()


def collect_deb_package_paths(deb: dict) -> tuple[set[str], set[str]]:
    installed_paths: set[str] = set()
    config_paths: set[str] = set()

    for asset in deb.get("assets", []):
        if not isinstance(asset, list) or len(asset) < 2:
            continue

        source = asset[0]
        dest = asset[1]
        if isinstance(source, str) and isinstance(dest, str):
            installed_paths.add(normalize_package_dest(dest, source))

    for conf_file in deb.get("conf-files", []):
        if isinstance(conf_file, str):
            config_paths.add(PurePosixPath(conf_file).as_posix())

    return installed_paths, config_paths


def collect_rpm_package_paths(rpm: dict) -> tuple[set[str], set[str]]:
    installed_paths: set[str] = set()
    config_paths: set[str] = set()

    for asset in rpm.get("assets", []):
        if not isinstance(asset, dict):
            continue

        source = asset.get("source")
        dest = asset.get("dest")
        if isinstance(source, str) and isinstance(dest, str):
            package_path = normalize_package_dest(dest, source)
            installed_paths.add(package_path)
            if asset.get("config") is True:
                config_paths.add(package_path)

    return installed_paths, config_paths


def systemd_unit_sources_from_deb(deb: dict) -> set[str]:
    sources: set[str] = set()

    for asset in deb.get("assets", []):
        if not isinstance(asset, list) or len(asset) < 2:
            continue

        source = asset[0]
        dest = asset[1]
        if not isinstance(source, str) or not isinstance(dest, str):
            continue

        dest_path = normalize_package_dest(dest, source)
        if "/systemd/system/" in dest_path and dest_path.endswith(".service"):
            sources.add(source)

    return sources


def systemd_unit_sources_from_rpm(rpm: dict) -> set[str]:
    sources: set[str] = set()

    for asset in rpm.get("assets", []):
        if not isinstance(asset, dict):
            continue

        source = asset.get("source")
        dest = asset.get("dest")
        if not isinstance(source, str) or not isinstance(dest, str):
            continue

        dest_path = normalize_package_dest(dest, source)
        if "/systemd/system/" in dest_path and dest_path.endswith(".service"):
            sources.add(source)

    return sources


def parse_systemd_assignments(unit_path: Path, wanted_key: str) -> list[tuple[int, str]]:
    assignments: list[tuple[int, str]] = []
    pending_lineno: int | None = None
    pending_value: str | None = None

    for lineno, line in enumerate(unit_path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue

        if pending_value is not None:
            continued = stripped.endswith("\\")
            fragment = stripped[:-1].rstrip() if continued else stripped
            pending_value = f"{pending_value} {fragment}".strip()
            if not continued:
                assignments.append((pending_lineno or lineno, pending_value))
                pending_lineno = None
                pending_value = None
            continue

        if "=" not in stripped:
            continue

        key, value = stripped.split("=", 1)
        if key != wanted_key:
            continue

        continued = value.rstrip().endswith("\\")
        if continued:
            pending_lineno = lineno
            pending_value = value.rstrip()[:-1].rstrip()
        else:
            assignments.append((lineno, value.strip()))

    if pending_value is not None:
        assignments.append((pending_lineno or 1, pending_value))

    return assignments


def parse_systemd_execstart(unit_path: Path) -> list[tuple[int, str]]:
    return parse_systemd_assignments(unit_path, "ExecStart")


def parse_systemd_environment(unit_path: Path) -> list[tuple[int, str]]:
    return parse_systemd_assignments(unit_path, "Environment")


def strip_systemd_exec_prefixes(token: str) -> str:
    stripped = token
    while stripped and stripped[0] in "-:+!@":
        stripped = stripped[1:]
    return stripped or token


def local_path_candidates(token: str) -> list[str]:
    fragments = [token]
    if "=" in token:
        fragments.append(token.split("=", 1)[1])

    candidates: list[str] = []
    for fragment in fragments:
        if fragment.startswith("/") and not fragment.startswith("//"):
            candidates.append(PurePosixPath(fragment).as_posix())
            continue

        scheme_match = LOCAL_SCHEME_PATH_RE.match(fragment)
        if scheme_match:
            candidates.append(PurePosixPath(scheme_match.group(1)).as_posix())

    return candidates


def execstart_referenced_paths(command: str) -> list[str]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as error:
        raise ValueError(f"could not parse ExecStart command {command!r}: {error}") from error

    paths: list[str] = []
    seen: set[str] = set()

    for index, token in enumerate(tokens):
        candidates = local_path_candidates(strip_systemd_exec_prefixes(token) if index == 0 else token)
        for candidate in candidates:
            if candidate not in seen:
                paths.append(candidate)
                seen.add(candidate)

    return paths


def environment_referenced_paths(environment: str) -> list[tuple[str, str]]:
    try:
        tokens = shlex.split(environment, posix=True)
    except ValueError as error:
        raise ValueError(f"could not parse Environment assignment {environment!r}: {error}") from error

    paths: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for token in tokens:
        if "=" not in token:
            continue

        name, value = token.split("=", 1)
        if name not in PACKAGE_OWNED_SYSTEMD_ENV_PATHS:
            continue

        for candidate in local_path_candidates(value):
            item = (name, candidate)
            if item not in seen:
                paths.append(item)
                seen.add(item)

    return paths


def validate_systemd_units(
    crate_dir: Path,
    package_label: str,
    unit_sources: set[str],
    installed_paths: set[str],
    config_paths: set[str],
    errors: list[str],
) -> None:
    available_paths = installed_paths | config_paths

    for source in sorted(unit_sources):
        unit_path = (crate_dir / source).resolve()
        if not unit_path.is_file():
            continue

        for lineno, command in parse_systemd_execstart(unit_path):
            try:
                referenced_paths = execstart_referenced_paths(command)
            except ValueError as error:
                errors.append(f"{package_label} systemd ExecStart parse error in {unit_path}:{lineno}: {error}")
                continue

            for referenced_path in referenced_paths:
                if referenced_path not in available_paths:
                    errors.append(
                        f"{package_label} systemd ExecStart references {referenced_path}, "
                        f"which is not installed by package assets/conf-files: {unit_path}:{lineno}"
                    )

        for lineno, environment in parse_systemd_environment(unit_path):
            try:
                referenced_paths = environment_referenced_paths(environment)
            except ValueError as error:
                errors.append(f"{package_label} systemd Environment parse error in {unit_path}:{lineno}: {error}")
                continue

            for name, referenced_path in referenced_paths:
                if referenced_path not in available_paths:
                    errors.append(
                        f"{package_label} systemd Environment {name} references {referenced_path}, "
                        f"which is not installed by package assets/conf-files: {unit_path}:{lineno}"
                    )


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


def validate_systemd_execstart_references(crate_dir: Path, metadata: dict, errors: list[str]) -> None:
    deb = metadata.get("deb", {})
    rpm = metadata.get("generate-rpm", {})

    deb_installed_paths, deb_config_paths = collect_deb_package_paths(deb)
    rpm_installed_paths, rpm_config_paths = collect_rpm_package_paths(rpm)

    validate_systemd_units(
        crate_dir,
        "deb",
        systemd_unit_sources_from_deb(deb),
        deb_installed_paths,
        deb_config_paths,
        errors,
    )
    validate_systemd_units(
        crate_dir,
        "rpm",
        systemd_unit_sources_from_rpm(rpm),
        rpm_installed_paths,
        rpm_config_paths,
        errors,
    )


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
    validate_systemd_execstart_references(crate_dir, metadata, errors)

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print(f"Package asset metadata is valid: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
