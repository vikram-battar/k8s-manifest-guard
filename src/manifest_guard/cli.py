"""CLI: scan manifest files/dirs, print findings, exit 1 on high-severity hits."""
import argparse
import sys
from pathlib import Path

import yaml

from .checks import scan_document
from .report import render_table, render_json
from .findings import SEVERITY_HIGH, SEVERITY_MEDIUM


def iter_manifest_files(paths):
    for p in paths:
        path = Path(p)
        if path.is_dir():
            yield from sorted(
                f for f in path.rglob("*") if f.suffix in (".yaml", ".yml") and f.is_file()
            )
        elif path.is_file():
            yield path
        else:
            print(f"warning: not found, skipping: {p}", file=sys.stderr)


def scan_path(path):
    findings = []
    try:
        docs = list(yaml.safe_load_all(path.read_text()))
    except yaml.YAMLError as e:
        print(f"error: could not parse {path}: {e}", file=sys.stderr)
        return findings, 0
    scanned = 0
    for doc in docs:
        if doc is None:
            continue
        scanned += 1
        findings.extend(scan_document(doc))
    return findings, scanned


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="manifest-guard",
        description="Scan Kubernetes YAML manifests for common misconfigurations. "
                    "Exits 1 when high-severity findings exist, so it can gate CI.",
    )
    parser.add_argument("paths", nargs="+", help="manifest files or directories to scan")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    parser.add_argument(
        "--strict", action="store_true",
        help="also fail on medium-severity findings (default: fail on high only)",
    )
    args = parser.parse_args(argv)

    all_findings, files_scanned = [], 0
    for path in iter_manifest_files(args.paths):
        findings, _ = scan_path(path)
        all_findings.extend(findings)
        files_scanned += 1

    if args.json:
        print(render_json(all_findings, files_scanned), end="")
    else:
        print(render_table(all_findings, files_scanned), end="")

    severities = {f.severity for f in all_findings}
    if SEVERITY_HIGH in severities:
        return 1
    if args.strict and SEVERITY_MEDIUM in severities:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
