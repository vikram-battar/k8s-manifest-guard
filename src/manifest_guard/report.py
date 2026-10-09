"""Human-readable table and machine-readable JSON output."""
import json
from .findings import SEVERITY_HIGH, SEVERITY_MEDIUM


def summarize(findings):
    counts = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def render_table(findings, files_scanned):
    if not findings:
        return f"OK: {files_scanned} file(s) scanned, no findings.\n"
    widths = {
        "severity": max(len("SEVERITY"), max(len(f.severity) for f in findings)),
        "workload": max(len("WORKLOAD"), max(len(f.workload) for f in findings)),
        "container": max(len("CONTAINER"), max(len(f.container) for f in findings)),
        "check": max(len("CHECK"), max(len(f.check_id) for f in findings)),
    }
    header = (
        f"{'SEVERITY':<{widths['severity']}}  "
        f"{'WORKLOAD':<{widths['workload']}}  "
        f"{'CONTAINER':<{widths['container']}}  "
        f"{'CHECK':<{widths['check']}}  MESSAGE"
    )
    lines = [header, "-" * len(header)]
    order = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1}
    for f in sorted(findings, key=lambda x: (order.get(x.severity, 9), x.workload, x.check_id)):
        lines.append(
            f"{f.severity:<{widths['severity']}}  "
            f"{f.workload:<{widths['workload']}}  "
            f"{f.container:<{widths['container']}}  "
            f"{f.check_id:<{widths['check']}}  {f.message}"
        )
    counts = summarize(findings)
    lines.append("")
    lines.append(
        f"{files_scanned} file(s) scanned: "
        + ", ".join(f"{counts[s]} {s}" for s in (SEVERITY_HIGH, SEVERITY_MEDIUM) if counts.get(s))
    )
    return "\n".join(lines) + "\n"


def render_json(findings, files_scanned):
    counts = summarize(findings)
    return json.dumps(
        {
            "files_scanned": files_scanned,
            "summary": counts,
            "findings": [f.to_dict() for f in findings],
        },
        indent=2,
    ) + "\n"
