"""k8s-manifest-guard: fail CI on insecure Kubernetes manifests."""
from .findings import Finding, SEVERITY_HIGH, SEVERITY_MEDIUM
from .checks import scan_document
from .report import render_table, render_json

__all__ = [
    "Finding",
    "SEVERITY_HIGH",
    "SEVERITY_MEDIUM",
    "scan_document",
    "render_table",
    "render_json",
]

__version__ = "0.1.0"
