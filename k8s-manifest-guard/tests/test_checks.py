import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from manifest_guard.checks import scan_document, extract_pod_spec
from manifest_guard.cli import main
from manifest_guard.report import render_table, render_json
from manifest_guard.findings import SEVERITY_HIGH, SEVERITY_MEDIUM

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def load(name):
    return list(yaml.safe_load_all((EXAMPLES / name).read_text()))


def checks_for(doc):
    return {f.check_id for f in scan_document(doc)}


def by_check(doc):
    out = {}
    for f in scan_document(doc):
        out.setdefault(f.check_id, []).append(f)
    return out


# ---------- fixtures ----------

def test_good_yaml_has_no_findings():
    for doc in load("good.yaml"):
        assert scan_document(doc) == []


def test_bad_yaml_fires_every_check():
    all_ids = set()
    for doc in load("bad.yaml"):
        all_ids |= checks_for(doc)
    assert {
        "IMAGE_LATEST",
        "RUN_AS_ROOT",
        "PRIVILEGED",
        "HOST_NAMESPACE",
        "MISSING_RESOURCES",
        "MISSING_LIVENESS_PROBE",
        "MISSING_READINESS_PROBE",
    } <= all_ids


# ---------- individual checks ----------

def _pod_doc(**container_overrides):
    container = {"name": "c", "image": "img:1.0"}
    container.update(container_overrides)
    return {
        "kind": "Pod",
        "metadata": {"name": "p"},
        "spec": {"containers": [container]},
    }


def test_image_latest_tag_is_high():
    ids = checks_for(_pod_doc(image="img:latest"))
    assert "IMAGE_LATEST" in ids
    f = by_check(_pod_doc(image="img:latest"))["IMAGE_LATEST"][0]
    assert f.severity == SEVERITY_HIGH


def test_image_without_tag_is_high():
    assert "IMAGE_LATEST" in checks_for(_pod_doc(image="img"))


def test_pinned_image_passes():
    assert "IMAGE_LATEST" not in checks_for(_pod_doc(image="img:1.2.3"))


def test_pinned_digest_passes():
    assert "IMAGE_LATEST" not in checks_for(_pod_doc(image="img@sha256:abc123"))


def test_run_as_root_defaults_to_high():
    assert "RUN_AS_ROOT" in checks_for(_pod_doc())


def test_run_as_non_root_container_level_passes():
    doc = _pod_doc(securityContext={"runAsNonRoot": True})
    assert "RUN_AS_ROOT" not in checks_for(doc)


def test_run_as_non_root_pod_level_passes():
    doc = _pod_doc()
    doc["spec"]["securityContext"] = {"runAsNonRoot": True}
    assert "RUN_AS_ROOT" not in checks_for(doc)


def test_privileged_is_high():
    doc = _pod_doc(securityContext={"privileged": True})
    ids = checks_for(doc)
    assert "PRIVILEGED" in ids
    assert by_check(doc)["PRIVILEGED"][0].severity == SEVERITY_HIGH


def test_not_privileged_passes():
    assert "PRIVILEGED" not in checks_for(_pod_doc())


def test_missing_resources_is_medium():
    doc = _pod_doc()
    assert "MISSING_RESOURCES" in checks_for(doc)
    assert by_check(doc)["MISSING_RESOURCES"][0].severity == SEVERITY_MEDIUM


def test_partial_resources_still_flagged():
    doc = _pod_doc(resources={"requests": {"cpu": "100m"}})
    assert "MISSING_RESOURCES" in checks_for(doc)


def test_full_resources_pass():
    doc = _pod_doc(resources={
        "requests": {"cpu": "100m", "memory": "128Mi"},
        "limits": {"cpu": "500m", "memory": "512Mi"},
    })
    assert "MISSING_RESOURCES" not in checks_for(doc)


def test_missing_probes():
    ids = checks_for(_pod_doc())
    assert "MISSING_LIVENESS_PROBE" in ids
    assert "MISSING_READINESS_PROBE" in ids


def test_present_probes_pass():
    probes = {"livenessProbe": {"exec": {"command": ["true"]}},
              "readinessProbe": {"exec": {"command": ["true"]}}}
    assert not ({"MISSING_LIVENESS_PROBE", "MISSING_READINESS_PROBE"} & checks_for(_pod_doc(**probes)))


def test_host_network_is_high():
    doc = {"kind": "Pod", "metadata": {"name": "p"},
           "spec": {"hostNetwork": True, "containers": []}}
    ids = checks_for(doc)
    assert "HOST_NAMESPACE" in ids
    assert by_check(doc)["HOST_NAMESPACE"][0].severity == SEVERITY_HIGH


def test_host_pid_and_ipc_flagged():
    doc = {"kind": "Pod", "metadata": {"name": "p"},
           "spec": {"hostPID": True, "hostIPC": True, "containers": []}}
    assert len(by_check(doc)["HOST_NAMESPACE"]) == 2


# ---------- workload extraction ----------

def test_deployment_pod_template_extracted():
    doc = {"kind": "Deployment", "metadata": {"name": "d"},
           "spec": {"template": {"spec": {"containers": [{"name": "c", "image": "i:x"}]}}}}
    workload, pod = extract_pod_spec(doc)
    assert workload == "Deployment/d"
    assert pod["containers"][0]["name"] == "c"


def test_cronjob_nested_template_extracted():
    doc = {"kind": "CronJob", "metadata": {"name": "cj"},
           "spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "c", "image": "i"}]}}}}}}
    workload, pod = extract_pod_spec(doc)
    assert workload == "CronJob/cj"
    # untagged image -> finding proves we reached the container
    assert "IMAGE_LATEST" in checks_for(doc)


def test_non_workload_kinds_ignored():
    for kind in ("Service", "ConfigMap", "Ingress", "ClusterRole"):
        doc = {"kind": kind, "metadata": {"name": "x"}, "spec": {}}
        assert scan_document(doc) == []


def test_init_containers_checked_too():
    doc = {"kind": "Pod", "metadata": {"name": "p"},
           "spec": {"containers": [{"name": "c", "image": "i:1"}],
                    "initContainers": [{"name": "init", "image": "busybox:latest"}]}}
    f = by_check(doc)["IMAGE_LATEST"][0]
    assert f.container == "init"


# ---------- CLI behaviour ----------

def test_cli_clean_manifest_exits_zero(capsys):
    assert main([str(EXAMPLES / "good.yaml")]) == 0
    out = capsys.readouterr().out
    assert "OK" in out


def test_cli_bad_manifest_exits_one(capsys):
    assert main([str(EXAMPLES / "bad.yaml")]) == 1
    out = capsys.readouterr().out
    assert "HIGH" in out


def test_cli_json_mode(capsys):
    assert main([str(EXAMPLES / "bad.yaml"), "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["files_scanned"] == 1
    assert data["summary"][SEVERITY_HIGH] > 0
    assert all("check" in f for f in data["findings"])


def test_cli_strict_fails_on_medium_only(tmp_path, capsys):
    manifest = tmp_path / "m.yaml"
    manifest.write_text(
        "kind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n"
        "  - name: c\n    image: i:1.0\n"
        "    securityContext:\n      runAsNonRoot: true\n"
    )
    # only MEDIUM findings (resources/probes) -> exit 0 normally, 1 with --strict
    assert main([str(manifest)]) == 0
    capsys.readouterr()
    assert main([str(manifest), "--strict"]) == 1


def test_cli_scans_directory():
    assert main([str(EXAMPLES)]) == 1  # bad.yaml inside fails the run


def test_table_sorts_high_first():
    doc = _pod_doc()  # HIGH (root, latest? no — image pinned) + MEDIUMs
    findings = scan_document(doc)
    table = render_table(findings, 1)
    first_high = table.index("HIGH")
    assert "MEDIUM" not in table[:first_high]


def test_render_json_shape():
    data = json.loads(render_json([], 3))
    assert data == {"files_scanned": 3, "summary": {"HIGH": 0, "MEDIUM": 0}, "findings": []}


# ---------- module entry point ----------

def test_python_m_entrypoint():
    r = subprocess.run(
        [sys.executable, "-m", "manifest_guard", str(EXAMPLES / "good.yaml")],
        capture_output=True, text=True, cwd=ROOT / "src",
    )
    assert r.returncode == 0
    assert "OK" in r.stdout
