"""The actual misconfiguration checks. Pure YAML dict inspection, no cluster needed."""
from .findings import Finding, SEVERITY_HIGH, SEVERITY_MEDIUM

# workload kinds we know how to extract a pod spec from
_POD_TEMPLATE_KINDS = {
    "Deployment",
    "ReplicaSet",
    "ReplicationController",
    "StatefulSet",
    "DaemonSet",
    "Job",
}


def extract_pod_spec(doc):
    """Return (workload_name, pod_spec) or (None, None) for non-workload kinds."""
    if not isinstance(doc, dict):
        return None, None
    kind = doc.get("kind", "")
    name = (doc.get("metadata") or {}).get("name", "<unnamed>")
    spec = doc.get("spec") or {}

    if kind in _POD_TEMPLATE_KINDS:
        pod = ((spec.get("template") or {}).get("spec")) or {}
    elif kind == "CronJob":
        job_spec = (spec.get("jobTemplate") or {}).get("spec") or {}
        pod = ((job_spec.get("template") or {}).get("spec")) or {}
    elif kind == "Pod":
        pod = spec
    else:
        return None, None
    return f"{kind}/{name}", pod


def _containers(pod_spec):
    """Yield (container_name, container_dict, is_init) for app + init containers."""
    for c in pod_spec.get("containers") or []:
        yield (c.get("name", "<unnamed>"), c, False)
    for c in pod_spec.get("initContainers") or []:
        yield (c.get("name", "<unnamed>"), c, True)


def check_image_tag(workload, cname, container):
    image = container.get("image", "")
    # no tag at all defaults to :latest in Kubernetes, so treat it the same
    if not image or image.endswith(":latest") or ":" not in image.split("/")[-1]:
        return Finding(
            "IMAGE_LATEST", SEVERITY_HIGH, workload, cname,
            f"image '{image or '<empty>'}' uses :latest or has no tag — pin a digest or version",
        )
    return None


def check_run_as_root(workload, cname, container, pod_spec):
    c_sc = container.get("securityContext") or {}
    p_sc = pod_spec.get("securityContext") or {}
    if c_sc.get("runAsNonRoot") is True or p_sc.get("runAsNonRoot") is True:
        return None
    return Finding(
        "RUN_AS_ROOT", SEVERITY_HIGH, workload, cname,
        "runAsNonRoot is not set — container runs as root by default",
    )


def check_privileged(workload, cname, container):
    c_sc = container.get("securityContext") or {}
    if c_sc.get("privileged") is True:
        return Finding(
            "PRIVILEGED", SEVERITY_HIGH, workload, cname,
            "privileged: true gives the container full host access",
        )
    return None


def check_resources(workload, cname, container):
    resources = container.get("resources") or {}
    missing = [k for k in ("requests", "limits") if not resources.get(k)]
    if missing:
        return Finding(
            "MISSING_RESOURCES", SEVERITY_MEDIUM, workload, cname,
            f"missing resource {', '.join(missing)} — no QoS class, noisy-neighbor risk",
        )
    return None


def check_probes(workload, cname, container):
    findings = []
    if not container.get("livenessProbe"):
        findings.append(Finding(
            "MISSING_LIVENESS_PROBE", SEVERITY_MEDIUM, workload, cname,
            "no livenessProbe — kubelet can't restart a truly dead container",
        ))
    if not container.get("readinessProbe"):
        findings.append(Finding(
            "MISSING_READINESS_PROBE", SEVERITY_MEDIUM, workload, cname,
            "no readinessProbe — traffic can hit a container that isn't ready",
        ))
    return findings


def check_host_namespaces(workload, pod_spec):
    findings = []
    for flag in ("hostNetwork", "hostPID", "hostIPC"):
        if pod_spec.get(flag) is True:
            findings.append(Finding(
                "HOST_NAMESPACE", SEVERITY_HIGH, workload, "-",
                f"{flag}: true breaks pod isolation",
            ))
    return findings


def scan_document(doc):
    """Run every check against one parsed YAML document. Returns [Finding]."""
    findings = []
    workload, pod_spec = extract_pod_spec(doc)
    if workload is None:
        return findings

    findings.extend(check_host_namespaces(workload, pod_spec))
    for cname, container, _is_init in _containers(pod_spec):
        for check in (
            lambda: check_image_tag(workload, cname, container),
            lambda: check_run_as_root(workload, cname, container, pod_spec),
            lambda: check_privileged(workload, cname, container),
            lambda: check_resources(workload, cname, container),
        ):
            f = check()
            if f:
                findings.append(f)
        findings.extend(check_probes(workload, cname, container))
    return findings
