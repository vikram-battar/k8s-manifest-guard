# k8s-manifest-guard

I got tired of the same conversation in every PR review: "this image is `:latest`", "where are the resource limits", "why is this running as root". So I wrote the check once, as a CLI, and now the pipeline has the conversation instead of me.

manifest-guard scans your Kubernetes YAML and fails CI when it finds something bad. No cluster needed — it's pure YAML parsing, so it runs in seconds on a laptop or in any pipeline.

This is a portfolio reference implementation I built from scratch. Not from any employer.

## what it catches

HIGH severity (fails the build):
- images on `:latest` or with no tag at all
- containers running as root (`runAsNonRoot` not set)
- `privileged: true`
- `hostNetwork` / `hostPID` / `hostIPC`

MEDIUM severity (reported, doesn't fail unless you pass `--strict`):
- missing resource requests or limits
- missing liveness or readiness probes

It understands Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, bare Pods, and the rest — it digs out the pod template wherever it lives. Init containers get checked too. Anything else (Services, ConfigMaps, etc.) is skipped quietly.

## try it

```bash
pip install -r requirements.txt

# scan a file or a whole directory
PYTHONPATH=src python -m manifest_guard examples/good.yaml
PYTHONPATH=src python -m manifest_guard manifests/

# machine-readable output for piping into other tools
PYTHONPATH=src python -m manifest_guard manifests/ --json

# also fail on medium findings
PYTHONPATH=src python -m manifest_guard manifests/ --strict
```

Exit code is `1` when there's anything high-severity, `0` otherwise. That's the whole CI contract:

```yaml
# .github/workflows/ci.yml
- run: pip install pyyaml
- run: PYTHONPATH=src python -m manifest_guard k8s/
```

Or Docker, if you'd rather not think about Python versions:

```bash
docker build -t manifest-guard .
docker run --rm -v $(pwd)/k8s:/k8s manifest-guard /k8s
```

## what the output looks like

```
SEVERITY  WORKLOAD              CONTAINER  CHECK                 MESSAGE
----------------------------------------------------------------------------------------
HIGH      Deployment/broken-app  app        IMAGE_LATEST          image 'myapp:latest' uses :latest or has no tag — pin a digest or version
HIGH      Deployment/broken-app  app        RUN_AS_ROOT           runAsNonRoot is not set — container runs as root by default
HIGH      Deployment/broken-app  sidecar    PRIVILEGED            privileged: true gives the container full host access
HIGH      Deployment/broken-app  -          HOST_NAMESPACE        hostNetwork: true breaks pod isolation
MEDIUM    Deployment/broken-app  app        MISSING_RESOURCES     missing resource requests, limits — no QoS class, noisy-neighbor risk
MEDIUM    Deployment/broken-app  app        MISSING_LIVENESS_PROBE  no livenessProbe — kubelet can't restart a truly dead container

1 file(s) scanned: 4 HIGH, 2 MEDIUM
```

`examples/bad.yaml` is deliberately broken — run the tool against it to see every check fire. `examples/good.yaml` passes clean and doubles as a template for new workloads.

## why not just use kube-linter / kubesec / checkov?

Those are good tools and you should probably run one of them too. I built this because I wanted something with zero dependencies beyond PyYAML, checks I actually agree with, and output I can read at a glance in a pipeline log. It's also small enough to audit in an afternoon — the whole thing is a few hundred lines.

## dev

```bash
make test          # pytest, must be green
make lint          # py_compile + yaml syntax on everything
make check-examples  # good.yaml exits 0, bad.yaml exits 1
```

## license

MIT.
