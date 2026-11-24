"""`fix` wrote a file for a pipeline to apply and exited 0 beside its own critical finding (G382).

`fix` is the only command that rewrites a manifest, so its exit code is the one a pipeline reads before
`kubectl apply`. Both of its branches ended in an unconditional `return 0`, and the summary it had just
printed carried the contradiction: `verdict: undetermined`, or `maxSeverity: critical` with
`privileged: true` still in the bytes it wrote. `audit` on the very file `fix` produced exits 1.

This is G370's defect in the branch directly below G370's own fix -- review class 21, fixing the reported
shape and not its neighbours, and class 25, moving arithmetic to one place while a caller keeps its copy.
The predicate here is `receipt.audit_undetermined`, the one the `validate` branch above calls, reading
`summary.verdict` and nothing else, so there is no second copy to drift (class 9).

Refused input moved 1 -> 4 in the same change: `AGENTS.md` gives 1 to "findings at or above `--fail-on`"
and 4 to "a kube-noob error, or refused input", and a caller that read 1 was told the manifest had
problems when the truth is that nothing could read it at all.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

PRIVILEGED = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: web
        image: nginx:latest
        securityContext:
          privileged: true
"""

UNDETERMINED = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: web
        image: nginx:latest
---
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: roll
  namespace: prod
spec:
  template:
    spec:
      containers:
      - name: c
        image: x:1
        securityContext:
          privileged: true
"""

HARDENED = """\
apiVersion: v1
kind: Pod
metadata:
  name: ok
  namespace: prod
spec:
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: c
    image: registry.example.com/app@sha256:%s
    readinessProbe:
      httpGet:
        path: /h
        port: 8080
    livenessProbe:
      httpGet:
        path: /h
        port: 8080
    resources:
      requests:
        cpu: 10m
        memory: 32Mi
      limits:
        memory: 64Mi
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      capabilities:
        drop: [ALL]
""" % ("a" * 64)

DUPLICATE_KEY = """\
apiVersion: v1
kind: Pod
metadata:
  name: a
  name: b
spec:
  containers: []
"""


def cli(tmp_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "kube_noob", *args],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
    )


def write(tmp_path: Path, name: str, body: str) -> str:
    (tmp_path / name).write_text(body, encoding="utf-8")
    return name


def test_fix_does_not_exit_zero_beside_its_own_critical_finding(tmp_path: Path) -> None:
    """The measured defect: `privileged: true` survives the fix and the exit said success."""
    src = write(tmp_path, "priv.yaml", PRIVILEGED)
    done = cli(tmp_path, "fix", "-f", src, "-o", "fixed.yaml", "--format", "json")
    after = json.loads(done.stdout)["after"]
    assert after["maxSeverity"] == "critical"
    assert after["counts"]["critical"] == 1
    assert done.returncode == 1
    assert "privileged: true" in (tmp_path / "fixed.yaml").read_text(encoding="utf-8")


def test_fix_agrees_with_audit_on_the_file_fix_itself_wrote(tmp_path: Path) -> None:
    """The sharpest form of the defect: two commands, one file, two answers."""
    src = write(tmp_path, "priv.yaml", PRIVILEGED)
    fixed = cli(tmp_path, "fix", "-f", src, "-o", "fixed.yaml", "--format", "json")
    audited = cli(tmp_path, "audit", "-f", "fixed.yaml", "--format", "json")
    assert fixed.returncode == audited.returncode == 1


def test_an_undetermined_after_verdict_is_never_zero(tmp_path: Path) -> None:
    """`summary.verdict: undetermined` printed by `fix` itself, beside exit 0. AGENTS.md: never 0 (G272, G281)."""
    src = write(tmp_path, "undet.yaml", UNDETERMINED)
    done = cli(tmp_path, "fix", "-f", src, "-o", "fixed.yaml", "--format", "json")
    after = json.loads(done.stdout)["after"]
    assert after["verdict"] == "undetermined"
    assert after["counts"]["high"] == after["counts"]["critical"] == 0, "the counts alone would say 0"
    assert done.returncode == 1


def test_fix_and_audit_agree_on_an_undetermined_input(tmp_path: Path) -> None:
    src = write(tmp_path, "undet.yaml", UNDETERMINED)
    fixed = cli(tmp_path, "fix", "-f", src, "-o", "out.yaml", "--format", "json")
    audited = cli(tmp_path, "audit", "-f", src, "--format", "json")
    assert fixed.returncode == audited.returncode == 1


def test_refused_input_is_four_not_one(tmp_path: Path) -> None:
    """1 means findings. A file the API server itself refuses has none: nothing read it (AGENTS.md, G382)."""
    src = write(tmp_path, "dup.yaml", DUPLICATE_KEY)
    done = cli(tmp_path, "fix", "-f", src, "-o", "fixed.yaml")
    assert done.returncode == 4
    assert "twice" in done.stderr
    assert not (tmp_path / "fixed.yaml").exists(), "a refused file is not rewritten"


def test_a_clean_manifest_still_exits_zero(tmp_path: Path) -> None:
    """The negative control. Low and medium findings do not flip it, matching `audit`'s own default."""
    src = write(tmp_path, "clean.yaml", HARDENED)
    fixed = cli(tmp_path, "fix", "-f", src, "-o", "out.yaml", "--format", "json")
    audited = cli(tmp_path, "audit", "-f", src, "--format", "json")
    after = json.loads(fixed.stdout)["after"]
    assert after.get("verdict") != "undetermined"
    assert after["counts"]["high"] == after["counts"]["critical"] == 0
    assert fixed.returncode == audited.returncode == 0


@pytest.mark.parametrize("fmt", ["text", "json", "yaml"])
def test_the_exit_code_does_not_depend_on_the_output_format(fmt: str, tmp_path: Path) -> None:
    """Both `return 0` sites were separate branches of one decision; only one of them was reached per format."""
    src = write(tmp_path, "priv.yaml", PRIVILEGED)
    assert cli(tmp_path, "fix", "-f", src, "-o", "fixed.yaml", "--format", fmt).returncode == 1


@pytest.mark.parametrize("fmt", ["text", "json"])
def test_the_exit_code_does_not_depend_on_whether_output_went_to_a_file(fmt: str, tmp_path: Path) -> None:
    """Without `-o` the document goes to stdout through the other branch, which had its own `return 0`."""
    src = write(tmp_path, "priv.yaml", PRIVILEGED)
    assert cli(tmp_path, "fix", "-f", src, "--format", fmt).returncode == 1


def test_the_fixed_document_is_still_written_when_the_exit_is_one(tmp_path: Path) -> None:
    """Exit 1 reports the remaining findings; it does not withhold the work `fix` did."""
    src = write(tmp_path, "priv.yaml", PRIVILEGED)
    done = cli(tmp_path, "fix", "-f", src, "-o", "fixed.yaml", "--format", "json")
    assert done.returncode == 1
    body = (tmp_path / "fixed.yaml").read_text(encoding="utf-8")
    assert "seccompProfile" in body and "runAsNonRoot" in body
    assert len(json.loads(done.stdout)["changes"]) == 2
