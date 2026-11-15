"""Helm hook resources are audited like every other template (G272).

A chart's `pre-install`/`post-install`/`pre-upgrade` Jobs, and the ServiceAccounts and RBAC they bring, run with
whatever the chart gives them, often before anything else in the release exists. If `helm-audit` or `gate --chart`
rendered without them -- `helm template --no-hooks` -- or dropped them on the way to the rules, a privileged hook
would be an absence read as a pass.

Neither does. `helm template` writes hooks after the release manifest, each under its own `# Source:` line, unless
`--no-hooks` is given, and skips test hooks only with `--skip-tests` (helm/helm pkg/cmd/template.go at v4.0.0 and
cmd/helm/template.go at v3.19.0, read 2026-11-11). kube-noob passes neither. These tests hold that, and hold that a
hook Job gets exactly the findings the same Job gets without the annotation.

The `helm` binary is not on this machine or in the unit-test job, so `subprocess.run` is replaced with output in
the exact shape that code writes; `ci/helm-and-dogfood` renders real charts.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

JOB = {
    "apiVersion": "batch/v1",
    "kind": "Job",
    "metadata": {"name": "migrate", "namespace": "shop"},
    "spec": {
        "template": {
            "spec": {
                "restartPolicy": "Never",
                "serviceAccountName": "migrate",
                "containers": [
                    {
                        "name": "migrate",
                        "image": "quay.io/acme/migrate:latest",
                        "securityContext": {"privileged": True, "runAsUser": 0},
                    }
                ],
            }
        }
    },
}
ROLE = {
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "kind": "ClusterRole",
    "metadata": {"name": "migrate"},
    "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
}
CONFIGMAP = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "web", "namespace": "shop"}, "data": {}}


def _hooked(doc: dict[str, Any], events: str) -> dict[str, Any]:
    out = yaml.safe_load(yaml.safe_dump(doc))
    out["metadata"]["annotations"] = {"helm.sh/hook": events, "helm.sh/hook-weight": "-5"}
    return out


def _helm_template_output(hooks: list[tuple[str, dict[str, Any]]]) -> str:
    """What `helm template` prints: the release manifest, then `---\\n# Source: <path>\\n<hook manifest>` per hook."""
    manifest = "---\n# Source: shop/templates/configmap.yaml\n" + yaml.safe_dump(CONFIGMAP, sort_keys=False)
    out = manifest.strip() + "\n"
    for path, doc in hooks:
        out += f"---\n# Source: shop/{path}\n{yaml.safe_dump(doc, sort_keys=False)}\n"
    return out


def _chart(tmp: Path) -> Path:
    chart = tmp / "shop"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: shop\nversion: 0.1.0\n")
    return chart


@pytest.fixture
def helm(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    seen: dict[str, Any] = {"stdout": ""}

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen["args"] = args
        return subprocess.CompletedProcess(args, 0, stdout=seen["stdout"], stderr="")

    monkeypatch.setattr("kube_noob.generate.helm_render.helm_binary", lambda: "helm")
    monkeypatch.setattr("kube_noob.generate.helm_render.subprocess.run", fake_run)
    return seen


def _signature(findings: list[Any]) -> list[tuple[str, str, str]]:
    return sorted((f.rule_id, f.path, f.message) for f in findings if f.resource.startswith(("Job/", "ClusterRole/")))


def test_charts_are_rendered_with_their_hooks_and_test_hooks(helm: dict[str, Any], tmp_path: Path) -> None:
    from kube_noob.generate.helm_render import render_chart

    render_chart(_chart(tmp_path))
    assert helm["args"][1] == "template"
    assert "--no-hooks" not in helm["args"] and "--skip-tests" not in helm["args"]


@pytest.mark.parametrize("events", ["pre-install", "post-install,post-upgrade", "pre-upgrade", "test"])
def test_a_privileged_hook_job_gets_the_same_findings_as_the_same_job_without_the_annotation(
    helm: dict[str, Any], tmp_path: Path, events: str
) -> None:
    from kube_noob.audit.engine import analyze
    from kube_noob.generate.helm_render import audit_chart

    chart = _chart(tmp_path)
    helm["stdout"] = _helm_template_output(
        [("templates/hooks/job.yaml", _hooked(JOB, events)), ("templates/hooks/rbac.yaml", _hooked(ROLE, events))]
    )
    hooked, _lint = audit_chart(chart)
    plain = analyze(yaml.safe_dump_all([CONFIGMAP, JOB, ROLE], sort_keys=False), "kubernetes", None)
    assert _signature(hooked.findings), "the hook Job produced no findings at all"
    assert _signature(hooked.findings) == _signature(plain.findings)
    assert {"KN-S001", "KN-S015"} <= {f.rule_id for f in hooked.findings}


def test_the_gate_audits_hook_resources_and_points_at_the_hook_template(helm: dict[str, Any], tmp_path: Path) -> None:
    from kube_noob import gate

    chart = _chart(tmp_path)
    helm["stdout"] = _helm_template_output([("templates/hooks/job.yaml", _hooked(JOB, "pre-install"))])
    sources = gate.render([str(chart)], [], "shop")
    report = gate.run(sources, fail_on="never")
    privileged = [f for f in report["findings"] if f["ruleId"] == "KN-S001"]
    assert privileged, "the pre-install hook Job was not audited by the gate"
    assert all(f["uri"].endswith("templates/hooks/job.yaml") for f in privileged)
