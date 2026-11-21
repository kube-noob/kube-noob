"""The gate's `incomplete` survives the hops that carry it onward (G329).

G272 and G281 made `audit` and `gate` answer `undetermined` for an object the rules did not read and for a rule
that declined. Three readers of that report were never told, and each turned it back into a clean answer one hop
out: `verify` printed `allow` and exited 0 above its own line saying the verdict was undetermined, `insight` handed
back `ran: audit` beside an empty list of findings, and the CI wrapper wrote `evidence=complete` beside a report
whose own `incomplete` was true. Each test here names the object and the reason, never just that something fired.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from kube_noob.config import load_settings
from tests.test_ci_wrappers import ROOT, _outputs, _report, _run

FX6 = Path(__file__).parent / "fixtures" / "control-plane" / "review6"

_POD = """\
    spec:
      containers:
      - {name: web, image: registry.example.com/web:1, securityContext: {privileged: true}}
"""
#: A Deployment under a group Kubernetes does not serve it in: `refusal` refuses it, so no rule read the container.
REFUSED_GROUP = (
    "apiVersion: apps.k8s.io/v1\nkind: Deployment\nmetadata: {name: web, namespace: shop}\n"
    "spec:\n  selector: {matchLabels: {app: web}}\n  template:\n    metadata: {labels: {app: web}}\n" + _POD
)
#: The same object with `kind` in lower case and only an init container, which the pod-spec detector does not see.
REFUSED_KIND = (
    "apiVersion: apps/v1\nkind: deployment\nmetadata: {name: web, namespace: shop}\n"
    "spec:\n  selector: {matchLabels: {app: web}}\n  template:\n    metadata: {labels: {app: web}}\n"
    "    spec:\n      initContainers:\n      - {name: web, image: nginx, securityContext: {privileged: true}}\n"
)
#: No pod spec at all: cluster-admin for everyone, under a group the rules do not know the kind in.
REFUSED_BINDING = (
    "apiVersion: rbac.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata: {name: everyone-admin}\n"
    'subjects: [{kind: Group, name: "system:unauthenticated", apiGroup: rbac.authorization.k8s.io}]\n'
    "roleRef: {kind: ClusterRole, name: cluster-admin, apiGroup: rbac.authorization.k8s.io}\n"
)
#: A Deployment every rule reads, with nothing at or above `high`: the control, which must stay `allow`.
READ = (
    "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web, namespace: shop}\n"
    "spec:\n  replicas: 2\n  selector: {matchLabels: {app: web}}\n  template:\n"
    "    metadata: {labels: {app: web}}\n    spec:\n      containers:\n"
    "      - {name: web, image: registry.example.com/web:1}\n"
)

UNDETERMINED = [
    ("refused-group", REFUSED_GROUP, None, "Deployment/shop/web"),
    ("refused-kind", REFUSED_KIND, None, "deployment/shop/web"),
    ("refused-binding", REFUSED_BINDING, None, "ClusterRoleBinding/everyone-admin"),
    ("declined-rule", (FX6 / "q2-declined.yaml").read_text(encoding="utf-8"), "1.30", "KN-S038"),
]


def _both(text: str, version: str | None) -> tuple[dict[str, Any], dict[str, Any]]:
    from kube_noob import gate, verify

    src = [gate.Source("manifests", text)]
    return gate.run(src, version=version), verify.evaluate([gate.Source("manifests", text)], version=version)


@pytest.mark.parametrize(("name", "text", "version", "named"), UNDETERMINED, ids=[u[0] for u in UNDETERMINED])
def test_verify_never_allows_what_the_gate_calls_incomplete(
    name: str, text: str, version: str | None, named: str
) -> None:
    """`verify -f X` and `gate -f X` read one audit, and a check before an action cannot be laxer than the gate."""
    from kube_noob import verify

    report, result = _both(text, version)
    assert report["incomplete"] is True and named in report["undetermined"], report.get("undetermined")
    assert result["verdict"] == "not-determined", (name, result["verdict"], result["notDetermined"])
    # The gate's own reason, in the list the verdict is read from -- not only in `notEvaluated` beside an `allow`.
    assert any(named in line and "undetermined" in line for line in result["notDetermined"]), result["notDetermined"]
    assert verify.exit_code(result) == 5
    assert verify.exit_code(result, allow_undetermined=True) == 0


def test_verify_still_allows_what_the_gate_passes_and_denies_what_it_fails() -> None:
    """The neighbours on both sides: a verdict that WAS reached keeps its word, so the fix is not `never allow`."""
    from kube_noob import verify

    report, result = _both(READ, None)
    assert report["incomplete"] is False and "undetermined" not in report
    assert result["verdict"] == "allow" and result["notDetermined"] == []
    # A deny with something unread is still a deny (exit 1): more evidence cannot turn it into an allow.
    privileged = READ.replace("name: web, namespace", "name: api, namespace").replace(
        "image: registry.example.com/web:1}", "image: registry.example.com/web:1, securityContext: {privileged: true}}"
    )
    both = REFUSED_GROUP + "---\n" + privileged
    report, result = _both(both, None)
    assert report["incomplete"] is True
    assert result["verdict"] == "deny" and verify.exit_code(result) == 1
    assert any("undetermined" in line for line in result["notDetermined"]), result["notDetermined"]


def test_the_verify_command_and_the_mcp_tool_say_not_determined(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The two doors an agent uses: the CLI the hook runs, and the tool a model calls."""
    from kube_noob import toolkit as tk
    from kube_noob.cli import main

    f = tmp_path / "web.yaml"
    f.write_text(REFUSED_GROUP, encoding="utf-8")
    code = main(["verify", "-f", str(f)])
    out = capsys.readouterr().out
    assert code == 5, out
    assert out.startswith("kube-noob verify: not-determined"), out[:200]
    assert "kube-noob verify: allow" not in out
    kit = tk.Toolkit(load_settings(overrides={"dataDir": str(tmp_path / "data")}))
    result = kit.verify_change(tk.VerifyIn(manifests=REFUSED_GROUP))
    assert result["verdict"] == "not-determined", result["verdict"]
    assert any("Deployment/shop/web" in line for line in result["notDetermined"]), result["notDetermined"]


def test_insight_says_the_audit_reached_no_verdict(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """`ran: audit` beside no findings read as "audited and clean" for an object no rule had read."""
    from kube_noob import toolkit as tk
    from kube_noob.cli import main

    kit = tk.Toolkit(load_settings(overrides={"dataDir": str(tmp_path / "data")}))
    res = kit.insight(tk.InsightIn(text=REFUSED_GROUP))
    assert "audit" in res["ran"] and res["findings"] == []
    rows = [s for s in res["skipped"] if s["kind"] == "manifests"]
    assert len(rows) == 1, res["skipped"]
    assert "undetermined" in rows[0]["why"] and "Deployment/shop/web" in rows[0]["why"], rows[0]["why"]
    # ... and the control: an audit that did reach a verdict adds no such row.
    clean = kit.insight(tk.InsightIn(text=READ))
    assert not [s for s in clean["skipped"] if s["kind"] == "manifests"], clean["skipped"]
    f = tmp_path / "web.yaml"
    f.write_text(REFUSED_GROUP, encoding="utf-8")
    main(["insight", "-f", str(f)])
    out = capsys.readouterr().out
    assert "not analysed (manifests):" in out and "undetermined" in out, out


def test_an_undetermined_gate_is_never_beside_complete_evidence(tmp_path: Path) -> None:
    """Every optional check supplied, so `notRun` is empty, and the audit under the gate reached no verdict."""
    why = "1 Deployment not audited: not read in full: Deployment/shop/web"
    _, sinks = _run(tmp_path, 1, _report(passed=False, incomplete=True, undetermined=why))
    out = _outputs(sinks)
    assert out["result"] == "failed" and out["exit-code"] == "1"
    assert out["evidence"] == "incomplete", out
    assert out["because"] == f"the audit is undetermined: {why}".replace("_", "\\_"), out["because"]
    headline = sinks["step_summary"].read_text(encoding="utf-8").splitlines()[0]
    assert "evidence: incomplete" in headline and "evidence: complete" not in headline, headline


@pytest.mark.parametrize(
    ("report", "because"),
    [
        # The reason is first, ahead of the standing entries, so the cut at 600 characters cannot remove it.
        ('{"notRun": ["x"], "incomplete": true, "undetermined": "r"}', "the audit is undetermined: r; x"),
        ('{"notRun": [], "incomplete": true}', "the gate reported itself incomplete"),
        ('{"notRun": [], "incomplete": "no"}', "the gate reported itself incomplete"),
        ('{"notRun": [], "undetermined": {"a": 1}}', "the audit is undetermined: {'a': 1}"),
    ],
)
def test_the_wrapper_reads_incomplete_in_any_shape(tmp_path: Path, report: str, because: str) -> None:
    _, sinks = _run(tmp_path, 1, report)
    out = _outputs(sinks)
    assert (out["evidence"], out["because"]) == ("incomplete", because)


def test_a_gate_that_is_not_incomplete_keeps_complete_evidence(tmp_path: Path) -> None:
    """The control: `incomplete: false` is the gate saying it reached a verdict, and is not a gap."""
    _, sinks = _run(tmp_path, 1, _report(passed=False, incomplete=False))
    assert _outputs(sinks)["evidence"] == "complete"


def test_the_real_gate_and_the_wrapper_agree_on_an_undetermined_audit(tmp_path: Path) -> None:
    """Through the real binary: the reason the gate prints is the reason the wrapper's `because` starts with."""
    d = tmp_path / "k8s"
    d.mkdir()
    (d / "web.yaml").write_text(REFUSED_GROUP, encoding="utf-8")
    real = {"PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin", "KN_PATHS": str(d), "KN_VERSION": ""}
    # Absolute, so the binary imports THIS checkout and not whatever wheel is installed beside the interpreter.
    real.update({"KN_PLATFORM": "kubernetes", "PYTHONPATH": str(ROOT / "src")})
    _run(tmp_path, 1, _report(), env=real)  # writes the stub; the real binary is first on PATH from here on
    (tmp_path / "bin" / "kube-noob").unlink()
    proc, sinks = _run(tmp_path, 1, _report(), env=real)
    assert proc.returncode == 1, proc.stderr
    out = _outputs(sinks)
    report = json.loads((tmp_path / "work" / "kube-noob-gate.json").read_text(encoding="utf-8"))
    assert report["incomplete"] is True
    assert out["evidence"] == "incomplete"
    assert out["because"].startswith("the audit is undetermined: 1 Deployment not audited"), out["because"]
