"""Nothing in the input is skipped silently: what a command did not read is named and changes its answer.

Five defects, one sentence. Each was a part of the input that a command left alone and then answered as if it had
read everything:

G442. `helm-audit` died with an AttributeError on a `values.yaml` whose `image:` is a string.
G443. Text that holds no Kubernetes object at all -- an empty file, a comment, a Helm values file -- was refused by
      `audit` and answered by `posture scan`, `posture snapshot`, `fix` and five MCP tools: "0 attack paths from 0
      exposures" at exit 0 under `--require-complete`, and a score of 100.0.
G444. A symbolic link to a directory was not walked and not mentioned, so a privileged Pod behind one scored 100.0,
      gated `passed` and verified `allow`.
G445. An unrendered Helm chart inside a directory was listed as "skipped" beside "gate passed", exit 0.
G446. A Kustomization, which rewrites the objects beside it when it is rendered, was read as one more object.

The inputs are the ones the audit that found these used, cut down, under `tests/fixtures/inputs/`. Every test here
is a row of a matrix over the commands and the MCP tools that read the same input, because each of these was
already right in at least one command: the defect was that the others did not agree with it.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from kube_noob import toolkit as tk
from kube_noob.cli import main
from kube_noob.errors import KubeNoobError
from kube_noob.generate.helm import lint_chart_metadata
from kube_noob.toolkit import Toolkit

INPUTS = Path(__file__).resolve().parent / "fixtures" / "inputs"

PRIVILEGED_POD = """\
apiVersion: v1
kind: Pod
metadata: {name: bad, namespace: default}
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: c
    image: nginx:latest
    securityContext: {privileged: true}
"""

EXPOSED = """\
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  replicas: 1
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      hostPID: true
      containers:
      - {name: c, image: "nginx:latest", securityContext: {privileged: true}, ports: [{containerPort: 80}]}
---
apiVersion: v1
kind: Service
metadata: {name: web, namespace: shop}
spec: {type: LoadBalancer, selector: {app: web}, ports: [{port: 80, targetPort: 80}]}
"""


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    capsys.readouterr()
    code = main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


def _copy(name: str, to: Path) -> Path:
    shutil.copytree(INPUTS / name, to, symlinks=True)
    return to


# -- G442: helm-audit and a values.yaml that is not the shape the lint expected ----------------------------------


def _chart(tmp_path: Path, values: str | bytes) -> Path:
    chart = _copy("chart-image-string", tmp_path / "chart")
    (chart / "values.yaml").write_bytes(values if isinstance(values, bytes) else values.encode())
    return chart


def test_a_string_image_in_values_is_read_rather_than_crashing_the_lint() -> None:
    """The repro, as found: `image: registry.example.com/api@sha256:...`. Pinned by digest, so nothing to say
    about its tag, and no AttributeError on the way to saying nothing."""
    issues = lint_chart_metadata(INPUTS / "chart-image-string")
    assert not any("image" in i for i in issues), issues
    assert any("values.schema.json" in i for i in issues), "the lint stopped before its last check"


@pytest.mark.parametrize(
    "values,said",
    [
        ("image: nginx:latest\n", "'latest'"),
        ("image: nginx\n", "no tag"),
        ("image: registry.example.com:5000/nginx\n", "no tag"),
        ("image:\n  repository: nginx\n  tag: latest\n", "'latest'"),
    ],
)
def test_a_moving_image_is_reported_in_either_shape(tmp_path: Path, values: str, said: str) -> None:
    issues = [i for i in lint_chart_metadata(_chart(tmp_path, values)) if "values.yaml image" in i]
    assert len(issues) == 1 and said in issues[0], issues


@pytest.mark.parametrize(
    "values",
    [
        "image: registry.example.com:5000/nginx:1.27\n",
        "image: nginx@sha256:" + "4" * 64 + "\n",
        "image:\n  repository: nginx\n  tag: '1.27'\n",
        "replicas: 2\n",
        "",
    ],
)
def test_a_pinned_or_absent_image_is_not_reported(tmp_path: Path, values: str) -> None:
    assert not [i for i in lint_chart_metadata(_chart(tmp_path, values)) if "image" in i]


@pytest.mark.parametrize("values", ["image: [nginx, latest]\n", "image: 7\n", "image:\n  tag: [latest]\n"])
def test_an_image_in_a_shape_the_lint_does_not_read_is_said_not_passed(tmp_path: Path, values: str) -> None:
    """An unrecognised shape is not a pinned image: the check says it did not look."""
    issues = [i for i in lint_chart_metadata(_chart(tmp_path, values)) if "image" in i]
    assert len(issues) == 1 and "not checked" in issues[0], issues


def test_dependencies_that_are_not_a_list_do_not_crash_the_lint(tmp_path: Path) -> None:
    """The neighbour of the string `image:`: the same unguarded read, one key over."""
    chart = _chart(tmp_path, "replicas: 1\n")
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: app\nversion: 0.1.0\ndependencies: 3\n")
    assert isinstance(lint_chart_metadata(chart), list)


def test_values_that_are_not_a_mapping_are_said_not_passed(tmp_path: Path) -> None:
    issues = [i for i in lint_chart_metadata(_chart(tmp_path, "- a\n- b\n")) if "values.yaml" in i]
    assert any("not a mapping" in i and "not checked" in i for i in issues), issues


@pytest.mark.parametrize("name", ["values.yaml", "Chart.yaml"])
@pytest.mark.parametrize("content", [b"image: [unclosed\n", b"\xff\xfe\x00not utf-8"])
def test_a_chart_file_that_cannot_be_read_is_a_refusal_with_a_message(
    tmp_path: Path, name: str, content: bytes
) -> None:
    chart = _chart(tmp_path, "replicas: 1\n")
    (chart / name).write_bytes(content)
    with pytest.raises(KubeNoobError, match=name):
        lint_chart_metadata(chart)


def test_helm_audit_answers_on_the_chart_that_crashed_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Through the command, with the render stubbed (the lint runs after it): exit 1 for the privileged
    container the chart renders, never exit 4 with `'str' object has no attribute 'get'`."""
    monkeypatch.setattr("kube_noob.generate.helm_render.render_chart", lambda *a, **k: PRIVILEGED_POD)
    code, out, err = _run(["--format", "json", "helm-audit", str(INPUTS / "chart-image-string")], capsys)
    assert "attribute" not in err and code == 1, (code, err)
    doc = json.loads(out)
    assert any(f["ruleId"] == "KN-S001" for f in doc["findings"]) and isinstance(doc["chartLint"], list)


def test_helm_audit_refuses_unreadable_values_in_one_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("kube_noob.generate.helm_render.render_chart", lambda *a, **k: PRIVILEGED_POD)
    code, out, err = _run(["helm-audit", str(_chart(tmp_path, b"image: [unclosed\n"))], capsys)
    assert code == 4 and "values.yaml" in err and "Traceback" not in err and len(err.strip().splitlines()) == 1
    assert "score" not in out, "an answer was printed beside the refusal"


# -- G443: input that holds no Kubernetes object is refused by every command, not only by audit ------------------

NOT_MANIFESTS = {
    "an empty file": "empty.yaml",
    "only a comment": "commentonly.yaml",
    "a Helm values file": "values.yaml",
}


def _cli_over_one_file(path: str, tmp_path: Path) -> dict[str, list[str]]:
    """Every command that states an answer over manifests given with -f."""
    return {
        "audit": ["audit", "-f", path],
        "validate": ["validate", "-f", path],
        "redteam": ["redteam", "-f", path],
        "fix": ["fix", "-f", path],
        "gate": ["gate", "-f", path],
        "verify": ["verify", "-f", path],
        "ksi": ["ksi", "-f", path],
        "posture scan": ["posture", "scan", "-f", path],
        "posture scan --require-complete": ["posture", "scan", "-f", path, "--require-complete"],
        "posture snapshot": ["posture", "snapshot", "-f", path, "-o", str(tmp_path / "snap.json")],
        "posture reach": ["posture", "reach", "Deployment/shop/web", "-f", path],
        "vuln threat": ["vuln", "threat", "-f", path],
    }


@pytest.mark.parametrize("what", sorted(NOT_MANIFESTS))
@pytest.mark.parametrize("command", sorted(_cli_over_one_file("x", Path("."))))
def test_every_command_refuses_input_that_holds_no_kubernetes_object(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], what: str, command: str
) -> None:
    """`audit` said exit 2, "nothing here is a Kubernetes manifest". The others agree with it now: no zero, no
    score, no file written, no exit 0."""
    path = str(INPUTS / "not-manifests" / NOT_MANIFESTS[what])
    code, out, err = _run(_cli_over_one_file(path, tmp_path)[command], capsys)
    assert code == 2, f"{command} on {what}: exit {code}\n{out}\n{err}"
    assert "nothing here is a Kubernetes" in err, err
    assert out.strip() == "", f"{command} printed an answer beside the refusal: {out[:200]}"
    assert not (tmp_path / "snap.json").exists(), "a snapshot of nothing was written"


def _tool(kit: Toolkit, name: str) -> Any:
    return next(s for s in kit.specs() if s.name == name)


#: Every MCP tool that states an answer over the manifests it is handed, and what else its input requires. A tool
#: that takes `manifests` and is absent here is named in `NOT_AN_ANSWER_OVER_MANIFESTS` with the reason, and
#: `test_every_tool_over_manifests_is_in_the_matrix` fails for one that is in neither.
TOOLS_OVER_MANIFESTS: dict[str, dict[str, Any]] = {
    "audit_manifests": {},
    "validate_manifests": {},
    "red_team": {},
    "fix_manifests": {},
    "fedramp_ksi": {},
    "verify_change": {},
    "posture_scan": {},
    "posture_reach": {"workload": "Deployment/shop/web"},
    "threat_model": {},
    "run_protocol": {"request": "review these manifests"},
}
NOT_AN_ANSWER_OVER_MANIFESTS = {
    "check_network_policy": "refuses a source it cannot find among the workloads, which an empty input has none of",
    "code_report": "`manifests` is optional context for SARIF it requires",
    "vuln_report": "`manifests` is optional context for scanner reports it requires",
    "containerfile_audit": "`manifests` is optional context for a Containerfile it requires",
    "verify_receipt": "replays a receipt; `manifests` is the input the receipt names, checked against its hash",
    "learn_mechanism": "walks one named path and says `stopped` when its objects are not there (G395)",
    "compliance_results": "answers `undetermined`, `complete: false` when no result object is in the input",
    "operator_inventory": "answers `not-determined`, `complete: false` when no ClusterServiceVersion is in the input",
    "operator_known_issues": "answers `not-determined`, `complete: false`, as operator_inventory",
}


def test_every_tool_over_manifests_is_in_the_matrix(settings: Any) -> None:
    found = {s.name for s in Toolkit(settings).specs() if "manifests" in getattr(s.model, "model_fields", {})}
    classified = set(TOOLS_OVER_MANIFESTS) | set(NOT_AN_ANSWER_OVER_MANIFESTS)
    assert not sorted(found - classified), f"a tool over manifests nobody decided about: {sorted(found - classified)}"
    assert not sorted(classified - found), f"classified and no longer a tool: {sorted(classified - found)}"


@pytest.mark.parametrize("what", sorted(NOT_MANIFESTS))
@pytest.mark.parametrize("tool", sorted(TOOLS_OVER_MANIFESTS))
def test_every_tool_refuses_input_that_holds_no_kubernetes_object(settings: Any, what: str, tool: str) -> None:
    """The same matrix for a caller that hands the text over. An empty string is refused by the input model (it
    needs a character); a comment and a values file reached `posture_scan`, `fix_manifests`, `red_team`,
    `validate_manifests` and `threat_model` and each answered."""
    text = (INPUTS / "not-manifests" / NOT_MANIFESTS[what]).read_text() or "\n"
    if tool == "run_protocol":
        # The one tool whose answer is a status word rather than a refusal: it must not be `ready`.
        spec = _tool(Toolkit(settings), tool)
        out = spec.fn(spec.model(manifests=text, **TOOLS_OVER_MANIFESTS[tool]))
        assert out["status"] in {"undetermined", "blocked"}, out["status"]
        return
    spec = _tool(Toolkit(settings), tool)
    with pytest.raises((KubeNoobError, ValueError)) as err:
        spec.fn(spec.model(manifests=text, **TOOLS_OVER_MANIFESTS[tool]))
    # Either refusal is one: the audit's own sentence, or the input model's for text too short to hold an object
    # (the empty file never reaches a tool, and `threat_model` asks for ten characters).
    assert any(w in str(err.value) for w in ("nothing here is a Kubernetes", "at least")), str(err.value)


def test_a_real_manifest_is_still_answered_by_every_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The control: the guard refuses input with no object in it, and nothing else."""
    path = tmp_path / "exposed.yaml"
    path.write_text(EXPOSED)
    code, out, _ = _run(["posture", "scan", "-f", str(path), "--require-complete"], capsys)
    assert code == 0 and "attack path" in out and not out.startswith("0 attack paths"), out
    code, out, _ = _run(["posture", "snapshot", "-f", str(path), "-o", str(tmp_path / "snap.json")], capsys)
    assert code == 0 and (tmp_path / "snap.json").is_file()
    code, out, _ = _run(["fix", "-f", str(path)], capsys)
    assert code in {0, 1} and "kind: Deployment" in out


def test_an_object_with_a_kind_and_no_api_version_is_still_an_object_to_the_scan(settings: Any) -> None:
    """The first version put the audit's guard, which asks for `apiVersion` AND `kind`, in front of the inventory.
    The in-cluster backend's list items carry no `apiVersion`, and the inventory ranks them on purpose (G330): the
    guard refused them, and `test_an_object_with_no_api_version_is_still_ranked` caught it. A `kind` is an object
    here; a values file has none."""
    bare = EXPOSED.replace("apiVersion: apps/v1\n", "").replace("apiVersion: v1\n", "")
    assert "apiVersion" not in bare
    assert Toolkit(settings).posture_scan(tk.PostureScanIn(manifests=bare))["workloads"] == 1
    assert Toolkit(settings).threat_model(tk.ThreatModelIn(manifests=bare))["applications"]


def test_a_values_block_above_a_manifest_does_not_refuse_the_manifest(settings: Any) -> None:
    """`refuse_if_not_manifests` needs ONE object: the guard must not become a refusal of mixed input."""
    out = Toolkit(settings).posture_scan(tk.PostureScanIn(manifests="replicas: 2\n---\n" + EXPOSED))
    assert out["total"] >= 1
