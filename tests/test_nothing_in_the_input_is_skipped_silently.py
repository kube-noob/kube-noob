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

import pytest

from kube_noob.cli import main
from kube_noob.errors import KubeNoobError
from kube_noob.generate.helm import lint_chart_metadata

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
