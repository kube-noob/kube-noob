"""Six places where something in the input was not read and the answer said "fine" anyway.

Each was found by building the input that would make it fire, on the commands as a user runs them, after G332-G343
had closed fourteen defects of the same sentence. Every one is the same shape: one component knows the answer is
withheld and another never asks it.

G350. `cli._read` took the readable files of a directory and dropped the rest without a word, so every command that
reads a directory through it answered about what was left: `posture scan -f k8s/ --fail-above 30 --require-complete`
exited 0 beside a file YAML could not parse.

G351. `audit -f k8s/` walked `.yaml` and `.yml` and had no record of anything else: a privileged Pod in `pod.json`
beside a clean `ok.yaml` scored 100.0 and exited 0, while the gate on the same directory exited 5 naming the file.

G352. The gate decided whether a file it had not opened was a manifest by asking the YAML parser, and tab-indented
JSON is not YAML. `pod.json` written with tabs, or as a stream of objects, gated `passed`.

G353. `posture scan --require-complete` returned 0 before it looked whenever `--fail-above` was absent.

G354. `verify -f .` took the gate's "a Helm template" for a file `kubectl apply -R -f .` sends as it stands.

G355. Three more names a container goes by -- Argo's `script`, Tekton's `stepTemplate`, KubeVirt's
`containerDisk` -- were read by no rule and reported by no detector.

The control comes first in each section: a gate that is incomplete on every repository is one nobody reads.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from kube_noob import cli, gate, verify
from kube_noob.audit import engine
from kube_noob.audit.podspec import _looks_like_a_pod_spec
from kube_noob.cli import main

CLEAN = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: cm, namespace: shop}\ndata: {a: b}\n"
PRIVILEGED: dict[str, Any] = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "p", "namespace": "shop"},
    "spec": {
        "containers": [{"name": "c", "image": "registry.example.com/a:1.0", "securityContext": {"privileged": True}}]
    },
}
PRIVILEGED_YAML = (
    "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: shop}\nspec:\n  containers:\n"
    "  - name: c\n    image: registry.example.com/a:1.0\n    securityContext: {privileged: true}\n"
)
WORKLOAD = (
    "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web, namespace: shop}\nspec:\n  replicas: 1\n"
    "  selector: {matchLabels: {app: web}}\n  template:\n    metadata: {labels: {app: web}}\n    spec:\n"
    "      containers:\n      - {name: c, image: registry.example.com/a:1.0}\n"
)
#: A tab cannot start a YAML token, so this is a file no YAML loader reads -- and it is not JSON either.
NOT_YAML = "a:\n\t- b\n"
#: A Deployment under a group the scan does not know the kind under: `refused`, and so `notRead`.
REFUSED = WORKLOAD.replace("apps/v1", "apps.k8s.io/v1")


def _dir(root: Path, **files: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        target = root / name.replace("__", ".").replace("--", "/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


# -- G350: a directory read through `_read` -----------------------------------------------------------------------

#: Every command that reads a directory through `cli._read` and answers about what is in it.
DIRECTORY_READERS: dict[str, list[str]] = {
    "posture scan": ["posture", "scan", "--fail-above", "30", "--require-complete"],
    "posture reach": ["posture", "reach", "deployment/web", "-n", "shop"],
    "policy reach": ["policy", "reach", "--from", "shop/deployment/web", "--to", "shop/deployment/web", "--port", "80"],
    "vuln threat": ["vuln", "threat"],
}


@pytest.mark.parametrize("command", sorted(DIRECTORY_READERS))
def test_a_directory_every_file_of_which_was_read_is_still_answered(
    command: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    d = _dir(tmp_path / "k8s", web__yaml=WORKLOAD)
    code, out, err = _run([*DIRECTORY_READERS[command], "-f", str(d), "--format", "json"], capsys)
    assert code == 0, err
    assert json.loads(out)


@pytest.mark.parametrize("command", sorted(DIRECTORY_READERS))
def test_a_file_the_directory_reader_could_not_read_is_not_dropped_in_silence(
    command: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    d = _dir(tmp_path / "k8s", web__yaml=WORKLOAD, broken__yaml=NOT_YAML)
    code, out, err = _run([*DIRECTORY_READERS[command], "-f", str(d), "--format", "json"], capsys)
    assert code == 5, f"{command} answered (exit {code}) about a directory one file of which it never read"
    assert out == "", "no answer is printed for a directory that was not read in full"
    assert "broken.yaml" in err and "could not be read" in err


def test_the_same_file_named_on_its_own_was_always_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Why the directory is refused too: the file alone never got an answer, so dropping it from a directory was
    an answer about less than was asked."""
    d = _dir(tmp_path / "k8s", broken__yaml=NOT_YAML)
    code, _, _ = _run(["posture", "scan", "-f", str(d / "broken.yaml"), "--format", "json"], capsys)
    assert code not in (0, 1)


def test_the_directory_reader_raises_rather_than_returning_what_was_left(tmp_path: Path) -> None:
    d = _dir(tmp_path / "k8s", web__yaml=WORKLOAD, broken__yaml=NOT_YAML)
    with pytest.raises(cli._UnreadInput) as caught:
        cli._read(str(d))
    assert [b["path"] for b in caught.value.bad] == ["broken.yaml"]


# -- G351: the audit's walk and a manifest it does not open -------------------------------------------------------


def test_an_audited_directory_with_other_files_in_it_still_scores(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control. `values.json` is JSON and no manifest, `broken.json` is not JSON, `notes.txt` is neither: none
    of them is a file the audit failed to read, and a directory holding them is still a clean one."""
    d = _dir(
        tmp_path / "k8s",
        ok__yaml=CLEAN,
        values__json='{"replicas": 2}',
        broken__json="{not json",
        notes__txt=PRIVILEGED_YAML,
    )
    code, out, err = _run(["audit", "-f", str(d), "--format", "json"], capsys)
    assert code == 0, err
    assert json.loads(out)["summary"]["score"] == 100.0


@pytest.mark.parametrize("name", ["pod.json", "pod.JSON", "pod.YAML", "pod.YML"])
def test_a_manifest_the_audit_walk_does_not_open_is_not_a_clean_audit(
    name: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    text = json.dumps(PRIVILEGED) if name.lower().endswith("json") else PRIVILEGED_YAML
    d = _dir(tmp_path / "k8s", ok__yaml=CLEAN)
    (d / name).write_text(text, encoding="utf-8")
    code, out, err = _run(["audit", "-f", str(d), "--format", "json"], capsys)
    assert code == 5, f"audit exited {code} over a directory holding a privileged Pod in {name} it never opened"
    assert out == ""
    assert name in err and gate.NOT_OPENED_PREFIX in err


def test_skip_unreadable_audits_the_rest_and_still_names_the_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    d = _dir(tmp_path / "k8s", ok__yaml=CLEAN, pod__json=json.dumps(PRIVILEGED))
    code, out, _ = _run(["audit", "-f", str(d), "--skip-unreadable", "--format", "json"], capsys)
    rows = json.loads(out)["unreadable"]
    assert code == 0
    assert [(r["path"], r["acceptedBy"]) for r in rows] == [("pod.json", "--skip-unreadable")]
    assert rows[0]["why"].startswith(gate.NOT_OPENED_PREFIX)


def test_the_audit_walk_and_the_gate_walk_ask_one_function(tmp_path: Path) -> None:
    """Class 9. Two walks over one directory that each decided what an unopened file meant is how `audit` scored
    100.0 where `gate` exited 5. They read different file sets on purpose (the audit enters dot-directories); what
    a file NEITHER opened means is one decision."""
    d = _dir(tmp_path / "k8s", ok__yaml=CLEAN, pod__json=json.dumps(PRIVILEGED))
    _, bad = cli._dir_yaml(d)
    skipped = [s for s in gate.collect([str(d)], lambda p: Path(p).read_text()) if s.skip]
    assert [b["why"] for b in bad] == [s.skip for s in skipped]
    assert [b["path"] for b in bad] == [Path(s.uri).name for s in skipped] == ["pod.json"]


def test_a_dot_directory_the_audit_does_read_is_not_reported_as_unopened(tmp_path: Path) -> None:
    """The audit's walk enters dot-directories, so a `.yaml` under one is read, not a gap -- and a ConfigMap
    volume's second name for a file it read is not a second file."""
    d = _dir(tmp_path / "k8s", ok__yaml=CLEAN)
    _dir(d / ".hidden", pod__yaml=PRIVILEGED_YAML)
    (d / "same.json").symlink_to(d / "ok.yaml")
    ok, bad = cli._dir_yaml(d)
    assert bad == []
    assert sorted(path for path, _ in ok) == [".hidden/pod.yaml", "ok.yaml"]


# -- G352: JSON that is not YAML ----------------------------------------------------------------------------------

TABBED = json.dumps(PRIVILEGED, indent="\t")
STREAM = json.dumps({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "a"}}) + "\n" + TABBED


def _gate(d: Path) -> dict[str, Any]:
    return gate.run(gate.collect([str(d)], lambda p: Path(p).read_text()), fail_on="never")


def test_json_that_is_neither_yaml_nor_a_manifest_does_not_hold_the_gate(tmp_path: Path) -> None:
    """The control: tab-indented JSON that is no manifest, and a file that is not JSON at all."""
    d = _dir(
        tmp_path / "k8s",
        ok__yaml=CLEAN,
        values__json=json.dumps({"replicas": 2, "image": {"tag": "1"}}, indent="\t"),
        broken__json='{\n\t"apiVersion": "v1",\n\t"kind": "Pod",\n',
    )
    rep = _gate(d)
    assert rep["passed"] is True and rep["incomplete"] is False
    assert rep["skipped"] == []


@pytest.mark.parametrize("text", [TABBED, STREAM], ids=["tab-indented", "a stream of objects"])
def test_a_json_manifest_yaml_cannot_parse_is_still_a_manifest_nobody_read(
    text: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert gate.unreadable_reason(text), "the fixture must be text the YAML loader refuses"
    d = _dir(tmp_path / "k8s", ok__yaml=CLEAN, pod__json=text)
    rep = _gate(d)
    assert rep["passed"] is False and rep["incomplete"] is True
    assert [(Path(s["file"]).name, s.get("forbidsVerdict")) for s in rep["skipped"]] == [("pod.json", True)]
    code, _, err = _run(["gate", "-f", str(d), "--format", "json"], capsys)
    assert code == 5 and "pod.json" in err


def test_the_json_fallback_is_bounded_and_refuses_what_is_not_json() -> None:
    assert gate._json_stream("{not json") == []
    assert gate._json_stream('{"a": 1} trailing') == []
    assert gate._json_stream("[" * 5000 + "]" * 5000) == []
    assert gate._json_stream(' {"a": 1}\n\t{"b": 2}\n') == [{"a": 1}, {"b": 2}]


# -- G353: --require-complete on its own --------------------------------------------------------------------------


def test_require_complete_passes_a_scan_that_read_all_of_it(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "web.yaml"
    f.write_text(WORKLOAD, encoding="utf-8")
    code, out, err = _run(["posture", "scan", "-f", str(f), "--require-complete", "--format", "json"], capsys)
    assert code == 0, err
    assert json.loads(out)["notRead"] == []


def test_a_scan_nobody_asked_to_gate_still_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The other control: with neither flag the command reports and does not gate, as documented."""
    f = tmp_path / "web.yaml"
    f.write_text(REFUSED, encoding="utf-8")
    code, out, _ = _run(["posture", "scan", "-f", str(f), "--format", "json"], capsys)
    assert code == 0 and json.loads(out)["refused"]


def test_require_complete_alone_is_not_a_flag_that_does_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    f = tmp_path / "web.yaml"
    f.write_text(REFUSED, encoding="utf-8")
    code, out, err = _run(["posture", "scan", "-f", str(f), "--require-complete", "--format", "json"], capsys)
    assert json.loads(out)["notRead"], "the fixture must leave something unread"
    assert code == 5, f"--require-complete exited {code} beside a notRead entry: the flag did nothing"
    assert "incomplete" in err and "notRead" in err


def test_a_score_threshold_is_still_what_exits_one(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The neighbour: making the flag work alone must not let it exit 1 for a score nobody set a threshold on, nor
    stop `--fail-above` from doing so."""
    f = tmp_path / "web.yaml"
    f.write_text(REFUSED, encoding="utf-8")
    code, _, _ = _run(["posture", "scan", "-f", str(f), "--fail-above", "30", "--format", "json"], capsys)
    assert code == 5
    f.write_text(WORKLOAD, encoding="utf-8")
    code, _, _ = _run(["posture", "scan", "-f", str(f), "--fail-above", "-1", "--format", "json"], capsys)
    assert code == 1


# -- G354: verify and a chart's templates directory ---------------------------------------------------------------


def _chart(root: Path, template: str) -> Path:
    _dir(root, ok__yaml=CLEAN)
    _dir(root / "chart", Chart__yaml="apiVersion: v2\nname: shop\nversion: 0.1.0\n")
    _dir(root / "chart" / "templates", pod__yaml=template)
    return root


def _verify(d: Path, capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, Any]]:
    code, out, _ = _run(["verify", "-f", str(d), "--format", "json"], capsys)
    return code, json.loads(out)


def test_a_template_that_is_not_yet_yaml_keeps_the_gate_s_answer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """kubectl cannot send this file, and the gate's answer about it is `verify`'s too. That answer was "skipped,
    and the verdict stands", so this asserted `allow`, exit 0, over a chart nobody rendered: the assertion was
    the defect (G445). The gate withholds its verdict for an unrendered template, and so does `verify`."""
    code, out = _verify(_chart(tmp_path / "repo", "apiVersion: v1\nkind: Pod\n{{- if .Values.x }}\n"), capsys)
    assert (code, out["verdict"]) == (5, "not-determined"), out
    assert any("pod.yaml" in u and "--chart" in u for u in out["notDetermined"]), out["notDetermined"]


def test_a_manifest_under_templates_is_checked_because_kubectl_would_send_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out = _verify(_chart(tmp_path / "repo", PRIVILEGED_YAML), capsys)
    assert out["verdict"] == "deny", "verify allowed a privileged Pod that kubectl apply -R -f would send"
    assert code == 1
    assert any(str(f.get("uri", "")).endswith("chart/templates/pod.yaml") for f in out["findings"]), out["findings"]


def test_the_gate_s_own_answer_about_a_chart_is_unchanged(tmp_path: Path) -> None:
    """The neighbour this fix must not move: the gate still names the template as skipped and to be rendered. Its
    reason is about a chart someone will render with `--chart`; `verify` is about what kubectl sends."""
    d = _chart(tmp_path / "repo", PRIVILEGED_YAML)
    whys = {Path(s.uri).name: s.skip for s in gate.collect([str(d)], lambda p: Path(p).read_text()) if s.skip}
    assert whys["pod.yaml"].startswith(gate.UNRENDERED_HELM + ":") and "--chart" in whys["pod.yaml"]
    seen = {Path(s.uri).name: s.skip for s in verify.collect([str(d)], lambda p: Path(p).read_text())}
    assert seen["pod.yaml"] is None and seen["Chart.yaml"] is not None


# -- G355: a container is a container whatever the field is called, continued -------------------------------------

ARGO_SCRIPT = """\
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata: {name: wf, namespace: ci}
spec:
  templates:
  - name: main
    script:
      image: docker:24-dind
      source: dockerd
      securityContext: {privileged: true}
"""
TEKTON_STEP_TEMPLATE = """\
apiVersion: tekton.dev/v1
kind: Task
metadata: {name: build, namespace: ci}
spec:
  stepTemplate:
    image: docker:24-dind
    securityContext: {privileged: true}
  steps:
  - name: s
    script: dockerd
"""
KUBEVIRT = """\
apiVersion: kubevirt.io/v1
kind: VirtualMachine
metadata: {name: vm, namespace: shop}
spec:
  template:
    spec:
      volumes:
      - name: root
        containerDisk:
          image: quay.io/containerdisks/fedora:latest
"""
SHAPES = {"argo script": ARGO_SCRIPT, "tekton stepTemplate": TEKTON_STEP_TEMPLATE, "kubevirt containerDisk": KUBEVIRT}

#: Objects that carry one of the new keys and run nothing through it. A Tekton step's `script` is a string; a
#: `script` mapping with no `image` declares no container; a ConfigMap key is not a field.
QUIET = {
    "a step's script string": {"steps": [{"name": "s", "script": "echo hi"}]},
    "a script with no image": {"script": {"source": "echo hi"}},
    "a stepTemplate with no image": {"stepTemplate": {"env": [{"name": "A", "value": "b"}]}},
    "an image that is not a string": {"containerDisk": {"image": {"repository": "a", "tag": "1"}}},
    "a string under the key": {"container": "nginx", "script": "x", "stepTemplate": "y", "containerDisk": "z"},
}


@pytest.mark.parametrize("name", sorted(QUIET))
def test_a_mapping_that_runs_nothing_is_still_not_a_pod_spec(name: str) -> None:
    assert not _looks_like_a_pod_spec(QUIET[name])


def test_a_configmap_with_a_key_called_image_is_still_clean() -> None:
    cm = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: cm, namespace: shop}\ndata: {image: nginx, script: x}\n"
    report = engine.analyze(cm).as_dict()
    assert report["notAudited"] == [] and report["summary"]["score"] == 100.0


@pytest.mark.parametrize("name", sorted(SHAPES))
def test_a_container_under_another_name_is_reported_as_not_audited(name: str) -> None:
    report = engine.analyze(SHAPES[name]).as_dict()
    assert report["summary"]["score"] is None, f"{name}: a score was stated over a container no rule read"
    assert report["summary"]["verdict"] == "undetermined"
    assert len(report["notAudited"]) == 1


@pytest.mark.parametrize("name", sorted(SHAPES))
def test_the_gate_and_verify_withhold_on_it_too(name: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "x.yaml"
    f.write_text(SHAPES[name], encoding="utf-8")
    code, out, _ = _run(["gate", "-f", str(f), "--format", "json"], capsys)
    rep = json.loads(out)
    assert code == 1 and rep["passed"] is False and rep["incomplete"] is True
    code, out, _ = _run(["verify", "-f", str(f), "--format", "json"], capsys)
    assert code == 5 and json.loads(out)["verdict"] == "not-determined"
