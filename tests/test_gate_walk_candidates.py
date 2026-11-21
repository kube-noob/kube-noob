"""A verdict about a directory is a verdict about every file in it, including the ones the walk did not open.

`gate -f k8s/` kept `.yaml` and `.yml` and did not enter dot-directories, and a file outside that was not recorded
anywhere -- not in `files`, not in `skipped`, not in `unreadable`. So a directory holding `pod.json` (privileged,
`hostPID`) and `.hidden/pod.yaml` (privileged, `hostNetwork`) answered:

    exit 0, passed: true, skipped: []

while `audit -f k8s/` on the same directory reported eleven findings. `skipped: []` is not a thin answer, it is a
false one: the gate asserted it had passed over nothing.

Which extensions the walk SHOULD read is a separate and still-open question -- `kubectl apply -f` sends `.json`,
`audit` enters dot-directories and the gate does not, and `.YAML` is a manifest to the API server and not to
`Path.suffix`. This file holds only the part that is true under every answer to it: a file nobody opened cannot be
the ground of a pass.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kube_noob import gate
from kube_noob.cli import main
from kube_noob.gate import NOT_OPENED_PREFIX

PRIVILEGED_JSON = json.dumps(
    {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "bad", "namespace": "prod"},
        "spec": {
            "hostPID": True,
            "containers": [{"name": "c", "image": "nginx:1.27", "securityContext": {"privileged": True}}],
        },
    }
)

BENIGN_YAML = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: fine, namespace: prod}\ndata: {a: b}\n"

PRIVILEGED_YAML = """\
apiVersion: v1
kind: Pod
metadata: {name: hidden, namespace: prod}
spec:
  hostNetwork: true
  containers: [{name: c, image: nginx:1.27, securityContext: {privileged: true}}]
"""


def _tree(root: Path) -> Path:
    d = root / "k8s"
    (d / ".hidden").mkdir(parents=True)
    (d / "ok.yaml").write_text(BENIGN_YAML, encoding="utf-8")
    (d / "pod.json").write_text(PRIVILEGED_JSON, encoding="utf-8")
    (d / "pod2.JSON").write_text(PRIVILEGED_JSON, encoding="utf-8")
    (d / "pod.YAML").write_text(BENIGN_YAML, encoding="utf-8")
    (d / ".hidden" / "pod.yaml").write_text(PRIVILEGED_YAML, encoding="utf-8")
    (d / "README.md").write_text("# how to deploy\n", encoding="utf-8")
    (d / "Chart.lock").write_text("dependencies: []\n", encoding="utf-8")
    (d / "values.json").write_text(json.dumps({"replicas": 2}), encoding="utf-8")
    (d / "broken.json").write_text("{not json at all", encoding="utf-8")
    ci = root / "repo" / ".github" / "workflows"
    ci.mkdir(parents=True)
    (ci / "ci.yml").write_text("on: push\njobs: {}\n", encoding="utf-8")
    return d


def test_a_directory_with_an_unopened_manifest_is_not_a_pass(tmp_path: Path) -> None:
    """The regression, end to end through the collector and the report."""
    rep = gate.run(gate.collect([str(_tree(tmp_path))], lambda p: Path(p).read_text()), fail_on="never")
    assert rep["passed"] is False, "the gate passed a directory holding manifests it never opened"
    blocking = [s for s in rep["skipped"] if s.get("forbidsVerdict")]
    assert {Path(s["file"]).name for s in blocking} == {"pod.json", "pod2.JSON", "pod.YAML", "pod.yaml"}
    assert all(s["why"].startswith(NOT_OPENED_PREFIX) for s in blocking)


def test_the_file_it_did_open_is_still_audited(tmp_path: Path) -> None:
    """The walk is not narrowed by this: `ok.yaml` is read exactly as before."""
    rep = gate.run(gate.collect([str(_tree(tmp_path))], lambda p: Path(p).read_text()), fail_on="never")
    assert [Path(f).name for f in rep["files"]] == ["ok.yaml"]


def test_a_file_that_could_not_hold_a_manifest_is_passed_over_silently(tmp_path: Path) -> None:
    """The other direction, and the one that decides whether this is usable. A README and a lockfile are in every
    repository; recording them would make every gate incomplete, and an alert on every run is one nobody reads."""
    rep = gate.run(gate.collect([str(_tree(tmp_path))], lambda p: Path(p).read_text()), fail_on="never")
    names = {Path(s["file"]).name for s in rep["skipped"]}
    assert "README.md" not in names and "Chart.lock" not in names


def test_a_directory_of_only_opened_manifests_still_passes(tmp_path: Path) -> None:
    """A gate that cannot pass is not a gate."""
    d = tmp_path / "clean"
    d.mkdir()
    (d / "ok.yaml").write_text(BENIGN_YAML, encoding="utf-8")
    (d / "README.md").write_text("# notes\n", encoding="utf-8")
    rep = gate.run(gate.collect([str(d)], lambda p: Path(p).read_text()), fail_on="never")
    assert rep["passed"] is True
    assert [s for s in rep["skipped"] if s.get("forbidsVerdict")] == []


def test_the_reason_says_which_rule_excluded_it_and_what_to_do(tmp_path: Path) -> None:
    """Two different exclusions reach the same `skipped` list, and they have different fixes. A reason that said
    only "not opened" would leave the caller guessing which of the two they hit."""
    rep = gate.run(gate.collect([str(_tree(tmp_path))], lambda p: Path(p).read_text()), fail_on="never")
    why = {Path(s["file"]).name: s["why"] for s in rep["skipped"]}
    assert "dot-directory" in why["pod.yaml"]
    assert "only .yaml and .yml" in why["pod.json"]
    assert all("name it with -f" in w for w in why.values())


def test_naming_the_file_on_the_command_line_audits_it(tmp_path: Path) -> None:
    """The remedy the reason gives has to work, or it is advice rather than a fix. A file named directly is always
    audited -- `_classify` only ever runs on files found by a walk -- and YAML is a superset of JSON, so the
    privileged pod in `pod.json` is read and reported."""
    d = _tree(tmp_path)
    rep = gate.run(gate.collect([str(d / "pod.json")], lambda p: Path(p).read_text()), fail_on="never")
    assert [s for s in rep["skipped"] if s.get("forbidsVerdict")] == [], rep["skipped"]
    assert rep["findings"], "the privileged pod was named directly and produced no finding"


def test_the_exit_code_is_evidence_incomplete_not_findings(tmp_path: Path, capsys: Any) -> None:
    """5 and 1 are not two answers to the same question: one says the checks failed, the other says the run could
    not see enough to answer. A caller that treats 5 as 1 goes looking for a finding that does not exist.

    Through `main`, because the exit code is decided there and this is the number CI reads.
    """
    code = main(["gate", "-f", str(_tree(tmp_path)), "--fail-on", "never", "--format", "json"])
    capsys.readouterr()
    assert code == 5


def test_the_same_directory_without_the_unopened_files_exits_zero(tmp_path: Path, capsys: Any) -> None:
    """The control for the exit code: 5 came from the unopened files and from nothing else about this tree."""
    d = _tree(tmp_path)
    for name in ("pod.json", "pod2.JSON", "pod.YAML"):
        (d / name).unlink()
    (d / ".hidden" / "pod.yaml").unlink()
    code = main(["gate", "-f", str(d), "--fail-on", "never", "--format", "json"])
    capsys.readouterr()
    assert code == 0


def test_a_workflow_file_does_not_hold_the_gate_incomplete(tmp_path: Path) -> None:
    """The regression the first version of this change would have shipped.

    `.github/workflows/ci.yml` is a `.yml` file in a dot-directory in every repository. A rule that guessed from
    the extension recorded it, so every real gate run read incomplete -- an alert on every repository is one
    nobody reads, and that is a worse outcome than the gap it replaces. `tests/test_gate.py`'s
    `test_directory_walks_skip_what_is_not_a_manifest` is what caught it; this holds it from the other side.
    """
    repo = tmp_path / "repo"
    ci = repo / ".github" / "workflows"
    ci.mkdir(parents=True)
    (ci / "ci.yml").write_text("on: push\njobs: {}\n", encoding="utf-8")
    (repo / "ok.yaml").write_text(BENIGN_YAML, encoding="utf-8")
    rep = gate.run(gate.collect([str(repo)], lambda p: Path(p).read_text()), fail_on="never")
    assert rep["passed"] is True
    assert "ci.yml" not in {Path(s["file"]).name for s in rep["skipped"]}


def test_a_file_that_does_not_parse_is_not_called_a_manifest(tmp_path: Path) -> None:
    """`broken.json` is not something `kubectl apply -f` would send either, and the walk never claimed to read it.
    Treating every unparseable file as a manifest would hold the gate incomplete on any repository with one."""
    rep = gate.run(gate.collect([str(_tree(tmp_path))], lambda p: Path(p).read_text()), fail_on="never")
    names = {Path(s["file"]).name for s in rep["skipped"]}
    assert "broken.json" not in names


def test_a_json_file_that_is_not_a_manifest_is_passed_over(tmp_path: Path) -> None:
    """`values.json` parses and carries neither `apiVersion` nor `kind`. The extension is a manifest extension and
    the file is not a manifest, which is why the decision is made by opening it."""
    rep = gate.run(gate.collect([str(_tree(tmp_path))], lambda p: Path(p).read_text()), fail_on="never")
    assert "values.json" not in {Path(s["file"]).name for s in rep["skipped"]}


def test_a_configmap_volume_mount_is_not_two_files(tmp_path: Path) -> None:
    """The false positive G332 shipped to CI, and the reason this is decided by identity rather than by name.

    A ConfigMap volume mount exposes each key TWICE: `key` is a symlink to `..data/key`, and `..data` is itself a
    symlink to a timestamped directory. The walk reads `key` and the dot-directory rule declines `..data/key` --
    the same bytes, reported as an unopened manifest. That took the Tekton Task in `gate-ci` from `passed` to
    `evidence-incomplete`, exit 5, and `..data` is the exact case the walk's own comment names as the reason it
    skips dot-directories. Anyone passing manifests into a Pod the standard way would have hit it.
    """
    mnt = tmp_path / "mnt"
    real = mnt / "..2026_11_21_16_00_00.123"
    real.mkdir(parents=True)
    (real / "gate.yaml").write_text(PRIVILEGED_YAML, encoding="utf-8")
    (mnt / "..data").symlink_to("..2026_11_21_16_00_00.123")
    (mnt / "gate.yaml").symlink_to("..data/gate.yaml")

    rep = gate.run(gate.collect([str(mnt)], lambda q: Path(q).read_text()), fail_on="never")
    assert [s for s in rep["skipped"] if s.get("forbidsVerdict")] == [], rep["skipped"]
    assert rep["passed"] is True
    assert rep["findings"], "the manifest behind the symlink was not audited at all"


def test_a_dot_directory_copy_that_is_a_DIFFERENT_file_is_still_a_gap(tmp_path: Path) -> None:
    """The limit of that de-duplication: it is identity, not a rule about dot-directories. A distinct manifest
    that happens to live in one is still a manifest nobody opened."""
    d = tmp_path / "k8s"
    (d / ".hidden").mkdir(parents=True)
    (d / "ok.yaml").write_text(BENIGN_YAML, encoding="utf-8")
    (d / ".hidden" / "other.yaml").write_text(PRIVILEGED_YAML, encoding="utf-8")
    rep = gate.run(gate.collect([str(d)], lambda q: Path(q).read_text()), fail_on="never")
    blocked = {Path(s["file"]).name for s in rep["skipped"] if s.get("forbidsVerdict")}
    assert blocked == {"other.yaml"}
