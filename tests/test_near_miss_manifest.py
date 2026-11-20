"""A manifest key spelled with the wrong case is a typo, not a file that is no manifest (G325).

``apiversion: v1`` beside ``kind: Pod`` was classified exactly as a GitHub Actions workflow is: "not a Kubernetes
manifest (no document with apiVersion and kind)", listed under ``skipped``, and then ``passed: true``,
``incomplete: false``, exit 0, with ``verify -f`` answering ``allow`` -- for a privileged pod. An unrecognised
shape must never read as a pass.

The detection stays deliberately tight: a required key must be ABSENT exactly and PRESENT as a spelling that
differs only by letter case, surrounding whitespace, or ``-``/``_`` separators. A kustomization, a Helm values
file or a CRD fragment that carries a ``kind`` and no ``apiVersion`` at all is not a near miss, because widening
it that far would turn every repository scanned with ``gate -f .`` red. The negative tests below are the point
of this file as much as the positive ones.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from kube_noob import gate
from kube_noob.cli import main

ROOT = Path(__file__).resolve().parents[1]

PRIVILEGED = """\
{key}: v1
kind: Pod
metadata:
  name: bad
  namespace: default
spec:
  hostNetwork: true
  containers:
    - name: app
      image: nginx:latest
      securityContext:
        privileged: true
        allowPrivilegeEscalation: true
        runAsUser: 0
"""

GOOD = """\
apiVersion: v1
kind: ConfigMap
metadata:
  name: c
  namespace: default
data:
  k: v
"""


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _run(paths: list[Path], **kw: object) -> dict:  # type: ignore[type-arg]
    return gate.run(gate.collect([str(p) for p in paths], _read), **kw)  # type: ignore[arg-type]


def _dir(tmp_path: Path, **files: str) -> Path:
    d = tmp_path / "manifests"
    d.mkdir(exist_ok=True)
    for name, text in files.items():
        (d / name.replace("__", ".")).write_text(text, encoding="utf-8")
    return d


# -- detection ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "apiversion",
        "APIVersion",
        "APIVERSION",
        "api_version",
        "api-version",
        "ApiVersion",
        # YAML strips a plain key, so surrounding whitespace only survives when the key is quoted -- and then it
        # is a different key to the API server, which is the whole point.
        '" apiVersion "',
    ],
)
def test_an_api_version_key_that_differs_only_in_shape_is_named_as_a_typo(tmp_path: Path, key: str) -> None:
    why = gate._classify(tmp_path / "pod.yaml", PRIVILEGED.format(key=key))
    assert why is not None
    assert why.startswith(gate.NEAR_MISS_PREFIX), why
    assert key.strip('" ') in why and "`apiVersion`" in why
    assert "case-sensitive" in why
    assert gate.forbids_verdict(why)


@pytest.mark.parametrize("key", ["Kind", "KIND", "kInD"])
def test_a_kind_key_that_differs_only_in_shape_is_named_as_a_typo(tmp_path: Path, key: str) -> None:
    text = f"apiVersion: v1\n{key}: Pod\nmetadata: {{name: p, namespace: default}}\n"
    why = gate._classify(tmp_path / "pod.yaml", text)
    assert why is not None and why.startswith(gate.NEAR_MISS_PREFIX), why
    assert key in why and "`kind`" in why
    assert gate.forbids_verdict(why)


# -- the negative half: what must stay silently skipped ----------------------------------------------------------

NOT_MANIFESTS = {
    "a GitHub Actions workflow": "name: ci\non:\n  push:\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
    "a Helm values file": "replicaCount: 2\nimage:\n  repository: nginx\n  tag: '1.27'\n",
    "a Helm values file naming a kind": "kind: Deployment\nreplicaCount: 2\n",
    "a kustomization": "resources:\n  - deploy.yaml\nnamespace: shop\n",
    "a plain list": "- one\n- two\n",
    "a scalar document": "just-a-string\n",
    "an empty file": "",
    "only comments": "# nothing here\n",
    "a key that is a different word": "apiVersions: v1\nkind: Pod\n",
}


@pytest.mark.parametrize("what,text", sorted(NOT_MANIFESTS.items()))
def test_a_file_that_really_is_not_a_manifest_is_still_skipped_in_silence(tmp_path: Path, what: str, text: str) -> None:
    why = gate._classify(tmp_path / "x.yaml", text)
    assert why == "not a Kubernetes manifest (no document with apiVersion and kind)", what
    assert not gate.forbids_verdict(why), what


def test_a_repository_of_non_manifests_beside_one_good_manifest_still_exits_zero(tmp_path: Path) -> None:
    files = {f"f{n}__yaml": text for n, text in enumerate(sorted(NOT_MANIFESTS.values()))}
    d = _dir(tmp_path, good__yaml=GOOD, **files)
    rep = _run([d])
    assert rep["passed"] and not rep["incomplete"]
    assert rep["skipped"] and not any(s.get("forbidsVerdict") for s in rep["skipped"])
    assert main(["gate", "-f", str(d), "--format", "json"]) == 0


def test_a_helm_template_keeps_its_own_reason_and_is_not_reclassified(tmp_path: Path) -> None:
    chart = tmp_path / "chart"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: shop\nversion: 0.1.0\n")
    tpl = chart / "templates" / "pod.yaml"
    tpl.write_text(PRIVILEGED.format(key="apiversion"))
    why = gate._classify(tpl, tpl.read_text())
    assert why == "a Helm template: render the chart with --chart"
    assert not gate.forbids_verdict(why)


# -- the verdict it forbids, in gate -----------------------------------------------------------------------------


def test_the_gate_does_not_pass_a_directory_holding_a_near_miss(tmp_path: Path) -> None:
    d = _dir(tmp_path, good__yaml=GOOD, pod__yaml=PRIVILEGED.format(key="apiversion"))
    rep = _run([d])
    assert not rep["passed"], "a file the walk declined to read must not read as a pass"
    assert rep["incomplete"] is True
    blocked = [s for s in rep["skipped"] if s.get("forbidsVerdict")]
    assert len(blocked) == 1 and blocked[0]["file"].endswith("pod.yaml")
    assert rep["failures"] and any("apiversion" in f for f in rep["failures"])
    assert any("pod.yaml" in n for n in rep["notRun"])
    assert gate.verdict_word(rep) == "incomplete"


def test_the_gate_exits_five_and_not_one_and_not_zero(tmp_path: Path) -> None:
    d = _dir(tmp_path, good__yaml=GOOD, pod__yaml=PRIVILEGED.format(key="apiversion"))
    code = main(["gate", "-f", str(d), "--format", "json"])
    assert code == 5, "a file the walk declined to read is not a policy violation (1) and not clean (0)"


def test_there_is_no_flag_that_lets_a_near_miss_through(tmp_path: Path) -> None:
    d = _dir(tmp_path, good__yaml=GOOD, pod__yaml=PRIVILEGED.format(key="apiversion"))
    assert main(["gate", "-f", str(d), "--format", "json", "--skip-unreadable"]) == 5


def test_a_directory_whose_only_file_is_a_near_miss_is_refused(tmp_path: Path) -> None:
    d = _dir(tmp_path, pod__yaml=PRIVILEGED.format(key="apiversion"))
    with pytest.raises(gate.GateError, match="apiversion"):
        _run([d])


def test_a_file_nested_past_the_loader_limit_forbids_a_verdict_too(tmp_path: Path) -> None:
    """`_classify` returns the depth refusal as a skip reason, and that file was not read either.

    Deliberately widened beyond the reported shape: on `origin/main` a directory holding a depth bomb beside one
    good manifest gave `passed: true` and exit 0, which is the same false pass with a different reason. Recording
    it as `False` in `SKIP_REASONS` would have been filing a known false pass as intended behaviour.
    """
    bomb = "a:\n" + "".join("  " * i + f"k{i}:\n" for i in range(1, 80)) + "  " * 80 + "x: 1\n"
    d = _dir(tmp_path, good__yaml=GOOD, bomb__yaml=bomb)
    why = gate._classify(d / "bomb.yaml", bomb)
    assert why is not None and why.startswith("YAML nested too deeply") and gate.forbids_verdict(why)
    rep = _run([d])
    assert not rep["passed"] and rep["incomplete"] is True
    assert main(["gate", "-f", str(d), "--format", "json"]) == 5


# -- the verdict it forbids, in verify ---------------------------------------------------------------------------


def test_verify_on_a_directory_holding_a_near_miss_is_not_determined(tmp_path: Path) -> None:
    from kube_noob import verify

    d = _dir(tmp_path, good__yaml=GOOD, pod__yaml=PRIVILEGED.format(key="apiversion"))
    result = verify.evaluate(verify.collect([str(d)], _read))
    assert result["verdict"] == "not-determined", "allow would be a pre-action verdict on a file verify never read"
    assert any("pod.yaml" in u for u in result["notDetermined"])
    assert verify.exit_code(result) == 5
    assert verify.exit_code(result, allow_undetermined=True) == 0
    assert main(["verify", "-f", str(d), "--format", "json"]) == 5
    assert main(["verify", "-f", str(d), "--format", "json", "--allow-undetermined"]) == 0


def test_verify_on_a_clean_directory_is_still_allow(tmp_path: Path) -> None:
    from kube_noob import verify

    d = _dir(tmp_path, good__yaml=GOOD, workflow__yaml=NOT_MANIFESTS["a GitHub Actions workflow"])
    result = verify.evaluate(verify.collect([str(d)], _read))
    assert result["verdict"] == "allow" and verify.exit_code(result) == 0


# -- several documents in one file -------------------------------------------------------------------------------


def test_a_file_whose_other_document_is_a_real_manifest_is_audited_and_does_not_pass(tmp_path: Path) -> None:
    """The file holds a manifest, so the walk reads it; the near-miss document is then audited as what it is --
    a mapping with no apiVersion -- and the audit's own findings keep the gate off a pass."""
    text = GOOD + "---\n" + PRIVILEGED.format(key="apiversion")
    d = _dir(tmp_path, both__yaml=text)
    assert gate._classify(d / "both.yaml", text) is None
    rep = _run([d])
    assert not rep["passed"], "a document the API server would reject must not leave a clean gate"


# -- every renderer ----------------------------------------------------------------------------------------------


def test_the_reason_survives_json_yaml_text_and_sarif(tmp_path: Path) -> None:
    d = _dir(tmp_path, good__yaml=GOOD, pod__yaml=PRIVILEGED.format(key="apiversion"))
    rep = _run([d])
    as_json = json.dumps(rep)
    assert gate.NEAR_MISS_PREFIX in as_json and '"forbidsVerdict": true' in json.dumps(rep, indent=1)
    assert gate.NEAR_MISS_PREFIX in yaml.safe_dump(rep)
    md = gate.markdown(rep)
    assert md.startswith("## kube-noob gate incomplete")
    assert "### Skipped" in md and "apiversion" in md
    assert "### Why it is incomplete" in md
    doc = gate.sarif_of_gate(rep)
    text = json.dumps(doc)
    assert "apiversion" in text and "kube-noob/undetermined" in text
    run = doc["runs"][0]
    assert run["invocations"][0]["properties"]["incomplete"] is True
    assert any(
        "not read as a manifest" in n["message"]["text"] for n in run["invocations"][0]["toolExecutionNotifications"]
    )


def test_the_report_is_the_same_whatever_the_order_and_the_hash_seed(tmp_path: Path) -> None:
    d = _dir(tmp_path, good__yaml=GOOD, pod__yaml=PRIVILEGED.format(key="apiversion"), z__yaml=GOOD.replace("c", "z"))
    first = gate.run(gate.collect([str(d)], _read))
    again = gate.run(gate.collect([str(d)], _read))
    digest = hashlib.sha256(json.dumps(first, sort_keys=True).encode()).hexdigest()
    assert hashlib.sha256(json.dumps(again, sort_keys=True).encode()).hexdigest() == digest
    out = []
    for seed in ("0", "1", "12345"):
        env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": str(ROOT / "src")}
        proc = subprocess.run(
            [sys.executable, "-m", "kube_noob", "gate", "-f", str(d), "--format", "json"],
            capture_output=True,
            text=True,
            env=env,
            cwd=str(ROOT),
            check=False,
        )
        assert proc.returncode == 5, proc.stderr
        out.append(hashlib.sha256(proc.stdout.encode()).hexdigest())
    assert len(set(out)) == 1, "the JSON report changed with PYTHONHASHSEED"


# -- the structural guard ----------------------------------------------------------------------------------------


def _classify_reasons() -> list[str]:
    """Every literal reason ``_classify`` can return, read out of its own source."""
    src = (ROOT / "src" / "kube_noob" / "gate.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    fn = next(
        n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name in {"_classify", "_near_miss_reason"}
    )
    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name not in {"_classify", "_near_miss_reason"}:
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Constant) and isinstance(sub.value.value, str):
                found.append(sub.value.value)
            if isinstance(sub, ast.Return) and isinstance(sub.value, ast.JoinedStr):
                head = sub.value.values[0]
                if isinstance(head, ast.Constant) and isinstance(head.value, str):
                    found.append(head.value)
    assert fn is not None and found, "no reason strings found: this guard would pass vacuously"
    return found


def test_every_skip_reason_decides_whether_it_forbids_a_verdict() -> None:
    """A new skip reason must be added to ``gate.SKIP_REASONS`` with a decision beside it.

    Without this, the next reason added to ``_classify`` silently inherits "this is fine, pass the gate" -- which
    is exactly how a case-variant ``apiVersion`` came to read as a GitHub Actions workflow (G325).
    """
    decided = [prefix for prefix, _ in gate.SKIP_REASONS]
    assert len(decided) == len(set(decided)), "a prefix is listed twice in SKIP_REASONS"
    for reason in _classify_reasons():
        assert any(reason.startswith(p) for p in decided), (
            f"{reason!r} is a skip reason with no entry in gate.SKIP_REASONS: add it there and decide whether a "
            "file skipped for that reason forbids a verdict"
        )
    # The depth refusal is raised, not returned, so the reader above cannot see it: name it here.
    assert any("YAML nested too deeply".startswith(p) or p in "YAML nested too deeply" for p in decided)
    assert all(isinstance(f, bool) for _, f in gate.SKIP_REASONS)
