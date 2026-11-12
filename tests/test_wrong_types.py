"""A field of the wrong type is input kube-noob could not read, never a crash and never exit 1 (G276).

A Role whose rule says `resources: 1` made `kube-noob audit` raise `TypeError: argument of type 'int' is not
iterable`. The exception escaped `main`, Python exited 1, and exit 1 is the public contract for "findings at or above
--fail-on": a pipeline read a crash as a policy violation, and the plugin's skills read it as an answer. Two layers
now: a rule that meets a shape it cannot read is recorded as NOT evaluated (never as clean), and anything that still
escapes `main` exits 4, "a kube-noob error", with one line on stderr.

The mutation test walks every distinct field of every rule fixture and sets it to the shapes YAML can give a field --
an int, a string, null, a list, a mapping, a boolean and a float -- and runs the commands that read manifests. It
fails on an `internal error` too, so the catch-all in `main` cannot hide a crash the readers should have declined.
"""

from __future__ import annotations

import copy
import io
import json
from collections.abc import Iterator
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import cli

ROOT = Path(__file__).resolve().parents[1]
WRONG: list[Any] = [7, "x", None, [1], {"a": 1}, True, 1.5]


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(argv)
    return rc, out.getvalue(), err.getvalue()


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUBE_NOOB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("KUBE_NOOB_LEARNING_ENABLED", "false")
    monkeypatch.delenv("KUBE_NOOB_CONFIG", raising=False)
    monkeypatch.delenv("KUBE_NOOB_DEBUG", raising=False)


def _paths(node: Any, prefix: tuple[Any, ...] = ()) -> Iterator[tuple[Any, ...]]:
    if isinstance(node, dict):
        for k, v in node.items():
            yield (*prefix, k)
            yield from _paths(v, (*prefix, k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield (*prefix, i)
            yield from _paths(v, (*prefix, i))


def _mutations() -> Iterator[tuple[str, int, list[dict[str, Any]]]]:
    """One mutation per distinct (kind, field path) across the rule fixtures -- the same field in two fixtures reaches
    the same code -- tried with two of the seven wrong shapes, rotating, so every shape meets every kind of field
    somewhere. Yields the label, the field's ordinal and the mutated documents."""
    seen: set[tuple[Any, ...]] = set()
    for fx in sorted((ROOT / "tests" / "fixtures" / "rules").glob("*.yaml")):
        raw = yaml.safe_load(fx.read_text())
        docs = [d for part in ("bad", "good") for d in yaml.safe_load_all(raw.get(part) or "") if isinstance(d, dict)]
        for di, doc in enumerate(docs):
            for p in _paths(doc):
                if p in {("apiVersion",), ("kind",)}:
                    continue
                key = (doc.get("kind"), tuple("[]" if isinstance(x, int) else x for x in p))
                if key in seen:
                    continue
                seen.add(key)
                n = len(seen)
                for value in (WRONG[n % len(WRONG)], WRONG[(n + 2) % len(WRONG)]):
                    mutated = copy.deepcopy(docs)
                    target: Any = mutated[di]
                    for k in p[:-1]:
                        target = target[k]
                    target[p[-1]] = value
                    yield f"{fx.stem}:{'.'.join(map(str, p))}={value!r}", n, mutated


def test_the_reviewers_role_is_read_not_crashed_on(tmp_path: Path) -> None:
    f = tmp_path / "role.yaml"
    f.write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata: {name: reader, namespace: shop}\n"
        "rules:\n- apiGroups: ['']\n  resources: 1\n  verbs: [get]\n"
    )
    rc, out, err = _run(["audit", "-f", str(f), "--format", "json"])
    report = json.loads(out)
    assert rc in (0, 1), err
    said = " ".join(report["assumptions"])
    assert "not evaluated" in said and "wrong type" in said, report["assumptions"]


def test_an_unexpected_error_exits_4_with_one_line_and_never_1(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_k: Any) -> int:
        raise TypeError("argument of type 'int'\nis not iterable")

    monkeypatch.setattr(cli, "_dispatch", boom)
    rc, out, err = _run(["audit", "-f", str(ROOT / "examples" / "insecure-deployment.yaml"), "--format", "json"])
    assert rc == 4 and out == ""
    assert err.startswith("error: internal error (TypeError)") and "Traceback" not in err
    assert len(err.strip().splitlines()) == 1
    monkeypatch.setenv("KUBE_NOOB_DEBUG", "1")
    with pytest.raises(TypeError):
        _run(["audit", "-f", str(ROOT / "examples" / "insecure-deployment.yaml")])


def _argv(command: str, path: Path, tmp: Path) -> list[str]:
    return {
        "audit": ["audit", "-f", str(path)],
        "redteam": ["redteam", "-f", str(path)],
        "validate": ["validate", "-f", str(path)],
        "vuln threat": ["vuln", "threat", "-f", str(path)],
        "posture scan": ["posture", "scan", "-f", str(path)],
        "fix": ["fix", "-f", str(path), "-o", str(tmp / "fixed.yaml")],
        "protocol": ["protocol", "review", "-f", str(path)],
    }[command] + ["--format", "json"]


def test_wrong_typed_fields_never_exit_1_without_a_json_document(tmp_path: Path) -> None:
    f = tmp_path / "m.yaml"
    bad: list[str] = []
    cases = 0
    previous = -1
    for label, n, docs in _mutations():
        f.write_text(yaml.safe_dump_all(docs))
        commands = ["audit"]
        if n != previous:  # the first of the two shapes for a field also goes through the other readers
            commands += ["redteam", "validate", "vuln threat", "posture scan"]
            if n % 4 == 0:
                commands += ["fix", "protocol"]
        previous = n
        for command in commands:
            cases += 1
            rc, out, err = _run(_argv(command, f, tmp_path))
            if rc not in (0, 1, 2, 4, 5):
                bad.append(f"{command} {label}: exit {rc}")
            elif rc in (0, 1):
                try:
                    json.loads(out)
                except ValueError:
                    bad.append(f"{command} {label}: exit {rc} with no JSON document")
            if "internal error" in err:
                bad.append(f"{command} {label}: {err.strip()[:160]}")
    assert cases > 2000, f"{cases} cases: the mutation walk found too few fields; it is measuring nothing"
    assert not bad, f"{len(bad)} of {cases}:\n" + "\n".join(sorted(set(bad))[:60])


_DEPLOY = (
    "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web, namespace: shop}\nspec:\n  replicas: 3\n"
    "  selector: {matchLabels: {app: web}}\n  template:\n    metadata: {labels: {app: web}}\n    spec:\n"
    "      volumes: 7\n      containers: [{name: web, image: nginx}]\n"
)


def test_a_red_team_scenario_that_cannot_read_its_input_is_undecided_not_mitigated(tmp_path: Path) -> None:
    f = tmp_path / "d.yaml"
    f.write_text(_DEPLOY)
    rc, out, _ = _run(["redteam", "-f", str(f), "--format", "json"])
    scenarios = {s["scenarioId"]: s for s in json.loads(out)["scenarios"]}
    rwx = scenarios["RT-RWX-SPLIT-BRAIN"]
    assert rc == 0 and rwx["verdict"] == "undecided", rwx
    assert any("spec.volumes is int" in e for e in rwx["evidence"])


def test_a_fix_that_cannot_read_a_document_leaves_it_untouched_and_says_so(tmp_path: Path) -> None:
    f = tmp_path / "np.yaml"
    f.write_text(
        "apiVersion: k8s.ovn.org/v1\nkind: EgressFirewall\nmetadata: {name: default, namespace: shop}\n"
        "spec:\n  egress:\n  - type: Allow\n    to: [1]\n"
    )
    rc, out, _ = _run(["fix", "-f", str(f), "-o", str(tmp_path / "out.yaml"), "--format", "json"])
    report = json.loads(out)
    assert rc == 0 and not report["changes"], report["changes"]
    assert any("not fixed, because" in m and "egress rule to is list" in m for m in report["manualFollowUps"])
    assert yaml.safe_load((tmp_path / "out.yaml").read_text())["spec"]["egress"][0]["to"] == [1]


def test_the_threat_model_reports_a_workload_it_could_not_read(tmp_path: Path) -> None:
    """Not "stateless": whether it keeps data was not decided, and the model says so under `notRead`."""
    f = tmp_path / "d.yaml"
    f.write_text(
        _DEPLOY.replace("replicas: 3", "replicas: 1")
        + "---\napiVersion: v1\nkind: Service\nmetadata: {name: web, namespace: shop}\n"
        "spec: {type: LoadBalancer, selector: {app: web}, ports: [{port: 80}]}\n"
    )
    rc, out, err = _run(["vuln", "threat", "-f", str(f), "--format", "json"])
    doc = json.loads(out)
    assert rc == 0, err
    assert any("Deployment/shop/web" in n and "not decided" in n for n in doc["notRead"]), doc.get("notRead")
    assert all("Deployment/shop/web" not in a["dataStores"] for a in doc["applications"])


def test_the_attack_path_scan_reports_a_service_it_could_not_read(tmp_path: Path) -> None:
    f = tmp_path / "s.yaml"
    f.write_text("apiVersion: v1\nkind: Service\nmetadata: {name: web, namespace: shop}\nspec: 7\n")
    rc, out, _ = _run(["posture", "scan", "-f", str(f), "--format", "json"])
    doc = json.loads(out)
    assert rc == 0 and any("Service/shop/web" in n and "not a mapping" in n for n in doc["notRead"]), doc["notRead"]
