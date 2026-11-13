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
import os
from collections.abc import Iterator
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import cli

ROOT = Path(__file__).resolve().parents[1]
# Every shape YAML can give a field, and the two floats arithmetic chokes on.
WRONG: list[Any] = [7, "x", None, [1], {"a": 1}, True, 1.5, float("nan"), float("inf")]
# KUBE_NOOB_EXHAUSTIVE_MUTATION=1: every field x every shape x every command (about 40,000 runs; the fuzz the
# release is measured with). Unset (CI): every field x every shape through `audit`, and every field x one
# shape, rotating, through the other six commands.
EXHAUSTIVE = os.environ.get("KUBE_NOOB_EXHAUSTIVE_MUTATION") == "1"


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


def _mutations() -> Iterator[tuple[str, int, int, list[dict[str, Any]]]]:
    """One mutation per distinct (kind, field path) across the rule fixtures and each wrong shape -- the same field in
    two fixtures reaches the same code. `kind` and `apiVersion` are fields too. Yields the label, the field's ordinal,
    the shape's ordinal and the mutated documents."""
    seen: set[tuple[Any, ...]] = set()
    for fx in sorted((ROOT / "tests" / "fixtures" / "rules").glob("*.yaml")):
        raw = yaml.safe_load(fx.read_text())
        docs = [d for part in ("bad", "good") for d in yaml.safe_load_all(raw.get(part) or "") if isinstance(d, dict)]
        for di, doc in enumerate(docs):
            for p in _paths(doc):
                key = (doc.get("kind"), tuple("[]" if isinstance(x, int) else x for x in p))
                if key in seen:
                    continue
                seen.add(key)
                n = len(seen)
                for w, value in enumerate(WRONG):
                    mutated = copy.deepcopy(docs)
                    target: Any = mutated[di]
                    for k in p[:-1]:
                        target = target[k]
                    target[p[-1]] = value
                    yield f"{fx.stem}:{'.'.join(map(str, p))}={value!r}", n, w, mutated


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
    assert err.startswith("error: unexpected TypeError") and "Traceback" not in err
    assert len(err.strip().splitlines()) == 1
    # With KUBE_NOOB_DEBUG the traceback is printed through the output boundary and the exit stays 4 (G279): a test
    # or a fuzz tells a crash from a refusal by the traceback, not by an exception escaping `main`.
    monkeypatch.setenv("KUBE_NOOB_DEBUG", "1")
    rc, _out, err = _run(["audit", "-f", str(ROOT / "examples" / "insecure-deployment.yaml")])
    assert rc == 4 and "Traceback" in err and "TypeError" in err


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


def test_wrong_typed_fields_never_exit_1_without_a_json_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Under KUBE_NOOB_DEBUG anything that is not a deliberate refusal -- including a bare KeyError or ValueError, which
    the CLI cannot tell from a refusal -- reaches the entry point and is printed with its traceback (exit 4, G279), so
    a crash fails here by that traceback instead of passing as a refusal."""
    monkeypatch.setenv("KUBE_NOOB_DEBUG", "1")
    f = tmp_path / "m.yaml"
    others = ["redteam", "validate", "vuln threat", "posture scan", "fix", "protocol"]
    bad: list[str] = []
    cases = 0
    for label, n, w, docs in _mutations():
        f.write_text(yaml.safe_dump_all(docs))
        commands = (
            ["audit", *others] if EXHAUSTIVE else ["audit"] + ([others[n % len(others)]] if w == n % len(WRONG) else [])
        )
        for command in commands:
            cases += 1
            try:
                rc, out, err = _run(_argv(command, f, tmp_path))
            except Exception as exc:  # noqa: BLE001 -- the point: anything that escapes is a crash
                bad.append(f"{command} {label}: {type(exc).__name__}: {str(exc)[:120]}")
                continue
            if rc == 4 and "Traceback" in err:
                crash = next((line for line in reversed(err.strip().splitlines()) if "Error" in line), err[-120:])
                bad.append(f"{command} {label}: crash: {crash[:160]}")
            elif rc not in (0, 1, 2, 3, 4, 5):
                bad.append(f"{command} {label}: exit {rc}")
            elif rc in (0, 1):
                try:
                    json.loads(out)
                except ValueError:
                    bad.append(f"{command} {label}: exit {rc} with no JSON document")
    assert cases > 5000, f"{cases} cases: the mutation walk found too few fields; it is measuring nothing"
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


def test_an_object_whose_metadata_is_not_a_mapping_is_not_read_by_the_attack_path_readers(tmp_path: Path) -> None:
    """`metadata: 7` crashed `posture scan` and `vuln threat` in three places; it is now refused once, where objects
    enter the inventory, and named under `notRead`."""
    f = tmp_path / "m.yaml"
    f.write_text(_DEPLOY.replace("metadata: {name: web, namespace: shop}", "metadata: 7").replace("volumes: 7", ""))
    for argv in (["posture", "scan"], ["vuln", "threat"]):
        rc, out, err = _run([*argv, "-f", str(f), "--format", "json"])
        doc = json.loads(out)
        assert rc == 0 and "internal error" not in err
        assert any("metadata is not a mapping" in n for n in doc.get("notRead", [])), (argv, doc.get("notRead"))


@pytest.mark.parametrize(
    "mutation,why",
    [
        (("metadata: {name: web, namespace: shop}", "metadata: 7"), "has the wrong type"),
        (("selector: {matchLabels: {app: web}}", "selector: 7"), "spec.selector is int"),
        (
            (
                "containers: [{name: web, image: nginx}]",
                "containers: [{name: web, image: nginx, securityContext: {capabilities: {add: 7}}}]",
            ),
            "capabilities.add is int",
        ),
    ],
    ids=["metadata", "pdb-selector", "capabilities-add"],
)
def test_fix_leaves_a_document_it_cannot_read_as_it_was(mutation: tuple[str, str], why: str, tmp_path: Path) -> None:
    pdb = "---\napiVersion: policy/v1\nkind: PodDisruptionBudget\nmetadata: {name: web, namespace: shop}\n"
    pdb += "spec: {minAvailable: 3, selector: {matchLabels: {app: web}}}\n"
    text = (_DEPLOY.replace("      volumes: 7\n", "") + pdb).replace(*mutation, 1)
    if mutation[0].startswith("selector"):
        text = _DEPLOY.replace("      volumes: 7\n", "") + pdb.replace(*mutation)
    f = tmp_path / "in.yaml"
    f.write_text(text)
    rc, out, err = _run(["fix", "-f", str(f), "-o", str(tmp_path / "out.yaml"), "--format", "json"])
    report = json.loads(out)
    assert rc == 0 and "internal error" not in err
    assert any(why in m for m in report["manualFollowUps"]), report["manualFollowUps"]


_PRIV = (
    "apiVersion: apps/v1\nkind: Deployment\nmetadata: 7\nspec:\n  replicas: 1\n  selector: {matchLabels: {app: p}}\n"
    "  template:\n    metadata: {labels: {app: p}}\n    spec:\n      hostNetwork: true\n"
    "      containers: [{name: p, image: nginx, securityContext: {privileged: true}}]\n---\n"
    "apiVersion: v1\nkind: Service\nmetadata: {name: p, namespace: default}\n"
    "spec: {type: LoadBalancer, selector: {app: p}, ports: [{port: 80}]}\n"
)


def test_an_object_with_unreadable_metadata_is_still_ranked_under_a_name_that_says_so(tmp_path: Path) -> None:
    """Refusing it left a privileged hostNetwork Deployment out, total 0, and `--fail-above` exited 0."""
    f = tmp_path / "pa.yaml"
    f.write_text(_PRIV)
    rc, out, _ = _run(["posture", "scan", "-f", str(f), "--fail-above", "5", "--format", "json"])
    doc = json.loads(out)
    assert doc["total"] >= 1 and rc == 1, (rc, doc["total"])
    assert any("<metadata not readable>" in n for n in doc["notRead"])


def test_a_gate_that_could_not_read_an_object_does_not_pass(tmp_path: Path) -> None:
    f = tmp_path / "s.yaml"
    f.write_text("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d, namespace: shop}\nspec: 7\n")
    rc, out, err = _run(["posture", "scan", "-f", str(f), "--fail-above", "29", "--format", "json"])
    assert rc == 5 and json.loads(out)["notRead"] and "incomplete" in err


def test_a_secret_is_never_named_whatever_shape_its_spec_has(tmp_path: Path) -> None:
    f = tmp_path / "s.yaml"
    f.write_text("apiVersion: v1\nkind: Secret\nmetadata: {name: db-password-prod, namespace: shop}\nspec: 7\n")
    _, out, _ = _run(["posture", "scan", "-f", str(f), "--format", "json"])
    assert "db-password-prod" not in out and json.loads(out)["secretsIgnored"] == 1


def test_a_custom_resource_whose_spec_is_not_a_mapping_is_not_reported_as_unread(tmp_path: Path) -> None:
    """A CRD may allow any spec; a kind the scan does not model was never going to be read, so it is not news."""
    f = tmp_path / "cr.yaml"
    f.write_text("apiVersion: example.com/v1\nkind: Widget\nmetadata: {name: w, namespace: shop}\nspec: [1, 2]\n")
    _, out, _ = _run(["posture", "scan", "-f", str(f), "--format", "json"])
    assert json.loads(out)["notRead"] == []
    _rc, out, _ = _run(["fix", "-f", str(f), "-o", str(tmp_path / "o.yaml"), "--format", "json"])
    assert not json.loads(out)["manualFollowUps"]


_POD = (
    "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: shop}\n"
    "spec:\n  containers:\n  - name: c\n    image: nginx\n"
)


@pytest.mark.parametrize(
    "argv,text",
    [
        (
            ["redteam"],
            _DEPLOY.replace("volumes: 7", "volumes: [{name: d, persistentVolumeClaim: {claimName: data}}]")
            + "---\napiVersion: v1\nkind: PersistentVolumeClaim\nmetadata: {name: data, namespace: shop}\n"
            "spec: {accessModes: .inf}\n",
        ),
        (["audit"], _POD + "    resources: {requests: {memory: .nan}, limits: {memory: 1Gi}}\n"),
        (
            ["vuln", "threat"],
            _DEPLOY.replace("volumes: 7\n", "").replace("image: nginx}", "image: nginx, ports: [{containerPort: [1]}]}")
            + "---\napiVersion: v1\nkind: Service\nmetadata: {name: web, namespace: shop}\n"
            "spec: {type: LoadBalancer, selector: {app: web}, ports: [{port: 80}]}\n",
        ),
        (["fix"], _POD.replace("kind: Pod", "kind: [Pod]")),
        # The whole document, not one field: the check added for a non-string `kind` read `.get` off it (G276 rerun).
        (["audit"], "!!set {a, b}\n---\n" + _POD),
        (["audit"], "1000000000000000000000\n---\n" + _POD),
    ],
    ids=["pvc-accessModes-inf", "memory-nan", "containerPort-list", "kind-list", "document-set", "document-int"],
)
def test_the_second_reviews_residual_sites_answer_instead_of_crashing(
    argv: list[str], text: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KUBE_NOOB_DEBUG", "1")
    f = tmp_path / "in.yaml"
    f.write_text(text)
    extra = ["-o", str(tmp_path / "o.yaml")] if argv == ["fix"] else []
    rc, out, err = _run([*argv, "-f", str(f), *extra, "--format", "json"])
    assert rc in (0, 1) and "Traceback" not in err and json.loads(out)


def test_a_document_whose_kind_is_not_a_string_is_not_audited_as_clean(tmp_path: Path) -> None:
    f = tmp_path / "k.yaml"
    f.write_text(_POD.replace("kind: Pod", "kind: [Pod]") + "    securityContext: {privileged: true}\n")
    _, out, _ = _run(["audit", "-f", str(f), "--format", "json"])
    assert any("NOT audited" in a and "kind is list" in a for a in json.loads(out)["assumptions"])


def test_one_unreadable_object_does_not_blind_a_rule_for_its_siblings(tmp_path: Path) -> None:
    """KN-S015 caught one Role with `resources: 1` and stopped, so the wildcard Role beside it went unreported."""
    f = tmp_path / "roles.yaml"
    f.write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata: {name: a-broken, namespace: shop}\n"
        "rules: [{apiGroups: [''], resources: 1, verbs: [get]}]\n---\n"
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata: {name: b-wild, namespace: shop}\n"
        "rules: [{apiGroups: ['*'], resources: ['*'], verbs: ['*']}]\n"
    )
    _, out, _ = _run(["audit", "-f", str(f), "--format", "json"])
    doc = json.loads(out)
    assert ("KN-S015", "Role/shop/b-wild") in {(x["ruleId"], x["resource"]) for x in doc["findings"]}
    assert any("evaluated without Role/shop/a-broken" in a for a in doc["assumptions"])


def test_the_withheld_part_of_a_long_not_read_list_is_counted(tmp_path: Path) -> None:
    f = tmp_path / "many.yaml"
    f.write_text(
        "".join(
            f"---\napiVersion: apps/v1\nkind: Deployment\nmetadata: {{name: d{i}, namespace: shop}}\nspec: 7\n"
            for i in range(60)
        )
    )
    _, out, _ = _run(["posture", "scan", "-f", str(f), "--format", "json"])
    doc = json.loads(out)
    assert len(doc["notRead"]) == 50 and doc["notReadWithheld"] == 10
