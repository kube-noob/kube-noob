"""What kube-noob could not read is never a pass, and what it did read is not called unread (G276, third review).

Each test names the review item it pins. The rule throughout: an object or a read that was refused (a field of the
wrong shape, a 403, a timeout) makes the answer incomplete and says so; an absence that is normal (a CRD a cluster
does not serve, a built-in role a bundle does not carry) is reported but does not fail a gate on its own.
"""

from __future__ import annotations

import io
import json
import random
import threading
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import attack_paths as ap
from kube_noob import cli
from kube_noob.audit import redteam
from kube_noob.audit.engine import analyze
from kube_noob.errors import ClusterAccessError


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


# --- D1: the posture gate fails on a refusal, not on a normal absence ---------------------------------------------

_AGG_API = """
apiVersion: v1
kind: ServiceAccount
metadata: {name: metrics-server, namespace: kube-system}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: metrics-server:system:auth-delegator}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: system:auth-delegator}
subjects: [{kind: ServiceAccount, name: metrics-server, namespace: kube-system}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: metrics-server-auth-reader, namespace: kube-system}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: extension-apiserver-authentication-reader}
subjects: [{kind: ServiceAccount, name: metrics-server, namespace: kube-system}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: metrics-server, namespace: kube-system}
spec:
  selector: {matchLabels: {k8s-app: metrics-server}}
  template:
    metadata: {labels: {k8s-app: metrics-server}}
    spec:
      serviceAccountName: metrics-server
      containers: [{name: metrics-server, image: registry.k8s.io/metrics-server/metrics-server:v0.7.2}]
"""


def test_the_roles_every_aggregated_api_server_binds_are_known(tmp_path: Path) -> None:
    """metrics-server and kube-prometheus bind these two; they exist on every cluster, so they are not unread."""
    f = tmp_path / "ms.yaml"
    f.write_text(_AGG_API)
    rc, out, _ = _run(["posture", "scan", "-f", str(f), "--fail-above", "30", "--format", "json"])
    assert rc == 0 and json.loads(out)["notRead"] == []


def test_a_role_not_in_the_input_is_reported_but_gates_only_with_require_complete(tmp_path: Path) -> None:
    f = tmp_path / "rb.yaml"
    f.write_text(_AGG_API.replace("extension-apiserver-authentication-reader", "team-reader"))
    rc, out, err = _run(["posture", "scan", "-f", str(f), "--fail-above", "30", "--format", "json"])
    doc = json.loads(out)
    assert rc == 0 and any("team-reader" in n for n in doc["notRead"]) and doc["refused"] == []
    rc, _, err = _run(["posture", "scan", "-f", str(f), "--fail-above", "30", "--require-complete", "--format", "json"])
    assert rc == 5 and "incomplete" in err


def test_an_object_refused_on_shape_gates_without_require_complete(tmp_path: Path) -> None:
    f = tmp_path / "s.yaml"
    f.write_text("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d, namespace: shop}\nspec: 7\n")
    rc, out, err = _run(["posture", "scan", "-f", str(f), "--fail-above", "30", "--format", "json"])
    assert rc == 5 and json.loads(out)["refused"] and "incomplete" in err


class _Backend:
    name = "fake"

    def __init__(self, failures: dict[str, str]) -> None:
        self.failures = failures

    def get(self, resource: str, name: str | None = None, namespace: str | None = None, **_: Any) -> dict[str, Any]:
        if resource in self.failures:
            raise ClusterAccessError(self.failures[resource])
        return {"items": []}


@pytest.mark.parametrize(
    "message,gates",
    [
        ("the server could not find the requested resource (inferenceservices)", False),
        ('error: the server doesn\'t have a resource type "routes"', False),
        ("Not found: GET /apis/ray.io/v1/rayclusters", False),
        ("Forbidden by RBAC: GET /api/v1/pods. Grant the sidecar's ServiceAccount read access", True),
        ("kubectl timed out after 30s", True),
        ("API error 500 for GET /apis/apps/v1/deployments: boom", True),
    ],
)
def test_a_live_read_gates_when_the_cluster_refused_it_not_when_it_does_not_serve_it(message: str, gates: bool) -> None:
    resource = "inferenceservices" if not gates else "deployments"
    out = ap.scan(ap.collect_live(_Backend({resource: message}), []))
    assert any(n.startswith(resource) for n in out["notRead"])
    assert bool(out["refused"]) is gates, out["refused"]


def test_a_live_answer_that_is_not_json_is_a_refused_read() -> None:
    class NotJson(_Backend):
        def get(self, resource: str, name: str | None = None, namespace: str | None = None, **_: Any) -> Any:
            if resource == "pods":
                raise ValueError("Expecting value: line 1 column 1 (char 0)")
            return {"items": []}

    out = ap.scan(ap.collect_live(NotJson({}), []))
    assert any(n.startswith("pods") for n in out["refused"])


def test_exit_5_is_documented_where_the_gate_is_used() -> None:
    root = Path(__file__).resolve().parents[1]
    helptext = io.StringIO()
    with redirect_stdout(helptext), pytest.raises(SystemExit):
        cli.main(["posture", "scan", "--help"])
    assert "exit 5" in helptext.getvalue() and "--require-complete" in helptext.getvalue()
    uc = (root / "docs" / "use-cases.md").read_text()
    gate = uc[uc.index("posture scan") :]
    assert "exit 5" in uc and "--require-complete" in gate
    skill = (root / "plugin" / "kube-noob-skills" / "skills" / "openshift-platform" / "SKILL.md").read_text()
    row = next(line for line in skill.splitlines() if line.startswith("| `posture scan`"))
    assert "5" in row and "refused" in row, row


# --- D8: the withheld part of a long notRead list is stated in text and on the exit-5 line -------------------------


def test_the_text_view_and_the_exit_5_line_count_what_the_list_withholds(tmp_path: Path) -> None:
    f = tmp_path / "many.yaml"
    f.write_text(
        "".join(
            f"---\napiVersion: apps/v1\nkind: Deployment\nmetadata: {{name: d{i:02}, namespace: shop}}\nspec: 7\n"
            for i in range(60)
        )
    )
    rc, out, err = _run(["posture", "scan", "-f", str(f), "--fail-above", "30"])
    assert rc == 5
    assert "60 object(s) not read" in out and "and 50 more" in out, out
    assert "60 object(s)" in err and "10 not listed" in err, err


# --- D10: a kind that carries a pod spec is not dropped when its spec has the wrong shape ----------------------------


def test_a_rollout_whose_spec_is_not_a_mapping_is_refused_not_dropped(tmp_path: Path) -> None:
    f = tmp_path / "r.yaml"
    f.write_text("apiVersion: argoproj.io/v1alpha1\nkind: Rollout\nmetadata: {name: r, namespace: shop}\nspec: 7\n")
    rc, out, _ = _run(["posture", "scan", "-f", str(f), "--fail-above", "30", "--format", "json"])
    doc = json.loads(out)
    assert rc == 5 and any("Rollout/shop/r" in n for n in doc["refused"]), doc


# --- D2: the rules a scenario read are recorded per run, not in a list threads share ------------------------------

_PDB_BUNDLE = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  replicas: 3
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec: {containers: [{name: web, image: nginx}]}
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: web, namespace: shop}
spec: {maxUnavailable: 1, selector: {matchLabels: {app: web}}}
"""


def test_threads_running_red_team_at_once_do_not_mix_up_what_each_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """The MCP server runs tools in threads. With one module-level list, a clean run cleared the list a bad run was
    filling, and the bad PDB's scenario came back `mitigated` three runs in four under contention."""
    import time

    orig = redteam._ids

    def slow(*args: Any, **kwargs: Any) -> Any:
        out = orig(*args, **kwargs)
        time.sleep(0.0005)  # where a thread pool switches threads in practice
        return out

    monkeypatch.setattr(redteam, "_ids", slow)
    bad = _PDB_BUNDLE.replace("selector: {matchLabels: {app: web}}}", "selector: 7}")
    verdicts: dict[str, set[str]] = {"bad": set(), "clean": set()}
    lock = threading.Lock()

    def work(text: str, tag: str) -> None:
        for _ in range(15):
            r = analyze(text, platform="kubernetes", version="1.33")
            v = {s.scenario_id: s.verdict for s in r.scenarios}["RT-UPGRADE-BLOCK"]
            with lock:
                verdicts[tag].add(v)

    threads = [threading.Thread(target=work, args=(bad, "bad")) for _ in range(3)]
    threads += [threading.Thread(target=work, args=(_PDB_BUNDLE, "clean")) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert verdicts == {"bad": {"undecided"}, "clean": {"mitigated"}}, verdicts


# --- D3: the "evaluated without" note is bounded and does not depend on input order -------------------------------


def _roles(n: int) -> list[str]:
    return [
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\n"
        f"metadata: {{name: broken-{i:03}, namespace: shop}}\n"
        "rules: [{apiGroups: [''], resources: 1, verbs: [get]}]\n"
        for i in range(n)
    ] + [
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata: {name: wild, namespace: shop}\n"
        "rules: [{apiGroups: ['*'], resources: ['*'], verbs: ['*']}]\n"
    ]


def test_the_evaluated_without_note_is_short_and_the_same_in_any_order() -> None:
    docs = _roles(40)
    notes = set()
    for seed in range(4):
        random.Random(seed).shuffle(docs)
        r = analyze("---\n".join(docs), platform="kubernetes", version="1.33")
        [note] = [a for a in r.assumptions if "evaluated without" in a]
        notes.add(note)
    [note] = notes
    assert len(note) < 1200 and "and 30 more" in note, note
    assert "Role/shop/broken-000" in note and "Role/shop/broken-039" not in note


# --- D4: an unreadable PodDisruptionBudget is never read as "no PDB" ------------------------------------------------

_PDB_SHAPES: list[Any] = [7, "x", None, [1], {"a": 1}, True, 1.5, float("nan"), float("inf"), "", []]


def _pdb_mutations() -> list[tuple[str, str]]:
    docs = list(yaml.safe_load_all(_PDB_BUNDLE))
    out = []
    for path in (
        ("spec",),
        ("spec", "maxUnavailable"),
        ("spec", "selector"),
        ("spec", "selector", "matchLabels"),
        ("spec", "selector", "matchLabels", "app"),
    ):
        for w in _PDB_SHAPES:
            m = yaml.safe_load(yaml.safe_dump(docs[1]))
            t = m
            for k in path[:-1]:
                t = t[k]
            t[path[-1]] = w
            out.append((f"{'.'.join(path)}={w!r}", yaml.safe_dump_all([docs[0], m])))
    return out


@pytest.mark.parametrize("label,text", _pdb_mutations(), ids=[x[0] for x in _pdb_mutations()])
def test_a_schema_invalid_pdb_never_leaves_the_upgrade_scenario_mitigated_without_a_caveat(
    label: str, text: str
) -> None:
    r = analyze(text, platform="kubernetes", version="1.33")
    invalid = any(f.rule_id == "KN-V007" and "PodDisruptionBudget" in f.resource for f in r.findings)
    s = {s.scenario_id: s for s in r.scenarios}["RT-UPGRADE-BLOCK"]
    caveat = s.verdict != "mitigated" or any("not evaluated" in e for e in s.evidence)
    assert caveat or not invalid, (label, s.verdict, s.evidence)


_HPA = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  replicas: 3
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec: {containers: [{name: web, image: nginx}]}
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata: {name: web, namespace: shop}
spec: {scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: web}, minReplicas: 2, maxReplicas: 5}
"""


_HPA_META = "metadata: {name: web, namespace: shop}\nspec: {scaleTargetRef"


@pytest.mark.parametrize(
    "hpa",
    [
        "metadata: 7\nspec: {scaleTargetRef",
        "metadata: {name: [web], namespace: shop}\nspec: {scaleTargetRef",
        "metadata: {name: web, namespace: shop}\nspec: 7\nx: {scaleTargetRef",
    ],
    ids=["metadata-7", "name-list", "spec-7"],
)
def test_a_cross_object_rule_whose_partner_cannot_be_read_is_not_evaluated_and_says_so(hpa: str) -> None:
    """KN-C014 needs the HPA to know the Deployment is scaled; an HPA it cannot read is not "no HPA"."""
    r = analyze(_HPA.replace(_HPA_META, hpa), platform="kubernetes", version="1.33")
    assert any("KN-C014" in a and "could not be read" in a for a in r.assumptions), r.assumptions


def test_a_readable_bundle_keeps_the_cross_object_rule_evaluated() -> None:
    r = analyze(_HPA, platform="kubernetes", version="1.33")
    assert any(f.rule_id == "KN-C014" for f in r.findings)
    assert not any("could not be read" in a for a in r.assumptions)


# --- D5: fix refuses a securityContext of the wrong shape instead of overwriting it ---------------------------------


@pytest.mark.parametrize("where", ["container", "pod"])
def test_fix_leaves_a_security_context_of_the_wrong_shape_alone(where: str, tmp_path: Path) -> None:
    sc_c = "securityContext: 7, " if where == "container" else ""
    sc_p = "      securityContext: 7\n" if where == "pod" else ""
    src = (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web, namespace: shop}\nspec:\n  replicas: 2\n"
        "  selector: {matchLabels: {app: web}}\n  template:\n    metadata: {labels: {app: web}}\n    spec:\n"
        f"{sc_p}      containers: [{{name: web, {sc_c}image: nginx}}]\n"
    )
    f, o = tmp_path / "in.yaml", tmp_path / "out.yaml"
    f.write_text(src)
    _, out, _ = _run(["fix", "-f", str(f), "-o", str(o), "--format", "json"])
    doc = json.loads(out)
    fixed = yaml.safe_load(o.read_text())
    pod = fixed["spec"]["template"]["spec"]
    held = pod["containers"][0].get("securityContext") if where == "container" else pod.get("securityContext")
    assert held == 7, held
    assert any("securityContext" in m for m in doc["manualFollowUps"]), doc["manualFollowUps"]
    assert not any(c.get("before") is None and "securityContext" in str(c.get("path")) for c in doc.get("changes", []))


# --- D6 / D9: a document is named as not audited exactly when no rule could read it --------------------------------


def test_a_non_string_api_version_is_said_separately_and_the_object_is_still_audited() -> None:
    r = analyze(
        "apiVersion: [v1]\nkind: Pod\nmetadata: {name: p, namespace: shop}\n"
        "spec: {containers: [{name: c, image: nginx, securityContext: {privileged: true}}]}\n",
        platform="kubernetes",
        version="1.33",
    )
    assert not any("NOT audited" in a for a in r.assumptions), r.assumptions
    assert any("apiVersion" in a and "not a string" in a for a in r.assumptions)
    assert any(f.resource == "Pod/shop/p" for f in r.findings if f.rule_id != "KN-V001")


@pytest.mark.parametrize(
    "doc",
    [
        "7",
        "[1, 2]",
        "metadata: {name: p}",
        "kind: ~\nmetadata: {name: p}",
        "kind: ''\nmetadata: {name: p}",
        "kind: pod\nmetadata: {name: p}",
        "kind: ' Pod'\nmetadata: {name: p}",
        "kind: [Pod]\nmetadata: {name: p}",
    ],
    ids=["int", "list", "no-kind", "kind-null", "kind-empty", "kind-lowercase", "kind-padded", "kind-list"],
)
def test_a_document_no_rule_can_read_is_named_as_not_audited(doc: str) -> None:
    r = analyze("apiVersion: v1\n" + doc if doc[0].isalpha() else doc, platform="kubernetes", version="1.33")
    assert any("NOT audited" in a and "document 1" in a for a in r.assumptions), r.assumptions


_SVC = """
---
apiVersion: v1
kind: Service
metadata: {name: web, namespace: shop}
spec: {selector: {app: web}, ports: [{port: 80}]}
"""


@pytest.mark.parametrize(
    "rule,text",
    [
        (
            "KN-C014",
            _HPA.replace("scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: web}", "scaleTargetRef: x"),
        ),
        ("KN-C014", _HPA.replace("kind: Deployment, name: web}", "kind: Deployment, name: .inf}")),
        (
            "KN-C014",
            _HPA.replace(
                "scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: web}", "scaleTargetRef: [null]"
            ),
        ),
        ("KN-C009", _PDB_BUNDLE.replace("metadata: {labels: {app: web}}", "metadata: {labels: {app: .inf}}")),
        ("KN-C009", _PDB_BUNDLE.replace("spec: {containers: [{name: web, image: nginx}]}", "spec: [[1]]")),
        ("KN-V012", _PDB_BUNDLE.replace("spec: {containers: [{name: web, image: nginx}]}", "spec: .nan") + _SVC),
        ("KN-V023", _PDB_BUNDLE.replace("containers: [{name: web, image: nginx}]", "containers: x") + _SVC),
    ],
    ids=[
        "hpa-target-string",
        "hpa-target-name-inf",
        "hpa-target-list",
        "template-label-inf",
        "pod-spec-list",
        "pod-spec-nan",
        "containers-string",
    ],
)
def test_a_partner_whose_pod_template_or_target_cannot_be_read_leaves_the_rule_undecided(rule: str, text: str) -> None:
    """The third-review rerun of the fuzz: findings that vanished from a sibling when the HPA's target or the
    workload's pod template had the wrong type, with no word that anything was not read."""
    r = analyze(text, platform="kubernetes", version="1.33")
    assert any(rule in a and "could not be read" in a for a in r.assumptions), (rule, r.assumptions)


def test_a_name_that_is_not_a_string_is_a_missing_name() -> None:
    r = analyze("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: 7}\n", platform="kubernetes", version="1.33")
    assert any(f.rule_id == "KN-V001" and "string" in f.message for f in r.findings)
