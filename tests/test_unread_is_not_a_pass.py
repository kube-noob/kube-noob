"""What kube-noob could not read is never a pass, and what it did read is not called unread (G276, third review).

Each test names the review item it pins. The rule throughout: an object or a read that was refused (a field of the
wrong shape, a 403, a timeout) makes the answer incomplete and says so; an absence that is normal (a CRD a cluster
does not serve, a built-in role a bundle does not carry) is reported but does not fail a gate on its own.
"""

from __future__ import annotations

import io
import json
import random
import re
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
        return {"kind": "List", "items": []}  # a complete, empty list, as the API server writes one (G279)


@pytest.mark.parametrize(
    "resource,message,gates",
    [
        # The backend's own words for THIS resource type: an absence (no KServe, no Ray), listed, not gated.
        ("inferenceservices", 'error: the server doesn\'t have a resource type "inferenceservices"', False),
        ("rayclusters", "Not found: GET /apis/ray.io/v1/rayclusters", False),
        # An aggregated group (OpenShift's Routes on plain Kubernetes, where kind runs the e2e gate): the verdict
        # keeps it not determined (G279), and the gate does not fail on it, because the cluster answered.
        ("routes", 'error: the server doesn\'t have a resource type "routes"', False),
        # Not the words for this resource: a 404 with no resource named, or naming another, is a read that failed
        # (G279), and a gate fails on it.
        ("inferenceservices", "the server could not find the requested resource (inferenceservices)", True),
        ("inferenceservices", 'error: the server doesn\'t have a resource type "routes"', True),
        ("deployments", "Forbidden by RBAC: GET /api/v1/pods. Grant the sidecar's ServiceAccount read access", True),
        ("deployments", "kubectl timed out after 30s", True),
        ("deployments", "API error 500 for GET /apis/apps/v1/deployments: boom", True),
    ],
)
def test_a_live_read_gates_when_the_cluster_refused_it_not_when_it_does_not_serve_it(
    resource: str, message: str, gates: bool
) -> None:
    out = ap.scan(ap.collect_live(_Backend({resource: message}), []))
    assert any(n.startswith(resource) for n in out["notRead"])
    assert bool(out["refused"]) is gates, out["refused"]


def test_a_live_answer_that_is_not_a_list_is_a_refused_read() -> None:
    """G279's structural check: a response with no kind, items that are not objects, or one page of several is a
    failed read; under G276 it is a refusal, because the cluster did not answer the list that was asked for."""
    for body in (
        {"items": []},
        {"kind": "List", "items": [7]},
        {"kind": "List", "items": [], "metadata": {"continue": "x"}},
    ):

        class Odd(_Backend):
            def get(self, resource: str, name: str | None = None, namespace: str | None = None, **_: Any) -> Any:
                return body if resource == "pods" else {"kind": "List", "items": []}  # noqa: B023

        out = ap.scan(ap.collect_live(Odd({}), []))
        assert any(n.startswith("pods") for n in out["refused"]), (body, out["notRead"])


def test_a_live_answer_that_is_not_json_is_a_refused_read() -> None:
    class NotJson(_Backend):
        def get(self, resource: str, name: str | None = None, namespace: str | None = None, **_: Any) -> Any:
            if resource == "pods":
                raise ValueError("Expecting value: line 1 column 1 (char 0)")
            return {"kind": "List", "items": []}

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


# --- the one rule: which notRead entries a gate fails on, over every site that writes one ------------------------

_WEB = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec: {serviceAccountName: sa, containers: [{name: web, image: nginx}]}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: sa, namespace: shop}
---
apiVersion: v1
kind: Service
metadata: {name: web, namespace: shop}
spec: {type: LoadBalancer, selector: {app: web}, ports: [{port: 80}]}
"""
_RBAC = "apiVersion: rbac.authorization.k8s.io/v1"
_SUBJECTS = "subjects: [{kind: ServiceAccount, name: sa, namespace: shop}]"
_ROLE_REF = "roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: r}"
_INGRESS = (
    "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata: {name: i, namespace: shop}\n"
    "spec: {rules: [{host: a, http: {paths: [{path: /, backend: {service: {name: gone, port: {number: 80}}}}]}}]}\n"
)


def _bound(role: str, rules: str = "rules: [{apiGroups: [''], resources: [secrets], verbs: [get]}]") -> str:
    return (
        f"{_WEB}---\n{_RBAC}\nkind: RoleBinding\nmetadata: {{name: rb, namespace: shop}}\n"
        f"{_ROLE_REF.replace('name: r', f'name: {role}')}\n{_SUBJECTS}\n"
        f"---\n{_RBAC}\nkind: Role\nmetadata: {{name: r, namespace: shop}}\n{rules}\n"
    )


_RB_TO_R = _bound("r")


def _docs(text: str) -> list[Any]:
    return list(yaml.safe_load_all(text))


def _inv(text: str) -> ap.Inventory:
    return ap.Inventory.from_documents(_docs(text))


def _scanned(text: str) -> ap.Inventory:
    inv = _inv(text)
    ap.scan(inv)  # RBAC is read as the accounts come up, so the inventory is complete only after a scan
    return inv


class _Live(_Backend):
    def __init__(self, failures: dict[str, Any]) -> None:
        super().__init__({})
        self.fail = failures

    def get(self, resource: str, name: str | None = None, namespace: str | None = None, **_: Any) -> Any:
        if resource in self.fail:
            f = self.fail[resource]
            if isinstance(f, BaseException):
                raise f
            return f
        return {"kind": "List", "items": []}


def _live(resource: str, failure: Any) -> ap.Inventory:
    return ap.collect_live(_Live({resource: failure}), [])


#: One row per site in attack_paths.py that records something as not read: (label, how the input is built, the words
#: the entry carries, the cause the site names). The rule is written once, in `Inventory.unread`: a `refused` cause
#: -- a field of the wrong shape, a read the cluster forbade or did not answer, a response that is not a list -- is
#: what `posture scan --fail-above` fails on; absent, unmodelled, unplaced and ambiguous are reported and fail a gate
#: only with --require-complete (G276 on G273 and G279). The source check below holds that every site names one of
#: these causes and that every cause named has a row here.
NOT_READ_SITES: list[tuple[str, Any, str, str]] = [
    # Inventory.add
    (
        "unmodelled routing object (Contour HTTPProxy)",
        lambda: _inv(
            _WEB + "---\napiVersion: projectcontour.io/v1\nkind: HTTPProxy\nmetadata: {name: p, namespace: shop}\n"
        ),
        "a routing object this scan does not read",
        "unmodelled",
    ),
    (
        "workload CRD whose spec is not a mapping (Rollout)",
        lambda: _inv(
            "apiVersion: argoproj.io/v1alpha1\nkind: Rollout\nmetadata: {name: r, namespace: shop}\nspec: 7\n"
        ),
        "spec is not a mapping",
        "refused",
    ),
    (
        "workload CRD this scan has no reader for (Rollout with pods)",
        lambda: _inv(
            "apiVersion: argoproj.io/v1alpha1\nkind: Rollout\nmetadata: {name: r, namespace: shop}\n"
            "spec: {template: {spec: {containers: [{name: c, image: nginx}]}}}\n"
        ),
        "carries a pod spec kube-noob has no reader for",
        "unmodelled",
    ),
    (
        "a Route of another group (Knative)",
        lambda: _inv(
            _WEB + "---\napiVersion: serving.knative.dev/v1\nkind: Route\nmetadata: {name: k, namespace: shop}\n"
        ),
        "apiVersion serving.knative.dev/v1 is not route.openshift.io",
        "unmodelled",
    ),
    (
        "legacy OpenShift binding the server would refuse (roleRef without a name)",
        lambda: _inv(
            _WEB + "---\napiVersion: authorization.openshift.io/v1\nkind: RoleBinding\n"
            "metadata: {name: legacy, namespace: shop}\nroleRef: {}\nsubjects: []\n"
        ),
        "roleRef does not name a role",
        "refused",
    ),
    (
        "a CRD called Role in another group",
        lambda: _inv(
            _WEB + "---\napiVersion: example.com/v1\nkind: Role\nmetadata: {name: r, namespace: shop}\nrules: 7\n"
        ),
        "apiVersion example.com/v1 is not rbac.authorization.k8s.io",
        "unmodelled",
    ),
    (
        "a Service whose spec is not a mapping",
        lambda: _inv("apiVersion: v1\nkind: Service\nmetadata: {name: web, namespace: shop}\nspec: 7\n"),
        "spec is not a mapping",
        "refused",
    ),
    (
        "a Deployment whose metadata is not a mapping",
        lambda: _inv(
            "apiVersion: apps/v1\nkind: Deployment\nmetadata: 7\n"
            "spec: {template: {spec: {containers: [{name: c, image: nginx}]}}}\n"
        ),
        "metadata is not a mapping",
        "refused",
    ),
    # Inventory.from_documents
    (
        "a List whose items is not a list",
        lambda: ap.Inventory.from_documents([{"apiVersion": "v1", "kind": "RoleBindingList", "items": 7}]),
        "items is not a list",
        "refused",
    ),
    (
        "an RBAC List holding an item that is not an object",
        lambda: ap.Inventory.from_documents([{"apiVersion": "v1", "kind": "RoleList", "items": [7]}]),
        "not an object",
        "refused",
    ),
    # _grants, through scan()
    (
        "a binding whose subjects is not a list",
        lambda: _scanned(_RB_TO_R.replace(_SUBJECTS, "subjects: 7")),
        "subjects is not a list",
        "refused",
    ),
    (
        "a binding with a subject this scan cannot read",
        lambda: _scanned(_RB_TO_R.replace(_SUBJECTS, "subjects: [sa]")),
        "not a subject this scan can read",
        "refused",
    ),
    (
        "a binding whose roleRef does not name a role",
        lambda: _scanned(_RB_TO_R.replace(_ROLE_REF, "roleRef: {}")),
        "roleRef does not name a role",
        "refused",
    ),
    (
        "a bound rule whose verbs is not a list",
        lambda: _scanned(_bound("r", "rules: [{apiGroups: [''], resources: [secrets], verbs: '*'}]")),
        "verbs is not a list",
        "refused",
    ),
    (
        "a bound Role whose rules is not a list",
        lambda: _scanned(_bound("r", "rules: 7")),
        "rules is a int, not a list",
        "refused",
    ),
    (
        "a bound name two different Roles carry",
        lambda: _scanned(
            _RB_TO_R + f"---\n{_RBAC}\nkind: Role\nmetadata: {{name: r, namespace: shop}}\n"
            "rules: [{apiGroups: [''], resources: [pods], verbs: [get]}]\n"
        ),
        "2 different objects named Role/shop/r",
        "refused",
    ),
    (
        "a bound Role with no namespace (pass -n)",
        lambda: _scanned(_RB_TO_R.replace("metadata: {name: r, namespace: shop}", "metadata: {name: r}")),
        "has no namespace",
        "unplaced",
    ),
    (
        "a bound Role not in the input",
        lambda: _scanned(_bound("other")),
        "Role/shop/other (bound by RoleBinding/shop/rb) is not in the input",
        "absent",
    ),
    (
        "a bound aggregated ClusterRole no ClusterRole in the input feeds",
        lambda: _scanned(
            _WEB + f"---\n{_RBAC}\nkind: ClusterRoleBinding\nmetadata: {{name: crb}}\n"
            f"{_ROLE_REF.replace('kind: Role, name: r', 'kind: ClusterRole, name: agg')}\n{_SUBJECTS}\n"
            f"---\n{_RBAC}\nkind: ClusterRole\nmetadata: {{name: agg}}\n"
            "aggregationRule: {clusterRoleSelectors: [{matchLabels: {x: y}}]}\nrules: []\n"
        ),
        "aggregates ClusterRoles by label and none in the input matches",
        "ambiguous",
    ),
    # scan(): what dangling() and duplicate_notes() add -- not through `unread`, so classified where they are built
    (
        "an Ingress to a Service the files do not carry",
        lambda: _scanned(_INGRESS),
        "routes to Service shop/gone, which is not in the input",
        "absent",
    ),
    (
        "an exposure field that is not the shape the API requires",
        lambda: _scanned(_WEB.replace("selector: {app: web}", "selector: web")),
        "spec.selector is not a mapping",
        "refused",
    ),
    (
        "a name two different Services carry",
        lambda: _scanned(
            _WEB
            + "---\napiVersion: v1\nkind: Service\nmetadata: {name: web, namespace: shop}\nspec: {selector: {app: x}}\n"
        ),
        "2 different objects named Service/shop/web",
        "ambiguous",
    ),
    # collect_live
    (
        "a live list the cluster says it does not serve",
        lambda: _live(
            "rayclusters", ClusterAccessError('error: the server doesn\'t have a resource type "rayclusters"')
        ),
        "rayclusters: ",
        "absent",
    ),
    (
        "a live list the cluster forbade",
        lambda: _live("pods", ClusterAccessError("Forbidden by RBAC: GET /api/v1/pods")),
        "pods: Forbidden",
        "refused",
    ),
    (
        "a live list that is not a list of what was asked (no kind)",
        lambda: _live("pods", {"items": []}),
        "pods: the response has no kind",
        "refused",
    ),
    (
        "a live answer that is not JSON",
        lambda: _live("pods", ValueError("Expecting value")),
        "pods: the answer was not JSON",
        "refused",
    ),
]


@pytest.mark.parametrize(("label", "build", "words", "cause"), NOT_READ_SITES, ids=[r[0] for r in NOT_READ_SITES])
def test_each_not_read_site_gates_exactly_when_the_rule_says(label: str, build: Any, words: str, cause: str) -> None:
    from kube_noob import blast_radius as br

    gates = cause in ap.GATED_CAUSES
    inv = build()
    out = ap.scan(inv)
    assert [n for n in out["notRead"] if words in n], (label, out["notRead"])
    assert bool([n for n in out["refused"] if words in n]) is gates, (label, out["refused"], out["notRead"])
    # The same two lists reach the blast radius document: what the scan refuses, reach refuses (G276).
    workloads = inv.of(*ap.WORKLOAD_KINDS)
    if workloads:
        first = workloads[0]
        anchor = f"{first.get('kind')}/{ap.object_name(first)}"
        try:
            g = br.reach(inv, anchor, ap.object_namespace(first), live=inv.live)
        except br.ReachError:
            return
        assert bool([n for n in g["refused"] if words in n]) is gates, (label, g["refused"])
        assert [n for n in g["notRead"] if words in n], (label, g["notRead"])


def _unread_calls(src: str) -> list[str]:
    """The last argument of every `.unread(` call in `src`, as written."""
    out = []
    for m in re.finditer(r"\.unread\(", src):
        depth, i = 1, m.end()
        while depth:
            depth += {"(": 1, ")": -1}.get(src[i], 0)
            i += 1
        call = src[m.end() : i - 1]
        depth, args, start = 0, [], 0
        for j, ch in enumerate(call):
            depth += {"(": 1, "[": 1, "{": 1, ")": -1, "]": -1, "}": -1}.get(ch, 0)
            if ch == "," and depth == 0:
                args.append(call[start:j].strip())
                start = j + 1
        args.append(call[start:].strip())
        out.append([a for a in args if a][-1])  # a multi-line call ends with a trailing comma
    return out


def test_every_not_read_site_goes_through_the_rule() -> None:
    """`not_read` and `refused` are appended in exactly one place, and every caller names its cause from the closed
    list, as a literal: a site that wrote to a list directly, or passed a cause computed elsewhere, could drift from
    the table above without a test noticing."""
    src = Path(ap.__file__).read_text(encoding="utf-8")
    helper = src.index("    def unread(self, entry: str, cause: UnreadCause) -> None:")
    helper_end = src.index("    def refuse(self, entry: str) -> None:")
    body = src[helper:helper_end]
    assert src.count("not_read.append(") == 1 and "self.not_read.append(entry)" in body
    assert src.count("refused.append(") == 1 and "self.refused.append(entry)" in body
    literal = re.compile(r'"([a-z]+)"\Z')
    conditional = re.compile(r'"absent" if says_not_served\(resource, exc\) else "refused"\Z')
    named: set[str] = set()
    for arg in _unread_calls(src):
        if arg == "cause":  # `refuse` handing its fixed cause on
            continue
        if conditional.match(arg):
            named |= {"absent", "refused"}
            continue
        m = literal.match(arg)
        assert m and m.group(1) in ap.UNREAD_CAUSES, arg
        named.add(m.group(1))
    assert frozenset({"refused"}) == ap.GATED_CAUSES
    assert named == set(ap.UNREAD_CAUSES), named
    assert {cause for _, _, _, cause in NOT_READ_SITES} == set(ap.UNREAD_CAUSES)
