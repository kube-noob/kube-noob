"""V3 blast radius (G273): what one workload reaches if compromised, as a bounded JSON graph and a Mermaid diagram.

The graph is built from the attack-path scan's own reach (one implementation of the view, not two), and what the
input cannot show is part of the answer: a leg whose ServiceAccount, Role or binding is not in it is "not
determined", never an empty list, and a reference that matches nothing is an error, never "no blast radius".
"""

from __future__ import annotations

import copy
import json
import random
import re
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import yaml

from kube_noob import attack_paths as ap
from kube_noob import blast_radius as br
from kube_noob import toolkit as tk
from kube_noob.cli import main
from kube_noob.config import load_settings
from tests.test_attack_paths import SA, SEEDED, FakeBackend, _binding, _exposed, _role

SEEDED_DOCS: list[dict[str, Any]] = [d for d in yaml.safe_load_all(SEEDED.read_text(encoding="utf-8")) if d]
READ_SECRETS = "read Secrets (credentials, tokens of other ServiceAccounts)"


def _reach(docs: list[dict[str, Any]], ref: str, namespace: str | None = None, **kw: Any) -> dict[str, Any]:
    return br.reach(ap.Inventory.from_documents(copy.deepcopy(docs)), ref, namespace, **kw)


def _node(graph: dict[str, Any], node_id: str) -> dict[str, Any]:
    return next(n for n in graph["nodes"] if n["id"] == node_id)


def _edges(graph: dict[str, Any], kind: str | None = None) -> list[dict[str, Any]]:
    return [e for e in graph["edges"] if kind is None or e["kind"] == kind]


def _undetermined(graph: dict[str, Any]) -> list[str]:
    return [n["reason"] for n in graph["notDetermined"]]


def _sa(name: str = "app-sa", ns: str = "shop") -> dict[str, Any]:
    return {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": name, "namespace": ns}}


SECRET_READER = [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}]


# --- the anchor ----------------------------------------------------------------------------------------------------


def test_a_workload_reaches_its_account_the_binding_and_the_secrets_with_the_scans_own_evidence() -> None:
    graph = _reach(SEEDED_DOCS, "deployment/web", "shop")
    assert graph["anchor"]["resolved"] == ["Deployment/shop/web"]
    token = _edges(graph, "uses token of")
    assert [(e["from"], e["to"]) for e in token] == [("workload:Deployment/shop/web", "sa:shop/web-sa")]
    assert token[0]["evidence"] == {
        "object": "Deployment/shop/web",
        "field": "spec.template.spec.serviceAccountName",
        "text": "spec.serviceAccountName=web-sa; token mounted (automount not turned off)",
    }
    bound = _edges(graph, "bound by")
    assert [(e["from"], e["to"]) for e in bound] == [("sa:shop/web-sa", "binding:RoleBinding/shop/web-secrets")]
    assert bound[0]["evidence"]["field"] == "subjects[0]"
    # The capability edge carries the evidence line `posture scan` prints for the same step, byte for byte.
    scan = ap.scan_manifests(SEEDED.read_text(encoding="utf-8"))
    printed = scan["paths"][0]["steps"][-1]["evidence"]
    grants = [e for e in _edges(graph, "grants") if READ_SECRETS in e["to"]]
    assert grants and grants[0]["evidence"]["text"] == printed
    assert grants[0]["evidence"]["object"] == "Role/shop/secret-reader" and grants[0]["evidence"]["field"] == "rules[0]"
    can_read = _edges(graph, "can read")
    assert [e["to"] for e in can_read] == ["secrets:namespace/shop"]
    assert _node(graph, "secrets:namespace/shop")["label"] == "every Secret in namespace shop"
    assert ("capability:namespace shop:" + READ_SECRETS, "scope:namespace/shop") in {
        (e["from"], e["to"]) for e in _edges(graph, "reaches")
    }
    # The exposed path is reported as the scan ranks it, and the leg list says what was found and what was not.
    assert graph["paths"][0]["summary"] == scan["paths"][0]["summary"]
    legs = {(leg["leg"], leg["status"]) for leg in graph["legs"]}
    assert legs == {
        ("exposure", "reached"),
        ("token", "reached"),
        ("rbac", "reached"),
        ("secrets", "reached"),
        ("node", "none"),
    }
    assert graph["notDetermined"] == [] and graph["truncated"] is None
    # Files cannot show what they leave out: complete only when the caller asserts they are the whole bundle.
    assert graph["complete"] is False and "--whole-bundle" in graph["completeness"]
    assert _reach(SEEDED_DOCS, "deployment/web", "shop", whole_bundle=True)["complete"] is True
    assert "hunter2" not in json.dumps(graph), "Secret contents are never read"


def test_the_full_reference_the_scan_prints_is_accepted_and_names_must_agree() -> None:
    graph = _reach(SEEDED_DOCS, "Deployment/shop/web")
    assert graph["anchor"]["resolved"] == ["Deployment/shop/web"]
    with pytest.raises(br.ReachError, match="namespace"):
        _reach(SEEDED_DOCS, "Deployment/shop/web", "ops")


def test_a_pod_in_the_input_is_scored_on_its_own_spec_with_its_owner_chain_as_context() -> None:
    """Defect 2: the Pod is what runs. An injected privileged sidecar, hostNetwork and another ServiceAccount on the
    Pod were answered with the Deployment's benign template -- `node none`, `token none`, complete."""
    rs = {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {
            "name": "web-5d8f",
            "namespace": "shop",
            "ownerReferences": [{"kind": "Deployment", "name": "web", "controller": True}],
        },
        "spec": {"template": {"metadata": {"labels": {"app": "web"}}, "spec": {"containers": [{"name": "w"}]}}},
    }
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "web-5d8f-x7k2q",
            "namespace": "shop",
            # pod-template-hash is the ReplicaSet controller's own label: not a difference worth stating (N12).
            "labels": {"app": "web", "pod-template-hash": "5d8f"},
            "ownerReferences": [{"kind": "ReplicaSet", "name": "web-5d8f", "controller": True}],
        },
        "spec": {
            "serviceAccountName": "web-sa",
            "containers": [{"name": "w", "image": "registry.example.com/web:1.0.0"}],
        },
    }
    graph = _reach([*SEEDED_DOCS, rs, pod], "pod/web-5d8f-x7k2q", "shop")
    assert graph["anchor"]["resolved"] == ["Pod/shop/web-5d8f-x7k2q"]
    assert graph["anchor"]["via"] == ["Pod/shop/web-5d8f-x7k2q", "ReplicaSet/shop/web-5d8f", "Deployment/shop/web"]
    assert graph["anchor"]["ownerDiffers"] == [], "same account, same escape, same images: nothing to say"
    # The shape the review found: the running Pod is not its template.
    hostile = copy.deepcopy(pod)
    hostile["spec"] = {
        "serviceAccountName": "batch-sa",
        "hostNetwork": True,
        "containers": [
            {"name": "w", "image": "registry.example.com/web:1.0.0"},
            {"name": "injected", "image": "j", "securityContext": {"privileged": True}},
        ],
    }
    got = _reach([*SEEDED_DOCS, rs, hostile], "pod/web-5d8f-x7k2q", "shop")
    legs = {x["leg"]: x for x in got["legs"]}
    assert (
        legs["node"]["status"] == "reached"
        and "container injected securityContext.privileged=true" in legs["node"]["detail"]
    )
    assert "spec.serviceAccountName=batch-sa" in legs["token"]["detail"]
    differs = " | ".join(got["anchor"]["ownerDiffers"])
    assert "the Pod batch-sa, Deployment/shop/web web-sa" in differs and "node escape" in differs
    assert "differs from its owner" in got["summary"] and any("differs from its owner" in x for x in got["limitations"])
    assert "the Pod differs from its owner" in br.render_text(got)
    # An owner that is not in the input is not invented.
    orphan = _reach([*SEEDED_DOCS, pod], "pod/web-5d8f-x7k2q", "shop")
    assert orphan["anchor"]["resolved"] == ["Pod/shop/web-5d8f-x7k2q"] and orphan["anchor"]["via"] == [
        "Pod/shop/web-5d8f-x7k2q"
    ]
    # The object named is the object scored (N5): a ReplicaSet is scored on its own template, its Deployment is
    # context. (Round 2 resolved it to the Deployment, which hid a privileged ReplicaSet under a benign one.)
    named_rs = _reach([*SEEDED_DOCS, rs], "rs/web-5d8f", "shop")
    assert named_rs["anchor"]["resolved"] == ["ReplicaSet/shop/web-5d8f"]
    assert named_rs["anchor"]["via"] == ["ReplicaSet/shop/web-5d8f", "Deployment/shop/web"]
    # An owner duplicated in the input (the review's a1.yaml): the Pod is still scored, the comparison is not made,
    # and a ReplicaSet whose owner is ambiguous is scored too, with the ambiguity said.
    twin = next(copy.deepcopy(d) for d in SEEDED_DOCS if d["kind"] == "Deployment" and d["metadata"]["name"] == "web")
    twin["spec"]["template"]["spec"]["hostPID"] = True
    dup = _reach([*SEEDED_DOCS, twin, rs, hostile], "pod/web-5d8f-x7k2q", "shop")
    assert dup["anchor"]["via"][-1] == "Deployment/shop/web (ambiguous)"
    # The ReplicaSet is unambiguous and is the Pod's direct owner, so the Pod is compared with it; the Deployment
    # level is the ambiguity, and is said.
    assert dup["anchor"]["ownerDiffers"][-1] == (
        "2 different Deployment objects named shop/web are in the input, so the owner chain stops below them "
        "and the Pod is not compared with either"
    )
    assert any("ReplicaSet/shop/web-5d8f" in d for d in dup["anchor"]["ownerDiffers"][:-1])
    amb = _reach([*SEEDED_DOCS, twin, rs], "rs/web-5d8f", "shop")
    assert amb["anchor"]["resolved"] == ["ReplicaSet/shop/web-5d8f"]
    assert amb["anchor"]["ownerDiffers"] == [
        "2 different Deployment objects named shop/web are in the input, so the owner chain stops below them "
        "and the ReplicaSet is not compared with either"
    ]


def test_a_reference_that_matches_nothing_is_an_error_and_not_an_empty_blast_radius(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(br.ReachError, match="no Deployment named nope in namespace shop"):
        _reach(SEEDED_DOCS, "deployment/nope", "shop")
    # A Pod name from `kubectl get pods` against manifests that only carry its Deployment: say which object to name,
    # do not guess it.
    with pytest.raises(br.ReachError, match="Deployment/shop/web"):
        _reach(SEEDED_DOCS, "pod/web-5d8f-x7k2q", "shop")
    with pytest.raises(br.ReachError, match="not a workload"):
        _reach(SEEDED_DOCS, "service/web", "shop")
    for bad in ("", "a/b/c/d", "deployment/", "deploy ment/x", "deployment/x\n", "x" * 600):
        with pytest.raises(br.ReachError):
            _reach(SEEDED_DOCS, bad, "shop")
    code = main(["posture", "reach", "deployment/nope", "-n", "shop", "-f", str(SEEDED)])
    captured = capsys.readouterr()
    assert code == 2 and captured.out == "" and "no Deployment named nope" in captured.err


# --- the honest half: what the input cannot show -------------------------------------------------------------------


def test_a_service_account_missing_from_the_input_is_not_determined() -> None:
    docs = _exposed("app", serviceAccountName="app-sa") + [
        _role("Role", "reader", SECRET_READER),
        _binding("RoleBinding", "reader", "Role", "reader", [SA]),
        _binding("ClusterRoleBinding", "unrelated", "ClusterRole", "view", [{"kind": "User", "name": "x"}]),
    ]
    graph = _reach(docs, "deployment/app", "shop")
    reasons = _undetermined(graph)
    assert any(
        "ServiceAccount shop/app-sa is not in the input" in r and "automountServiceAccountToken" in r for r in reasons
    )
    assert graph["complete"] is False
    # What the bindings do show is still reported, on the assumption the scan makes (the token is mounted).
    assert any(e["to"] == "secrets:namespace/shop" for e in _edges(graph, "can read"))
    leg = next(leg for leg in graph["legs"] if leg["leg"] == "token")
    assert leg["status"] == "not determined"
    # With the account in the input the leg is determined.
    assert not any("ServiceAccount" in r for r in _undetermined(_reach([*docs, _sa()], "deployment/app", "shop")))


def test_a_bound_role_missing_from_the_input_is_not_determined_not_an_empty_list() -> None:
    docs = [
        *_exposed("app", serviceAccountName="app-sa"),
        _sa(),
        _binding("RoleBinding", "ghost", "Role", "ghost-role", [SA]),
        _binding("ClusterRoleBinding", "unrelated", "ClusterRole", "view", [{"kind": "User", "name": "x"}]),
    ]
    graph = _reach(docs, "deployment/app", "shop")
    nd = graph["notDetermined"]
    assert [n["reason"] for n in nd] == ["Role/shop/ghost-role is not in the input"]
    edge = next(e for e in _edges(graph, "not determined"))
    assert edge["from"] == "binding:RoleBinding/shop/ghost" and edge["to"] == nd[0]["id"]
    rbac = next(leg for leg in graph["legs"] if leg["leg"] == "rbac")
    assert rbac["status"] == "not determined"


def test_a_bundle_without_bindings_does_not_read_as_an_account_without_rights() -> None:
    docs = [*_exposed("app", serviceAccountName="app-sa"), _sa()]
    graph = _reach(docs, "deployment/app", "shop")
    reasons = " | ".join(_undetermined(graph))
    assert "no RoleBinding is in the input" in reasons and "no ClusterRoleBinding is in the input" in reasons
    assert "system:authenticated" in reasons, "the group subjects are why a missing ClusterRoleBinding matters"
    assert next(leg for leg in graph["legs"] if leg["leg"] == "rbac")["status"] == "not determined"
    # A token that is not mounted needs no RBAC answer: the leg is "none", determined, with its field.
    off = _reach(
        [*_exposed("app", serviceAccountName="app-sa", automountServiceAccountToken=False), _sa()],
        "deployment/app",
        "shop",
        whole_bundle=True,
    )
    assert off["notDetermined"] == [] and off["complete"] is True
    assert {(leg["leg"], leg["status"]) for leg in off["legs"]} >= {("token", "none"), ("rbac", "none")}


def test_an_aggregated_cluster_role_is_not_determined_beyond_what_the_input_carries() -> None:
    agg = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {"name": "agg"},
        "aggregationRule": {"clusterRoleSelectors": [{"matchLabels": {"team": "x"}}]},
        "rules": [],
    }
    base = [
        *_exposed("app", serviceAccountName="app-sa"),
        _sa(),
        agg,
        _binding("RoleBinding", "agg", "ClusterRole", "agg", [SA]),
        _binding("ClusterRoleBinding", "unrelated", "ClusterRole", "view", [{"kind": "User", "name": "x"}]),
    ]
    empty = _reach(base, "deployment/app", "shop")
    assert any("ClusterRole/agg aggregates" in r and "none in the input matches" in r for r in _undetermined(empty))
    # The scan says so too: an aggregation it could not fill is not read, not "no rights".
    assert any("ClusterRole/agg" in n for n in ap.scan(ap.Inventory.from_documents(copy.deepcopy(base)))["notRead"])
    part = _role("ClusterRole", "part", SECRET_READER)
    part["metadata"]["labels"] = {"team": "x"}
    some = _reach([*base, part], "deployment/app", "shop")
    assert any("1 in the input counted (ClusterRole/part)" in r for r in _undetermined(some))
    assert any(e["to"] == "secrets:namespace/shop" for e in _edges(some, "can read"))


def test_group_subjects_reach_the_account_with_the_subject_as_evidence() -> None:
    docs = [
        *_exposed("app", serviceAccountName="app-sa"),
        _sa(),
        _role("ClusterRole", "read-all", SECRET_READER),
        _binding(
            "ClusterRoleBinding",
            "everyone",
            "ClusterRole",
            "read-all",
            [{"kind": "Group", "name": "system:authenticated", "apiGroup": "rbac.authorization.k8s.io"}],
        ),
        _binding(
            "RoleBinding",
            "ns-sas",
            "ClusterRole",
            "read-all",
            [{"kind": "Group", "name": "system:serviceaccounts:shop"}],
            ns="billing",
        ),
        _binding(
            "RoleBinding",
            "other-ns",
            "ClusterRole",
            "read-all",
            [{"kind": "Group", "name": "system:serviceaccounts:ops"}],
            ns="billing",
        ),
    ]
    graph = _reach(docs, "deployment/app", "shop")
    bound = {e["to"]: e["evidence"]["text"] for e in _edges(graph, "bound by")}
    assert bound["binding:ClusterRoleBinding/everyone"] == "subject Group system:authenticated"
    assert bound["binding:RoleBinding/billing/ns-sas"] == "subject Group system:serviceaccounts:shop"
    assert "binding:RoleBinding/billing/other-ns" not in bound
    targets = {e["to"] for e in _edges(graph, "can read")}
    assert targets == {"secrets:cluster", "secrets:namespace/billing"}
    scopes = {e["to"] for e in _edges(graph, "reaches")}
    assert {"scope:cluster", "scope:namespace/billing"} <= scopes, "other namespaces and cluster-wide reach"
    # The scan reads the same grants: a RoleBinding in another namespace reaches the account through a group, and
    # the scan used to skip every such binding that had no ServiceAccount subject.
    scan = ap.scan(ap.Inventory.from_documents(copy.deepcopy(docs)))
    assert any(
        "RoleBinding/billing/ns-sas (subject Group system:serviceaccounts:shop)" in s["evidence"]
        for p in scan["paths"]
        for s in p["steps"]
    )
    users = [
        *docs[:-2],
        _binding(
            "RoleBinding",
            "as-user",
            "ClusterRole",
            "read-all",
            [{"kind": "User", "name": "system:serviceaccount:shop:app-sa"}],
            ns="billing",
        ),
    ]
    assert "binding:RoleBinding/billing/as-user" in {
        e["to"] for e in _edges(_reach(users, "deployment/app", "shop"), "bound by")
    }


def test_named_secrets_are_listed_by_name_and_never_read() -> None:
    rule = [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"], "resourceNames": ["db", "tls"]}]
    docs = [
        *_exposed("app", serviceAccountName="app-sa"),
        _sa(),
        _role("Role", "named", rule),
        _binding("RoleBinding", "named", "Role", "named", [SA]),
        _binding("ClusterRoleBinding", "unrelated", "ClusterRole", "view", [{"kind": "User", "name": "x"}]),
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "db", "namespace": "shop"},
            "data": {"k": "aHVudGVy"},
        },
    ]
    graph = _reach(docs, "deployment/app", "shop")
    assert sorted(e["to"] for e in _edges(graph, "can read")) == ["secret:shop/db", "secret:shop/tls"]
    assert _node(graph, "secret:shop/db")["label"] == "Secret shop/db"
    assert graph["droppedUnread"] == 1 and "aHVudGVy" not in json.dumps(graph)


def test_node_escape_legs_name_the_field_that_proves_them() -> None:
    docs = [
        *_exposed(
            "app",
            automountServiceAccountToken=False,
            hostPID=True,
            volumes=[{"name": "sock", "hostPath": {"path": "/var/run/docker.sock"}}],
            containers=[{"name": "c", "image": "x:1", "securityContext": {"privileged": True}}],
        ),
    ]
    graph = _reach(docs, "deployment/app", "shop")
    fields = {e["evidence"]["field"] for e in _edges(graph, "escapes through")}
    assert fields == {
        "spec.template.spec.containers[0].securityContext.privileged",
        "spec.template.spec.volumes[0].hostPath.path",
        "spec.template.spec.hostPID",
    }
    assert {e["to"] for e in _edges(graph, "reaches")} == {"scope:node"}
    assert next(leg for leg in graph["legs"] if leg["leg"] == "node")["status"] == "reached"


def test_an_unexposed_workload_still_has_a_blast_radius() -> None:
    graph = _reach(SEEDED_DOCS, "cronjob/batch", "ops")
    assert graph["paths"] == [] and graph["exposure"] == []
    # Read from files the exposure leg is open, and the summary says so rather than "not reached" (item 8).
    assert "exposure not determined" in graph["summary"]
    assert "not reached by any exposure" in _reach(SEEDED_DOCS, "cronjob/batch", "ops", whole_bundle=True)["summary"]
    assert any(e["to"] == "scope:cluster" for e in _edges(graph, "reaches"))
    assert "secrets:cluster" in {e["to"] for e in _edges(graph, "can read")}


def test_live_reads_that_failed_or_were_scoped_make_their_leg_not_determined() -> None:
    backend = FakeBackend(SEEDED_DOCS, forbidden={"clusterrolebindings"})
    inv = ap.collect_live(backend, [])
    graph = br.reach(inv, "deployment/web", "shop", live=True)
    assert any("clusterrolebindings" in r and "forbidden" in r for r in _undetermined(graph))
    # Read live, an empty list is an answer, not an absence: a namespace with no RoleBinding is not "not determined".
    scoped = br.reach(
        ap.collect_live(FakeBackend(SEEDED_DOCS), ["shop"]),
        "deployment/web",
        "shop",
        live=True,
        namespaces_read=["shop"],
    )
    assert any("RoleBindings outside the namespaces read (shop)" in r for r in _undetermined(scoped))
    full = br.reach(ap.collect_live(FakeBackend(SEEDED_DOCS), []), "deployment/web", "shop", live=True)
    assert full["notDetermined"] == []


# --- determinism, bounds, schema -----------------------------------------------------------------------------------


def test_same_input_same_bytes_and_document_order_does_not_matter() -> None:
    docs = [
        *SEEDED_DOCS,
        _binding(
            "RoleBinding", "second-reader", "Role", "secret-reader", [{"kind": "ServiceAccount", "name": "web-sa"}]
        ),
    ]
    first = json.dumps(_reach(docs, "deployment/web", "shop"), sort_keys=False)
    assert first == json.dumps(_reach(docs, "deployment/web", "shop"), sort_keys=False)
    mermaid = br.to_mermaid(_reach(docs, "deployment/web", "shop"))
    rng = random.Random(273)
    for _ in range(5):
        shuffled = docs[:]
        rng.shuffle(shuffled)
        again = _reach(shuffled, "deployment/web", "shop")
        assert json.dumps(again, sort_keys=False) == first
        assert br.to_mermaid(again) == mermaid


def _many_secrets(n: int) -> list[dict[str, Any]]:
    rule = [
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"], "resourceNames": [f"s{i:03}" for i in range(n)]}
    ]
    return [
        *_exposed("app", serviceAccountName="app-sa"),
        _sa(),
        _role("Role", "named", rule),
        _binding("RoleBinding", "named", "Role", "named", [SA]),
    ]


def test_the_graph_is_capped_and_says_how_much_it_withheld() -> None:
    graph = _reach(_many_secrets(60), "deployment/app", "shop", max_nodes=20, max_edges=25)
    assert len(graph["nodes"]) == 20 and len(graph["edges"]) <= 25
    t = graph["truncated"]
    assert t is not None and t["nodesWithheld"] > 0 and t["maxNodes"] == 20 and t["maxEdges"] == 25
    assert graph["complete"] is False
    # What cannot be determined is kept ahead of what can be listed: truncation never hides an unknown.
    assert graph["notDetermined"] and all(n["id"] in {x["id"] for x in graph["nodes"]} for n in graph["notDetermined"])
    ids = {n["id"] for n in graph["nodes"]}
    assert all(e["from"] in ids and e["to"] in ids for e in graph["edges"])
    assert "withheld" in br.to_mermaid(graph)
    # The defaults hold a hostile bundle to a size an MCP caller can take.
    big = _reach(_many_secrets(5000), "deployment/app", "shop")
    assert len(big["nodes"]) == br.MAX_NODES and len(json.dumps(big)) < 120_000
    with pytest.raises(br.ReachError):
        _reach(SEEDED_DOCS, "deployment/web", "shop", max_nodes=0)


def test_every_emitted_document_is_valid_against_its_schema() -> None:
    graphs = [
        _reach(SEEDED_DOCS, "deployment/web", "shop"),
        _reach(SEEDED_DOCS, "cronjob/batch", "ops"),
        _reach([*_exposed("app", serviceAccountName="app-sa")], "deployment/app", "shop"),
        _reach(_many_secrets(60), "deployment/app", "shop", max_nodes=20, max_edges=25),
    ]
    jsonschema.Draft202012Validator.check_schema(br.SCHEMA)
    for g in graphs:
        jsonschema.validate(g, br.SCHEMA, cls=jsonschema.Draft202012Validator)
        assert g["schema"] == "kube-noob/blast-radius" and g["schemaVersion"] == br.SCHEMA_VERSION == 1
    broken = copy.deepcopy(graphs[0])
    broken["edges"][0]["evidence"].pop("text")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(broken, br.SCHEMA, cls=jsonschema.Draft202012Validator)


# --- Mermaid -------------------------------------------------------------------------------------------------------

_LINE = re.compile(
    r"(flowchart LR"
    r"|  %% [ -~]*"
    r"|  (n\d+|t\d+)\[\"[A-Za-z0-9 ./:_\-=,()'+*@!?#;]*\"\]"
    r"|  n\d+ -->\|[a-z ]+\| n\d+"
    r"|  n\d+ -\. [a-z ]+ \.-> n\d+"
    r"|  classDef (undetermined|note) [a-z0-9:;# -]+"
    r"|  class n\d+(,n\d+)* undetermined"
    r"|  class t\d+(,t\d+)* note)\Z"
)
_EDGE = re.compile(r"  (n\d+) (?:-->\|([a-z ]+)\||-\. ([a-z ]+) \.->) (n\d+)\Z")

HOSTILE = [
    'web"]; click n1 "javascript:alert(1)"; x["',
    "%%{init: {'securityLevel': 'loose'}}%%",
    "`**md**`",
    'line\nclick n1 href "https://evil.example"',
    "<img src=x onerror=alert(1)>",
    "a#quot;b&amp;c",
    "a|b|c-->d",
    "u v\x00w",
]


def _hostile_docs(name: str) -> list[dict[str, Any]]:
    sa = {"kind": "ServiceAccount", "name": name, "namespace": "shop"}
    return [
        *_exposed("app", serviceAccountName=name),
        _sa(name),
        _role("Role", name, SECRET_READER),
        _binding("RoleBinding", name, "Role", name, [sa]),
        _binding("RoleBinding", "ghost", "Role", name + "-missing", [sa]),
    ]


@pytest.mark.parametrize("name", HOSTILE)
def test_a_hostile_object_name_cannot_break_the_diagram_or_inject_a_directive(name: str) -> None:
    graph = _reach(_hostile_docs(name), "deployment/app", "shop")
    text = br.to_mermaid(graph)
    lines = text.splitlines()
    assert text.isascii(), "no control character or terminal escape reaches the diagram or the terminal"
    for line in lines:
        assert _LINE.fullmatch(line), line
    assert sum(1 for line in lines if line.lstrip().startswith("%%")) == 1, "only the header comment"
    assert not any(line.lstrip().startswith(("click", "%%{", "style", "linkStyle")) for line in lines)
    for ch in '<>`"\n':
        inner = "".join(re.findall(r'\["(.*?)"\]', text))
        assert ch not in inner, repr(ch)


def test_the_diagram_is_derived_from_the_graph_and_shows_what_was_not_determined() -> None:
    graph = _reach(_hostile_docs("app-sa"), "deployment/app", "shop")
    text = br.to_mermaid(graph)
    order = [n["id"] for n in graph["nodes"]]
    drawn = set()
    for line in text.splitlines():
        m = _EDGE.fullmatch(line)
        if m:
            src, kind, dotted_kind, dst = m.group(1), m.group(2), m.group(3), m.group(4)
            drawn.add((order[int(src[1:]) - 1], kind or dotted_kind, order[int(dst[1:]) - 1], bool(dotted_kind)))
    in_json = {(e["from"], e["kind"], e["to"], e["kind"] == "not determined") for e in graph["edges"]}
    assert drawn == in_json, "every drawn edge is in the JSON graph, and every JSON edge is drawn"
    assert any(d for *_, d in drawn), "a not-determined leg is a dashed edge"
    assert "not determined: Role/shop/app-sa-missing is not in the input" in text
    assert re.search(r"class n\d+(,n\d+)* undetermined", text)
    assert br.to_mermaid(graph) == text


# --- surfaces ------------------------------------------------------------------------------------------------------


def test_cli_text_json_and_mermaid(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["posture", "reach", "deployment/web", "-n", "shop", "-f", str(SEEDED)]) == 0
    text = capsys.readouterr().out
    assert text.startswith("Deployment/shop/web") and "ServiceAccount/shop/web-sa" in text
    assert "RoleBinding/shop/web-secrets" in text and "every Secret in namespace shop" in text
    assert main(["--format", "json", "posture", "reach", "Deployment/shop/web", "-f", str(SEEDED)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out == _reach(SEEDED_DOCS, "Deployment/shop/web")
    assert main(["--format", "mermaid", "posture", "reach", "deployment/web", "-n", "shop", "-f", str(SEEDED)]) == 0
    assert capsys.readouterr().out == br.to_mermaid(out) + "\n"
    assert main(["posture", "reach", "deployment/app", "-n", "shop", "-f", str(SEEDED), "--require-complete"]) == 2
    capsys.readouterr()


def test_require_complete_exits_5_when_a_leg_is_not_determined(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    f = tmp_path / "app.yaml"
    f.write_text(yaml.safe_dump_all(_exposed("app", serviceAccountName="app-sa")), encoding="utf-8")
    assert main(["posture", "reach", "deployment/app", "-n", "shop", "-f", str(f)]) == 0
    text = capsys.readouterr().out
    assert "not determined: ServiceAccount shop/app-sa is not in the input" in text
    assert main(["posture", "reach", "deployment/app", "-n", "shop", "-f", str(f), "--require-complete"]) == 5
    capsys.readouterr()
    # Files alone are never complete: a set of files cannot show the bindings it leaves out. Asserting the bundle is
    # whole is what lets a determined answer pass, and it does not hide a leg that is still open.
    seeded = ["posture", "reach", "deployment/web", "-n", "shop", "-f", str(SEEDED), "--require-complete"]
    assert main(seeded) == 5
    capsys.readouterr()
    assert main([*seeded, "--whole-bundle"]) == 0
    capsys.readouterr()
    assert (
        main(["posture", "reach", "deployment/app", "-n", "shop", "-f", str(f), "--require-complete", "--whole-bundle"])
        == 5
    )
    capsys.readouterr()


def test_mermaid_is_refused_where_there_is_no_graph(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--format", "mermaid", "posture", "scan", "-f", str(SEEDED)]) == 2
    assert "posture reach" in capsys.readouterr().err
    assert main(["--format", "sarif", "posture", "reach", "deployment/web", "-n", "shop", "-f", str(SEEDED)]) == 2
    capsys.readouterr()


def test_mcp_tools_file_and_live() -> None:
    kit = tk.Toolkit(load_settings())
    names = {s.name for s in kit.specs()}
    assert "posture_reach" in names and "cluster_posture_reach" not in names
    out = kit.posture_reach(
        tk.PostureReachIn(manifests=SEEDED.read_text(encoding="utf-8"), workload="deployment/web", namespace="shop")
    )
    assert out == _reach(SEEDED_DOCS, "deployment/web", "shop") and "mermaid" not in out
    with_diagram = kit.posture_reach(
        tk.PostureReachIn(
            manifests=SEEDED.read_text(encoding="utf-8"), workload="deployment/web", namespace="shop", mermaid=True
        )
    )
    assert with_diagram["mermaid"] == br.to_mermaid(out)
    with pytest.raises(br.ReachError):
        kit.posture_reach(tk.PostureReachIn(manifests=SEEDED.read_text(encoding="utf-8"), workload="deployment/nope"))
    with pytest.raises(ValueError):
        tk.PostureReachIn(manifests="x", workload="a\nb")
    live = tk.Toolkit(load_settings(overrides={"cluster": {"enabled": True}}))
    assert "cluster_posture_reach" in {s.name for s in live.specs()}
    with pytest.raises(ValueError):
        tk.ClusterPostureReachIn(workload="deployment/web", namespaces=["Bad NS"])


# --- the adversarial review of 4d7b00d: one test per defect ------------------------------------------------------
#
# Each base carries one unrelated RoleBinding and one unrelated ClusterRoleBinding, so "no binding of a kind is in
# the input" is not what is under test.


def _web(**pod: Any) -> list[dict[str, Any]]:
    spec = {"serviceAccountName": "web", "containers": [{"name": "c", "image": "i"}], **pod}
    return [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "web", "namespace": "shop"},
            "spec": {"template": {"metadata": {"labels": {"app": "web"}}, "spec": spec}},
        },
        _sa("web"),
        _binding("ClusterRoleBinding", "unrelated", "ClusterRole", "view", [{"kind": "User", "name": "bob"}]),
        _binding("RoleBinding", "unrelated", "ClusterRole", "view", [{"kind": "User", "name": "bob"}], ns="zzz"),
    ]


WEB = {"kind": "ServiceAccount", "name": "web", "namespace": "shop"}


def _leg(graph: dict[str, Any], name: str) -> dict[str, Any]:
    return next(x for x in graph["legs"] if x["leg"] == name)


def _bound(rules: list[dict[str, Any]], kind: str = "Role", name: str = "r", ns: str = "shop") -> list[dict[str, Any]]:
    binding_kind = "RoleBinding" if kind == "Role" else "ClusterRoleBinding"
    return [_role(kind, name, rules, ns=ns), _binding(binding_kind, f"{name}-b", kind, name, [WEB], ns=ns)]


def test_truncation_keeps_the_strongest_capabilities_and_the_summary_counts_the_whole_graph() -> None:
    """Defect 1: 125 namespace grants filled the cap with bindings, the cluster-admin and privileged capabilities
    were cut, and the summary -- computed after the cut -- said "reaches no capability"."""
    priv = _web(containers=[{"name": "c", "image": "i", "securityContext": {"privileged": True}}])
    admin = _binding("ClusterRoleBinding", "adm", "ClusterRole", "cluster-admin", [WEB])
    many = [
        doc
        for i in range(125)
        for doc in (
            _role(
                "Role",
                f"r{i:03d}",
                [{"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]}],
                ns=f"ns{i:03d}",
            ),
            _binding(
                "RoleBinding",
                f"r{i:03d}-b",
                "Role",
                f"r{i:03d}",
                [{"kind": "Group", "name": "system:serviceaccounts"}],
                ns=f"ns{i:03d}",
            ),
        )
    ]
    graph = _reach([*priv, admin, *many], "deployment/web", "shop")
    assert graph["truncated"] is not None
    assert "top: full control (cluster)" in graph["summary"] and "no capability" not in graph["summary"]
    kept = {n["label"] for n in graph["nodes"] if n["type"] == "capability"}
    assert "full control (cluster)" in kept and "privileged container: full access to the node (node)" in kept
    assert {e["kind"] for e in graph["edges"]} >= {"escapes through", "grants", "uses token of"}
    ids = {n["id"] for n in graph["nodes"]}
    for e in graph["edges"]:
        assert e["from"] in ids and e["to"] in ids
    # Every binding kept is needed by something kept: a capability it grants, a gap it carries or a Secret it reads.
    needed = {e["from"] for e in graph["edges"] if e["kind"] in {"grants", "not determined", "can read"}}
    assert all(n["id"] in needed for n in graph["nodes"] if n["type"] == "binding")
    # The T1 shape: 130 gaps beside cluster-admin. The gaps do not crowd out the capability, nor the reverse.
    gaps = [
        _binding(
            "RoleBinding",
            f"g{i:03d}",
            "Role",
            "gone",
            [{"kind": "Group", "name": "system:authenticated"}],
            ns=f"ns{i:03d}",
        )
        for i in range(130)
    ]
    t1 = _reach([*priv, admin, *gaps], "deployment/web", "shop")
    assert "top: full control (cluster)" in t1["summary"]
    kept = {n["type"] for n in t1["nodes"]}
    assert {"serviceaccount", "capability", "undetermined"} <= kept
    assert all(x["from"] for x in t1["notDetermined"]), "every reason says where it hangs from"
    assert t1["truncated"]["notDeterminedWithheld"] + len(t1["notDetermined"]) == 130


def test_a_projected_service_account_token_is_a_token_even_with_automount_off() -> None:
    """Defect 3: `automountServiceAccountToken: false` with a projected `serviceAccountToken` volume read as "no token,
    no API rights", complete -- and the scan dropped the same paths."""
    projected = {
        "automountServiceAccountToken": False,
        "containers": [
            {"name": "c", "image": "i", "volumeMounts": [{"name": "t", "mountPath": "/var/run/secrets/tokens"}]}
        ],
        "volumes": [{"name": "t", "projected": {"sources": [{"serviceAccountToken": {"path": "token"}}]}}],
    }
    docs = [*_web(**projected), _binding("ClusterRoleBinding", "adm", "ClusterRole", "cluster-admin", [WEB])]
    graph = _reach(docs, "deployment/web", "shop")
    assert _leg(graph, "token")["status"] == "reached" and _leg(graph, "rbac")["status"] == "reached"
    edge = _edges(graph, "uses token of")[0]
    assert edge["evidence"]["field"] == "spec.template.spec.volumes[0].projected.sources[0].serviceAccountToken"
    assert "projects its token" in edge["evidence"]["text"]
    exposed = [
        *docs,
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "web", "namespace": "shop"},
            "spec": {"type": "LoadBalancer", "selector": {"app": "web"}},
        },
    ]
    scan = ap.scan(ap.Inventory.from_documents(copy.deepcopy(exposed)))
    assert any(p["blastRadius"]["capability"] == "full control" for p in scan["paths"]), "posture scan sees it too"
    # Declared but mounted by no container: no token in the pod.
    unmounted = copy.deepcopy(projected)
    unmounted["containers"][0].pop("volumeMounts")
    assert _leg(_reach([*_web(**unmounted)], "deployment/web", "shop"), "token")["status"] == "none"
    # Another audience: whether the API server accepts it is not in the input.
    vault = copy.deepcopy(projected)
    vault["volumes"][0]["projected"]["sources"][0]["serviceAccountToken"]["audience"] = "vault"
    other = _reach([*_web(**vault)], "deployment/web", "shop")
    assert _leg(other, "token")["status"] == "not determined"
    assert any("audience vault" in r and "--api-audiences" in r for r in _undetermined(other))


def test_duplicate_objects_are_an_ambiguity_not_a_pick() -> None:
    """Defect 4: two Deployments named shop/web, or two ServiceAccounts shop/web that disagree, were settled by JSON
    sort order: the privileged document was never mentioned."""
    evil = copy.deepcopy(_web()[0])
    evil["spec"]["template"]["spec"].update(
        hostPID=True, containers=[{"name": "z", "image": "i", "securityContext": {"privileged": True}}]
    )
    with pytest.raises(br.ReachError, match="2 different Deployment objects named shop/web"):
        _reach([*_web(), evil], "deployment/web", "shop")
    # The same document twice is one object, not an ambiguity.
    assert _reach([*_web(), copy.deepcopy(_web()[0])], "deployment/web", "shop")["anchor"]["resolved"]
    quiet = _sa("web")
    quiet["automountServiceAccountToken"] = False
    admin = _binding("ClusterRoleBinding", "adm", "ClusterRole", "cluster-admin", [WEB])
    graph = _reach([*_web(), quiet, admin], "deployment/web", "shop")
    assert _leg(graph, "token")["status"] == "not determined"
    assert any("2 ServiceAccount objects named shop/web" in r for r in _undetermined(graph))
    assert _leg(graph, "rbac")["status"] == "reached", "the worst case is listed: the token is assumed mounted"
    svc = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "web", "namespace": "shop"},
        "spec": {"type": "LoadBalancer", "selector": {"app": "web"}},
    }
    scan = ap.scan(ap.Inventory.from_documents(copy.deepcopy([*_web(), quiet, admin, svc])))
    assert any(p["blastRadius"]["capability"] == "full control" for p in scan["paths"]), "the scan takes the worst case"


def test_the_node_leg_counts_what_the_audit_flags_and_says_what_it_checked() -> None:
    """Defect 5: procMount Unmasked, NET_RAW / SYS_RAWIO / SYS_BOOT / MAC_ADMIN and a Windows HostProcess pod each
    read `node none`, while `audit` fired on the same file."""
    from kube_noob.audit.rules import DANGEROUS_CAPS

    sc = {
        "procMount": "Unmasked",
        "capabilities": {"drop": ["ALL"], "add": ["NET_RAW", "SYS_RAWIO", "SYS_BOOT", "MAC_ADMIN"]},
    }
    graph = _reach(
        _web(
            securityContext={"windowsOptions": {"hostProcess": True}},
            containers=[{"name": "c", "image": "i", "securityContext": sc}],
        ),
        "deployment/web",
        "shop",
    )
    names = {n["label"] for n in graph["nodes"] if n["type"] == "capability"}
    assert "unmasked /proc: host kernel interfaces (node)" in names
    assert "dangerous capabilities ['MAC_ADMIN', 'NET_RAW', 'SYS_BOOT', 'SYS_RAWIO'] (node)" in names
    assert "Windows HostProcess pod: privileged access to the host (node)" in names
    container = _reach(
        _web(containers=[{"name": "c", "image": "i", "securityContext": {"windowsOptions": {"hostProcess": True}}}]),
        "deployment/web",
        "shop",
    )
    assert _leg(container, "node")["status"] == "reached"
    # One list: every capability the audit calls dangerous is counted here.
    for cap in sorted(DANGEROUS_CAPS):
        one = _reach(
            _web(containers=[{"name": "c", "image": "i", "securityContext": {"capabilities": {"add": [cap]}}}]),
            "deployment/web",
            "shop",
        )
        assert _leg(one, "node")["status"] == "reached", cap
    # hostPort is an exposure, not an escape, and the `none` detail lists what was checked rather than implying all.
    port = _reach(
        _web(containers=[{"name": "c", "image": "i", "ports": [{"containerPort": 80, "hostPort": 80}]}]),
        "deployment/web",
        "shop",
    )
    assert _leg(port, "node")["status"] == "none"
    detail = _leg(port, "node")["detail"]
    assert "procMount Unmasked" in detail and "hostProcess" in detail and "MAC_ADMIN" in detail
    assert any("hostPort is not a node escape" in x for x in port["limitations"])
    # Paths are what they resolve to, and an unnamed KServe `model:` container is named by its field.
    etc = _reach(_web(volumes=[{"name": "h", "hostPath": {"path": "/etc/../"}}]), "deployment/web", "shop")
    assert any(n["label"] == "host path /etc/../: node takeover (node)" and n["weight"] == 9 for n in etc["nodes"])
    isvc = {
        "apiVersion": "serving.kserve.io/v1beta1",
        "kind": "InferenceService",
        "metadata": {"name": "llm", "namespace": "ml"},
        "spec": {"predictor": {"model": {"modelFormat": {"name": "x"}, "securityContext": {"privileged": True}}}},
    }
    model = _reach([isvc], "isvc/llm", "ml")
    assert "container model securityContext.privileged=true" in json.dumps(
        model
    ) and "container None" not in json.dumps(model)


def test_the_documented_escalation_rights_are_ranked() -> None:
    """Defect 6, first half: rights the Kubernetes RBAC good-practices and authorization pages name as escalation
    paths read `rbac none`. Each one is verified there and pinned in attack_paths._api_capabilities."""
    cases = {
        "mint tokens for its ServiceAccounts (serviceaccounts/token create)": (
            [{"apiGroups": [""], "resources": ["serviceaccounts/token"], "verbs": ["create"]}],
            "Role",
        ),
        "exec into pods": ([{"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["get"]}], "Role"),
        "add containers to running pods (pods/ephemeralcontainers)": (
            [{"apiGroups": [""], "resources": ["pods/ephemeralcontainers"], "verbs": ["patch"]}],
            "Role",
        ),
        "mint long-lived ServiceAccount tokens (create a service-account-token Secret)": (
            # N11: a minted token counts only with a way to use it -- here, a pod that mounts it.
            [{"apiGroups": [""], "resources": ["secrets", "pods"], "verbs": ["create"]}],
            "Role",
        ),
        "control admission webhooks (read and change every admitted object)": (
            [
                {
                    "apiGroups": ["admissionregistration.k8s.io"],
                    "resources": ["mutatingwebhookconfigurations"],
                    "verbs": ["create"],
                }
            ],
            "ClusterRole",
        ),
        "create PersistentVolumes (a hostPath on a node)": (
            [{"apiGroups": [""], "resources": ["persistentvolumes"], "verbs": ["create"]}],
            "ClusterRole",
        ),
        "issue client certificates (create and approve CertificateSigningRequests)": (
            [
                {
                    "apiGroups": ["certificates.k8s.io"],
                    "resources": ["certificatesigningrequests"],
                    "verbs": ["create"],
                },
                {
                    "apiGroups": ["certificates.k8s.io"],
                    "resources": ["certificatesigningrequests/approval"],
                    "verbs": ["update"],
                },
            ],
            "ClusterRole",
        ),
    }
    for name, (rules, kind) in cases.items():
        graph = _reach([*_web(), *_bound(rules, kind=kind)], "deployment/web", "shop")
        caps = {n["label"].rsplit(" (", 1)[0] for n in graph["nodes"] if n["type"] == "capability"}
        assert name in caps, (name, caps)
        assert _leg(graph, "rbac")["status"] == "reached", name


def test_rights_the_model_does_not_rank_are_not_determined_not_none() -> None:
    """Defect 6, second half: a bound rule that matched no capability made the leg `none`, complete. Unclassified is
    an unknown, named and counted; a plain read is known and stays quiet."""
    rules = [
        {"apiGroups": [""], "resources": ["nodes"], "verbs": ["patch"]},
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["update"]},
        {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "list"]},
    ]
    files = _reach([*_web(), *_bound(rules, kind="ClusterRole")], "deployment/web", "shop")
    assert _leg(files, "rbac")["status"] == "not determined"
    graph = _reach([*_web(), *_bound(rules, kind="ClusterRole")], "deployment/web", "shop", whole_bundle=True)
    assert _leg(graph, "rbac")["status"] == "not determined" and graph["complete"] is False
    reason = next(r for r in _undetermined(graph) if "not classify" in r)
    assert reason.startswith("2 bound rule(s)")
    assert (
        "ClusterRole/r rules[0] (patch on nodes)" in reason and "ClusterRole/r rules[1] (update on secrets)" in reason
    )
    assert "configmaps" not in reason
    reads = _reach([*_web(), *_bound(rules[2:])], "deployment/web", "shop", whole_bundle=True)
    assert _leg(reads, "rbac")["status"] == "none" and reads["complete"] is True
    many = [{"apiGroups": ["x.io"], "resources": [f"r{i}"], "verbs": ["create"]} for i in range(15)]
    capped = _reach([*_web(), *_bound(many)], "deployment/web", "shop")
    assert any(r.startswith("15 bound rule(s)") and "and 5 more" in r for r in _undetermined(capped))


def test_creating_workloads_or_impersonating_reaches_the_secrets_of_its_scope() -> None:
    """Defect 6: `create pods` said `secrets none` beside "run as any ServiceAccount of the namespace"; a pod it
    creates mounts any Secret there (Kubernetes authorization, "Escalation paths")."""
    pods = _reach(
        [*_web(), *_bound([{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}])], "deployment/web", "shop"
    )
    assert _leg(pods, "secrets")["status"] == "reached"
    assert "secrets:namespace/shop" in {e["to"] for e in _edges(pods, "can read")}
    imp = _reach(
        [
            *_web(),
            *_bound(
                [{"apiGroups": [""], "resources": ["users", "groups"], "verbs": ["impersonate"]}], kind="ClusterRole"
            ),
        ],
        "deployment/web",
        "shop",
    )
    assert "secrets:cluster" in {e["to"] for e in _edges(imp, "can read")}


def test_limitations_reach_the_text_and_the_diagram_and_files_are_never_complete(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Defect 7: the binding that grants is not in the files; text said `rbac none`, exit 0 under --require-complete,
    and the Mermaid was one edge with no word that the files cannot show what they leave out."""
    f = tmp_path / "base.yaml"
    f.write_text(yaml.safe_dump_all(_web()), encoding="utf-8")
    argv = ["posture", "reach", "deployment/web", "-n", "shop", "-f", str(f)]
    assert main([*argv, "--require-complete"]) == 5
    text = capsys.readouterr().out
    assert "rbac      not determined" in text and "one outside them cannot be ruled out" in text
    assert "limitation: File input: a set of files cannot show the bindings" in text
    assert main(["--format", "mermaid", *argv]) == 0
    diagram = capsys.readouterr().out
    assert "File input: a set of files cannot show the bindings" in diagram and "not determined: " in diagram
    assert re.search(r"class t0(,t\d+)* note", diagram)
    # Asserting the bundle is whole turns the same absence into an answer.
    assert main([*argv, "--whole-bundle", "--require-complete"]) == 0
    assert "rbac      none" in capsys.readouterr().out


def test_the_built_in_aggregated_roles_honour_aggregate_to_labels_in_the_bundle() -> None:
    """Defect 8: a ClusterRole labelled aggregate-to-view that reads Secrets, bound through `view`, read `rbac none`;
    and the stand-in for a built-in role was presented as a determined answer."""
    extra = _role(
        "ClusterRole", "extra-view", [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list", "watch"]}]
    )
    extra["metadata"]["labels"] = {"rbac.authorization.k8s.io/aggregate-to-view": "true"}
    view = _binding("RoleBinding", "v", "ClusterRole", "view", [WEB])
    graph = _reach([*_web(), extra, view], "deployment/web", "shop")
    assert _leg(graph, "secrets")["status"] == "reached"
    assert any(
        "ClusterRole/view is not in the input" in r and "1 in the input counted (ClusterRole/extra-view)" in r
        for r in _undetermined(graph)
    )
    plain = _reach([*_web(), view], "deployment/web", "shop", whole_bundle=True)
    assert _leg(plain, "rbac")["status"] == "not determined", "a stand-in for an aggregated role is not an answer"


def test_an_aggregated_role_merges_its_own_rules_and_resolves_chains_whatever_the_label_names() -> None:
    """Defect 16: own rules plus a matching source dropped the source; a chain top <- mid <- leaf was found or lost
    depending on how its label names sorted."""
    agg = _role("ClusterRole", "agg", [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}])
    agg["aggregationRule"] = {"clusterRoleSelectors": [{"matchLabels": {"agg": "true"}}]}
    src = _role("ClusterRole", "src", SECRET_READER)
    src["metadata"]["labels"] = {"agg": "true"}
    merged = _reach(
        [*_web(), agg, src, _binding("ClusterRoleBinding", "v", "ClusterRole", "agg", [WEB])], "deployment/web", "shop"
    )
    assert _leg(merged, "secrets")["status"] == "reached"
    assert not any("only the ones in the input" in r for r in _undetermined(merged))
    for top_label, mid_label in (("to-top", "to-mid"), ("a-to-top", "z-to-mid"), ("z-to-top", "a-to-mid")):
        top = _role("ClusterRole", "top", [])
        top["aggregationRule"] = {"clusterRoleSelectors": [{"matchLabels": {top_label: "true"}}]}
        mid = _role("ClusterRole", "mid", [])
        mid["metadata"]["labels"] = {top_label: "true"}
        mid["aggregationRule"] = {"clusterRoleSelectors": [{"matchLabels": {mid_label: "true"}}]}
        leaf = _role("ClusterRole", "leaf", SECRET_READER)
        leaf["metadata"]["labels"] = {mid_label: "true"}
        chain = _reach(
            [*_web(), top, mid, leaf, _binding("ClusterRoleBinding", "v", "ClusterRole", "top", [WEB])],
            "deployment/web",
            "shop",
        )
        assert _leg(chain, "secrets")["status"] == "reached", top_label
        assert any("2 in the input counted (ClusterRole/leaf, ClusterRole/mid)" in r for r in _undetermined(chain)), (
            top_label
        )


def test_exposure_is_a_leg_and_a_refused_exposure_read_is_not_determined() -> None:
    """Defect 9: with Services, Routes and Ingresses refused, the summary said "not reached by any exposure", complete;
    and a refused Deployments list gave "no Deployment named web" with no word that the list was refused."""
    docs = [*_web(), *_bound(SECRET_READER)]
    refused = br.reach(
        ap.collect_live(FakeBackend(docs, forbidden={"services", "routes", "ingresses"}), []),
        "deployment/web",
        "shop",
        live=True,
    )
    assert _leg(refused, "exposure")["status"] == "not determined" and refused["complete"] is False
    assert any(r.startswith("services: services is forbidden") for r in _undetermined(refused))
    clean = br.reach(ap.collect_live(FakeBackend(docs), []), "deployment/web", "shop", live=True)
    assert _leg(clean, "exposure")["status"] == "none" and clean["complete"] is True
    with pytest.raises(br.ReachError, match=re.escape("that list was not read (deployments: deployments is forbidden")):
        br.reach(ap.collect_live(FakeBackend(docs, forbidden={"deployments"}), []), "deployment/web", "shop", live=True)
    with pytest.raises(br.ReachError, match=re.escape("namespace shop was not read (read: zzz)")):
        br.reach(
            ap.collect_live(FakeBackend(docs), ["zzz"]), "deployment/web", "shop", live=True, namespaces_read=["zzz"]
        )


def test_malformed_rbac_shapes_and_list_kinds_are_read_or_reported_never_nothing() -> None:
    """Defect 10: `rules` as a mapping, `subjects` as a mapping and `verbs: "*"` read as no rights; a typed
    ClusterRoleBindingList was dropped and the document then said "no ClusterRoleBinding is in the input"."""
    rules_map = _role("Role", "r", [])
    rules_map["rules"] = {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}
    a = _reach([*_web(), rules_map, _binding("RoleBinding", "v", "Role", "r", [WEB])], "deployment/web", "shop")
    assert any("rules is a dict, not a list" in r for r in _undetermined(a))
    subj = _binding("ClusterRoleBinding", "v", "ClusterRole", "cluster-admin", [])
    subj["subjects"] = dict(WEB)
    b = _reach([*_web(), subj], "deployment/web", "shop")
    assert any("subjects is not a list" in r for r in _undetermined(b))
    assert "no binding in these files" not in _leg(b, "rbac")["detail"]
    scalar = _reach(
        [*_web(), *_bound([{"apiGroups": "*", "resources": "*", "verbs": "*"}], kind="ClusterRole")],
        "deployment/web",
        "shop",
    )
    assert any("rules[0] apiGroups, resources, verbs are not a list" in r for r in _undetermined(scalar))
    typed = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBindingList",
        "items": [
            {"metadata": {"name": "v"}, "subjects": [WEB], "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}
        ],
    }
    listed = _reach([*_web()[:2], typed], "deployment/web", "shop")
    assert "full control (cluster)" in {n["label"] for n in listed["nodes"]}
    assert not any("no ClusterRoleBinding is in the input" in r for r in _undetermined(listed))


def test_the_rbac_leg_names_its_reason_when_the_gap_hangs_from_a_binding() -> None:
    """Defect 11: a missing Role printed `rbac     not determined` and nothing after it."""
    graph = _reach([*_web(), _binding("RoleBinding", "x", "Role", "gone", [WEB])], "deployment/web", "shop")
    assert _leg(graph, "rbac")["detail"] == "Role/shop/gone is not in the input"


def test_a_path_step_names_the_namespace_of_the_grant() -> None:
    """Defect 12: a RoleBinding in `other` gave a path ending `(shop)`; the same document's graph said `(other)`."""
    svc = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "web", "namespace": "shop"},
        "spec": {"type": "LoadBalancer", "selector": {"app": "web"}},
    }
    docs = [*_web(), svc, *_bound([{"apiGroups": [""], "resources": ["secrets"], "verbs": ["list"]}], ns="other")]
    scan = ap.scan(ap.Inventory.from_documents(copy.deepcopy(docs)))
    assert scan["paths"][0]["summary"].endswith(f"{READ_SECRETS} (other)")
    graph = _reach(docs, "deployment/web", "shop")
    assert graph["paths"][0]["steps"][-1]["to"] in {n["label"] for n in graph["nodes"]}


def test_scan_and_reach_print_the_same_evidence_and_the_scan_is_stable_under_shuffle() -> None:
    """Defect 13: two equal proofs of full control; the scan named one and reach the other, and the scan itself gave
    several outputs for one input in shuffled order."""
    svc = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "web", "namespace": "shop"},
        "spec": {"type": "LoadBalancer", "selector": {"app": "web"}},
    }
    full = [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
    docs = [
        *_web(),
        svc,
        _role("ClusterRole", "zz", full),
        _binding("ClusterRoleBinding", "zz-b", "ClusterRole", "zz", [WEB]),
        _role("ClusterRole", "aa", full),
        _binding(
            "ClusterRoleBinding", "aa-b", "ClusterRole", "aa", [{"kind": "Group", "name": "system:authenticated"}]
        ),
    ]
    scan = ap.scan(ap.Inventory.from_documents(copy.deepcopy(docs)))
    graph = _reach(docs, "deployment/web", "shop")
    assert scan["paths"][0]["steps"][-1]["evidence"] == graph["paths"][0]["steps"][-1]["evidence"]
    outputs = set()
    rng = random.Random(13)
    for _ in range(20):
        shuffled = copy.deepcopy(docs)
        rng.shuffle(shuffled)
        outputs.add(json.dumps(ap.scan(ap.Inventory.from_documents(shuffled))))
    assert len(outputs) == 1


def test_a_newline_in_input_cannot_forge_a_row_in_either_text_view(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Defect 14: a hostPath carrying newlines printed a forged `node     none ...` row."""
    forged = "/data\n\n  node     none            no privileged container\n\x1b[2K"
    f = tmp_path / "inj.yaml"
    exposed = _exposed("web", volumes=[{"name": "v", "hostPath": {"path": forged}}])
    f.write_text(yaml.safe_dump_all([*exposed, _sa("default", "shop")]), encoding="utf-8")
    assert main(["posture", "reach", "deployment/web", "-n", "shop", "-f", str(f)]) == 0
    reach_text = capsys.readouterr().out
    assert main(["posture", "scan", "-f", str(f)]) == 0
    scan_text = capsys.readouterr().out
    for text in (reach_text, scan_text):
        assert not any(line.lstrip().startswith("node     none") for line in text.splitlines()), text
        assert "/data node none" in text


def test_text_legs_name_their_component() -> None:
    """Defect 15: an InferenceService printed two rows per leg with no word of which component each was."""
    isvc = {
        "apiVersion": "serving.kserve.io/v1beta1",
        "kind": "InferenceService",
        "metadata": {"name": "llm", "namespace": "ml"},
        "spec": {
            "predictor": {"containers": [{"name": "p", "image": "i", "securityContext": {"privileged": True}}]},
            "transformer": {"containers": [{"name": "t", "image": "i"}]},
        },
    }
    text = br.render_text(_reach([isvc], "isvc/llm", "ml"))
    assert "  [InferenceService/ml/llm[predictor]]" in text and "  [InferenceService/ml/llm[transformer]]" in text


def test_the_mcp_result_is_bounded_in_bytes_and_says_what_it_withheld() -> None:
    """Defect 17: 200 bindings with 2,300-character names returned 1.67 MB of JSON to an MCP caller."""
    long = "n" * 2300
    parts = [*_web()] + [
        _binding(
            "RoleBinding",
            f"{long}{i}",
            "Role",
            f"{long}{i}",
            [{"kind": "Group", "name": "system:authenticated"}],
            ns=f"ns{i}",
        )
        for i in range(200)
    ]
    kit = tk.Toolkit(load_settings())
    out = kit.posture_reach(
        tk.PostureReachIn(
            manifests=yaml.safe_dump_all(parts), workload="deployment/web", namespace="shop", mermaid=True
        )
    )
    assert len(json.dumps(out)) <= 96_000, "1.67 MB before"
    assert br.MAX_BYTES == 96_000
    t = out["truncated"]
    assert t["stringsClipped"] > 0 and t["notDeterminedWithheld"] > 0 and t["maxBytes"] == br.MAX_BYTES
    assert "withheld" in out["summary"] and "withheld" in out["mermaid"]
    jsonschema.validate(
        {k: v for k, v in out.items() if k != "mermaid"}, br.SCHEMA, cls=jsonschema.Draft202012Validator
    )


def test_the_deprecated_service_account_field_is_named_as_it_is_written() -> None:
    """Defect 17: `spec.serviceAccount: adm` was reported as `serviceAccountName=adm`, a field not in the object."""
    docs = [*_web(), _sa("adm")]
    docs[0]["spec"]["template"]["spec"] = {"serviceAccount": "adm", "containers": [{"name": "c", "image": "i"}]}
    edge = _edges(_reach(docs, "deployment/web", "shop"), "uses token of")[0]
    assert edge["evidence"]["field"] == "spec.template.spec.serviceAccount"
    assert edge["evidence"]["text"].startswith("spec.serviceAccount=adm;")


# --- lessons of the operator-inventory review (G270) that apply to the shared scan code -----------------------------


def test_a_live_list_without_an_items_list_is_not_read_rather_than_empty() -> None:
    """A response with no `items` read as "no RoleBindings": the RBAC leg then said nothing was bound."""

    class NoItems(FakeBackend):
        def get(
            self, resource: str, name: str | None = None, namespace: str | None = None, **kw: Any
        ) -> dict[str, Any]:
            return {"kind": "List"} if resource == "rolebindings" else super().get(resource, name, namespace, **kw)

    inv = ap.collect_live(NoItems([*_web(), *_bound(SECRET_READER)]), [])
    assert any(n.startswith("rolebindings: the response carried no items list") for n in inv.not_read)
    graph = br.reach(inv, "deployment/web", "shop", live=True)
    assert _leg(graph, "rbac")["status"] == "not determined" and graph["complete"] is False


def test_a_role_of_another_api_group_is_not_rbac() -> None:
    """A CRD called Role in another API group is not RBAC: reading it as one would invent a right."""
    fake = _role("Role", "r", SECRET_READER)
    fake["apiVersion"] = "example.io/v1"
    docs = [*_web(), fake, _binding("RoleBinding", "v", "Role", "r", [WEB])]
    inv = ap.Inventory.from_documents(copy.deepcopy(docs))
    assert any("apiVersion example.io/v1 is not rbac.authorization.k8s.io" in n for n in inv.not_read)
    graph = _reach(docs, "deployment/web", "shop")
    assert _leg(graph, "secrets")["status"] != "reached"
    assert any("Role/shop/r is not in the input" in r for r in _undetermined(graph))


def test_invisible_and_bidirectional_characters_are_removed_from_the_text_views(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """One implementation, `sanitize.visible`: a right-to-left override or an Arabic letter mark in a name could make
    a printed path read as something else."""
    name = "web" + chr(0x202E) + "gnp.exe" + chr(0x061C) + chr(0x200B)
    graph = _reach([*_web(volumes=[{"name": "v", "hostPath": {"path": f"/data/{name}"}}])], "deployment/web", "shop")
    text = br.render_text(graph)
    for ch in (chr(0x202E), chr(0x061C), chr(0x200B)):
        assert ch not in text
    assert br.flat("a" + chr(0x1B) + "[31mb" + chr(0x2028) + "c") == "a b c"


# --- the second adversarial review (56235e3): fixes that moved a defect instead of closing it ---------------------


class _NotServed(FakeBackend):
    """A cluster that does not serve some resource types (vanilla Kubernetes has no Routes or SCCs), in the exact
    words kubectl writes, plus one whose list is refused."""

    def __init__(self, docs: list[dict[str, Any]], missing: set[str], forbidden: set[str] | None = None) -> None:
        super().__init__(docs, forbidden=forbidden or set())
        self.missing = missing

    def get(self, resource: str, name: str | None = None, namespace: str | None = None, **kw: Any) -> dict[str, Any]:
        from kube_noob.errors import ClusterAccessError

        if resource in self.missing:
            raise ClusterAccessError(f'error: the server doesn\'t have a resource type "{resource}"')
        return super().get(resource, name, namespace, **kw)


ALL_UNSERVED = {"routes", "securitycontextconstraints", "httproutes", "virtualservices", "deploymentconfigs"} | {
    "inferenceservices",
    "rayclusters",
    "rayservices",
    "rayjobs",
}


def _svc(name: str = "web", kind: str = "ClusterIP", selector: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name, "namespace": "shop"},
        "spec": {"type": kind, "selector": selector or {"app": "web"}, "ports": [{"port": 80}]},
    }


def _caps(graph: dict[str, Any]) -> set[str]:
    return {n["label"].rsplit(" (", 1)[0] for n in graph["nodes"] if n["type"] == "capability"}


def test_subresource_wildcards_match_as_the_api_server_matches_them() -> None:
    """N1: `*/exec`, `*/proxy` with `get` read as plain reads -- `rbac none`, complete, exit 0. Kubernetes matches a
    rule's resource by `*`, by the exact name, or by `*/<subresource>` (ResourceMatches, v1.34.0)."""
    star = [{"apiGroups": [""], "resources": ["*/proxy", "*/exec", "*/attach", "*/portforward"], "verbs": ["get"]}]
    graph = _reach([*_web(), *_bound(star, kind="ClusterRole")], "deployment/web", "shop", whole_bundle=True)
    assert {"exec into pods", "kubelet API through nodes/proxy"} <= _caps(graph)
    assert _leg(graph, "rbac")["status"] == "not determined" and graph["complete"] is False
    reason = next(r for r in _undetermined(graph) if "not classify" in r)
    assert "*/portforward" in reason and "*/proxy" in reason
    for resource in ("pods/proxy", "services/proxy", "pods/portforward"):
        one = _reach(
            [*_web(), *_bound([{"apiGroups": [""], "resources": [resource], "verbs": ["get"]}])],
            "deployment/web",
            "shop",
            whole_bundle=True,
        )
        assert _leg(one, "rbac")["status"] == "not determined", resource
    # Neighbour: `*/status` also matches certificatesigningrequests/status, which issues a certificate.
    status = _reach(
        [*_web(), *_bound([{"apiGroups": ["*"], "resources": ["*/status"], "verbs": ["update"]}], kind="ClusterRole")],
        "deployment/web",
        "shop",
        whole_bundle=True,
    )
    assert _leg(status, "rbac")["status"] == "not determined"
    # The scan reads the same primitive.
    scan = ap.scan(ap.Inventory.from_documents([*_web(), *_bound(star, kind="ClusterRole"), _svc(kind="LoadBalancer")]))
    assert {"exec into pods", "kubelet API through nodes/proxy"} <= {
        p["blastRadius"]["capability"] for p in scan["paths"]
    }


def test_bootstrap_and_leader_election_rights_are_named_harmless_and_nothing_else_is() -> None:
    """N2(a): self-reviews bound to every authenticated user, a leader-elected controller's leases and events, token
    and access reviews and a CR's own status made every real workload "not determined"."""
    harmless = [
        {
            "apiGroups": ["authorization.k8s.io"],
            "resources": ["selfsubjectaccessreviews", "selfsubjectrulesreviews"],
            "verbs": ["create"],
        },
        {
            "apiGroups": ["authentication.k8s.io"],
            "resources": ["selfsubjectreviews", "tokenreviews"],
            "verbs": ["create"],
        },
        {"apiGroups": ["authorization.k8s.io"], "resources": ["subjectaccessreviews"], "verbs": ["create"]},
        {
            "apiGroups": ["coordination.k8s.io"],
            "resources": ["leases"],
            "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"],
        },
        {"apiGroups": ["", "events.k8s.io"], "resources": ["events"], "verbs": ["create", "patch", "update"]},
        {"apiGroups": ["example.io"], "resources": ["widgets/status"], "verbs": ["get", "update", "patch"]},
        {"apiGroups": [""], "resources": ["pods/status"], "verbs": ["update", "patch"]},
        {"nonResourceURLs": ["/healthz", "/version"], "verbs": ["get"]},
    ]
    graph = _reach([*_web(), *_bound(harmless, kind="ClusterRole")], "deployment/web", "shop", whole_bundle=True)
    assert _leg(graph, "rbac")["status"] == "none", _leg(graph, "rbac")["detail"]
    assert graph["complete"] is True
    # Neighbours stay open, each for a reason: config another workload reads, a certificate, every status.
    for rule in (
        {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["create", "update"]},
        {"apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests/status"], "verbs": ["update"]},
        {"apiGroups": ["coordination.k8s.io"], "resources": ["*"], "verbs": ["update"]},
    ):
        one = _reach([*_web(), *_bound([rule], kind="ClusterRole")], "deployment/web", "shop", whole_bundle=True)
        assert _leg(one, "rbac")["status"] == "not determined", rule


def test_a_list_the_cluster_did_not_answer_is_never_an_absence_live() -> None:
    """N2(b), N10, revised by the third review: a 404 was read as "not served", and an Istio older than 1.22 (no
    networking.istio.io/v1), a Gateway API older than v1.0 (HTTPRoute only at v1beta1), an unavailable
    openshift-apiserver and the phrase inside a warning line all answer that way -- so a pod behind a
    VirtualService read `exposure none, complete`. Without API discovery kube-noob cannot tell an absent group from
    another version, so every failed list leaves its leg not determined; a refused SCC list opens the RBAC leg once
    the account can create pods."""
    docs = [*_web(), *_bound([{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}])]
    vanilla = br.reach(ap.collect_live(_NotServed(docs, ALL_UNSERVED), []), "deployment/web", "shop", live=True)
    assert _leg(vanilla, "exposure")["status"] == "not determined" and vanilla["complete"] is False
    assert any("virtualservices" in r for r in _undetermined(vanilla))
    assert not hasattr(ap, "not_served") and "notServed" not in ap.scan(ap.collect_live(_NotServed(docs, set()), []))
    for words in (
        "couldn't get resource list for route.openshift.io/v1: the server is currently unable to handle the request",
        'Warning: something\nerror: the server doesn\'t have a resource type "virtualservices"',
        "Not found: GET /apis/networking.istio.io/v1/namespaces/shop/virtualservices",
    ):

        class _Old(FakeBackend):
            def get(self, resource: str, name: str | None = None, namespace: str | None = None, **kw: Any) -> Any:
                from kube_noob.errors import ClusterAccessError

                if resource in {"virtualservices", "httproutes", "routes"}:
                    raise ClusterAccessError(words)  # noqa: B023 -- used inside this iteration only
                return super().get(resource, name=name, namespace=namespace, **kw)

        old = br.reach(ap.collect_live(_Old(docs, forbidden=set()), []), "deployment/web", "shop", live=True)
        assert _leg(old, "exposure")["status"] == "not determined" and old["complete"] is False, words
    refused = br.reach(
        ap.collect_live(_NotServed(docs, ALL_UNSERVED - {"routes"}, forbidden={"routes"}), []),
        "deployment/web",
        "shop",
        live=True,
    )
    assert _leg(refused, "exposure")["status"] == "not determined"
    pods = [*_web(), *_bound([{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}])]
    no_scc = br.reach(
        ap.collect_live(
            _NotServed(pods, ALL_UNSERVED - {"securitycontextconstraints"}, forbidden={"securitycontextconstraints"}),
            [],
        ),
        "deployment/web",
        "shop",
        live=True,
    )
    scc = [r for r in _undetermined(no_scc) if "securitycontextconstraints" in r and "privileged" in r]
    # The refusal is quoted whole or cut at a word, never mid-word.
    assert scc and "is forbidden" in scc[0]


def _httproute(backend: str = "web") -> dict[str, Any]:
    return {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": {"name": "r", "namespace": "shop"},
        "spec": {"parentRefs": [{"name": "public"}], "rules": [{"backendRefs": [{"name": backend, "port": 80}]}]},
    }


def test_gateway_api_and_mesh_routes_are_exposure_and_unread_kinds_are_not_none() -> None:
    """N3: an HTTPRoute or an Istio VirtualService in front of the Service read as `exposure none`, complete."""
    via_route = _reach([*_web(), _svc(), _httproute()], "deployment/web", "shop", whole_bundle=True)
    assert _leg(via_route, "exposure")["status"] == "reached"
    assert via_route["exposure"][0]["kind"] == "internet (Gateway API HTTPRoute)"
    vs = {
        "apiVersion": "networking.istio.io/v1",
        "kind": "VirtualService",
        "metadata": {"name": "v", "namespace": "shop"},
        "spec": {
            "gateways": ["istio-system/public"],
            "hosts": ["web.example.com"],
            "http": [{"route": [{"destination": {"host": "web.shop.svc.cluster.local"}}]}],
        },
    }
    assert (
        _leg(_reach([*_web(), _svc(), vs], "deployment/web", "shop", whole_bundle=True), "exposure")["status"]
        == "reached"
    )
    mesh_only = copy.deepcopy(vs)
    mesh_only["spec"]["gateways"] = ["mesh"]
    assert (
        _leg(_reach([*_web(), _svc(), mesh_only], "deployment/web", "shop", whole_bundle=True), "exposure")["status"]
        == "none"
    )
    other = {
        "apiVersion": "projectcontour.io/v1",
        "kind": "HTTPProxy",
        "metadata": {"name": "p", "namespace": "shop"},
        "spec": {},
    }
    unread = _reach([*_web(), _svc(), other], "deployment/web", "shop", whole_bundle=True)
    assert (
        _leg(unread, "exposure")["status"] == "not determined"
        and "HTTPProxy/shop/p" in _leg(unread, "exposure")["detail"]
    )
    port = _reach(
        _web(containers=[{"name": "c", "image": "i", "ports": [{"containerPort": 80, "hostPort": 8080}]}]),
        "deployment/web",
        "shop",
        whole_bundle=True,
    )
    assert _leg(port, "exposure")["status"] == "reached" and "hostPort 8080" in _leg(port, "exposure")["detail"]
    host = _reach(_web(hostNetwork=True), "deployment/web", "shop", whole_bundle=True)
    assert _leg(host, "exposure")["status"] == "reached" and "hostNetwork" in _leg(host, "exposure")["detail"]
    assert {"httproutes", "virtualservices"} <= set(ap.LIVE_RESOURCES)


def test_a_route_or_ingress_to_a_service_not_in_the_input_is_a_gap() -> None:
    """N4: under --whole-bundle an Ingress whose backend Service is absent read as `exposure none`, complete."""
    ing = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {"name": "i", "namespace": "shop"},
        "spec": {
            "rules": [
                {
                    "http": {
                        "paths": [
                            {
                                "path": "/",
                                "pathType": "Prefix",
                                "backend": {"service": {"name": "web", "port": {"number": 80}}},
                            }
                        ]
                    }
                }
            ]
        },
    }
    route = {
        "apiVersion": "route.openshift.io/v1",
        "kind": "Route",
        "metadata": {"name": "r", "namespace": "shop"},
        "spec": {"to": {"kind": "Service", "name": "web"}},
    }
    for front in (ing, route, _httproute()):
        graph = _reach([*_web(), front], "deployment/web", "shop", whole_bundle=True)
        assert _leg(graph, "exposure")["status"] == "not determined", front["kind"]
        assert "Service shop/web" in _leg(graph, "exposure")["detail"] and graph["complete"] is False
        assert any(
            "Service shop/web" in n and "not in the input" in n
            for n in ap.scan(ap.Inventory.from_documents(copy.deepcopy([*_web(), front])))["notRead"]
        )


def test_the_object_named_is_the_object_scored_for_every_anchorable_kind() -> None:
    """N5: a privileged ReplicaSet under a benign Deployment, or a Job under a CronJob, was answered with the
    owner's spec. The named object is scored; the owner chain is context and its differences are stated."""
    dep = _web()[0]
    rs = {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {
            "name": "web-old",
            "namespace": "shop",
            "ownerReferences": [{"kind": "Deployment", "name": "web", "controller": True}],
        },
        "spec": {
            "template": {
                "metadata": {"labels": {"app": "web"}},
                "spec": {
                    "serviceAccountName": "web",
                    "containers": [{"name": "c", "image": "i", "securityContext": {"privileged": True}}],
                },
            }
        },
    }
    graph = _reach([*_web(), rs], "rs/web-old", "shop", whole_bundle=True)
    assert graph["anchor"]["resolved"] == ["ReplicaSet/shop/web-old"] and _leg(graph, "node")["status"] == "reached"
    assert any("node escape" in d for d in graph["anchor"]["ownerDiffers"])
    cron = {
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": {"name": "c", "namespace": "shop"},
        "spec": {
            "schedule": "* * * * *",
            "jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "c", "image": "i"}]}}}},
        },
    }
    job = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": "c-1",
            "namespace": "shop",
            "ownerReferences": [{"kind": "CronJob", "name": "c", "controller": True}],
        },
        "spec": {"template": {"spec": {"hostPID": True, "containers": [{"name": "c", "image": "i"}]}}},
    }
    j = _reach([dep, cron, job], "job/c-1", "shop")
    assert j["anchor"]["resolved"] == ["Job/shop/c-1"] and _leg(j, "node")["status"] == "reached"
    assert any("CronJob/shop/c" in d for d in j["anchor"]["ownerDiffers"])


def test_an_rbac_object_that_could_not_be_read_opens_the_rbac_leg() -> None:
    """N6, R1: an RBAC-shaped object dropped into notRead left `rbac none`; and OpenShift's legacy
    authorization.openshift.io bindings -- proxies of the same objects -- were dropped altogether."""
    broken_list = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBindingList", "items": {"a": 1}}
    graph = _reach([*_web(), broken_list], "deployment/web", "shop", whole_bundle=True)
    assert _leg(graph, "rbac")["status"] == "not determined"
    assert any("RoleBindingList" in r for r in _undetermined(graph))
    foreign = _binding("ClusterRoleBinding", "x", "ClusterRole", "cluster-admin", [WEB])
    foreign["apiVersion"] = "example.io/v1"
    other = _reach([*_web(), foreign], "deployment/web", "shop", whole_bundle=True)
    assert _leg(other, "rbac")["status"] == "not determined"
    legacy = {
        "apiVersion": "authorization.openshift.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": "legacy"},
        "subjects": [{"kind": "ServiceAccount", "name": "web", "namespace": "shop"}],
        "roleRef": {"name": "cluster-admin"},
    }
    assert "full control" in _caps(_reach([*_web(), legacy], "deployment/web", "shop"))
    by_name = {**legacy, "subjects": [], "userNames": ["system:serviceaccount:shop:web"], "groupNames": None}
    assert "full control" in _caps(_reach([*_web(), by_name], "deployment/web", "shop"))
    bad_ref = {**legacy, "roleRef": {"name": "cluster-admin", "namespace": "shop"}}
    assert (
        _leg(_reach([*_web(), bad_ref], "deployment/web", "shop", whole_bundle=True), "rbac")["status"]
        == "not determined"
    )


def test_the_scan_reads_openshift_legacy_rbac_as_main_did_and_better() -> None:
    """R1: main scored six paths (top 30) for a legacy ClusterRoleBinding to cluster-admin; the first round scored
    none. The group's four kinds are served as proxies of rbac.authorization.k8s.io (openshift-apiserver)."""
    legacy = {
        "apiVersion": "authorization.openshift.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": "legacy"},
        "subjects": [{"kind": "ServiceAccount", "name": "web", "namespace": "shop"}],
        "roleRef": {"name": "cluster-admin"},
    }
    out = ap.scan(ap.Inventory.from_documents([*_web(), legacy, _svc(kind="LoadBalancer")]))
    assert out["total"] == 6 and out["paths"][0]["score"] == 30


def test_a_secret_mounted_service_account_token_is_a_token() -> None:
    """N8: automount off and the legacy token Secret mounted at the ServiceAccount path read `token none`."""
    sa_path = "/var/run/secrets/kubernetes.io/serviceaccount"
    pod = {
        "automountServiceAccountToken": False,
        "containers": [{"name": "c", "image": "i", "volumeMounts": [{"name": "t", "mountPath": sa_path}]}],
        "volumes": [{"name": "t", "secret": {"secretName": "adm-token"}}],
    }
    secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "kubernetes.io/service-account-token",
        "metadata": {
            "name": "adm-token",
            "namespace": "shop",
            "annotations": {"kubernetes.io/service-account.name": "adm"},
        },
        "data": {"token": "c2VjcmV0LXZhbHVl"},
    }
    admin = _binding(
        "ClusterRoleBinding",
        "adm",
        "ClusterRole",
        "cluster-admin",
        [{"kind": "ServiceAccount", "name": "adm", "namespace": "shop"}],
    )
    graph = _reach([*_web(**pod), _sa("adm"), secret, admin], "deployment/web", "shop", whole_bundle=True)
    assert _leg(graph, "token")["status"] == "reached" and "ServiceAccount/shop/adm" in _leg(graph, "token")["detail"]
    assert "full control" in _caps(graph) and "c2VjcmV0" not in json.dumps(graph)
    # The Secret is not in the input: a Secret volume at the token path may carry any account's token.
    blind = _reach([*_web(**pod), admin], "deployment/web", "shop", whole_bundle=True)
    assert _leg(blind, "token")["status"] == "not determined"


def test_a_rule_is_classified_pair_by_pair() -> None:
    """N9: a rule reading Secrets also patching nodes and deleting namespaces showed only the Secrets."""
    rule = [{"apiGroups": [""], "resources": ["secrets", "nodes", "namespaces"], "verbs": ["get", "patch", "delete"]}]
    graph = _reach([*_web(), *_bound(rule, kind="ClusterRole")], "deployment/web", "shop", whole_bundle=True)
    assert "read Secrets (credentials, tokens of other ServiceAccounts)" in _caps(graph)
    reason = next(r for r in _undetermined(graph) if "not classify" in r)
    assert "patch, delete on secrets, nodes, namespaces" in reason


def test_creating_a_secret_mints_a_token_only_with_a_way_to_read_it() -> None:
    """N11: `secrets create` alone was ranked as minting a token; the token is only usable read back (get on
    secrets) or mounted in a pod the account creates. A TokenRequest for its own account is no new right."""
    alone = _reach(
        [*_web(), *_bound([{"apiGroups": [""], "resources": ["secrets"], "verbs": ["create"]}])],
        "deployment/web",
        "shop",
        whole_bundle=True,
    )
    assert not any("mint long-lived" in c for c in _caps(alone)) and _leg(alone, "rbac")["status"] == "not determined"
    assert any("read it back" in r for r in _undetermined(alone))
    with_get = _reach(
        [*_web(), *_bound([{"apiGroups": [""], "resources": ["secrets"], "verbs": ["create", "get"]}])],
        "deployment/web",
        "shop",
    )
    assert any("mint long-lived" in c for c in _caps(with_get))
    own = [{"apiGroups": [""], "resources": ["serviceaccounts/token"], "verbs": ["create"], "resourceNames": ["web"]}]
    assert (
        _leg(_reach([*_web(), *_bound(own)], "deployment/web", "shop", whole_bundle=True), "rbac")["status"] == "none"
    )
    other = [
        {"apiGroups": [""], "resources": ["serviceaccounts/token"], "verbs": ["create"], "resourceNames": ["deployer"]}
    ]
    assert any("mint tokens" in c for c in _caps(_reach([*_web(), *_bound(other)], "deployment/web", "shop")))
    # seeded.yaml's `edit` path stands: edit also reads Secrets.
    assert any(
        p["blastRadius"]["capability"].startswith("mint long-lived")
        for p in ap.scan_manifests(SEEDED.read_text(encoding="utf-8"))["paths"]
    )


def test_owner_differences_name_images_and_labels_and_small_wording() -> None:
    """N12."""
    rs = {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {
            "name": "web-1",
            "namespace": "shop",
            "ownerReferences": [{"kind": "Deployment", "name": "web", "controller": True}],
        },
        "spec": {
            "template": {
                "metadata": {"labels": {"app": "web"}},
                "spec": {"serviceAccountName": "web", "containers": [{"name": "c", "image": "i"}]},
            }
        },
    }
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "web-1-x",
            "namespace": "shop",
            "labels": {"app": "other"},
            "ownerReferences": [{"kind": "ReplicaSet", "name": "web-1", "controller": True}],
        },
        "spec": {"serviceAccountName": "web", "containers": [{"name": "c", "image": "evil:1"}]},
    }
    differs = " | ".join(_reach([*_web(), rs, pod], "pod/web-1-x", "shop")["anchor"]["ownerDiffers"])
    assert "evil:1" in differs and "i" in differs and "labels" in differs
    rb = [
        {
            "apiGroups": ["rbac.authorization.k8s.io"],
            "resources": ["rolebindings"],
            "verbs": ["create", "update", "patch", "delete"],
        }
    ]
    detail = _leg(_reach([*_web(), *_bound(rb)], "deployment/web", "shop", whole_bundle=True), "rbac")["detail"]
    assert "plain reads" not in detail
    for path in ("/etc/kubernetes/pki", "/var/lib/kubelet/pods"):
        g = _reach(_web(volumes=[{"name": "h", "hostPath": {"path": path}}]), "deployment/web", "shop")
        assert any(n.get("weight") == 9 for n in g["nodes"] if n["type"] == "capability"), path
    from kube_noob.audit.rules import takes_over_node

    assert takes_over_node("/etc/kubernetes/pki") and not takes_over_node("/var/log")


def test_mermaid_refusal_points_to_posture_reach(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--format", "mermaid", "posture", "scan", "-f", str(SEEDED)]) == 2
    err = capsys.readouterr().err
    assert "`posture scan` has no graph to draw" in err and "kube-noob posture reach" in err


def test_differing_duplicate_roles_are_an_ambiguity_not_a_union() -> None:
    """R2: two Roles named shop/r -- one creates pods, the other uses SCC privileged -- made a "run privileged pods"
    path that neither grants. A duplicate that differs is stated, and nothing is built from the union."""
    one = _role("Role", "r", [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}])
    two = _role(
        "Role",
        "r",
        [
            {
                "apiGroups": ["security.openshift.io"],
                "resources": ["securitycontextconstraints"],
                "verbs": ["use"],
                "resourceNames": ["privileged"],
            }
        ],
    )
    docs = [*_web(), one, two, _binding("RoleBinding", "r-b", "Role", "r", [WEB]), _svc(kind="LoadBalancer")]
    out = ap.scan(ap.Inventory.from_documents(copy.deepcopy(docs)))
    assert not any("privileged pods" in p["blastRadius"]["capability"] for p in out["paths"])
    assert any("2 different objects named Role/shop/r" in n for n in out["notRead"])
    graph = _reach(docs, "deployment/web", "shop")
    assert "run privileged pods" not in " ".join(_caps(graph)) and _leg(graph, "rbac")["status"] == "not determined"


def test_differing_duplicate_services_keep_every_candidate_and_say_so() -> None:
    """R3: two Services shop/web with different selectors behind one Route: main picked by document order, the
    first round lost both paths."""
    route = {
        "apiVersion": "route.openshift.io/v1",
        "kind": "Route",
        "metadata": {"name": "r", "namespace": "shop"},
        "spec": {"to": {"kind": "Service", "name": "web"}},
    }
    other = copy.deepcopy(_web()[0])
    other["metadata"]["name"] = "api"
    other["spec"]["template"]["metadata"]["labels"] = {"app": "api"}
    other["spec"]["template"]["spec"]["containers"][0]["securityContext"] = {"privileged": True}
    web = copy.deepcopy(_web()[0])
    web["spec"]["template"]["spec"]["hostPID"] = True
    docs = [web, other, route, _svc(), _svc(selector={"app": "api"})]
    outs = set()
    rng = random.Random(3)
    for _ in range(8):
        shuffled = copy.deepcopy(docs)
        rng.shuffle(shuffled)
        outs.add(json.dumps(ap.scan(ap.Inventory.from_documents(shuffled))))
    assert len(outs) == 1
    out = json.loads(outs.pop())
    reached = {p["steps"][2]["to"] for p in out["paths"]}
    assert reached == {"Deployment/shop/web", "Deployment/shop/api"}
    assert any("2 different objects named Service/shop/web" in n for n in out["notRead"])
    # The note sits on the step that depends on which object is meant: the Service's selector.
    assert all("one of 2 different Services named shop/web" in p["steps"][2]["evidence"] for p in out["paths"])


def test_openshift_scope_impersonation_is_not_a_capability() -> None:
    """OpenShift binds system:authenticated to impersonate `userextras/scopes.authorization.openshift.io` only:
    "purely tightening" (openshift-apiserver bootstrappolicy). It must not make every workload critical."""
    scope = [
        {
            "apiGroups": ["authentication.k8s.io"],
            "resources": ["userextras/scopes.authorization.openshift.io"],
            "verbs": ["impersonate"],
        }
    ]
    docs = [
        *_web(),
        _role("ClusterRole", "system:scope-impersonation", scope),
        _binding(
            "ClusterRoleBinding",
            "system:scope-impersonation",
            "ClusterRole",
            "system:scope-impersonation",
            [{"kind": "Group", "name": "system:authenticated"}],
        ),
        _svc(kind="LoadBalancer"),
    ]
    assert ap.scan(ap.Inventory.from_documents(copy.deepcopy(docs)))["total"] == 0
    assert _leg(_reach(docs, "deployment/web", "shop", whole_bundle=True), "rbac")["status"] == "none"


def test_the_scan_names_malformed_rbac_instead_of_scoring_nothing_silently() -> None:
    """Also on main: `verbs: "*"` as a scalar and `rules` as a mapping gave 0 paths and an empty notRead."""
    scalar = _bound([{"apiGroups": "*", "resources": "*", "verbs": "*"}], kind="ClusterRole")
    mapping = _role("Role", "m", [])
    mapping["rules"] = {"verbs": ["*"]}
    for extra in (scalar, [mapping, _binding("RoleBinding", "m-b", "Role", "m", [WEB])]):
        out = ap.scan(ap.Inventory.from_documents(copy.deepcopy([*_web(), *extra, _svc(kind="LoadBalancer")])))
        assert any("not a list" in n for n in out["notRead"]), out["notRead"]


def test_full_control_is_one_path_family_not_twelve() -> None:
    """A cluster-admin binding gave 12 paths per exposure in the first round (6 on main): the new capabilities a
    full-control grant already covers are not listed again for the same grant and scope."""
    docs = [
        *_web(),
        _binding("ClusterRoleBinding", "adm", "ClusterRole", "cluster-admin", [WEB]),
        _svc(kind="LoadBalancer"),
    ]
    out = ap.scan(ap.Inventory.from_documents(docs))
    assert out["total"] == 6


def test_two_different_workloads_of_one_name_keep_the_worse_in_the_threat_model() -> None:
    """Found diffing `vuln threat` against main: two Deployments shop/web, one benign and one privileged, kept the
    one last in the canonical order -- the benign one -- and the privileged node detail vanished. Main kept the last
    in document order, so it depended on the file. Both are kept (their union, see the third review's test below),
    in any order, and the scan names the pair."""
    benign = _web()[0]
    priv = copy.deepcopy(benign)
    priv["spec"]["template"]["spec"]["hostPID"] = True
    for docs in ([benign, priv], [priv, benign]):
        reach = ap.workload_reach(ap.Inventory.from_documents(copy.deepcopy(docs)))
        assert {c.name for c in reach["Deployment/shop/web"].node} == {"host namespace hostPID"}
    out = ap.scan(ap.Inventory.from_documents([benign, priv]))
    assert any("2 different objects named Deployment/shop/web" in n for n in out["notRead"])


def test_neighbours_found_rerunning_the_reproducers() -> None:
    """Class 21, rerunning /tmp/rt-v3b/n: an old chart's Ingress (`serviceName`) routed to nothing; the same
    Deployment in two files was scored twice by the scan and once by the blast radius; a Deployment written without
    a namespace and the same one naming `default` were "two different objects"; and the capability the summary
    names as top was not always one the truncated graph kept."""
    legacy = {
        "apiVersion": "extensions/v1beta1",
        "kind": "Ingress",
        "metadata": {"name": "i", "namespace": "shop"},
        "spec": {"rules": [{"http": {"paths": [{"backend": {"serviceName": "web", "servicePort": 80}}]}}]},
    }
    graph = _reach([*_web(), _svc(), legacy], "deployment/web", "shop", whole_bundle=True)
    assert _leg(graph, "exposure")["status"] == "reached"
    twice = [*_web(), _svc(kind="LoadBalancer"), *copy.deepcopy(_web())]
    scan = ap.scan(ap.Inventory.from_documents(twice))
    assert scan["total"] == len(_reach(twice, "deployment/web", "shop")["paths"]) and scan["workloads"] == 1
    bare = copy.deepcopy(_web()[0])
    bare["metadata"] = {"name": "web"}
    spelled = copy.deepcopy(bare)
    spelled["metadata"]["namespace"] = "default"
    resolved = _reach([bare, spelled], "deployment/web", "default")["anchor"]["resolved"]  # no "2 different" error
    assert len(resolved) == 1 and resolved[0].startswith("Deployment/") and resolved[0].endswith("/web")
    many = [
        doc
        for i in range(150)
        for doc in _bound(
            [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}], name=f"r{i:03d}", ns=f"ns{i:03d}"
        )
    ]
    tied = _reach(
        [*_web(), *many, *_bound([{"apiGroups": [""], "resources": ["pods"], "verbs": ["*"]}], name="zz", ns="zzz")],
        "deployment/web",
        "shop",
    )
    top = tied["summary"].split("(top: ")[1].split(");")[0]
    assert top in {n["label"] for n in tied["nodes"] if n["type"] == "capability"}
    # Unreadable shapes are unknowns, not absences: a subject that is a string or of a kind the API does not define,
    # a binding whose metadata is a list (which crashed), and `containers` as a mapping.
    for subject in ("system:serviceaccount:shop:web", {"kind": "serviceaccount", "name": "web"}):
        bad = _binding("ClusterRoleBinding", "b", "ClusterRole", "cluster-admin", [subject])
        g = _reach([*_web(), bad], "deployment/web", "shop", whole_bundle=True)
        assert _leg(g, "rbac")["status"] == "not determined", subject
    listed = _binding("ClusterRoleBinding", "b", "ClusterRole", "cluster-admin", [WEB])
    listed["metadata"] = ["b"]
    assert _reach([*_web(), listed], "deployment/web", "shop", whole_bundle=True)["legs"]
    mapping = _web(containers={"c": {"image": "i", "securityContext": {"privileged": True}}})
    assert _leg(_reach(mapping, "deployment/web", "shop", whole_bundle=True), "node")["status"] == "not determined"
    # `deployments` in a group that does not serve Deployments is some CRD's resource: not "create workloads".
    crd = [{"apiGroups": ["example.com"], "resources": ["deployments"], "verbs": ["create"]}]
    other = _reach([*_web(), *_bound(crd)], "deployment/web", "shop", whole_bundle=True)
    assert not _caps(other) and _leg(other, "rbac")["status"] == "not determined"


def _raycluster(groups: int, name_len: int = 8) -> dict[str, Any]:
    worker = {
        "template": {
            "spec": {
                "hostPID": True,
                "volumes": [{"name": "h", "hostPath": {"path": "/"}}],
                "containers": [{"name": "w", "image": "ray", "securityContext": {"privileged": True}}],
            }
        }
    }
    return {
        "apiVersion": "ray.io/v1",
        "kind": "RayCluster",
        "metadata": {"name": "rc", "namespace": "shop"},
        "spec": {
            "headGroupSpec": copy.deepcopy(worker),
            "workerGroupSpecs": [
                {**copy.deepcopy(worker), "groupName": f"g{i:04d}" + "x" * name_len} for i in range(groups)
            ],
        },
    }


def test_every_list_in_the_document_is_bounded_and_the_byte_cap_holds_for_any_input() -> None:
    """N7: the byte loop halved nodes and edges only; 400 Ray worker groups gave 2,000 legs and 400 resolved
    references, and the document went past MAX_BYTES. Every list is bounded, the open legs first, and what was
    withheld is counted."""
    graph = _reach([_raycluster(400)], "raycluster/rc", "shop")
    assert len(json.dumps(graph)) <= br.MAX_BYTES
    jsonschema.validate(graph, br.SCHEMA, cls=jsonschema.Draft202012Validator)
    t = graph["truncated"]
    assert t is not None and t["legsWithheld"] > 0 and t["resolvedWithheld"] > 0
    assert len(graph["legs"]) + t["legsWithheld"] == 401 * 5
    assert len(graph["anchor"]["resolved"]) + t["resolvedWithheld"] == 401
    # The open legs come first: none of the withheld legs is `not determined` while a shown one is `none`.
    statuses = [x["status"] for x in graph["legs"]]
    assert statuses == sorted(statuses, key=lambda s: {"not determined": 0, "reached": 1, "none": 2}[s])
    # Property: whatever the size and the cap, the document fits.
    rng = random.Random(7)
    for _ in range(12):
        groups, name_len = rng.randint(0, 300), rng.randint(0, 400)
        cap = rng.choice([4_000, 9_000, 20_000, br.MAX_BYTES])
        doc = _reach([_raycluster(groups, name_len)], "raycluster/rc", "shop", max_bytes=cap)
        assert len(json.dumps(doc)) <= cap, (groups, name_len, cap)
        jsonschema.validate(doc, br.SCHEMA, cls=jsonschema.Draft202012Validator)


# --- third review (9445b1f) ----------------------------------------------------------------------------------------


def _vs(name: str, ns: str, spec: dict[str, Any]) -> dict[str, Any]:
    return {
        "apiVersion": "networking.istio.io/v1",
        "kind": "VirtualService",
        "metadata": {"name": name, "namespace": ns},
        "spec": spec,
    }


def test_the_scan_calls_only_the_narrowed_paths_node_takeover() -> None:
    """Item 1: the scan's "node takeover" label uses KN-S010's narrowed list, so kube-proxy's xtables lock is a host
    path, not a takeover, and /etc/kubernetes/pki still is."""
    for path, takeover in (("/run/xtables.lock", False), ("/etc/cni/net.d", False), ("/etc/kubernetes/pki", True)):
        g = _reach(_web(volumes=[{"name": "h", "hostPath": {"path": path}}]), "deployment/web", "shop")
        labels = [n["label"] for n in g["nodes"] if n["type"] == "capability"]
        assert any(("node takeover" in x) is takeover for x in labels if path in x), (path, labels)


def test_routes_from_namespaces_not_read_leave_exposure_open() -> None:
    """Item 3: with --read-namespace shop, a VirtualService or HTTPRoute in another namespace can route to shop/web,
    so `none` is not an answer; in files, an unmodelled routing object counts where its BACKEND is."""
    live = br.reach(
        ap.collect_live(FakeBackend([*_web(), _svc()], forbidden=set()), ["shop"]),
        "deployment/web",
        "shop",
        live=True,
        namespaces_read=["shop"],
    )
    assert _leg(live, "exposure")["status"] == "not determined"
    assert "namespaces not read" in _leg(live, "exposure")["detail"]
    grpc = {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GRPCRoute",
        "metadata": {"name": "g", "namespace": "gw"},
        "spec": {
            "parentRefs": [{"name": "public"}],
            "rules": [{"backendRefs": [{"name": "web", "namespace": "shop"}]}],
        },
    }
    files = _reach([*_web(), _svc(), grpc], "deployment/web", "shop", whole_bundle=True)
    assert (
        _leg(files, "exposure")["status"] == "not determined" and "GRPCRoute/gw/g" in _leg(files, "exposure")["detail"]
    )


def test_two_workloads_of_one_name_are_both_kept_never_one_dropped() -> None:
    """Item 4: "keep the worse" compared node weight before API rights, so a hostPID copy displaced a copy holding
    cluster-admin's token, and `vuln threat` lost the identity. Both are kept, and the ambiguity is named."""
    from kube_noob.vuln.threat import model

    benign = _web()[0]
    a = copy.deepcopy(benign)
    a["spec"]["template"]["spec"]["hostPID"] = True
    c = copy.deepcopy(benign)
    c["spec"]["template"]["spec"]["serviceAccountName"] = "adm"
    crb = _binding(
        "ClusterRoleBinding",
        "adm",
        "ClusterRole",
        "cluster-admin",
        [{"kind": "ServiceAccount", "name": "adm", "namespace": "shop"}],
    )
    for docs in ([a, c, crb], [c, a, crb]):
        r = ap.workload_reach(ap.Inventory.from_documents(copy.deepcopy(docs)))["Deployment/shop/web"]
        assert {x.name for x in r.node} == {"host namespace hostPID"}
        assert "full control" in {cap.name for cap, _ in r.api} and r.copies == 2
        text = "---\n".join(yaml.safe_dump(d) for d in docs)
        out = model(text, platform="kubernetes")
        ids = {i for app in out["applications"] for i in app["identities"]}
        assert {"ServiceAccount/shop/adm", "ServiceAccount/shop/web"} <= ids
        assert any("2 different objects named Deployment/shop/web" in n for n in out["ambiguous"])


def _token_secret(name: str = "adm-token", account: str = "adm") -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "kubernetes.io/service-account-token",
        "metadata": {"name": name, "namespace": "shop", "annotations": {"kubernetes.io/service-account.name": account}},
    }


def test_a_token_reaches_the_pod_by_every_secret_route_or_the_leg_is_open() -> None:
    """Item 5: a projected `sources[].secret` of a token Secret is a token; an env or envFrom reference to a token
    Secret, or to a Secret of unknown type, is not determined; read live (Secrets are never read), any Secret
    reference leaves the leg open -- never "no ServiceAccount token is mounted"."""
    off = {"automountServiceAccountToken": False}
    projected = _web(
        **off,
        containers=[{"name": "c", "image": "i", "volumeMounts": [{"name": "t", "mountPath": "/creds"}]}],
        volumes=[{"name": "t", "projected": {"sources": [{"secret": {"name": "adm-token"}}]}}],
    )
    g = _reach([*projected, _token_secret()], "deployment/web", "shop", whole_bundle=True)
    assert _leg(g, "token")["status"] == "reached" and "ServiceAccount/shop/adm" in _leg(g, "token")["detail"]
    env = [{"name": "T", "valueFrom": {"secretKeyRef": {"name": "adm-token", "key": "token"}}}]
    for container in (
        {"name": "c", "image": "i", "env": env},
        {"name": "c", "image": "i", "envFrom": [{"secretRef": {"name": "adm-token"}}]},
    ):
        for extra in ([_token_secret()], []):  # a token Secret, and a Secret the input does not carry
            g = _reach([*_web(**off, containers=[container]), *extra], "deployment/web", "shop", whole_bundle=True)
            assert _leg(g, "token")["status"] == "not determined", (container, extra)
    plain = {
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "Opaque",
        "metadata": {"name": "adm-token", "namespace": "shop"},
    }
    g = _reach(
        [*_web(**off, containers=[{"name": "c", "image": "i", "env": env}]), plain],
        "deployment/web",
        "shop",
        whole_bundle=True,
    )
    assert _leg(g, "token")["status"] == "none"
    vol = _web(
        **off,
        containers=[{"name": "c", "image": "i", "volumeMounts": [{"name": "t", "mountPath": "/creds"}]}],
        volumes=[{"name": "t", "secret": {"secretName": "db"}}],
    )
    live = br.reach(ap.collect_live(FakeBackend(vol, forbidden=set()), []), "deployment/web", "shop", live=True)
    assert _leg(live, "token")["status"] == "not determined"


def test_istio_delegates_and_mirrors_carry_the_parents_exposure() -> None:
    """Item 6: a delegate VirtualService inherits its parent's gateways; an unresolved delegate is a gap; a mirror
    sends traffic to the workload too."""
    root = _vs(
        "root",
        "istio-system",
        {
            "gateways": ["istio-system/public"],
            "hosts": ["x.example.com"],
            "http": [{"delegate": {"name": "d", "namespace": "shop"}}],
        },
    )
    child = _vs("d", "shop", {"http": [{"route": [{"destination": {"host": "web"}}]}]})
    g = _reach([*_web(), _svc(), root, child], "deployment/web", "shop", whole_bundle=True)
    assert _leg(g, "exposure")["status"] == "reached"
    gap = _reach([*_web(), _svc(), root], "deployment/web", "shop", whole_bundle=True)
    assert (
        _leg(gap, "exposure")["status"] == "not determined"
        and "VirtualService shop/d" in _leg(gap, "exposure")["detail"]
    )
    mirror = _vs(
        "m",
        "shop",
        {
            "gateways": ["istio-system/public"],
            "http": [{"route": [{"destination": {"host": "other"}}], "mirror": {"host": "web"}}],
        },
    )
    assert (
        _leg(_reach([*_web(), _svc(), mirror], "deployment/web", "shop", whole_bundle=True), "exposure")["status"]
        == "reached"
    )


def test_route_header_values_are_masked_before_they_leave_the_backend() -> None:
    """Item 7: cluster_get on a VirtualService or HTTPRoute returned `Authorization: Basic ...` in clear."""
    from kube_noob.debug.cluster import _redact_obj

    hr = {
        "kind": "HTTPRoute",
        "spec": {
            "rules": [
                {
                    "matches": [{"headers": [{"type": "Exact", "name": "x-api-key", "value": "k-123"}]}],
                    "filters": [
                        {"requestHeaderModifier": {"set": [{"name": "Authorization", "value": "Basic dXNlcjpwYXNz"}]}},
                        {"responseHeaderModifier": {"add": [{"name": "x-token", "value": "t-456"}]}},
                    ],
                }
            ]
        },
    }
    vs = {
        "kind": "VirtualService",
        "spec": {"http": [{"headers": {"request": {"set": {"Authorization": "Bearer abc"}}}}]},
    }
    listed = {"items": [{k: v for k, v in vs.items() if k != "kind"}]}
    from kube_noob.debug.cluster import _list_hint

    for obj, hint in ((hr, None), (vs, None), (listed, _list_hint(listed, "virtualservices"))):
        text = json.dumps(_redact_obj(obj, hint))
        for secret in ("k-123", "dXNlcjpwYXNz", "t-456", "abc"):
            assert secret not in text, (secret, text)
        assert "Authorization" in text or "x-api-key" in text


def test_the_summary_says_what_the_exposure_leg_says() -> None:
    """Item 8: a hostPort pod's leg said reached and its summary "not reached by any exposure"."""
    g = _reach(
        _web(containers=[{"name": "c", "image": "i", "ports": [{"containerPort": 80, "hostPort": 8080}]}]),
        "deployment/web",
        "shop",
        whole_bundle=True,
    )
    assert _leg(g, "exposure")["status"] == "reached"
    assert "not reached by any exposure" not in g["summary"] and "hostPort 8080" in g["summary"]


def test_duplicates_the_scan_names_are_named_by_reach_too() -> None:
    """Item 9: a duplicate RoleBinding (one copy binds web to cluster-admin) and a duplicate Ingress were named by
    the scan and not by reach, which claimed complete."""
    b1 = _binding("RoleBinding", "b", "ClusterRole", "cluster-admin", [{"kind": "User", "name": "bob"}])
    b2 = _binding("RoleBinding", "b", "ClusterRole", "cluster-admin", [WEB])
    g = _reach([*_web(), b1, b2], "deployment/web", "shop", whole_bundle=True)
    assert any("2 different objects named RoleBinding/shop/b" in n for n in g["notRead"]) and g["complete"] is False
    ing = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {"name": "i", "namespace": "shop"},
        "spec": {"defaultBackend": {"service": {"name": "web", "port": {"number": 80}}}},
    }
    ing2 = copy.deepcopy(ing)
    ing2["spec"]["rules"] = [{"host": "a.example.com"}]
    g = _reach([*_web(), _svc(), ing, ing2], "deployment/web", "shop", whole_bundle=True)
    assert any("2 different objects named Ingress/shop/i" in n for n in g["notRead"]) and g["complete"] is False


def test_malformed_exposure_fields_are_unknowns_not_absences() -> None:
    """Item 10: `gateways: gw` as a string, `parentRefs` as a string, `backendRefs` as a map and a Service
    `selector: app=web` string read as nothing."""
    cases = [
        _vs("v", "shop", {"gateways": "istio-system/public", "http": [{"route": [{"destination": {"host": "web"}}]}]}),
        {**_httproute(), "spec": {"parentRefs": "public", "rules": [{"backendRefs": [{"name": "web"}]}]}},
        {**_httproute(), "spec": {"parentRefs": [{"name": "public"}], "rules": [{"backendRefs": {"name": "web"}}]}},
    ]
    for front in cases:
        g = _reach([*_web(), _svc(), front], "deployment/web", "shop", whole_bundle=True)
        assert _leg(g, "exposure")["status"] == "not determined", front
        assert any("not a list" in n or "is not" in n for n in g["notRead"]), g["notRead"]
    bad_svc = _svc(kind="LoadBalancer")
    bad_svc["spec"]["selector"] = "app=web"
    g = _reach([*_web(), bad_svc], "deployment/web", "shop", whole_bundle=True)
    assert _leg(g, "exposure")["status"] == "not determined"
    assert any("selector" in n for n in ap.scan(ap.Inventory.from_documents([*_web(), bad_svc]))["notRead"])


def test_server_set_fields_do_not_make_two_objects() -> None:
    """Minor: a `kubectl get -o yaml` copy and the applied file differ in resourceVersion, uid and status."""
    a = _web()[0]
    b = copy.deepcopy(a)
    b["metadata"].update(
        {"resourceVersion": "42", "uid": "u-1", "generation": 3, "creationTimestamp": "2026-01-01T00:00:00Z"}
    )
    b["status"] = {"replicas": 1}
    g = _reach([*_web(), b], "deployment/web", "shop")  # no "2 different objects" error
    assert g["anchor"]["resolved"] == ["Deployment/shop/web"]
    none = _reach([*_web(), _svc()], "deployment/web", "shop", whole_bundle=True)
    detail = _leg(none, "exposure")["detail"]
    assert all(k in detail for k in ("Service", "Route", "Ingress", "HTTPRoute", "VirtualService")), detail
