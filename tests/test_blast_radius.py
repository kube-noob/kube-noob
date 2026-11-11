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
    assert legs == {("token", "reached"), ("rbac", "reached"), ("secrets", "reached"), ("node", "none")}
    assert graph["complete"] is True and graph["notDetermined"] == [] and graph["truncated"] is None
    assert "hunter2" not in json.dumps(graph), "Secret contents are never read"


def test_the_full_reference_the_scan_prints_is_accepted_and_names_must_agree() -> None:
    graph = _reach(SEEDED_DOCS, "Deployment/shop/web")
    assert graph["anchor"]["resolved"] == ["Deployment/shop/web"]
    with pytest.raises(br.ReachError, match="namespace"):
        _reach(SEEDED_DOCS, "Deployment/shop/web", "ops")


def test_a_pod_name_resolves_to_the_owner_the_scan_scores() -> None:
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
            "ownerReferences": [{"kind": "ReplicaSet", "name": "web-5d8f", "controller": True}],
        },
        "spec": {"serviceAccountName": "web-sa", "containers": [{"name": "w"}]},
    }
    graph = _reach([*SEEDED_DOCS, rs, pod], "pod/web-5d8f-x7k2q", "shop")
    assert graph["anchor"]["resolved"] == ["Deployment/shop/web"]
    assert graph["anchor"]["via"] == ["Pod/shop/web-5d8f-x7k2q", "ReplicaSet/shop/web-5d8f", "Deployment/shop/web"]
    # An owner that is not in the input is not invented: the Pod is what the scan scores, so it is the anchor.
    orphan = _reach([*SEEDED_DOCS, pod], "pod/web-5d8f-x7k2q", "shop")
    assert orphan["anchor"]["resolved"] == ["Pod/shop/web-5d8f-x7k2q"]


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
    assert any("only the ones in the input are counted" in r for r in _undetermined(some))
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
    assert graph["secretsIgnored"] == 1 and "aHVudGVy" not in json.dumps(graph)


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
    assert "not reached by any exposure in the input" in graph["summary"]
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
    r"|  (n\d+|t0)\[\"[A-Za-z0-9 ./:_\-=,()'+*@!?#;]*\"\]"
    r"|  n\d+ -->\|[a-z ]+\| n\d+"
    r"|  n\d+ -\. [a-z ]+ \.-> n\d+"
    r"|  classDef (undetermined|truncated) [a-z0-9:;# -]+"
    r"|  class n\d+(,n\d+)* undetermined"
    r"|  class t0 truncated)\Z"
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
    assert main(["posture", "reach", "deployment/web", "-n", "shop", "-f", str(SEEDED), "--require-complete"]) == 0
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
