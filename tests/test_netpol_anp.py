"""AdminNetworkPolicy and BaselineAdminNetworkPolicy change the answer, so they are evaluated.

The NetworkPolicy evaluator used to list ANP and BANP under "not evaluated". That is not a gap in coverage, it is a
wrong verdict: an ANP ``Deny`` blocks traffic every NetworkPolicy allows, an ANP ``Allow`` permits traffic every
NetworkPolicy denies, and a BANP decides the cases no NetworkPolicy selects. Precedence is ANP, then NetworkPolicy,
then BANP; within the ANP tier, lower ``priority`` first and then rule order, first match wins.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from kube_noob.debug.netpol import Inventory, check_reachability


def _not_found(plural: str, namespace: str | None = None, name: str | None = None) -> str:
    """What the in-cluster backend writes for a 404 on this resource's own path (debug/backends.py). A bare "the
    server could not find the requested resource" or "not there" is a read that failed, not an absent API or
    object (G279), so a stub that means "absent" says it in a backend's own words."""
    from kube_noob.debug.cluster import ALLOWED_RESOURCES

    return f"Not found: GET {ALLOWED_RESOURCES[plural].path(namespace, name)}"


WORKLOADS = """
apiVersion: v1
kind: Namespace
metadata:
  name: shop
  labels:
    tier: app
---
apiVersion: v1
kind: Namespace
metadata:
  name: monitoring
  labels:
    tier: platform
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: orders
  namespace: shop
spec:
  template:
    metadata:
      labels:
        app: orders
    spec:
      containers:
        - name: c
          image: orders:1
          ports:
            - name: http
              containerPort: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus
  namespace: monitoring
spec:
  template:
    metadata:
      labels:
        app: prometheus
    spec:
      containers:
        - name: c
          image: prom:1
"""

ALLOW_ALL_NP = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-everything
  namespace: shop
spec:
  podSelector:
    matchLabels:
      app: orders
  policyTypes: [Ingress]
  ingress:
    - {}
"""

DENY_ALL_NP = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-everything
  namespace: shop
spec:
  podSelector:
    matchLabels:
      app: orders
  policyTypes: [Ingress]
"""


def _anp(priority: int, action: str, name: str = "guardrail", from_ns: str = "monitoring") -> str:
    return f"""
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: {name}
spec:
  priority: {priority}
  subject:
    namespaces:
      matchLabels:
        tier: app
  ingress:
    - name: "from-{from_ns}"
      action: "{action}"
      from:
        - namespaces:
            matchLabels:
              kubernetes.io/metadata.name: {from_ns}
"""


def _banp(action: str) -> str:
    return f"""
apiVersion: policy.networking.k8s.io/v1alpha1
kind: BaselineAdminNetworkPolicy
metadata:
  name: default
spec:
  subject:
    namespaces:
      matchLabels:
        tier: app
  ingress:
    - name: "baseline"
      action: "{action}"
      from:
        - namespaces: {{}}
"""


def _check(*parts: str, port: int | str = 8080) -> dict[str, Any]:
    inv = Inventory.from_yaml("\n---\n".join((WORKLOADS, *parts)))
    return check_reachability(inv, "monitoring/prometheus", "shop/orders", port)


def test_an_admin_deny_beats_a_networkpolicy_that_allows_everything() -> None:
    """The verdict without ANP is 'allowed'. With a cluster admin's Deny in front of it, the traffic does not flow,
    and reporting 'allowed' would send an operator looking for the problem in the wrong namespace."""
    assert _check(ALLOW_ALL_NP)["verdict"] == "allowed"
    out = _check(ALLOW_ALL_NP, _anp(10, "Deny"))
    assert out["verdict"] == "denied"
    assert out["ingress"]["tier"] == "AdminNetworkPolicy"
    assert "guardrail" in out["ingress"]["reason"]
    assert "allow-everything" not in out["summary"]


def test_an_admin_allow_beats_a_networkpolicy_that_denies_everything() -> None:
    """The mirror case: an admin Allow short-circuits the tier, so the namespace's own deny never runs."""
    assert _check(DENY_ALL_NP)["verdict"] == "denied"
    out = _check(DENY_ALL_NP, _anp(10, "Allow"))
    assert out["verdict"] == "allowed"
    assert out["ingress"]["tier"] == "AdminNetworkPolicy"


def test_pass_hands_the_decision_back_to_the_namespace() -> None:
    """Pass is the delegation action: it stops the ANP tier and lets the NetworkPolicy decide, which is the whole
    point of the tier for a platform team that wants to set guardrails without owning every namespace."""
    allowed = _check(ALLOW_ALL_NP, _anp(10, "Pass"))
    assert allowed["verdict"] == "allowed"
    assert allowed["ingress"]["tier"] == "NetworkPolicy"
    assert allowed["ingress"]["passedBy"] == "AdminNetworkPolicy/guardrail"
    assert "guardrail" in allowed["ingress"]["reason"] and "allow-everything" in allowed["ingress"]["reason"]
    denied = _check(DENY_ALL_NP, _anp(10, "Pass"))
    assert denied["verdict"] == "denied"
    assert denied["ingress"]["tier"] == "NetworkPolicy"
    assert denied["ingress"]["passedBy"] == "AdminNetworkPolicy/guardrail"


def test_the_lowest_priority_number_decides() -> None:
    """Lower priority wins, so a Deny at 10 beats an Allow at 20 and the order in the file is irrelevant."""
    for parts in (
        (_anp(10, "Deny", "deny-first"), _anp(20, "Allow", "allow-second")),
        (_anp(20, "Allow", "allow-second"), _anp(10, "Deny", "deny-first")),
    ):
        out = _check(ALLOW_ALL_NP, *parts)
        assert out["verdict"] == "denied"
        assert "deny-first" in out["ingress"]["reason"]


def test_rule_order_inside_one_policy_decides() -> None:
    """Within one ANP the first matching rule wins, whatever the later rules say."""
    both = """
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: ordered
spec:
  priority: 5
  subject:
    namespaces:
      matchLabels:
        tier: app
  ingress:
    - name: "first-allow"
      action: "Allow"
      from:
        - namespaces: {}
    - name: "then-deny"
      action: "Deny"
      from:
        - namespaces: {}
"""
    out = _check(DENY_ALL_NP, both)
    assert out["verdict"] == "allowed"
    assert "first-allow" in out["ingress"]["reason"]


def test_the_baseline_decides_only_what_no_networkpolicy_selects() -> None:
    """BANP is the tier for traffic nobody wrote a NetworkPolicy for. Where a NetworkPolicy does select the pod,
    the namespace's answer is final and the baseline never runs -- which is what makes BANP safe to default-deny."""
    bare = _check(_banp("Deny"))
    assert bare["verdict"] == "denied"
    assert bare["ingress"]["tier"] == "BaselineAdminNetworkPolicy"
    covered = _check(ALLOW_ALL_NP, _banp("Deny"))
    assert covered["verdict"] == "allowed"
    assert covered["ingress"]["tier"] == "NetworkPolicy"


def test_nothing_matching_anywhere_is_allowed() -> None:
    """No tier has an implicit deny of its own: with no NetworkPolicy and a baseline that does not select the pod,
    the traffic flows."""
    elsewhere = _banp("Deny").replace("tier: app", "tier: nothing-here")
    out = _check(elsewhere)
    assert out["verdict"] == "allowed"
    assert out["ingress"]["tier"] == "NetworkPolicy"


def test_a_pod_subject_is_narrower_than_a_namespace_subject() -> None:
    """``subject.pods`` carries a namespaceSelector and a podSelector; a policy whose pod selector misses the
    workload must not decide its traffic."""
    missing = """
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: other-pods
spec:
  priority: 1
  subject:
    pods:
      namespaceSelector:
        matchLabels:
          tier: app
      podSelector:
        matchLabels:
          app: payments
  ingress:
    - name: "deny"
      action: "Deny"
      from:
        - namespaces: {}
"""
    assert _check(ALLOW_ALL_NP, missing)["verdict"] == "allowed"
    hits = missing.replace("app: payments", "app: orders")
    assert _check(ALLOW_ALL_NP, hits)["verdict"] == "denied"


def test_ports_narrow_an_admin_rule() -> None:
    """An ANP rule with ports only decides the ports it names; other ports fall through to the next tier."""
    scoped = """
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: port-scoped
spec:
  priority: 1
  subject:
    namespaces:
      matchLabels:
        tier: app
  ingress:
    - name: "deny-9090"
      action: "Deny"
      from:
        - namespaces: {}
      ports:
        - portNumber:
            protocol: TCP
            port: 9090
"""
    assert _check(ALLOW_ALL_NP, scoped, port=9090)["verdict"] == "denied"
    other = _check(ALLOW_ALL_NP, scoped, port=8080)
    assert other["verdict"] == "allowed"
    assert other["ingress"]["tier"] == "NetworkPolicy"


def test_a_port_range_is_honoured() -> None:
    ranged = """
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: ranged
spec:
  priority: 1
  subject:
    namespaces:
      matchLabels:
        tier: app
  ingress:
    - name: "deny-range"
      action: "Deny"
      from:
        - namespaces: {}
      ports:
        - portRange:
            protocol: TCP
            start: 8000
            end: 8100
"""
    assert _check(ALLOW_ALL_NP, ranged, port=8080)["verdict"] == "denied"
    assert _check(ALLOW_ALL_NP, ranged, port=9000)["verdict"] == "allowed"


def test_egress_is_evaluated_in_the_same_tiers() -> None:
    """Both directions must allow, so an ANP that denies the source's egress denies the connection."""
    egress_deny = """
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: no-egress
spec:
  priority: 3
  subject:
    namespaces:
      matchLabels:
        tier: platform
  egress:
    - name: "deny-to-shop"
      action: "Deny"
      to:
        - namespaces:
            matchLabels:
              tier: app
"""
    out = _check(ALLOW_ALL_NP, egress_deny)
    assert out["verdict"] == "denied"
    assert out["egress"]["tier"] == "AdminNetworkPolicy"


def test_the_tiers_it_now_evaluates_leave_the_not_evaluated_list() -> None:
    """The list is read as the limits of the answer, so a tier that is evaluated must not still be listed as one
    that is not -- and the tiers that genuinely are not evaluated must stay."""
    out = _check(ALLOW_ALL_NP, _anp(10, "Deny"))
    joined = " ".join(out["notEvaluated"])
    assert "AdminNetworkPolicy" not in joined
    assert "EgressFirewall" in joined and "Cilium" in joined
    assert "AdminNetworkPolicy/guardrail" not in " ".join(out.get("notes", []))


def test_a_baseline_not_named_default_is_reported_not_applied() -> None:
    """BANP is a singleton that must be named ``default``; the API server rejects any other name, so a manifest
    with one is a mistake worth naming rather than a policy to evaluate."""
    wrong = _banp("Deny").replace("name: default", "name: baseline")
    out = _check(wrong)
    assert out["verdict"] == "allowed"
    assert any("default" in n for n in out.get("notes", [])), out.get("notes")


@pytest.mark.parametrize("priority", [-1, 1001])
def test_an_out_of_range_priority_is_reported(priority: int) -> None:
    out = _check(ALLOW_ALL_NP, _anp(priority, "Deny"))
    assert any("priority" in n for n in out.get("notes", [])), out.get("notes")


def test_an_unknown_action_is_reported_and_not_guessed() -> None:
    """A typo in ``action`` must not be read as the nearest valid action; the rule is skipped and said so."""
    out = _check(ALLOW_ALL_NP, _anp(10, "Drop"))
    assert out["verdict"] == "allowed"
    assert any("Drop" in n for n in out.get("notes", [])), out.get("notes")


def test_the_live_check_reads_the_admin_tiers_too() -> None:
    """The offline and live checks must not disagree. The live path reads the cluster, so it has to read the two
    cluster-scoped tiers as well, or the same traffic gets opposite verdicts depending on where the manifests came
    from -- and the live one, which an operator trusts more, would be the wrong one."""
    from kube_noob.debug.cluster import ALLOWED_RESOURCES as RESOURCES
    from kube_noob.debug.netpol import inventory_from_cluster

    assert "adminnetworkpolicies" in RESOURCES
    assert "baselineadminnetworkpolicies" in RESOURCES
    assert RESOURCES["adminnetworkpolicies"].namespaced is False
    assert RESOURCES["baselineadminnetworkpolicies"].namespaced is False

    reads: list[tuple[str, Any]] = []

    class Backend:
        name = "fake"

        def get(self, plural: str, name: str | None = None, namespace: str | None = None) -> dict[str, Any]:
            reads.append((plural, namespace))
            if plural == "adminnetworkpolicies":
                import yaml

                return {"kind": "List", "items": [yaml.safe_load(_anp(10, "Deny"))]}
            if plural == "baselineadminnetworkpolicies":
                return {"kind": "List", "items": []}
            if plural == "namespaces":
                return {"kind": "Namespace", "metadata": {"name": name, "labels": {"tier": "app"}}}
            if plural == "networkpolicies":
                return {"kind": "List", "items": []}
            if plural in (
                "clusternetworkpolicies",
                "ciliumclusterwidenetworkpolicies",
                "globalnetworkpolicies",
            ):
                raise __import__("kube_noob.errors", fromlist=["x"]).ClusterAccessError(
                    _not_found(plural, namespace, name)
                )
            if name == "orders":
                import yaml

                for doc in yaml.safe_load_all(WORKLOADS):
                    if doc and doc.get("metadata", {}).get("name") == "orders":
                        return dict(doc)
            raise __import__("kube_noob.errors", fromlist=["x"]).ClusterAccessError(_not_found(plural, namespace, name))

    inv = inventory_from_cluster(Backend(), "monitoring/prometheus", "shop/orders")
    assert [p for p, _ in reads].count("adminnetworkpolicies") == 1, "read once, not per namespace"
    assert len(inv.admin) == 1


def test_a_cluster_that_has_no_admin_tier_api_is_not_an_error() -> None:
    """ANP and BANP are a separate API that many clusters do not have installed. A 404 on them is normal and must
    leave a working NetworkPolicy answer, with a note rather than a failure."""
    from kube_noob.debug.netpol import inventory_from_cluster
    from kube_noob.errors import ClusterAccessError

    class Backend:
        name = "fake"

        def get(self, plural: str, name: str | None = None, namespace: str | None = None) -> dict[str, Any]:
            if plural in (
                "adminnetworkpolicies",
                "baselineadminnetworkpolicies",
                "clusternetworkpolicies",
                "ciliumclusterwidenetworkpolicies",
                "globalnetworkpolicies",
            ):
                raise ClusterAccessError(_not_found(plural, namespace, name))
            if plural == "namespaces":
                return {"kind": "Namespace", "metadata": {"name": name, "labels": {}}}
            if plural == "networkpolicies":
                return {"kind": "List", "items": []}
            raise ClusterAccessError(_not_found(plural, namespace, name))

    inv = inventory_from_cluster(Backend(), "monitoring/prometheus", "shop/orders")
    assert inv.admin == [] and inv.baseline == []
    assert any("AdminNetworkPolicy" in n for n in inv.notes), inv.notes


def test_it_does_not_propose_a_change_that_the_admin_tier_would_still_block() -> None:
    """A proposed NetworkPolicy cannot unblock an AdminNetworkPolicy Deny: the admin tier runs first and decides.
    Handing one over is worse than proposing nothing -- the operator applies it, the traffic still fails, and the
    next verdict from this tool is not believed. The change has to name the policy and rule that actually decided,
    and say who can change it."""
    out = _check(ALLOW_ALL_NP, _anp(10, "Deny"))
    assert out["verdict"] == "denied"
    changes = out.get("proposedChanges") or []
    assert changes, "a denied verdict still explains what would change it"
    manifests = " ".join(str(c.get("manifest", "")) for c in changes)
    assert "kind: NetworkPolicy" not in manifests, "a NetworkPolicy would not survive the admin tier"
    text = " ".join(str(c.get("change", "")) for c in changes)
    assert "AdminNetworkPolicy/guardrail" in text
    assert "from-monitoring" in text
    assert "administrator" in text.lower() or "cluster-scoped" in text.lower()


def test_a_baseline_denial_is_fixed_by_a_networkpolicy_and_says_so() -> None:
    """The mirror case: a BANP denial IS fixed by a NetworkPolicy, because any NetworkPolicy that selects the pod
    takes the decision away from the baseline. That change is worth proposing, and the reason is worth stating."""
    out = _check(_banp("Deny"))
    assert out["verdict"] == "denied"
    changes = out.get("proposedChanges") or []
    manifests = " ".join(str(c.get("manifest", "")) for c in changes)
    assert "kind: NetworkPolicy" in manifests
    assert any("baseline" in str(c.get("change", "")).lower() for c in changes), changes


def test_the_read_only_steps_name_the_tier_that_decided_first() -> None:
    """The next steps are what an operator runs to confirm the verdict. When an admin tier decided it, reading the
    namespace's NetworkPolicies first sends them to the wrong place; and the tiers are upstream CRDs, so they are
    worth reading on kubectl too, not only on oc."""
    out = _check(ALLOW_ALL_NP, _anp(10, "Deny"))
    steps = [s["command"] for s in out["readOnlyNextSteps"]]
    assert steps[0].endswith("get adminnetworkpolicy,baselineadminnetworkpolicy,clusternetworkpolicy")
    assert steps[0].startswith("kubectl ")
    plain = _check(DENY_ALL_NP)
    plain_steps = [s["command"] for s in plain["readOnlyNextSteps"]]
    assert any("adminnetworkpolicy" in s for s in plain_steps)
    assert not plain_steps[0].endswith("get adminnetworkpolicy,baselineadminnetworkpolicy")


def test_two_policies_at_one_priority_whose_rules_disagree_are_not_determined() -> None:
    """The API's own words: two AdminNetworkPolicies at the same priority in the same tier are undefined behaviour,
    so which one decides is up to the implementation and may differ between clusters and between restarts. The
    evaluator used to break the tie by the order the documents arrived in, which made a coin toss look like a
    verdict. It has to say it could not determine this instead -- and it must not then propose a NetworkPolicy,
    because a NetworkPolicy cannot override the admin tier whichever way the tie lands.
    """
    for parts in (
        (_anp(10, "Deny", "deny-side"), _anp(10, "Allow", "allow-side")),
        (_anp(10, "Allow", "allow-side"), _anp(10, "Deny", "deny-side")),
    ):
        out = _check(ALLOW_ALL_NP, *parts)
        assert out["verdict"] == "undetermined", out["verdict"]
        ing = out["ingress"]
        assert ing["undetermined"] is True
        assert ing["tier"] == "AdminNetworkPolicy"
        assert ing["evaluated"] is False
        # Both policies are named, so the operator knows which two to reconcile.
        assert set(ing["tiedPolicies"]) == {"AdminNetworkPolicy/deny-side", "AdminNetworkPolicy/allow-side"}
        assert "priority 10" in ing["reason"]
        assert "undefined" in ing["reason"]
        assert "could not determine" in out["summary"]
        # No manifest may be proposed: it would be applied and change nothing if the Deny wins.
        for change in out.get("proposedChanges") or []:
            assert "manifest" not in change, change


def test_two_policies_at_one_priority_that_agree_still_decide() -> None:
    """A tie is only undetermined when the tied policies disagree. Two Denies at the same priority deny the traffic
    whichever one the API server picks, so refusing to answer there would be a false unknown."""
    out = _check(ALLOW_ALL_NP, _anp(10, "Deny", "deny-a"), _anp(10, "Deny", "deny-b"))
    assert out["verdict"] == "denied"
    assert out["ingress"]["tier"] == "AdminNetworkPolicy"
    assert not out["ingress"].get("undetermined")


def test_a_duplicate_priority_is_reported_even_when_the_tie_does_not_change_the_verdict() -> None:
    """Relying on undefined behaviour is worth saying out loud: the config is fragile even in the run where both
    tied policies happen to agree."""
    out = _check(ALLOW_ALL_NP, _anp(10, "Deny", "deny-a"), _anp(10, "Deny", "deny-b"))
    notes = " ".join(out.get("notes") or [])
    assert "priority 10" in notes
    assert "deny-a" in notes and "deny-b" in notes


def test_a_tie_at_a_priority_that_never_matches_is_still_only_a_note() -> None:
    """A duplicate priority among policies that do not select this traffic cannot change this verdict, so it stays a
    note and does not turn a real answer into an unknown."""
    out = _check(
        ALLOW_ALL_NP,
        _anp(10, "Deny", "deny-other", from_ns="kube-system"),
        _anp(10, "Allow", "allow-other", from_ns="kube-system"),
    )
    assert out["verdict"] == "allowed"
    assert not out["ingress"].get("undetermined")
    assert "priority 10" in " ".join(out.get("notes") or [])


def _egress(priority: int, body: str, name: str = "edge") -> str:
    return f"""
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: {name}
spec:
  priority: {priority}
  subject:
    pods:
      namespaceSelector:
        matchLabels:
          tier: app
      podSelector:
        matchLabels:
          app: orders
  egress:
{body}
"""


def test_a_cidr_that_covers_every_address_denies_before_a_later_allow() -> None:
    """0.0.0.0/0 matches the pod we do not have an IP for. Skipping it used to let the next Allow decide."""
    inv = Inventory.from_yaml(
        "\n---\n".join(
            (
                WORKLOADS,
                _egress(
                    10,
                    """
    - name: wide
      action: Deny
      to:
        - networks: ["0.0.0.0/0"]
    - name: later
      action: Allow
      to:
        - namespaces:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
""",
                ),
            )
        )
    )
    out = check_reachability(inv, "shop/orders", "monitoring/prometheus", 8080)
    assert out["verdict"] == "denied"
    assert out["egress"]["tier"] == "AdminNetworkPolicy"
    assert out["egress"]["rule"] == "wide"


def test_an_address_inside_a_named_cidr_is_denied() -> None:
    inv = Inventory.from_yaml(
        WORKLOADS
        + _egress(
            10,
            """
    - name: lab
      action: Deny
      to:
        - networks: ["203.0.113.0/24"]
""",
        )
    )
    out = check_reachability(inv, "shop/orders", "203.0.113.10", 443)
    assert out["verdict"] == "denied"
    assert out["egress"]["rule"] == "lab"


def test_an_address_outside_a_named_cidr_is_not_denied_by_it() -> None:
    inv = Inventory.from_yaml(
        WORKLOADS
        + _egress(
            10,
            """
    - name: lab
      action: Deny
      to:
        - networks: ["203.0.113.0/24"]
""",
        )
    )
    out = check_reachability(inv, "shop/orders", "198.51.100.10", 443)
    assert out["verdict"] == "allowed"


def test_a_cidr_that_might_cover_a_pod_ip_does_not_let_a_later_rule_allow() -> None:
    """The pod IP is not in the manifests. The Deny might match it, so the later Allow must not win."""
    inv = Inventory.from_yaml(
        "\n---\n".join(
            (
                WORKLOADS,
                _egress(
                    10,
                    """
    - name: lab
      action: Deny
      to:
        - networks: ["203.0.113.0/24"]
    - name: later
      action: Allow
      to:
        - namespaces:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
""",
                ),
            )
        )
    )
    out = check_reachability(inv, "shop/orders", "monitoring/prometheus", 8080)
    assert out["verdict"] == "undetermined"
    assert out["egress"].get("undetermined") is True


def test_a_priority_ovn_does_not_implement_does_not_decide() -> None:
    out = _check(ALLOW_ALL_NP, _anp(100, "Deny"))
    assert out["verdict"] == "allowed"
    assert out["ingress"].get("tier") != "AdminNetworkPolicy"
    assert "not evaluated" in " ".join(out.get("notes") or [])


def test_a_forbidden_read_of_the_admin_tier_is_not_a_networkpolicy_answer() -> None:
    from kube_noob.debug.netpol import inventory_from_cluster
    from kube_noob.errors import ClusterAccessError

    class Backend:
        name = "fake"

        def get(self, plural: str, name: str | None = None, namespace: str | None = None) -> dict[str, Any]:
            if plural == "adminnetworkpolicies":
                raise ClusterAccessError("Forbidden by RBAC: GET adminnetworkpolicies")
            if plural in (
                "baselineadminnetworkpolicies",
                "clusternetworkpolicies",
                "ciliumclusterwidenetworkpolicies",
                "globalnetworkpolicies",
            ):
                raise ClusterAccessError(_not_found(plural, namespace, name))
            if plural == "namespaces":
                return {"kind": "Namespace", "metadata": {"name": name, "labels": {"tier": "app"}}}
            if plural == "networkpolicies":
                return {"kind": "List", "items": []}
            if name == "orders":
                import yaml

                for doc in yaml.safe_load_all(WORKLOADS):
                    if doc and doc.get("metadata", {}).get("name") == "orders":
                        return dict(doc)
            if name == "prometheus":
                import yaml

                for doc in yaml.safe_load_all(WORKLOADS):
                    if doc and doc.get("metadata", {}).get("name") == "prometheus":
                        return dict(doc)
            raise ClusterAccessError(_not_found(plural, namespace, name))

    inv = inventory_from_cluster(Backend(), "monitoring/prometheus", "shop/orders")
    out = check_reachability(inv, "monitoring/prometheus", "shop/orders", 8080)
    assert out["verdict"] == "undetermined"
    assert "AdminNetworkPolicy" in out["undeterminedBy"]
    assert not out.get("proposedChanges")


def test_the_text_surface_shows_the_note_and_exits_unknown(tmp_path: Path, capsys: Any) -> None:
    from kube_noob.cli import main

    manifest = tmp_path / "anp.yaml"
    manifest.write_text(
        "\n---\n".join(
            (
                WORKLOADS,
                _egress(
                    10,
                    """
    - name: lab
      action: Deny
      to:
        - networks: ["203.0.113.0/24"]
    - name: later
      action: Allow
      to:
        - namespaces:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
""",
                ),
            )
        ),
        encoding="utf-8",
    )
    code = main(
        [
            "policy",
            "reach",
            "--from",
            "shop/orders",
            "--to",
            "monitoring/prometheus",
            "--port",
            "8080",
            "-f",
            str(manifest),
            "--format",
            "text",
        ]
    )
    text = capsys.readouterr().out
    assert code == 1
    assert "UNDETERMINED" in text
    assert "might select" in text


def test_a_lower_priority_decides_before_a_tie_higher_up() -> None:
    """Precedence still runs lowest number first: a clean Deny at 5 settles the traffic and the conflicting pair at
    10 is never reached, so the answer is a verdict, not an unknown."""
    out = _check(ALLOW_ALL_NP, _anp(5, "Deny", "clean-deny"), _anp(10, "Allow", "tie-a"), _anp(10, "Deny", "tie-b"))
    assert out["verdict"] == "denied"
    assert "clean-deny" in out["ingress"]["reason"]
    assert not out["ingress"].get("undetermined")


def test_the_reach_command_prints_and_exits_on_an_undetermined_verdict(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Two things a CI job depends on: the unknown is visible in the default text output, not only in the JSON, and
    the exit code is not 0. ``policy reach`` returns 0 only for 'allowed'."""
    from kube_noob.cli import main

    bundle = tmp_path / "tie.yaml"
    bundle.write_text(
        "\n---\n".join((WORKLOADS, ALLOW_ALL_NP, _anp(10, "Deny", "deny-side"), _anp(10, "Allow", "allow-side")))
    )
    args = ["policy", "reach", "--from", "monitoring/prometheus", "--to", "shop/orders", "--port", "8080"]
    rc = main([*args, "-f", str(bundle)])
    text = capsys.readouterr().out
    assert rc == 1, text
    assert text.startswith("UNDETERMINED  "), text
    assert "deny-side" in text and "allow-side" in text
    assert "fix (needs approval)" not in text, text


def test_a_host_network_pod_is_not_reported_as_allowed() -> None:
    """NetworkPolicy does not apply to hostNetwork. The old answer said so and then set allowed, so the verdict
    was allowed and a job exited 0. Unknown is the answer. It is not denied: the policy was not evaluated."""
    host = WORKLOADS.replace(
        "    spec:\n      containers:\n        - name: c\n          image: orders:1",
        "    spec:\n      hostNetwork: true\n      containers:\n        - name: c\n          image: orders:1",
        1,
    )
    inv = Inventory.from_yaml("\n---\n".join((host, ALLOW_ALL_NP)))
    out = check_reachability(inv, "monitoring/prometheus", "shop/orders", 8080)
    assert out["verdict"] == "undetermined", out["summary"]
    assert out["ingress"].get("undetermined") is True
    assert out["ingress"]["allowed"] is False
    assert "proposedChanges" not in out


def test_a_host_network_direction_does_not_hide_a_deny() -> None:
    """The source uses hostNetwork, so its egress is unknown. The destination's NetworkPolicy still denies
    ingress. That deny stands. Unknown does not promote it, and it does not become allowed."""
    host = WORKLOADS.replace(
        "    spec:\n      containers:\n        - name: c\n          image: prom:1",
        "    spec:\n      hostNetwork: true\n      containers:\n        - name: c\n          image: prom:1",
        1,
    )
    inv = Inventory.from_yaml("\n---\n".join((host, DENY_ALL_NP)))
    out = check_reachability(inv, "monitoring/prometheus", "shop/orders", 8080)
    assert out["verdict"] == "denied", out["summary"]
    assert out["egress"].get("undetermined") is True
    assert out["ingress"]["allowed"] is False


@pytest.mark.parametrize("kind", ["CiliumClusterwideNetworkPolicy", "GlobalNetworkPolicy"])
def test_an_unread_cluster_scoped_policy_is_not_allowed(kind: str) -> None:
    body = f"""
apiVersion: example.com/v1
kind: {kind}
metadata:
  name: extra
"""
    out = _check(ALLOW_ALL_NP, body)
    assert out["verdict"] == "undetermined", out
    assert any(ref.startswith(f"{kind}/") for ref in out["undeterminedBy"])
    assert "decided before any NetworkPolicy" not in out["summary"]


@pytest.mark.parametrize("kind", ["CiliumNetworkPolicy", "MultiNetworkPolicy", "EgressFirewall", "EgressNetworkPolicy"])
def test_a_policy_that_does_not_decide_this_flow_does_not_flip_it(kind: str) -> None:
    """An EgressFirewall does not decide pod-to-pod traffic. A namespace Cilium policy and a MultiNetworkPolicy
    do not decide the primary interface. Naming them is honest. Calling the NetworkPolicy answer unknown is not."""
    body = f"""
apiVersion: example.com/v1
kind: {kind}
metadata:
  name: extra
  namespace: shop
"""
    out = _check(ALLOW_ALL_NP, body)
    assert out["verdict"] == "allowed", out["summary"]
    assert any(kind in line for line in out["notEvaluated"])


def test_a_host_network_direction_does_not_hide_an_admin_deny() -> None:
    """The source uses hostNetwork, so its egress is unknown. An AdminNetworkPolicy still denies ingress.
    That deny is a decision, and unknown must not promote it to allowed or to undetermined."""
    host = WORKLOADS.replace(
        "    spec:\n      containers:\n        - name: c\n          image: prom:1",
        "    spec:\n      hostNetwork: true\n      containers:\n        - name: c\n          image: prom:1",
        1,
    )
    inv = Inventory.from_yaml("\n---\n".join((host, ALLOW_ALL_NP, _anp(10, "Deny", "admin-deny"))))
    out = check_reachability(inv, "monitoring/prometheus", "shop/orders", 8080)
    assert out["verdict"] == "denied", out["summary"]
    assert out["egress"].get("undetermined") is True
    assert out["ingress"]["allowed"] is False
    assert out["ingress"]["tier"] == "AdminNetworkPolicy"


def test_an_admin_deny_still_decides_a_host_network_subject() -> None:
    """AdminNetworkPolicy runs before NetworkPolicy. hostNetwork makes the NetworkPolicy tier unknown; it does
    not throw away a Deny the admin tier already returned for that same pod."""
    host = WORKLOADS.replace(
        "    spec:\n      containers:\n        - name: c\n          image: orders:1",
        "    spec:\n      hostNetwork: true\n      containers:\n        - name: c\n          image: orders:1",
        1,
    )
    inv = Inventory.from_yaml("\n---\n".join((host, ALLOW_ALL_NP, _anp(10, "Deny", "admin-deny"))))
    out = check_reachability(inv, "monitoring/prometheus", "shop/orders", 8080)
    assert out["verdict"] == "denied", out["summary"]
    assert out["ingress"]["tier"] == "AdminNetworkPolicy"
    assert out["ingress"].get("undetermined") is not True


def test_an_unread_cluster_policy_can_reverse_a_deny() -> None:
    body = """
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: extra
"""
    out = _check(DENY_ALL_NP, body)
    assert out["verdict"] == "undetermined", out["summary"]
    assert "would deny" in out["summary"]
    assert "decided before any NetworkPolicy" not in out["summary"]


def test_an_egress_firewall_does_not_erase_a_pod_to_pod_deny() -> None:
    body = """
apiVersion: k8s.ovn.org/v1
kind: EgressFirewall
metadata:
  name: extra
  namespace: shop
"""
    out = _check(DENY_ALL_NP, body)
    assert out["verdict"] == "denied", out["summary"]
    assert any("EgressFirewall" in line for line in out["notEvaluated"])


def test_host_network_plus_an_unread_policy_is_not_called_a_deny() -> None:
    """hostNetwork sets allowed to false because unknown is not a pass. That flag must not be narrated as
    'the NetworkPolicies would deny' when the only other fact is a policy that was never read.

    Nor as 'would allow', which is what this test used to assert. `decided` was computed from the directions that
    WERE evaluated, so one allowed direction beside one undetermined direction read as "the NetworkPolicies would
    allow this traffic" -- a claim about a decision nobody made. With a direction undecided the pair has no
    answer, and the summary now carries that direction's own reason instead.
    """
    host = WORKLOADS.replace(
        "    spec:\n      containers:\n        - name: c\n          image: orders:1",
        "    spec:\n      hostNetwork: true\n      containers:\n        - name: c\n          image: orders:1",
        1,
    )
    body = """
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: extra
"""
    inv = Inventory.from_yaml("\n---\n".join((host, ALLOW_ALL_NP, body)))
    out = check_reachability(inv, "monitoring/prometheus", "shop/orders", 8080)
    assert out["verdict"] == "undetermined", out["summary"]
    assert "would deny" not in out["summary"]
    assert "would allow" not in out["summary"]
    assert "hostNetwork" in out["summary"] and out["undetermined"] == ["Ingress"]


# Published CRDs, not guessed names. Cilium v1.18.3
# pkg/k8s/apis/cilium.io/client/crds/v2/ciliumclusterwidenetworkpolicies.yaml:
# group cilium.io, version v2 (storage), scope Cluster, plural ciliumclusterwidenetworkpolicies, shortName ccnp.
# Calico v3.30.3 libcalico-go/config/crd/crd.projectcalico.org_globalnetworkpolicies.yaml:
# group crd.projectcalico.org, version v1 (storage), scope Cluster, plural globalnetworkpolicies, no shortName.
_PUBLISHED_CLUSTER_POLICIES = (
    ("CiliumClusterwideNetworkPolicy", "ciliumclusterwidenetworkpolicies", "cilium.io/v2", "ccnp"),
    ("GlobalNetworkPolicy", "globalnetworkpolicies", "crd.projectcalico.org/v1", None),
)


def test_the_live_allowlist_uses_the_published_crd() -> None:
    """A name that is not on the published CRD is a new guess. The namespace Cilium policy is a different
    question and is not smuggled in beside the cluster-scoped one."""
    from kube_noob.debug.cluster import ALIASES, ALLOWED_RESOURCES, ResourceDef

    for _kind, plural, group_version, short in _PUBLISHED_CLUSTER_POLICIES:
        assert ALLOWED_RESOURCES[plural] == ResourceDef(group_version, plural, False)
        singular = plural[:-3] + "y" if plural.endswith("ies") else plural[:-1]
        assert ALIASES[singular] == plural
        if short:
            assert ALIASES[short] == plural
    assert "gnp" not in ALIASES
    assert "ciliumnetworkpolicies" not in ALLOWED_RESOURCES


def test_the_check_that_resolves_an_unread_cluster_policy_is_the_first_one() -> None:
    """Naming the policy in JSON and then printing checks that cannot see it is the same miss as G177."""
    for kind, plural, group_version, _short in _PUBLISHED_CLUSTER_POLICIES:
        body = f"""
apiVersion: {group_version}
kind: {kind}
metadata:
  name: extra
"""
        out = _check(ALLOW_ALL_NP, body)
        commands = [step["command"] for step in out["readOnlyNextSteps"]]
        assert commands[0] == f"kubectl get {plural} -o yaml", commands


def _live(extra: dict[str, Any], policies: str = ALLOW_ALL_NP) -> Any:
    import yaml

    from kube_noob.debug.netpol import inventory_from_cluster
    from kube_noob.errors import ClusterAccessError

    docs = [d for d in yaml.safe_load_all(WORKLOADS + "\n---\n" + policies) if isinstance(d, dict)]

    class Backend:
        name = "fake"

        def __init__(self) -> None:
            self.reads: list[tuple[str, str | None]] = []

        def get(self, plural: str, name: str | None = None, namespace: str | None = None) -> dict[str, Any]:
            self.reads.append((plural, namespace))
            if plural in extra:
                spec = extra[plural]
                if spec == "absent":
                    raise ClusterAccessError(_not_found(plural, namespace, name))
                if spec == "forbidden":
                    raise ClusterAccessError("Forbidden (403)")
                return {"kind": "List", "items": spec}
            if plural in {
                "adminnetworkpolicies",
                "baselineadminnetworkpolicies",
                "clusternetworkpolicies",
                "ciliumclusterwidenetworkpolicies",
                "globalnetworkpolicies",
            }:
                raise ClusterAccessError(_not_found(plural, namespace, name))
            if plural == "namespaces" and name:
                for doc in docs:
                    if doc.get("kind") == "Namespace" and doc["metadata"]["name"] == name:
                        return doc
            if plural == "networkpolicies":
                return {
                    "kind": "NetworkPolicyList",
                    "items": [
                        doc
                        for doc in docs
                        if doc.get("kind") == "NetworkPolicy" and doc["metadata"].get("namespace") == namespace
                    ],
                }
            if name:
                wanted = {
                    "deployments": "Deployment",
                    "statefulsets": "StatefulSet",
                    "daemonsets": "DaemonSet",
                    "pods": "Pod",
                }.get(plural)
                for doc in docs:
                    meta = doc.get("metadata") or {}
                    if doc.get("kind") == wanted and meta.get("name") == name and meta.get("namespace") == namespace:
                        return doc
            raise ClusterAccessError(_not_found(plural, namespace, name))

    backend = Backend()
    inv = inventory_from_cluster(backend, "monitoring/prometheus", "shop/orders")
    return backend, inv


@pytest.mark.parametrize(
    "kind,plural",
    [(k, p) for k, p, _gv, _s in _PUBLISHED_CLUSTER_POLICIES],
)
def test_a_live_cluster_policy_is_not_a_false_allow(kind: str, plural: str) -> None:
    """Pasted files already refuse these. `policy reach` against the cluster did not list them, so the answer
    an operator trusts more was still allowed."""
    backend, inv = _live({plural: [{"metadata": {"name": "extra"}}]})
    assert [ns for got, ns in backend.reads if got == plural] == [None]
    out = check_reachability(inv, "monitoring/prometheus", "shop/orders", 8080)
    assert out["verdict"] == "undetermined", out["summary"]
    assert f"{kind}/extra" in out["undeterminedBy"]
    assert out["readOnlyNextSteps"][0]["command"] == f"kubectl get {plural} -o yaml"


@pytest.mark.parametrize("plural", ["ciliumclusterwidenetworkpolicies", "globalnetworkpolicies"])
def test_a_cluster_without_that_crd_keeps_the_networkpolicy_answer(plural: str) -> None:
    _backend, inv = _live({plural: "absent"})
    out = check_reachability(inv, "monitoring/prometheus", "shop/orders", 8080)
    assert out["verdict"] == "allowed", out["summary"]
    assert plural not in " ".join(out.get("undeterminedBy") or [])
    assert any("not installed" in note for note in inv.notes)


@pytest.mark.parametrize(
    "kind,plural",
    [(k, p) for k, p, _gv, _s in _PUBLISHED_CLUSTER_POLICIES],
)
def test_a_forbidden_read_of_a_cluster_policy_is_not_installed(kind: str, plural: str) -> None:
    _backend, inv = _live({plural: "forbidden"})
    out = check_reachability(inv, "monitoring/prometheus", "shop/orders", 8080)
    assert out["verdict"] == "undetermined", out["summary"]
    assert kind in out["undeterminedBy"]
    assert not any("not installed" in note and kind in note for note in inv.notes)


def test_a_live_cluster_policy_does_not_let_a_namespace_deny_stand_as_the_answer() -> None:
    _backend, inv = _live(
        {"ciliumclusterwidenetworkpolicies": [{"metadata": {"name": "extra"}}]},
        policies=DENY_ALL_NP,
    )
    out = check_reachability(inv, "monitoring/prometheus", "shop/orders", 8080)
    assert out["verdict"] == "undetermined", out["summary"]
    assert "would deny" in out["summary"]
