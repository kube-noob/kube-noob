"""A ClusterNetworkPolicy in the input must never be dropped without a word.

`policy.networking.k8s.io/v1alpha1` AdminNetworkPolicy and BaselineAdminNetworkPolicy are listed by
kubernetes-sigs/network-policy-api as "Previous (APIs that have evolved to the next stage and are no longer actively
developed)". The API under active development is `ClusterNetworkPolicy` v1alpha2, one cluster-scoped CRD carrying
both tiers in `spec.tier`. Calico enforces it from 3.32; what other
CNIs do is not something upstream states, and `cni.py` says so rather than guessing.

kube-noob did not know the kind at all, so a cluster-scoped Admin-tier Deny written in the current API was dropped
in silence: the verdict was attributed to the NetworkPolicy tier, and the proposed fix was a NetworkPolicy that the
Admin tier would override -- applied, changing nothing. A tool whose pitch is that it says what it could not
determine cannot do that.

Since P4 the kind is EVALUATED, so these tests assert the stronger thing: the policy decides, by name and by
rule, and the fix proposed is one that would actually work. The caveat they were written for is gone, and what
replaces it has to be checked just as hard -- an answer that is confidently right is one defect away from an
answer that is confidently wrong.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kube_noob.debug.netpol import Inventory, check_reachability


def _not_found(plural: str, namespace: str | None = None, name: str | None = None) -> str:
    """What the in-cluster backend writes for a 404 on this resource's own path (debug/backends.py). A bare "the
    server could not find the requested resource" or "not there" is a read that failed, not an absent API or
    object (G279), so a stub that means "absent" says it in a backend's own words."""
    from kube_noob.debug.cluster import ALLOWED_RESOURCES

    return f"Not found: GET {ALLOWED_RESOURCES[plural].path(namespace, name)}"


ROOT = Path(__file__).resolve().parents[1]

_CNP = """
apiVersion: policy.networking.k8s.io/v1alpha2
kind: ClusterNetworkPolicy
metadata:
  name: no-cross-team-payments
spec:
  tier: Admin
  priority: 10
  subject:
    pods:
      namespaceSelector:
        matchLabels:
          team: shop
      podSelector:
        matchLabels:
          app: payments
  ingress:
    - name: "only-shop-reaches-payments"
      action: "Deny"
      from:
        - namespaces:
            matchExpressions:
              - key: team
                operator: NotIn
                values: ["shop"]
"""


def _without_admin_tier() -> str:
    """The shipped example, with its v1alpha1 admin tier removed: NetworkPolicies and workloads only."""
    text = (ROOT / "examples" / "netpol-admin-tiers.yaml").read_text(encoding="utf-8")
    return text.split("# A platform team's cluster-wide guardrail")[0]


def _reach(yaml_text: str) -> dict[str, Any]:
    inv = Inventory.from_yaml(yaml_text)
    return check_reachability(inv, "web/frontend", "shop/payments", "9090", "TCP")


def test_a_clusternetworkpolicy_decides_the_answer() -> None:
    """What the guard was holding the place for: the Admin-tier Deny is read, and it is what the verdict says."""
    out = _reach(_without_admin_tier() + _CNP)
    assert out["verdict"] == "denied"
    ingress = out["ingress"]
    assert ingress["tier"] == "ClusterNetworkPolicy"
    assert ingress["policy"] == "ClusterNetworkPolicy/no-cross-team-payments"
    assert ingress["rule"] == "only-shop-reaches-payments"
    assert "Admin tier, priority 10" in ingress["reason"]
    assert "ClusterNetworkPolicy" not in " ".join(out.get("notEvaluated", [])), (
        "a kind that is evaluated must not also be listed as one that was not"
    )


def test_the_fix_for_a_cluster_scoped_deny_is_not_a_networkpolicy() -> None:
    """The defect the old caveat existed to prevent, now that there is no caveat. A NetworkPolicy cannot
    override an Admin-tier Deny: proposing one gets it applied, changes nothing, and costs the next verdict its
    credibility. Evaluating the kind removed the warning, so the proposal itself has to be right."""
    out = _reach(_without_admin_tier() + _CNP)
    changes = out.get("proposedChanges") or []
    assert changes, "a denied answer still owes the reader a way forward"
    for change in changes:
        assert not change.get("manifest"), f"a namespace-scoped manifest cannot fix this: {change}"
        assert change.get("ownedBy") == "cluster administrator"
        assert "no NetworkPolicy in shop can override it" in change["change"]
        # v1alpha2 renamed the action, and a fix telling an administrator to add an "Allow" rule names an
        # action the API server rejects.
        assert "an Accept or Pass rule" in change["change"], change["change"]
        assert "LOWER priority number" in change["change"], "lower priority is ambiguous when lower wins"


def test_the_answer_is_printed_where_the_reader_reads_it(tmp_path: Path, capsys: Any) -> None:
    """A verdict only in the JSON is a verdict nobody sees: `policy reach` prints text by default."""
    from kube_noob.cli import main

    manifest = tmp_path / "cnp.yaml"
    manifest.write_text(_without_admin_tier() + _CNP, encoding="utf-8")
    code = main(
        [
            "policy",
            "reach",
            "--from",
            "web/frontend",
            "--to",
            "shop/payments",
            "--port",
            "9090",
            "-f",
            str(manifest),
            "--format",
            "text",
        ]
    )
    text = capsys.readouterr().out
    assert code == 1, f"a denied reachability check must exit 1; got {code}"
    assert "ClusterNetworkPolicy/no-cross-team-payments" in text
    assert "caveat:" not in text, "the kind is evaluated now, so there is nothing left to caveat"


def test_no_caveat_when_nothing_cluster_scoped_is_in_the_input() -> None:
    """The caveat machinery survives for the next unread kind, so it still has to be noise-free."""
    out = _reach(_without_admin_tier())
    for change in out.get("proposedChanges") or []:
        assert not change.get("caveat"), f"caveat added with no cluster-scoped policy present: {change}"
    assert "ClusterNetworkPolicy" not in " ".join(out.get("notEvaluated", []))


def test_the_evaluated_v1alpha1_tier_is_not_listed_as_unevaluated() -> None:
    """AdminNetworkPolicy IS evaluated, so it must not appear in the not-evaluated list alongside the new kind."""
    text = (ROOT / "examples" / "netpol-admin-tiers.yaml").read_text(encoding="utf-8")
    out = _reach(text)
    listed = " ".join(out.get("notEvaluated", []))
    assert "AdminNetworkPolicy" not in listed
    assert out["ingress"]["tier"] == "AdminNetworkPolicy"


def test_the_live_cluster_check_reads_clusternetworkpolicies_too() -> None:
    """The guard above covered pasted manifests only. `inventory_from_cluster` read the two v1alpha1 tiers and
    not `clusternetworkpolicies`, so on a cluster running the current API the live answer -- the one an operator
    trusts more, because it came from their cluster -- went back to being confidently wrong. Now the kind is
    read AND evaluated, so what this checks is that the live path collects it into the tier rather than into
    the list of policies nobody read.
    """
    from kube_noob.debug.cluster import ALLOWED_RESOURCES as RESOURCES
    from kube_noob.debug.netpol import inventory_from_cluster

    assert "clusternetworkpolicies" in RESOURCES, "the read-only allowlist has no entry for the current API"
    assert RESOURCES["clusternetworkpolicies"].namespaced is False
    assert RESOURCES["clusternetworkpolicies"].group_version.endswith("v1alpha2")

    reads: list[str] = []

    class Backend:
        name = "fake"

        def get(self, plural: str, name: str | None = None, namespace: str | None = None) -> dict[str, Any]:
            reads.append(plural)
            if plural == "clusternetworkpolicies":
                import yaml

                return {"kind": "List", "items": [yaml.safe_load(_CNP)]}
            if plural in {"ciliumclusterwidenetworkpolicies", "globalnetworkpolicies"}:
                raise __import__("kube_noob.errors", fromlist=["x"]).ClusterAccessError(
                    _not_found(plural, namespace, name)
                )
            if plural in {"adminnetworkpolicies", "baselineadminnetworkpolicies", "networkpolicies"}:
                return {"kind": "List", "items": []}
            if plural == "namespaces":
                return {"kind": "Namespace", "metadata": {"name": name, "labels": {"team": name}}}
            raise __import__("kube_noob.errors", fromlist=["x"]).ClusterAccessError(_not_found(plural, namespace, name))

    inv = inventory_from_cluster(Backend(), "web/frontend", "shop/payments")
    assert reads.count("clusternetworkpolicies") == 1, "read once, cluster-scoped, not per namespace"
    assert inv.cnp_admin.policies, f"the kind was read but never reached the Admin tier: {inv.other_policies}"
    assert not any(ref.startswith("ClusterNetworkPolicy/") for ref in inv.other_policies), (
        f"an evaluated kind must not also be listed as unevaluated: {inv.other_policies}"
    )


def test_a_cluster_without_the_current_api_is_not_an_error() -> None:
    """Most clusters do not have the v1alpha2 CRD. A 404 is normal and must leave a working answer with a note."""
    from kube_noob.debug.netpol import inventory_from_cluster
    from kube_noob.errors import ClusterAccessError

    class Backend:
        name = "fake"

        def get(self, plural: str, name: str | None = None, namespace: str | None = None) -> dict[str, Any]:
            if plural in {
                "clusternetworkpolicies",
                "ciliumclusterwidenetworkpolicies",
                "globalnetworkpolicies",
            }:
                raise ClusterAccessError(_not_found(plural, namespace, name))
            if plural in {"adminnetworkpolicies", "baselineadminnetworkpolicies", "networkpolicies"}:
                return {"kind": "List", "items": []}
            if plural == "namespaces":
                return {"kind": "Namespace", "metadata": {"name": name, "labels": {}}}
            raise ClusterAccessError(_not_found(plural, namespace, name))

    inv = inventory_from_cluster(Backend(), "web/frontend", "shop/payments")
    assert any("ClusterNetworkPolicy" in n for n in inv.notes), f"no note explaining the gap: {inv.notes}"
    assert inv.other_policies == []


def test_the_read_only_steps_name_the_cluster_s_own_command() -> None:
    """On OpenShift the whole answer is written in `oc`; a lone `kubectl` is a command the reader may not have."""
    inv = Inventory.from_yaml(_without_admin_tier() + _CNP)
    out = check_reachability(inv, "web/frontend", "shop/payments", "9090", "TCP", cli="oc")
    steps = [s["command"] for s in out.get("readOnlyNextSteps", [])]
    assert any("oc get adminnetworkpolicy,baselineadminnetworkpolicy,clusternetworkpolicy" in s for s in steps)
    assert not any("kubectl" in s for s in steps)
