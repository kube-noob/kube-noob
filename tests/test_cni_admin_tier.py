"""A policy the CNI does not enforce must not decide the answer (roadmap P7).

kube-noob evaluates AdminNetworkPolicy and BaselineAdminNetworkPolicy with OVN-Kubernetes semantics. Calico does
not enforce either from 3.32 onward -- "they stop taking effect silently" (Tigera upgrade notes) -- so on such a
cluster the tier kube-noob trusts most is the one that does nothing, and a `Deny` it reports is a deny that is not
happening. Cilium is listed upstream with only a tracking issue and no stated support, so for Cilium the answer is
not "enforced" and not "ignored": it is unknown, and an unknown must not read as either.
"""

from __future__ import annotations

from typing import Any

import pytest

from kube_noob.debug.cni import ADMIN_TIER_SOURCES, admin_tier_support, parse_cni
from kube_noob.debug.netpol import Inventory, check_reachability
from tests.test_netpol_anp import ALLOW_ALL_NP, DENY_ALL_NP, WORKLOADS, _anp, _banp


def _check(*parts: str, cni: str | None = None) -> dict[str, Any]:
    inv = Inventory.from_yaml("\n---\n".join((WORKLOADS, *parts)), cni=cni)
    return check_reachability(inv, "monitoring/prometheus", "shop/orders", 8080)


# -- the table ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "version", "expected"),
    [
        ("calico", "3.32", "not-enforced"),
        ("calico", "v3.32.1", "not-enforced"),
        ("calico", "3.33", "not-enforced"),
        ("calico", "3.31", "enforced"),
        ("calico", "3.29.0", "enforced"),
        ("calico", "3.28", "unknown"),  # before the first version upstream lists as implementing it
        ("calico", None, "unknown"),  # the version is what decides, so without it there is no answer
        ("ovn-kubernetes", None, "enforced"),
        ("antrea", "2.4", "enforced"),
        ("cilium", "1.18", "unknown"),  # upstream lists a tracking issue and no stated support
        ("flannel", None, "unknown"),
    ],
)
def test_the_table_answers_only_where_upstream_does(name: str, version: str | None, expected: str) -> None:
    assert admin_tier_support(name, version) == expected


def test_every_entry_names_where_it_comes_from() -> None:
    """A claim about someone else's enforcement needs a citation, or it is this tool guessing."""
    assert ADMIN_TIER_SOURCES
    for url, retrieved in ADMIN_TIER_SOURCES:
        assert url.startswith("https://") and len(retrieved) == 10


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("calico:3.32", ("calico", "3.32")),
        ("Calico", ("calico", None)),
        ("calico:v3.32.1", ("calico", "3.32.1")),
        ("  ovn-kubernetes : 1.0 ", ("ovn-kubernetes", "1.0")),
    ],
)
def test_the_flag_parses(raw: str, expected: tuple[str, str | None]) -> None:
    assert parse_cni(raw) == expected


@pytest.mark.parametrize("raw", ["", ":", "calico:", "calico:3.32:1", "x" * 80, "calico:not-a-version"])
def test_a_bad_value_is_refused_rather_than_read_as_a_cni(raw: str) -> None:
    with pytest.raises(ValueError):
        parse_cni(raw)


# -- the verdict ----------------------------------------------------------------------------------------------


def test_an_admin_deny_a_cni_ignores_does_not_deny() -> None:
    """The headline case. The ANP says Deny, the NetworkPolicy allows everything, and Calico 3.32 enforces the
    second one only -- so the traffic flows, and the operator needs to know their guardrail is not a guardrail."""
    assert _check(ALLOW_ALL_NP, _anp(10, "Deny"))["verdict"] == "denied"
    out = _check(ALLOW_ALL_NP, _anp(10, "Deny"), cni="calico:3.32")
    assert out["verdict"] == "allowed"
    assert out["ingress"]["tier"] == "NetworkPolicy"
    inert = out["inertPolicies"]
    assert [p["policy"] for p in inert] == ["AdminNetworkPolicy/guardrail"]
    assert inert[0]["replacement"] == "ClusterNetworkPolicy"
    assert "3.32" in inert[0]["reason"] and "calico" in inert[0]["reason"].lower()
    assert "not enforced" in out["summary"].lower() or "inert" in out["summary"].lower()


def test_an_admin_allow_a_cni_ignores_does_not_allow() -> None:
    """The same error in the other direction: the ANP Allow was overriding a NetworkPolicy deny."""
    assert _check(DENY_ALL_NP, _anp(10, "Allow"))["verdict"] == "allowed"
    out = _check(DENY_ALL_NP, _anp(10, "Allow"), cni="calico:3.32")
    assert out["verdict"] == "denied"
    assert out["ingress"]["tier"] == "NetworkPolicy"


def test_a_baseline_a_cni_ignores_leaves_the_traffic_allowed() -> None:
    """A BANP decides what no NetworkPolicy selects. Ignored, that traffic is allowed by default."""
    assert _check(_banp("Deny"))["verdict"] == "denied"
    out = _check(_banp("Deny"), cni="calico:3.32")
    assert out["verdict"] == "allowed"
    assert [p["policy"] for p in out["inertPolicies"]] == ["BaselineAdminNetworkPolicy/default"]


def test_a_version_that_still_enforces_decides_as_before() -> None:
    out = _check(ALLOW_ALL_NP, _anp(10, "Deny"), cni="calico:3.31")
    assert out["verdict"] == "denied"
    assert out["ingress"]["tier"] == "AdminNetworkPolicy"
    assert "inertPolicies" not in out


def test_an_unknown_cni_makes_the_answer_undetermined_rather_than_either() -> None:
    """Cilium may or may not enforce the tier. Evaluating it guesses enforcement; dropping it guesses the reverse."""
    out = _check(ALLOW_ALL_NP, _anp(10, "Deny"), cni="cilium:1.18")
    assert out["verdict"] == "undetermined"
    assert "AdminNetworkPolicy" in " ".join(out.get("notEvaluated", []) + out.get("notes", []))


def test_an_unknown_cni_with_no_admin_policy_answers_normally() -> None:
    """The unknown is about the tier, not about the cluster: with nothing in that tier there is nothing unknown."""
    assert _check(ALLOW_ALL_NP, cni="cilium:1.18")["verdict"] == "allowed"
    assert _check(DENY_ALL_NP, cni="calico:3.32")["verdict"] == "denied"


def test_nothing_is_reported_inert_when_the_tier_is_empty() -> None:
    assert "inertPolicies" not in _check(ALLOW_ALL_NP, cni="calico:3.32")


def test_no_cni_keeps_the_documented_ovn_kubernetes_semantics() -> None:
    """The default is unchanged: this feature is opt-in, so an existing answer cannot move under anyone."""
    assert _check(ALLOW_ALL_NP, _anp(10, "Deny"))["verdict"] == "denied"
    assert _check(_banp("Deny"))["verdict"] == "denied"


# -- the surfaces -------------------------------------------------------------------------------------------------


def test_the_flag_reaches_the_evaluator_and_the_terminal(capsys: pytest.CaptureFixture[str], tmp_path: Any) -> None:
    """A finding only the JSON carries is a finding the operator does not read."""
    from kube_noob.cli import main

    f = tmp_path / "policies.yaml"
    f.write_text("\n---\n".join((WORKLOADS, ALLOW_ALL_NP, _anp(10, "Deny"))))
    args = ["policy", "reach", "--from", "monitoring/prometheus", "--to", "shop/orders", "--port", "8080", "-f", str(f)]
    assert main(args) == 1  # the ANP denies it, so the command exits non-zero
    assert capsys.readouterr().out.startswith("DENIED")
    assert main([*args, "--cni", "calico:3.32"]) == 0
    text = capsys.readouterr().out
    assert text.startswith("ALLOWED")
    assert "NOT ENFORCED  AdminNetworkPolicy/guardrail" in text
    assert "replace it with an equivalent ClusterNetworkPolicy" in text


def test_a_bad_flag_value_is_refused_by_the_schema(tmp_path: Any) -> None:
    from pydantic import ValidationError

    from kube_noob.toolkit import NetpolCheckIn

    with pytest.raises(ValidationError):
        NetpolCheckIn(manifests=WORKLOADS, source="a/b", destination="c/d", port=80, cni="calico:")
    ok = NetpolCheckIn(manifests=WORKLOADS, source="a/b", destination="c/d", port=80, cni="Calico:v3.32.1")
    assert ok.cni == "calico:3.32.1"  # normalised once, at the boundary


def test_the_tool_schema_documents_the_flag() -> None:
    """An MCP client can only pass it if the schema says it exists and what it decides."""
    from kube_noob.toolkit import NetpolCheckIn

    prop = NetpolCheckIn.model_json_schema()["properties"]["cni"]
    assert "3.32" in prop["description"] and "undetermined" in prop["description"]


# -- a red team on the above found these ------------------------------------------------------------------------


@pytest.mark.parametrize("version", ["3", "v3", "03", "4", "9999"])
def test_a_version_too_coarse_to_decide_is_unknown(version: str) -> None:
    """`calico:3` does not distinguish 3.31 from 3.32, and the first version read it as enforcing.

    The comparison truncated the TABLE's bound to the length of the INPUT, so (3,) >= (3,) answered "enforced"
    -- an unknown read as a pass, on the very question this module exists to answer.
    """
    assert admin_tier_support("calico", version) == "unknown"


def test_a_version_past_the_removal_is_not_enforced_however_far_past() -> None:
    """Tigera's wording is "from 3.32 onward", so extrapolating forward is reading the source, not guessing."""
    assert admin_tier_support("calico", "4.0") == "not-enforced"
    assert admin_tier_support("calico", "3.1000") == "not-enforced"


def test_an_implementation_upstream_lists_without_a_support_level_is_unknown() -> None:
    """The table's own rule is to answer only where upstream does. kube-network-policies has a conformance-report
    link and no stated support level, so claiming it enforces the tier overstated the source."""
    assert admin_tier_support("kube-network-policies", "0.8.1") == "unknown"
    for name in ("ovn-kubernetes", "antrea", "kube-ovn"):
        assert admin_tier_support(name) == "enforced", name


def test_an_unknown_cni_keeps_the_answer_when_the_doubt_cannot_change_it() -> None:
    """An unknown must not read as a pass. It must not discard an answer that is the same either way either.

    Both the ANP and the NetworkPolicy deny this. Whether the CNI enforces the tier is unknown, and the verdict is
    `denied` under either reading -- so withholding it told the operator nothing and failed CI for nothing. On a
    Cilium cluster one ANP anywhere made every question unanswerable.
    """
    out = _check(DENY_ALL_NP, _anp(10, "Deny"), cni="cilium:1.18")
    assert out["verdict"] == "denied"
    assert "same" in " ".join(out.get("notes", [])).lower()


def test_an_unknown_cni_keeps_an_allow_the_tier_does_not_touch() -> None:
    """The ANP here selects nothing, so the doubt is about a tier that was never going to decide."""
    narrow = _anp(10, "Deny", from_ns="nowhere")
    assert _check(ALLOW_ALL_NP, narrow, cni="cilium:1.18")["verdict"] == "allowed"


def test_the_withheld_verdict_carries_the_caveat_on_the_fix_it_proposes() -> None:
    """A proposed NetworkPolicy that an enforced admin tier would make a no-op must say so where it is read."""
    out = _check(DENY_ALL_NP, _anp(10, "Allow"), cni="cilium:1.18")
    assert out["verdict"] == "undetermined"
    fixes = [c for c in out.get("proposedChanges", []) if c.get("manifest")]
    assert fixes, "a NetworkPolicy fix is proposed here"
    assert all("changes nothing" in (c.get("caveat") or "") for c in fixes)


def test_a_direction_that_was_never_evaluated_is_not_summarised_as_allowed() -> None:
    """`decided` came from the evaluated directions only, so one allowed and one unknown direction read as
    "the NetworkPolicies would allow this traffic" -- a claim about a direction nobody decided."""
    hostnet = """
apiVersion: v1
kind: Pod
metadata:
  name: hostnet
  namespace: shop
  labels:
    app: hostnet
spec:
  hostNetwork: true
  containers:
    - name: c
      image: x:1
      ports:
        - containerPort: 8080
"""
    inv = Inventory.from_yaml("\n---\n".join((WORKLOADS, hostnet, ALLOW_ALL_NP, _anp(10, "Deny"))), cni="cilium:1.18")
    out = check_reachability(inv, "monitoring/prometheus", "shop/hostnet", 8080)
    assert out["verdict"] == "undetermined"
    assert "would allow this traffic" not in out["summary"]
    assert out.get("undetermined") == ["Ingress"] or "hostNetwork" in out["summary"]


def test_the_next_steps_name_the_kind_that_decides_now() -> None:
    """With the tier inert, `get adminnetworkpolicy` reads a kind the cluster may not even serve, and the kind
    that replaced it was missing from the list entirely."""
    out = _check(ALLOW_ALL_NP, _anp(10, "Deny"), cni="calico:3.32")
    commands = [s["command"] for s in out["readOnlyNextSteps"]]
    assert commands[0].endswith("get clusternetworkpolicy -o yaml")
    assert any("adminnetworkpolicy" in c for c in commands)


def test_a_failed_read_of_a_tier_the_cni_ignores_does_not_withhold_the_verdict() -> None:
    """A 403 on a tier the caller has just said is inert was making the live answer undetermined: the flag's whole
    promise was unapplied on the one path where the operator cannot read the policies themselves.

    The first fix stopped reading that tier at all, which dismissed the 403 and lost the finding that matters
    most -- "this AdminNetworkPolicy is in your cluster and decides nothing" needs the policy in hand. So the
    tier is read, and only its FAILURE is dismissed. Written out because the two halves pull opposite ways.
    """
    from kube_noob.debug.netpol import inventory_from_cluster
    from kube_noob.errors import ClusterAccessError

    reads: list[str] = []

    class Backend:
        name = "fake"

        def get(self, plural: str, name: str | None = None, namespace: str | None = None) -> Any:
            reads.append(plural)
            if plural in ("adminnetworkpolicies", "baselineadminnetworkpolicies"):
                # The error type a real backend raises. The first version of this fake raised RuntimeError and
                # passed only because the tier was being skipped instead of read.
                raise ClusterAccessError("forbidden: User cannot list adminnetworkpolicies at the cluster scope")
            if name is not None:  # a named read answers with the object or NotFound, never a list (G279)
                from kube_noob.debug.cluster import ALLOWED_RESOURCES

                raise ClusterAccessError(f"Not found: GET {ALLOWED_RESOURCES[plural].path(namespace, name)}")
            return {"items": []}

    inv = inventory_from_cluster(Backend(), "monitoring/prometheus", "shop/orders", "calico:3.32")
    assert "adminnetworkpolicies" in reads, "the tier is read, so an inert policy can be reported as inert"
    assert inv.tier_unreadable == [], "a failed read of a tier that decides nothing must not withhold the verdict"
    assert any("does not enforce it" in n for n in inv.notes), inv.notes


def test_a_bad_cni_is_refused_even_with_nothing_in_that_tier() -> None:
    """The early return skipped the parse, so a library caller's typo was accepted silently."""
    with pytest.raises(ValueError):
        Inventory.from_yaml(WORKLOADS, cni="not a cni")


def test_the_unknown_line_agrees_with_itself_grammatically() -> None:
    out = _check(ALLOW_ALL_NP, _anp(10, "Deny"), _anp(20, "Deny", name="second"), cni="cilium:1.18")
    assert out["verdict"] == "undetermined"
    assert "policies were read" in out["summary"] or "were read and not evaluated" in out["summary"]
