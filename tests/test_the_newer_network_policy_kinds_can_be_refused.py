"""`AdminNetworkPolicy`, `BaselineAdminNetworkPolicy` and `ClusterNetworkPolicy` can be refused (G371).

G365 made `policy reach` and `check_network_policy` ask `rules.refusal` which objects the audit reads, and
recorded the gap this file closes: the three cluster-scoped tiers have their own collectors, and `refusal` knew no
API group for `ClusterNetworkPolicy` at all, so `SUBJECT_GROUPS.get` returned `None` and nothing of that kind
could ever be refused.

Measured on this branch before the change, with the real CLI on a two-pod fixture:

* `audit -f <dir>` over an `evil.example.com/v1alpha2 ClusterNetworkPolicy`: exit 0, `notAudited: []`, no verdict
  -- an unrecognised shape read as an absent one (class 1, class 4). The same file with an
  `evil.example.com/v1alpha2 AdminNetworkPolicy` already exited 1 with the refusal row, because that kind has a
  group here; so one product gave the two kinds two different answers about the same mistake.
* `policy reach --from app/client --to app/server --port 8080` over each of the three kinds under
  `evil.example.com/v1alpha2`: `verdict: denied`, exit 1, "blocked by the ingress policies of app/pod/server" --
  the G365 shape, one API later. `anp.collect` matched `kind` alone and never looked at `apiVersion`;
  `cnp.collect` checked only that the version *ended* `/v1alpha2`, which any group can.

After: the audit refuses the `ClusterNetworkPolicy` with the same fixed phrase as every other kind, and all three
kinds under an unknown group are named under `invalid_policies` and decide nothing. The negative controls below
are the point of the change: the correct group still decides, and so does no `apiVersion` at all, which is what an
in-cluster list's items carry.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from typing import Any

import pytest

from kube_noob import cli
from kube_noob import toolkit as tk
from kube_noob.audit.rules import SUBJECT_GROUPS, refusal
from kube_noob.debug.netpol import Inventory, check_reachability
from kube_noob.toolkit import Toolkit
from kube_noob.yamlio import Document

_PODS = """\
apiVersion: v1
kind: Pod
metadata: {name: client, namespace: app, labels: {app: client}}
spec:
  containers:
  - {name: c, image: registry.example.com/c:1}
---
apiVersion: v1
kind: Pod
metadata: {name: server, namespace: app, labels: {app: server}}
spec:
  containers:
  - {name: c, image: registry.example.com/c:1}
"""

_ANP = """\
kind: AdminNetworkPolicy
metadata: {name: p1}
spec:
  priority: 10
  subject: {namespaces: {}}
  ingress:
  - {name: deny-all, action: Deny, from: [{namespaces: {}}]}
"""

_BANP = """\
kind: BaselineAdminNetworkPolicy
metadata: {name: default}
spec:
  subject: {namespaces: {}}
  ingress:
  - {name: deny-all, action: Deny, from: [{namespaces: {}}]}
"""

_CNP = """\
kind: ClusterNetworkPolicy
metadata: {name: p1}
spec:
  tier: Admin
  priority: 10
  subject: {namespaces: {}}
  ingress:
  - {name: deny-all, action: Deny, from: [{namespaces: {}}]}
"""

#: Per kind: the body, the group kube-noob reads it under, and the CNI that enforces that API. The v1alpha1 pair
#: is OVN-Kubernetes'; `ClusterNetworkPolicy` is enforced by Calico from 3.32, which is also where the v1alpha1
#: pair stops being enforced -- so each kind is asked under a CNI that does apply it, and a verdict that changes
#: is the refusal and not the enforcement table.
KINDS: dict[str, tuple[str, str, str, str]] = {
    "AdminNetworkPolicy": (_ANP, "policy.networking.k8s.io/v1alpha1", "ovn-kubernetes", "AdminNetworkPolicy/p1"),
    "BaselineAdminNetworkPolicy": (
        _BANP,
        "policy.networking.k8s.io/v1alpha1",
        "ovn-kubernetes",
        "BaselineAdminNetworkPolicy/default",
    ),
    "ClusterNetworkPolicy": (_CNP, "policy.networking.k8s.io/v1alpha2", "calico:3.32", "ClusterNetworkPolicy/p1"),
}

#: Groups that are not the one kube-noob knows these kinds under: a real group that serves no such kind, a
#: vendor's, and one nothing serves. Each keeps a `/v1alpha2` version, because the ClusterNetworkPolicy collector
#: used to accept any apiVersion whose version part ended that way.
FOREIGN = ["projectcalico.org/v1alpha2", "rbac.authorization.k8s.io/v1alpha2", "policy.networking.example/v1alpha2"]


def _manifests(kind: str, api: str | None) -> str:
    body, _, _, _ = KINDS[kind]
    head = f"apiVersion: {api}\n" if api else ""
    return f"{_PODS}---\n{head}{body}"


def _reach(kind: str, api: str | None) -> dict[str, Any]:
    _, _, cni, _ = KINDS[kind]
    inv = Inventory.from_yaml(_manifests(kind, api), "default", cni)
    return check_reachability(inv, "app/client", "app/server", 8080, "TCP", "kubectl")


# -- the negative controls first: a change that made these kinds unreadable would be the worse bug -------------


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_each_kind_under_its_own_group_is_still_read_and_still_decides(kind: str) -> None:
    out = _reach(kind, KINDS[kind][1])
    assert out["verdict"] == "denied", out.get("summary")
    assert out["ingress"]["evaluated"] is True
    assert not out.get("undeterminedBy")


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_each_kind_with_no_apiversion_at_all_is_still_read_and_still_decides(kind: str) -> None:
    """An in-cluster list's items carry no `apiVersion`, and `refusal` returns `None` for that on purpose:
    refusing them evaluated three rules on a live cluster. These collectors inherit that decision whole."""
    out = _reach(kind, None)
    assert out["verdict"] == "denied", out.get("summary")
    assert not out.get("undeterminedBy")


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_each_kind_under_its_own_group_is_not_listed_as_not_audited(kind: str, settings: Any) -> None:
    report = dict(Toolkit(settings).audit(tk.AuditIn(manifests=_manifests(kind, KINDS[kind][1]))))
    assert [row["object"] for row in report["notAudited"]] == []
    assert report["summary"].get("verdict") != "undetermined"


def test_an_absent_tier_is_still_an_absent_tier() -> None:
    """The control for every assertion above: with no policy of any kind in the input the traffic is allowed, and
    nothing is named as read-and-not-evaluated. A refusal must not be manufactured out of an absence either."""
    inv = Inventory.from_yaml(_PODS, "default", "ovn-kubernetes")
    out = check_reachability(inv, "app/client", "app/server", 8080, "TCP", "kubectl")
    assert out["verdict"] == "allowed", out.get("summary")
    assert not inv.invalid_policies
    assert not inv.other_policies


# -- the defect ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_refusal_knows_a_group_for_every_tier_kind_the_evaluator_reads(kind: str) -> None:
    """`SUBJECT_GROUPS.get(kind)` returning `None` is what made the whole kind unrefusable: `refusal` answers
    `None` for every document of it, so no apiVersion can be wrong and no row can say so."""
    assert SUBJECT_GROUPS.get(kind) == frozenset({"policy.networking.k8s.io"})
    doc = Document(index=0, data={"apiVersion": FOREIGN[0], "kind": kind, "metadata": {"name": "p1"}})
    assert refusal(doc) == f"apiVersion names a group kube-noob does not know {kind} under"


@pytest.mark.parametrize("api", FOREIGN)
@pytest.mark.parametrize("kind", sorted(KINDS))
def test_a_tier_policy_under_a_group_the_audit_refuses_decides_nothing(kind: str, api: str) -> None:
    out = _reach(kind, api)
    assert out["verdict"] == "undetermined", (
        f"a {api} {kind} was evaluated as the Kubernetes kind of that name and answered {out['verdict']!r}"
    )
    ref = KINDS[kind][3]
    assert ref in out["summary"]
    assert f"does not know {kind} under" in out["summary"]
    # It decided no direction, and it is not reported as a policy that merely happens to be present either.
    for direction in ("egress", "ingress"):
        assert ref not in json.dumps(out[direction])


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_the_audit_names_the_refused_tier_policy_and_withholds_its_verdict(kind: str, settings: Any) -> None:
    report = dict(Toolkit(settings).audit(tk.AuditIn(manifests=_manifests(kind, FOREIGN[0]))))
    rows = [row for row in report["notAudited"] if row["kind"] == kind]
    assert rows, report["notAudited"]
    assert rows[0]["why"] == f"apiVersion names a group kube-noob does not know {kind} under"
    assert report["summary"]["verdict"] == "undetermined"


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_reach_and_audit_refuse_the_same_tier_objects(kind: str, settings: Any) -> None:
    """One predicate, asked twice (class 9). Before this, `audit` refused an `AdminNetworkPolicy` under a foreign
    group while `policy reach` denied traffic from it, and neither command refused a `ClusterNetworkPolicy`."""
    for api, refused in ((KINDS[kind][1], False), (None, False), (FOREIGN[0], True), (FOREIGN[2], True)):
        manifests = _manifests(kind, api)
        report = dict(Toolkit(settings).audit(tk.AuditIn(manifests=manifests)))
        audit_refuses = any(row["kind"] == kind for row in report["notAudited"])
        inv = Inventory.from_yaml(manifests, "default", KINDS[kind][2])
        reach_refuses = any(entry.startswith(KINDS[kind][3]) for entry in inv.invalid_policies)
        assert audit_refuses == reach_refuses == refused, (kind, api, audit_refuses, reach_refuses)


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_the_mcp_tool_gives_the_same_answer(kind: str, settings: Any) -> None:
    """At the call site an agent uses: `check_network_policy` builds its own inventory."""
    out = Toolkit(settings).check_network_policy(
        tk.NetpolCheckIn(
            manifests=_manifests(kind, FOREIGN[0]),
            source="app/client",
            destination="app/server",
            port=8080,
            cni=KINDS[kind][2],
        )
    )
    assert out["verdict"] == "undetermined"


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_the_commands_do_not_print_denied_or_exit_zero(kind: str, tmp_path: Path) -> None:
    """The real commands over a real directory, which is how the defect was measured."""
    (tmp_path / "bundle.yaml").write_text(_manifests(kind, FOREIGN[0]), encoding="utf-8")
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(
            [
                "policy",
                "reach",
                "--from",
                "app/client",
                "--to",
                "app/server",
                "--port",
                "8080",
                "--cni",
                KINDS[kind][2],
                "-f",
                str(tmp_path),
            ]
        )
    text = out.getvalue()
    assert code == 1
    assert text.startswith("UNDETERMINED"), text[:200]
    assert "DENIED" not in text
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = cli.main(["audit", "-f", str(tmp_path), "--format", "json", "--fail-on", "never"])
    report = json.loads(out.getvalue())
    assert code == 1
    assert report["summary"]["verdict"] == "undetermined"
    assert [row["kind"] for row in report["notAudited"]] == [kind]


# -- class 7: the reason is built from the kind the rules declare, never from the document ---------------------


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_the_refusal_reason_is_never_built_from_the_documents_own_text(kind: str) -> None:
    """A group is a DNS-1123 subdomain, so `allowed.by.kube-noob` is a *well-formed* group and reaches the
    refusal branch rather than the malformed one. Its words must not reach the sentence that explains the
    refusal: the phrase is built from a key of `SUBJECT_GROUPS` and the fixed text around it."""
    out = _reach(kind, "allowed.by.kube-noob/v1alpha2")
    assert out["verdict"] == "undetermined"
    assert "allowed.by.kube-noob" not in out["summary"], out["summary"]
    assert f"does not know {kind} under" in out["summary"]
