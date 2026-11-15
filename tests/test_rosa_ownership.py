"""What Red Hat owns on a ROSA cluster and what the customer owns, as one table rather than four conditionals (G304).

`--platform rosa-hcp` and `--platform rosa-classic` existed before this and the rules did not know what they
meant. The three worst answers a control-plane rule can give on a managed platform, in order: reporting a
finding the customer cannot fix; reading an absent control plane as CLEAN; and -- the one that was actually
there -- giving all three OpenShift-family platforms the same sentence, which called a control plane that runs
in a Red Hat-owned AWS account "operator-managed".

The split is NOT "managed platform, read nothing": Red Hat's own documentation says the worker kubelet is the
customer's on every ROSA architecture (`rosa create kubeletconfig` plus a machine pool), while the API server,
etcd and the control-plane kubelet are Red Hat's. `audit/ownership.py` carries the sources and the retrieval
date.
"""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Report
from kube_noob.audit.ownership import COMPONENTS, RESPONSIBILITY, owner
from kube_noob.catalog import PLATFORMS

MANAGED = ("rosa-classic", "rosa-hcp")


def _report(text: str, platform: str, version: str | None = "4.20") -> Report:
    return analyze(text, platform, version)


def _hits(report: Report, rule_id: str) -> list[Any]:
    return [f for f in report.findings if f.rule_id == rule_id]


def _declined(report: Report, rule_id: str) -> bool:
    said = any(a.startswith(f"{rule_id} was not evaluated") for a in report.assumptions)
    return rule_id not in report.evaluated_rules and said


def _why(report: Report, rule_id: str) -> str:
    return " ".join(a for a in report.assumptions if a.startswith(f"{rule_id} was not evaluated"))


def _pod(name: str, command: list[str]) -> str:
    doc = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": "kube-system"},
        "spec": {
            "hostNetwork": True,
            "containers": [{"name": name, "image": f"registry.k8s.io/{name}:v1.35.0", "command": command}],
        },
    }
    return yaml.safe_dump(doc, sort_keys=False)


APISERVER = _pod("kube-apiserver", ["kube-apiserver", "--authorization-mode=AlwaysAllow"])
ETCD = _pod(
    "etcd", ["etcd", "--listen-client-urls=http://10.0.0.10:2379", "--advertise-client-urls=http://10.0.0.10:2379"]
)
KUBELET = _pod("kubelet", ["kubelet", "--read-only-port=10255", "--authorization-mode=AlwaysAllow"])


def _kubeletconfig(role: str | None) -> str:
    spec: dict[str, Any] = {"kubeletConfig": {"readOnlyPort": 10255}}
    if role is not None:
        spec["machineConfigPoolSelector"] = {
            "matchLabels": {f"pools.operator.machineconfiguration.openshift.io/{role}": ""}
        }
    doc = {
        "apiVersion": "machineconfiguration.openshift.io/v1",
        "kind": "KubeletConfig",
        "metadata": {"name": "set-kubelet-config"},
        "spec": spec,
    }
    return yaml.safe_dump(doc, sort_keys=False)


def _machineconfig(role: str | None) -> str:
    import base64
    import json

    body = json.dumps(
        {"apiVersion": "kubelet.config.k8s.io/v1beta1", "kind": "KubeletConfiguration", "readOnlyPort": 10255}
    )
    metadata: dict[str, Any] = {"name": "99-kubelet"}
    if role is not None:
        metadata["labels"] = {"machineconfiguration.openshift.io/role": role}
    doc = {
        "apiVersion": "machineconfiguration.openshift.io/v1",
        "kind": "MachineConfig",
        "metadata": metadata,
        "spec": {
            "config": {
                "ignition": {"version": "3.4.0"},
                "storage": {
                    "files": [
                        {
                            "path": "/etc/kubernetes/kubelet.conf",
                            "contents": {"source": "data:;base64," + base64.b64encode(body.encode()).decode()},
                        }
                    ]
                },
            }
        },
    }
    return yaml.safe_dump(doc, sort_keys=False)


# =====================================================================================================
# The table itself
# =====================================================================================================


def test_every_platform_kube_noob_accepts_has_a_row_for_every_component() -> None:
    """A platform added to PLATFORMS without a row would fall through to "the customer's" (class 4)."""
    assert set(RESPONSIBILITY) == set(PLATFORMS)
    for platform, row in RESPONSIBILITY.items():
        assert set(row) == set(COMPONENTS), platform


def test_a_component_nobody_owns_has_a_reason_and_one_the_customer_owns_has_none() -> None:
    for platform, row in RESPONSIBILITY.items():
        for component, own in row.items():
            assert bool(own.why) is not own.theirs, (platform, component)
            if own.why:
                assert own.why == own.why.strip() and not own.why.endswith("."), (platform, component)


def test_the_two_rosa_architectures_do_not_share_one_sentence() -> None:
    """They are different facts: on HCP the control plane is not in this cluster, on Classic it is."""
    for component in ("kube-apiserver", "etcd"):
        hcp = owner("rosa-hcp", component).why
        classic = owner("rosa-classic", component).why
        assert hcp != classic
        assert "hosted control planes" in hcp
        assert "ROSA Classic" in classic


def test_the_worker_kubelet_is_the_customers_on_every_platform() -> None:
    """Red Hat documents `rosa create kubeletconfig` plus a machine pool, so this one IS theirs to configure."""
    for platform in PLATFORMS:
        assert owner(platform, "kubelet-worker").theirs, platform


def test_the_control_plane_kubelet_is_not_the_customers_on_rosa() -> None:
    for platform in MANAGED:
        assert not owner(platform, "kubelet").theirs, platform


def test_every_decline_cites_the_document_the_split_came_from() -> None:
    """A reader told "this is not yours to configure" is being told something about their support contract, and
    should be able to check it against the page it came from rather than take kube-noob's word (G309)."""
    from kube_noob.audit.ownership import RESPONSIBILITY_SOURCE

    assert "retrieved" in RESPONSIBILITY_SOURCE
    for platform, row in RESPONSIBILITY.items():
        for component, own in row.items():
            if own.theirs:
                assert own.cited == "", (platform, component)
            else:
                assert own.cited.endswith(f"({RESPONSIBILITY_SOURCE})"), (platform, component)
                assert own.why in own.cited


@pytest.mark.parametrize(("text", "rule_id"), [(APISERVER, "KN-S038"), (ETCD, "KN-S039"), (KUBELET, "KN-S042")])
def test_the_reason_a_rule_prints_names_that_document(text: str, rule_id: str) -> None:
    from kube_noob.audit.ownership import RESPONSIBILITY_SOURCE

    assert RESPONSIBILITY_SOURCE in _why(_report(text, "rosa-hcp"), rule_id)


def test_an_unknown_platform_is_read_rather_than_silenced() -> None:
    """A typo must not turn every control-plane rule off; the CLI refuses a platform outside PLATFORMS."""
    assert owner("rosa-hpc", "kube-apiserver").theirs


# =====================================================================================================
# What the rules do with it
# =====================================================================================================


@pytest.mark.parametrize("platform", MANAGED)
@pytest.mark.parametrize(
    ("text", "rule_id"),
    [(APISERVER, "KN-S038"), (ETCD, "KN-S039"), (KUBELET, "KN-S042"), (KUBELET, "KN-S043")],
)
def test_a_control_plane_component_on_rosa_declines_and_never_reports_a_finding(
    platform: str, text: str, rule_id: str
) -> None:
    report = _report(text, platform)
    assert not _hits(report, rule_id)
    assert _declined(report, rule_id)
    assert "not yours to configure" in _why(report, rule_id)


@pytest.mark.parametrize("platform", MANAGED)
@pytest.mark.parametrize("rule_id", ["KN-S038", "KN-S039", "KN-S042"])
def test_a_control_plane_component_on_rosa_is_never_read_as_clean(platform: str, rule_id: str) -> None:
    """The worst of the three answers: a control plane that is not the customer's, reported as examined and fine."""
    text = _pod("kube-apiserver", ["kube-apiserver", "--authorization-mode=Node,RBAC", "--anonymous-auth=false"])
    report = _report(text + "---\n" + ETCD + "---\n" + KUBELET, platform)
    assert rule_id not in report.evaluated_rules


@pytest.mark.parametrize("platform", MANAGED)
@pytest.mark.parametrize("shape", ["kubeletconfig", "machineconfig"])
def test_a_worker_kubelet_on_rosa_is_read_because_the_customer_configures_it(platform: str, shape: str) -> None:
    text = _kubeletconfig("worker") if shape == "kubeletconfig" else _machineconfig("worker")
    report = _report(text, platform)
    assert any("10255" in f.message for f in _hits(report, "KN-S042")), _why(report, "KN-S042")


@pytest.mark.parametrize("platform", MANAGED)
@pytest.mark.parametrize("shape", ["kubeletconfig", "machineconfig"])
def test_a_master_kubelet_on_rosa_is_declined(platform: str, shape: str) -> None:
    text = _kubeletconfig("master") if shape == "kubeletconfig" else _machineconfig("master")
    report = _report(text, platform)
    assert not _hits(report, "KN-S042")
    assert _declined(report, "KN-S042")


@pytest.mark.parametrize("platform", MANAGED)
@pytest.mark.parametrize("shape", ["kubeletconfig", "machineconfig"])
def test_a_kubelet_object_that_does_not_state_its_role_is_declined_on_rosa(platform: str, shape: str) -> None:
    """class 4: an unstated role must not be read as the worker's, which is the owner that CAN be audited."""
    text = _kubeletconfig(None) if shape == "kubeletconfig" else _machineconfig(None)
    report = _report(text, platform)
    assert not _hits(report, "KN-S042")
    assert "does not say which node role" in _why(report, "KN-S042")


def test_a_custom_pool_selector_does_not_count_as_a_role() -> None:
    doc = yaml.safe_dump(
        {
            "apiVersion": "machineconfiguration.openshift.io/v1",
            "kind": "KubeletConfig",
            "metadata": {"name": "k"},
            "spec": {
                "machineConfigPoolSelector": {"matchLabels": {"custom-kubelet": "small-pods"}},
                "kubeletConfig": {"readOnlyPort": 10255},
            },
        }
    )
    report = _report(doc, "rosa-hcp")
    assert not _hits(report, "KN-S042")
    assert _declined(report, "KN-S042")


def test_a_selector_naming_both_pools_does_not_pick_one() -> None:
    """class 5: two roles in one selector is a conflict, not a reason to pick whichever sorts first."""
    doc = yaml.safe_dump(
        {
            "apiVersion": "machineconfiguration.openshift.io/v1",
            "kind": "KubeletConfig",
            "metadata": {"name": "k"},
            "spec": {
                "machineConfigPoolSelector": {
                    "matchLabels": {
                        "pools.operator.machineconfiguration.openshift.io/master": "",
                        "pools.operator.machineconfiguration.openshift.io/worker": "",
                    }
                },
                "kubeletConfig": {"readOnlyPort": 10255},
            },
        }
    )
    assert _declined(_report(doc, "rosa-hcp"), "KN-S042")


# =====================================================================================================
# Off the managed platforms nothing changed (class 21: the neighbouring platform)
# =====================================================================================================


@pytest.mark.parametrize(("text", "rule_id"), [(APISERVER, "KN-S038"), (ETCD, "KN-S039"), (KUBELET, "KN-S043")])
def test_the_same_manifests_are_still_read_on_plain_kubernetes(text: str, rule_id: str) -> None:
    assert _hits(_report(text, "kubernetes", None), rule_id)


def test_etcd_is_still_read_on_self_managed_openshift_where_a_person_may_run_their_own() -> None:
    """OpenShift's own etcd is operator-managed, so the table declines it there as it does the API server."""
    report = _report(ETCD, "openshift")
    assert not _hits(report, "KN-S039")
    assert "operator-managed" in _why(report, "KN-S039")


def test_a_kubelet_on_self_managed_openshift_is_the_persons_to_configure() -> None:
    report = _report(_kubeletconfig("master"), "openshift")
    assert any("10255" in f.message for f in _hits(report, "KN-S042"))


def test_no_ownership_reason_repeats_a_value_from_the_input() -> None:
    """G281: the object's own reference is named (cleaned, as every decline names it); its VALUES are not."""
    marker = "ZZmarkerZZ"
    text = _pod("kube-apiserver", ["kube-apiserver", f"--authorization-mode={marker}", f"--anonymous-auth={marker}"])
    why = _why(_report(text, "rosa-hcp"), "KN-S038")
    assert why
    assert marker not in why
