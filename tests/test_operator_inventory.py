"""E2: the installed-operator inventory. Which OLM operators are installed, at what version, from which catalog and
channel, with what approval, in which namespaces, in what phase -- and, as part of the answer, what could not be
read. Every test is named for a behaviour; most of them are about an absence not reading as "no operators"."""

from __future__ import annotations

import io
import json
import random
import tarfile
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import operators as ops
from kube_noob import toolkit as tk
from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.errors import ClusterAccessError
from kube_noob.mustgather import ingest, sample
from kube_noob.mustgather import operators as mg_ops

ROOT = "mg/img"
MARKER = "KN-PLANTED-SECRET"


def _csv(
    name: str,
    ns: str,
    *,
    version: str | None = "1.2.3",
    phase: str = "Succeeded",
    reason: str = "InstallSucceeded",
    labels: dict[str, str] | None = None,
    annotations: dict[str, str] | None = None,
    message: str = "",
) -> dict[str, Any]:
    spec: dict[str, Any] = {"displayName": name}
    if version is not None:
        spec["version"] = version
    status: dict[str, Any] = {"phase": phase, "reason": reason}
    if message:
        status["message"] = message
    meta: dict[str, Any] = {"name": name, "namespace": ns}
    if labels:
        meta["labels"] = labels
    if annotations:
        meta["annotations"] = annotations
    return {
        "apiVersion": "operators.coreos.com/v1alpha1",
        "kind": "ClusterServiceVersion",
        "metadata": meta,
        "spec": spec,
        "status": status,
    }


def _copy(name: str, ns: str, origin: str, **kw: Any) -> dict[str, Any]:
    """A copy the way OLM writes it (operator-lifecycle-manager csvCopyPrototype): label olm.copiedFrom=<origin>,
    status.reason Copied, the source's spec and status."""
    return _csv(name, ns, reason="Copied", labels={"olm.copiedFrom": origin}, **kw)


def _sub(
    name: str,
    ns: str,
    package: str,
    *,
    installed: str | None = None,
    current: str | None = None,
    approval: str | None = "Automatic",
    channel: str = "stable",
    source: str = "redhat-operators",
    state: str = "",
    conditions: list[dict[str, Any]] | None = None,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "name": package,
        "source": source,
        "sourceNamespace": "openshift-marketplace",
        "channel": channel,
    }
    if approval is not None:
        spec["installPlanApproval"] = approval
    if config is not None:
        spec["config"] = config
    status: dict[str, Any] = {}
    if installed:
        status["installedCSV"] = installed
    if current:
        status["currentCSV"] = current
    if state:
        status["state"] = state
    if conditions:
        status["conditions"] = conditions
    return {
        "apiVersion": "operators.coreos.com/v1alpha1",
        "kind": "Subscription",
        "metadata": {"name": name, "namespace": ns},
        "spec": spec,
        "status": status,
    }


def _plan(name: str, ns: str, csvs: list[str], *, phase: str, approval: str = "Manual", approved: bool = False) -> Any:
    return {
        "apiVersion": "operators.coreos.com/v1alpha1",
        "kind": "InstallPlan",
        "metadata": {"name": name, "namespace": ns},
        "spec": {"clusterServiceVersionNames": csvs, "approval": approval, "approved": approved},
        "status": {"phase": phase},
    }


def _yaml(*docs: dict[str, Any]) -> str:
    return yaml.safe_dump_all(list(docs), sort_keys=True)


def _inv(*docs: dict[str, Any]) -> dict[str, Any]:
    return ops.inventory(ops.from_manifests(_yaml(*docs)))


def _one(inv: dict[str, Any], csv: str | None = None, subscription: str | None = None) -> dict[str, Any]:
    hits = [
        o
        for o in inv["operators"]
        if (csv is None or o.get("csv") == csv) and (subscription is None or o.get("subscription") == subscription)
    ]
    assert len(hits) == 1, inv["operators"]
    return hits[0]


def _bundle(tmp_path: Path, files: dict[str, str], name: str = "t.tgz") -> ingest.Bundle:
    path = tmp_path / name
    with tarfile.open(path, "w:gz") as tf:
        for rel, data in files.items():
            raw = data.encode()
            info = tarfile.TarInfo(f"{ROOT}/{rel}")
            info.size, info.mode = len(raw), 0o644
            tf.addfile(info, io.BytesIO(raw))
    return ingest.open_bundle(path)


def _list(*docs: dict[str, Any]) -> str:
    return json.dumps({"apiVersion": "v1", "kind": "List", "items": list(docs)})


class FakeBackend:
    """The read-only backend's shape: get(resource, namespace=, selector=). Errors are what the real backends raise."""

    name = "fake"

    def __init__(self, data: dict[str, list[dict[str, Any]]], errors: dict[str, str] | None = None) -> None:
        self.data = data
        self.errors = errors or {}
        self.calls: list[tuple[str, str | None, str | None]] = []

    def get(
        self,
        resource: str,
        name: str | None = None,
        namespace: str | None = None,
        selector: str | None = None,
        field_selector: str | None = None,
    ) -> dict[str, Any]:
        self.calls.append((resource, namespace, selector))
        if resource in self.errors:
            raise ClusterAccessError(self.errors[resource])
        items = [i for i in self.data.get(resource, []) if namespace is None or i["metadata"]["namespace"] == namespace]
        if selector == "!olm.copiedFrom":
            items = [i for i in items if "olm.copiedFrom" not in (i["metadata"].get("labels") or {})]
        return {"kind": "List", "items": items}


# -- absence is never "no operators" -------------------------------------------------------------------------------


def test_an_input_with_no_olm_data_is_not_determined_rather_than_empty() -> None:
    deploy = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web", "namespace": "shop"}}
    inv = _inv(deploy)
    assert inv["verdict"] == "not-determined" and inv["complete"] is False
    assert inv["operators"] == []
    csvs = next(s for s in inv["sources"] if s["resource"] == "clusterserviceversions")
    assert csvs["state"] == "not-read" and "no ClusterServiceVersion" in csvs["reason"]
    assert "not determined" in inv["summary"] and "no operators" not in inv["summary"].lower()


def test_olm_data_read_with_zero_operators_is_listed_as_zero(tmp_path: Path) -> None:
    b = _bundle(
        tmp_path,
        {
            "namespaces/openshift-operators/operators.coreos.com/clusterserviceversions.yaml": _list(),
            "namespaces/openshift-operators/operators.coreos.com/subscriptions.yaml": _list(),
        },
    )
    inv = ops.inventory(mg_ops.collect(b))
    assert inv["verdict"] == "listed" and inv["complete"] is True and inv["operators"] == []
    assert inv["counts"]["operators"] == 0
    assert "0 operators" in inv["summary"]


def test_a_must_gather_without_olm_directories_is_not_determined(tmp_path: Path) -> None:
    node = "kind: Node\nmetadata: {name: n1}\n"
    inv = ops.inventory(mg_ops.collect(_bundle(tmp_path, {"cluster-scoped-resources/core/nodes/n1.yaml": node})))
    assert inv["verdict"] == "not-determined" and inv["operators"] == []
    reasons = {s["resource"]: s for s in inv["sources"]}
    assert reasons["clusterserviceversions"]["state"] == "not-read"
    assert "not in this must-gather" in reasons["clusterserviceversions"]["reason"]
    assert "operators.coreos.com/clusterserviceversions" in reasons["clusterserviceversions"]["reason"]


def test_an_unreadable_csv_file_makes_the_answer_partial_and_names_the_file(tmp_path: Path) -> None:
    good = _list(_csv("a.v1.0.0", "a"))
    b = _bundle(
        tmp_path,
        {
            "namespaces/a/operators.coreos.com/clusterserviceversions.yaml": good,
            "namespaces/b/operators.coreos.com/clusterserviceversions.yaml": "kind: [unterminated\n",
            "namespaces/a/operators.coreos.com/subscriptions.yaml": _list(),
            "namespaces/b/operators.coreos.com/subscriptions.yaml": _list(),
        },
    )
    inv = ops.inventory(mg_ops.collect(b))
    assert inv["verdict"] == "partial" and inv["complete"] is False
    assert [u["path"] for u in inv["unreadable"]] == [
        f"{ROOT}/namespaces/b/operators.coreos.com/clusterserviceversions.yaml"
    ]
    assert len(inv["operators"]) == 1


def test_a_forbidden_live_read_is_unknown_and_a_missing_api_group_says_not_an_olm_cluster() -> None:
    forbidden = FakeBackend(
        {}, {"clusterserviceversions": "Forbidden by RBAC: GET /apis/operators.coreos.com/v1alpha1/x"}
    )
    inv = ops.inventory(ops.collect_live(forbidden, []))
    assert inv["verdict"] == "not-determined" and inv["complete"] is False and inv["operators"] == []
    assert "forbidden" in inv["summary"].lower() or "could not be read" in inv["summary"]
    kubectl_forbidden = FakeBackend(
        {},
        {
            "clusterserviceversions": "oc get clusterserviceversions.operators.coreos.com failed: Error from server "
            '(Forbidden): clusterserviceversions.operators.coreos.com is forbidden: User "x" cannot list'
        },
    )
    assert ops.inventory(ops.collect_live(kubectl_forbidden, []))["verdict"] == "not-determined"

    for message in (
        "Not found: GET /apis/operators.coreos.com/v1alpha1/clusterserviceversions",
        "oc get clusterserviceversions.operators.coreos.com failed: error: the server doesn't have a resource type "
        '"clusterserviceversions"',
    ):
        absent = FakeBackend({}, {"clusterserviceversions": message, "subscriptions": message})
        inv = ops.inventory(ops.collect_live(absent, []))
        assert inv["verdict"] == "no-olm", message
        assert inv["operators"] == [] and "not an OLM cluster" in inv["summary"]
        assert next(s for s in inv["sources"] if s["resource"] == "clusterserviceversions")["state"] == "not-served"
    assert (
        ops.inventory(ops.collect_live(forbidden, []))["verdict"]
        != ops.inventory(ops.collect_live(absent, []))["verdict"]
    )


def test_subscriptions_that_could_not_be_read_leave_channel_and_catalog_not_determined() -> None:
    backend = FakeBackend(
        {"clusterserviceversions": [_csv("web-operator.v2.0.0", "ops")]},
        {"subscriptions": "Forbidden by RBAC: GET /apis/operators.coreos.com/v1alpha1/subscriptions"},
    )
    inv = ops.inventory(ops.collect_live(backend, []))
    assert inv["verdict"] == "partial"
    op = _one(inv, csv="web-operator.v2.0.0")
    assert op["state"] == "subscription-not-read"
    assert op.get("channel") is None and op.get("catalog") is None and op.get("approval") is None
    assert any("Subscriptions" in c and "not" in c for c in inv["caveats"])


# -- copies --------------------------------------------------------------------------------------------------------


def test_copied_csvs_fold_into_one_operator_with_its_namespaces() -> None:
    name = "amq.v7.12.0"
    inv = _inv(
        _csv(name, "openshift-operators", annotations={"olm.targetNamespaces": ""}),
        _copy(name, "team-b", "openshift-operators"),
        _copy(name, "team-a", "openshift-operators"),
        # upstream IsCopied also counts reason Copied alone, and an olm.operatorNamespace naming another namespace
        _csv(name, "team-c", reason="Copied"),
        _csv(name, "team-d", annotations={"olm.operatorNamespace": "openshift-operators"}),
        _sub("amq", "openshift-operators", "amq-streams", installed=name, current=name),
    )
    assert inv["counts"]["operators"] == 1
    op = _one(inv, csv=name)
    assert op["namespace"] == "openshift-operators"
    assert op["copiedInto"] == ["team-a", "team-b", "team-c", "team-d"]
    assert op["allNamespaces"] is True and op["state"] == "installed"


def test_copies_without_their_original_still_make_one_operator() -> None:
    inv = _inv(_copy("x.v1.0.0", "a", "x-ops"), _copy("x.v1.0.0", "b", "x-ops"))
    op = _one(inv, csv="x.v1.0.0")
    assert op["namespace"] == "x-ops" and op["copiedInto"] == ["a", "b"]
    assert any("original" in n for n in op["notes"])


def test_two_installs_of_the_same_csv_in_different_namespaces_stay_two() -> None:
    inv = _inv(_csv("db.v3.1.0", "team-a"), _csv("db.v3.1.0", "team-b"))
    assert inv["counts"]["operators"] == 2
    assert sorted(o["namespace"] for o in inv["operators"]) == ["team-a", "team-b"]


# -- subscriptions without a CSV, CSVs without a subscription -----------------------------------------------------


def test_a_subscription_without_its_csv_is_its_own_state_and_never_installed() -> None:
    inv = _inv(
        _csv("cert.v1.4.0", "cert", version="1.4.0"),
        _sub("pending", "p", "pending-op", current="pending-op.v1.0.0"),
        _sub(
            "failed",
            "f",
            "failed-op",
            conditions=[
                {
                    "type": "ResolutionFailed",
                    "status": "True",
                    "reason": "ConstraintsNotSatisfiable",
                    "message": "no operators found in channel stable",
                }
            ],
        ),
        _sub("gone", "g", "gone-op", installed="gone-op.v2.0.0", current="gone-op.v2.0.0"),
        _sub("cert", "cert", "cert-manager", installed="cert.v1.4.0", current="cert.v1.5.0", state="UpgradePending"),
    )
    pending = _one(inv, subscription="pending")
    assert pending["state"] == "not-installed" and pending.get("csv") is None and pending.get("phase") is None
    failed = _one(inv, subscription="failed")
    assert failed["state"] == "not-installed" and any("ResolutionFailed" in p for p in failed["problems"])
    gone = _one(inv, subscription="gone")
    assert gone["state"] == "csv-missing" and gone["installedCSV"] == "gone-op.v2.0.0"
    upgrade = _one(inv, subscription="cert")
    assert upgrade["state"] == "upgrade-pending" and upgrade["upgradeTo"] == "cert.v1.5.0"
    assert upgrade["version"] == "1.4.0"
    assert inv["counts"]["installed"] == 1  # only the one CSV that is present is counted installed


def test_a_manual_approval_waiting_on_an_install_plan_is_reported() -> None:
    inv = _inv(
        _csv("ocs.v4.16.0", "storage"),
        _sub("ocs", "storage", "ocs-operator", installed="ocs.v4.16.0", current="ocs.v4.16.1", approval="Manual"),
        _plan("install-abcde", "storage", ["ocs.v4.16.1"], phase="RequiresApproval"),
        # first install, Manual, known only from the Subscription's condition (a live read has no InstallPlans)
        _sub(
            "lso",
            "lso",
            "local-storage-operator",
            current="lso.v4.16.0",
            approval="Manual",
            conditions=[{"type": "InstallPlanPending", "status": "True", "reason": "RequiresApproval"}],
        ),
    )
    ocs = _one(inv, subscription="ocs")
    assert (ocs["state"], ocs["approval"], ocs["awaitingApproval"]) == ("upgrade-pending", "Manual", True)
    lso = _one(inv, subscription="lso")
    assert (lso["state"], lso["awaitingApproval"]) == ("not-installed", True)
    assert inv["counts"]["awaitingApproval"] == 2


def test_an_absent_approval_is_automatic_and_says_it_was_defaulted() -> None:
    op = _one(_inv(_csv("a.v1.0.0", "a"), _sub("a", "a", "a", installed="a.v1.0.0", approval=None)), csv="a.v1.0.0")
    assert op["approval"] == "Automatic" and op["approvalDefaulted"] is True


def test_a_csv_without_a_subscription_has_unknown_channel_and_catalog() -> None:
    inv = _inv(
        _csv("packageserver", "openshift-operator-lifecycle-manager", version="0.0.1-snapshot"),
        _csv("other.v1.0.0", "other"),
        _sub("other", "other", "other", installed="other.v1.0.0"),
    )
    op = _one(inv, csv="packageserver")
    assert op["state"] == "no-subscription"
    assert op.get("channel") is None and op.get("catalog") is None and op.get("approval") is None
    assert any("no Subscription" in n for n in op["notes"])
    text = ops.render_text(inv)
    assert "catalog unknown" in text and "channel unknown" in text
    # an input with no Subscriptions at all did not show that there are none: that is "not read", not "none"
    alone = _one(_inv(_csv("packageserver", "olm")), csv="packageserver")
    assert alone["state"] == "subscription-not-read"


# -- version and package --------------------------------------------------------------------------------------------


def test_version_prefers_spec_version_and_labels_a_derived_one() -> None:
    props = json.dumps({"properties": [{"type": "olm.package", "value": {"packageName": "p", "version": "9.9.9"}}]})
    inv = _inv(
        _csv("spec.v1.0.0", "a", version="2.3.4"),
        _csv("props.v1.0.0", "b", version=None, annotations={"operatorframework.io/properties": props}),
        _csv("named.v5.6.7", "c", version=None),
        _csv("nothing", "d", version=None),
        _csv("bad.v1.0.0", "e", version="not a version; rm -rf"),
    )
    assert (_one(inv, "spec.v1.0.0")["version"], _one(inv, "spec.v1.0.0")["versionFrom"]) == ("2.3.4", "spec.version")
    assert (_one(inv, "props.v1.0.0")["version"], _one(inv, "props.v1.0.0")["versionFrom"]) == (
        "9.9.9",
        "csv-properties",
    )
    named = _one(inv, "named.v5.6.7")
    assert (named["version"], named["versionFrom"]) == ("5.6.7", "derived-from-name")
    assert _one(inv, "nothing").get("version") is None and _one(inv, "nothing").get("versionFrom") is None
    bad = _one(inv, "bad.v1.0.0")
    assert bad["versionFrom"] == "derived-from-name" and any("spec.version" in n for n in bad["notes"])
    assert "rm -rf" not in json.dumps(inv)
    text = ops.render_text(inv)
    assert "1.0.0 (derived from the name)" in text and "version unknown" in text


def test_the_package_name_comes_from_the_subscription_or_the_csv_properties() -> None:
    props = json.dumps({"properties": [{"type": "olm.package", "value": {"packageName": "loki-operator"}}]})
    inv = _inv(
        _csv("a.v1.0.0", "a"),
        _sub("a", "a", "a-package", installed="a.v1.0.0"),
        _csv("loki.v6.0.0", "b", annotations={"operatorframework.io/properties": props}),
        _csv("bare.v1.0.0", "c", annotations={"operatorframework.io/properties": "{not json" * 9000}),
    )
    assert (_one(inv, "a.v1.0.0")["package"], _one(inv, "a.v1.0.0")["packageFrom"]) == ("a-package", "subscription")
    assert (_one(inv, "loki.v6.0.0")["package"], _one(inv, "loki.v6.0.0")["packageFrom"]) == (
        "loki-operator",
        "csv-properties",
    )
    assert _one(inv, "bare.v1.0.0").get("package") is None


def test_a_nesting_bomb_in_the_properties_annotation_is_refused_by_depth_not_by_the_machine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from kube_noob import sanitize

    calls: list[int] = []
    real = sanitize.loads_bounded

    def spy(data: str | bytes, limit: int = sanitize.MAX_JSON_DEPTH) -> Any:
        calls.append(len(data))
        return real(data, limit)

    monkeypatch.setattr(sanitize, "loads_bounded", spy)
    bomb = "[" * 20_000 + "]" * 20_000
    op = _one(_inv(_csv("deep.v1.0.0", "a", annotations={"operatorframework.io/properties": bomb})), "deep.v1.0.0")
    assert calls and op.get("package") is None and op["version"] == "1.2.3"


# -- safety ---------------------------------------------------------------------------------------------------------


def test_secrets_in_the_input_are_never_read() -> None:
    secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "s", "namespace": "a"},
        "data": {"token": MARKER},
    }
    sub = _sub("a", "a", "a", installed="a.v1.0.0", config={"env": [{"name": "API_TOKEN", "value": MARKER}]})
    inv = _inv(secret, _csv("a.v1.0.0", "a", phase="Failed", message=f"password={MARKER}"), sub)
    assert _one(inv, csv="a.v1.0.0")["message"] == "password=***"
    assert MARKER not in json.dumps(inv) and MARKER not in ops.render_text(inv)
    assert inv["secretsIgnored"] == 1


def test_hostile_strings_are_flattened_and_redacted() -> None:
    hostile = _csv(
        "evil.v1.0.0",
        "a",
        phase="Failed",
        reason="Bad\x1b[31mReason",
        message="line1\nline2\x1b]0;title\x07 token=abcdefgh12345678 \u202egnp.exe",
    )
    hostile["spec"]["version"] = "1.0.0\n2.0.0"
    inv = _inv(hostile, _sub("x\x1b[2Jy", "a", "pkg\u200bname", installed="evil.v1.0.0"))
    blob = json.dumps(inv) + ops.render_text(inv)
    for bad in ("\x1b", "\n2.0.0", "\u202e", "\u200b", "abcdefgh12345678", "\x07"):
        assert bad not in blob, repr(bad)
    op = _one(inv, csv="evil.v1.0.0")
    assert op.get("reason") is None  # not a valid reason word, so not shown as one
    assert op.get("package") is None  # a package name that is not a valid name is not a stable key


def test_output_is_bounded_and_deterministic() -> None:
    docs = [_csv(f"op{i}.v1.0.{i}", f"ns{i % 40}") for i in range(ops.MAX_OPERATORS + 50)]
    docs += [
        _sub(f"s{i}", f"ns{i % 40}", f"op{i}", installed=f"op{i}.v1.0.{i}") for i in range(0, ops.MAX_OPERATORS + 50, 3)
    ]
    first = _inv(*docs)
    assert json.dumps(first) == json.dumps(_inv(*docs))  # same input, same bytes

    def without_evidence(inv: dict[str, Any]) -> str:  # evidence names document positions, which a shuffle moves
        return json.dumps({**inv, "operators": [{**o, "evidence": []} for o in inv["operators"]]})

    random.Random(7).shuffle(docs)
    assert without_evidence(first) == without_evidence(_inv(*docs))
    assert len(first["operators"]) == ops.MAX_OPERATORS
    assert first["operatorsTotal"] == ops.MAX_OPERATORS + 50 and first["notShown"] == 50
    names = [(o["namespace"], o.get("package") or "", o.get("csv") or "") for o in first["operators"]]
    assert names == sorted(names)


def test_objects_past_the_read_cap_make_the_answer_partial_rather_than_silently_shorter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ops, "MAX_ITEMS", 3)
    docs = [_csv(f"op{i}.v1.0.0", "a") for i in range(5)] + [_sub("s", "a", "op0", installed="op0.v1.0.0")]
    inv = _inv(*docs)
    assert inv["verdict"] == "partial" and inv["complete"] is False
    assert any("2 clusterserviceversions past the first 3" in c for c in inv["caveats"])


def test_many_target_namespaces_are_capped_with_a_count() -> None:
    targets = ",".join(f"t{i:04d}" for i in range(ops.MAX_NAMESPACES + 30))
    op = _one(_inv(_csv("wide.v1.0.0", "w", annotations={"olm.targetNamespaces": targets})), csv="wide.v1.0.0")
    assert len(op["targetNamespaces"]) == ops.MAX_NAMESPACES and op["targetNamespacesTotal"] == ops.MAX_NAMESPACES + 30


# -- live ------------------------------------------------------------------------------------------------------------


def test_the_live_read_skips_copies_cluster_wide_and_reads_them_per_namespace() -> None:
    data = {
        "clusterserviceversions": [
            _csv("amq.v7.12.0", "openshift-operators", annotations={"olm.targetNamespaces": ""}),
            _copy("amq.v7.12.0", "shop", "openshift-operators"),
        ],
        "subscriptions": [_sub("amq", "openshift-operators", "amq-streams", installed="amq.v7.12.0")],
    }
    wide = FakeBackend(data)
    inv = ops.inventory(ops.collect_live(wide, []))
    assert ("clusterserviceversions", None, "!olm.copiedFrom") in wide.calls
    assert ("subscriptions", None, None) in wide.calls
    assert not any(r in {"secrets", "installplans", "operatorgroups"} for r, _, _ in wide.calls)
    assert inv["verdict"] == "listed" and _one(inv, csv="amq.v7.12.0")["allNamespaces"] is True

    narrow = FakeBackend(data)
    inv = ops.inventory(ops.collect_live(narrow, ["shop"]))
    assert ("clusterserviceversions", "shop", None) in narrow.calls
    op = _one(inv, csv="amq.v7.12.0")
    assert op["namespace"] == "openshift-operators" and op["copiedInto"] == ["shop"]
    # the operator's own namespace was not read, so whether it has a Subscription is not known
    assert op["state"] == "subscription-not-read"
    assert inv["verdict"] == "partial" and any("only" in c and "shop" in c for c in inv["caveats"])


def test_the_two_resources_are_allowlisted_namespaced_and_never_secrets() -> None:
    from kube_noob.debug.cluster import ALIASES, ALLOWED_RESOURCES, ResourceDef, resolve_resource

    for plural in ("clusterserviceversions", "subscriptions"):
        assert ALLOWED_RESOURCES[plural] == ResourceDef("operators.coreos.com/v1alpha1", plural, True)
    assert resolve_resource("csv")[0] == "clusterserviceversions"
    assert resolve_resource("sub")[0] == "subscriptions"
    assert "installplans" not in ALLOWED_RESOURCES and "operatorgroups" not in ALLOWED_RESOURCES
    assert {ALIASES.get(a) for a in ALIASES} <= set(ALLOWED_RESOURCES)


# -- the sample, the CLI and the tools -------------------------------------------------------------------------------


def test_the_sample_must_gather_has_one_failed_operator_and_says_what_it_could_not_read(tmp_path: Path) -> None:
    tgz = sample.write(tmp_path / "case")
    inv = ops.inventory(mg_ops.collect(ingest.open_bundle(tgz)))
    assert inv["verdict"] == "partial" and inv["counts"]["operators"] == 1
    op = _one(inv, csv="rhacs-operator.v4.6.0")
    assert (op["namespace"], op["phase"], op["reason"]) == ("rhacs-operator", "Failed", "InstallCheckFailed")
    assert op["copiedInto"] == ["shop"]
    assert (op["version"], op["versionFrom"]) == ("4.6.0", "derived-from-name")
    assert op["state"] == "subscription-not-read"
    assert MARKER not in json.dumps(inv)
    text = ops.render_text(inv)
    assert "not read: subscriptions" in text and "derived from the name" in text


def test_the_cli_prints_text_json_and_yaml_and_exits_5_only_when_asked_and_incomplete(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tgz = sample.write(tmp_path / "case")
    assert main(["operators", "inventory", "--must-gather", str(tgz)]) == 0
    text = capsys.readouterr().out
    assert "rhacs-operator.v4.6.0" in text and "not read: subscriptions" in text and "partial" in text
    assert main(["operators", "inventory", "--must-gather", str(tgz), "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"] == "partial" and out["caveats"] and out["sources"]
    assert main(["operators", "inventory", "--must-gather", str(tgz), "--format", "yaml"]) == 0
    assert yaml.safe_load(capsys.readouterr().out)["verdict"] == "partial"
    assert main(["operators", "inventory", "--must-gather", str(tgz), "--require-complete"]) == 5
    capsys.readouterr()

    full = tmp_path / "full.yaml"
    full.write_text(_yaml(_csv("a.v1.0.0", "a"), _sub("a", "a", "a", installed="a.v1.0.0")))
    assert main(["operators", "inventory", "-f", str(full), "--require-complete"]) == 0
    capsys.readouterr()
    for argv in (
        ["operators", "inventory"],
        ["operators", "inventory", "-f", str(full), "--must-gather", str(tgz)],
        ["operators", "inventory", "--live"],
        ["operators", "inventory", "-f", str(full), "-n", "shop"],
        ["operators", "inventory", "-f", str(tmp_path / "missing.yaml")],
    ):
        assert main(argv) == 2, argv
        capsys.readouterr()
    assert main(["operators", "inventory", "-f", str(full), "--format", "sarif"]) == 2
    capsys.readouterr()


def test_the_inventory_is_offered_as_tools_and_in_the_must_gather_analysis(tmp_path: Path) -> None:
    kit = tk.Toolkit(load_settings())
    names = {s.name for s in kit.specs()}
    assert "operator_inventory" in names and "cluster_operator_inventory" not in names
    out = kit.operator_inventory(
        tk.OperatorInventoryIn(manifests=_yaml(_csv("a.v1.0.0", "a"), _sub("a", "a", "a", installed="a.v1.0.0")))
    )
    assert out["verdict"] == "listed" and out["operators"][0]["package"] == "a"
    live = tk.Toolkit(load_settings(overrides={"cluster": {"enabled": True}}))
    assert "cluster_operator_inventory" in {s.name for s in live.specs()}
    with pytest.raises(ValueError):
        tk.ClusterOperatorInventoryIn(namespaces=["Bad NS"])

    tgz = sample.write(tmp_path / "case")
    mg = kit.analyze_must_gather(tk.MustGatherIn(path=str(tgz)))
    assert mg["operatorInventory"]["verdict"] == "partial"
    assert mg["operatorInventory"]["operators"][0]["csv"] == "rhacs-operator.v4.6.0"


def test_the_plugin_ships_the_inventory_but_not_the_must_gather_reader() -> None:
    import importlib.util
    import sys

    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("kn_sync_plugin", root / "scripts" / "sync_plugin_server.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["kn_sync_plugin"] = mod
    spec.loader.exec_module(mod)
    shipped = mod.plugin_modules(root)
    assert "kube_noob.operators" in shipped
    assert "kube_noob.mustgather.operators" not in shipped
