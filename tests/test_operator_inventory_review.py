"""E2 under an adversarial review (G270): 21 ways the operator inventory answered `listed`, complete or installed for
an input it had not fully read. Each test reproduces one defect from the review and is named for the behaviour that
must hold instead. Most of them are one defect class: a skipped, unreadable, truncated, foreign-kind or status-less
input reading as an answer."""

from __future__ import annotations

import json
import os
import random
import stat
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import operators as ops
from kube_noob.cli import main
from kube_noob.mustgather import ingest
from kube_noob.mustgather import operators as mg_ops

G = "namespaces/%s/operators.coreos.com/%s"
API = "operators.coreos.com/v1alpha1"


def csv(name: str, ns: str, version: Any = "1.0.0", phase: Any = "Succeeded", **meta: Any) -> dict[str, Any]:
    d: dict[str, Any] = {"apiVersion": API, "kind": "ClusterServiceVersion", "metadata": {"name": name, "namespace": ns}}
    d["metadata"].update(meta)
    if version is not None:
        d["spec"] = {"version": version}
    if phase is not None:
        d["status"] = {"phase": phase}
    return d


def sub(name: str, ns: str, pkg: str, installed: str | None = None, current: str | None = None, **spec: Any) -> Any:
    d: dict[str, Any] = {
        "apiVersion": API,
        "kind": "Subscription",
        "metadata": {"name": name, "namespace": ns},
        "spec": {"name": pkg, "source": "redhat-operators", "sourceNamespace": "openshift-marketplace", **spec},
    }
    d["spec"].setdefault("channel", "stable")
    status = {k: v for k, v in (("installedCSV", installed), ("currentCSV", current)) if v}
    if status:
        d["status"] = status
    return d


def y(*docs: Any) -> str:
    return "\n---\n".join(yaml.safe_dump(d) for d in docs)


def inv_of(*docs: Any) -> dict[str, Any]:
    return ops.inventory(ops.from_manifests(y(*docs)))


def by_csv(inv: dict[str, Any], name: str) -> list[dict[str, Any]]:
    return [o for o in inv["operators"] if o.get("csv") == name]


def mgdir(tmp_path: Path, files: dict[str, str | bytes]) -> Path:
    root = tmp_path / "mg"
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return root


def mg_inv(root: Path) -> dict[str, Any]:
    return ops.inventory(mg_ops.collect(ingest.open_bundle(root)))


BASE = {
    G % ("a", "clusterserviceversions/foo.v1.0.0.yaml"): y(csv("foo.v1.0.0", "a")),
    G % ("a", "subscriptions/foo.yaml"): y(sub("foo", "a", "foo", "foo.v1.0.0", "foo.v1.0.0")),
}


# -- 1: -f DIR ---------------------------------------------------------------------------------------------------------


def test_files_in_a_directory_that_cannot_be_read_make_the_answer_partial_and_are_named(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    d = tmp_path / "olm"
    d.mkdir()
    (d / "a.yaml").write_text(y(csv("foo.v1.0.0", "a"), sub("foo", "a", "foo", "foo.v1.0.0")))
    (d / "b.yaml").write_bytes(y(csv("bar.v1.0.0", "a", phase="Failed")).encode() + b"\xff\xfe")
    (d / "c.yaml").write_text("kind: ClusterServiceVersion\nmetadata: {name: baz.v1.0.0, namespace: a\n")
    (d / "d.json").write_text(json.dumps(csv("qux.v1.0.0", "a")))
    (d / "e.YAML").write_text(y(csv("quux.v1.0.0", "a")))
    assert main(["operators", "inventory", "-f", str(d), "--require-complete", "--format", "json"]) == 5
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"] == "partial" and out["complete"] is False
    assert sorted(u["path"] for u in out["unreadable"]) == ["b.yaml", "c.yaml"]
    assert {o.get("csv") for o in out["operators"]} >= {"foo.v1.0.0", "qux.v1.0.0", "quux.v1.0.0"}
    for name in ("b.yaml", "c.yaml"):  # a single file named directly is still refused outright
        assert main(["operators", "inventory", "-f", str(d / name)]) == 4
        capsys.readouterr()


# -- 2 and 19: live --------------------------------------------------------------------------------------------------


def _stub_kubectl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, script: str) -> Any:
    from kube_noob.debug.backends import KubectlBackend

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    kubectl = bin_dir / "kubectl"
    kubectl.write_text("#!/bin/sh\nres=\"$2\"\n" + script)
    kubectl.chmod(kubectl.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return KubectlBackend("kubectl", None, 5)


SUBS_JSON = json.dumps({"kind": "List", "items": [sub("foo", "a", "foo", "foo.v1.0.0")]})


@pytest.mark.parametrize(
    "stderr",
    [
        "Unable to connect to the server: getting credentials: exec: executable gke-gcloud-auth-plugin not found",
        "Error from server (NotFound): the server could not find the requested resource",
        'Error from server (NotFound): namespaces "typo" not found',
    ],
)
def test_a_failure_that_merely_says_not_found_is_not_a_cluster_without_olm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stderr: str
) -> None:
    backend = _stub_kubectl(tmp_path, monkeypatch, f"echo '{stderr}' >&2; exit 1\n")
    inv = ops.inventory(ops.collect_live(backend, []))
    assert inv["verdict"] == "not-determined" and inv["complete"] is False


def test_only_a_404_on_the_olm_group_reads_as_not_an_olm_cluster(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    absent = _stub_kubectl(
        tmp_path, monkeypatch, "echo \"error: the server doesn't have a resource type \\\"${res%%.*}\\\"\" >&2; exit 1\n"
    )
    inv = ops.inventory(ops.collect_live(absent, []))
    assert inv["verdict"] == "no-olm" and inv["complete"] is True

    # a 404 for CSVs while Subscriptions answer is a contradiction, not a cluster without OLM
    mixed = _stub_kubectl(
        tmp_path,
        monkeypatch,
        'case "$res" in clusterserviceversions*) echo "error: the server doesn\'t have a resource type '
        '\\"clusterserviceversions\\"" >&2; exit 1;; *) cat <<\'EOF\'\n' + SUBS_JSON + "\nEOF\nexit 0;; esac\n",
    )
    inv = ops.inventory(ops.collect_live(mixed, []))
    assert inv["verdict"] == "not-determined" and inv["complete"] is False

    in_cluster = ops._not_served(
        "clusterserviceversions", "Not found: GET /apis/operators.coreos.com/v1alpha1/clusterserviceversions"
    )
    assert in_cluster is True
    assert ops._not_served("clusterserviceversions", "Not found: GET /api/v1/namespaces/typo") is False


def test_a_live_response_without_an_items_list_is_not_zero_objects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = _stub_kubectl(tmp_path, monkeypatch, "exit 0\n")
    inv = ops.inventory(ops.collect_live(empty, []))
    assert inv["verdict"] == "not-determined" and inv["complete"] is False
    assert "items" in next(s for s in inv["sources"] if s["resource"] == "clusterserviceversions")["reason"]


# -- 3, 4, 5: must-gather gaps ---------------------------------------------------------------------------------------


def test_an_operator_whose_file_name_looks_like_a_secret_is_read(tmp_path: Path) -> None:
    files = dict(BASE)
    files[G % ("b", "clusterserviceversions/secrets-store-csi-driver-operator.v4.14.0.yaml")] = y(
        csv("secrets-store-csi-driver-operator.v4.14.0", "b")
    )
    files[G % ("b", "clusterserviceversions/secret-store.v1.0.0.yaml")] = y(csv("secret-store.v1.0.0", "b"))
    files[G % ("secrets", "clusterserviceversions/x.v1.0.0.yaml")] = y(csv("x.v1.0.0", "secrets"))
    files["namespaces/b/core/secrets.yaml"] = "kind: SecretList\nitems:\n- metadata: {name: s}\n  data: {k: KN-MARK}\n"
    inv = mg_inv(mgdir(tmp_path, files))
    assert {o.get("csv") for o in inv["operators"]} == {
        "foo.v1.0.0",
        "secrets-store-csi-driver-operator.v4.14.0",
        "secret-store.v1.0.0",
        "x.v1.0.0",
    }
    assert "KN-MARK" not in json.dumps(inv)
    assert ingest.secret_like("namespaces/b/core/secrets.yaml")
    assert ingest.secret_like("namespaces/b/core/secrets/x.yaml")


def test_an_olm_file_the_must_gather_reader_skipped_makes_the_answer_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files = dict(BASE)
    files[G % ("b", "clusterserviceversions/bar.v2.0.0.yaml")] = y(csv("bar.v2.0.0", "b"))
    root = mgdir(tmp_path / "link", files)
    target = root / (G % ("b", "clusterserviceversions/bar.v2.0.0.yaml"))
    link = root / (G % ("c", "clusterserviceversions/baz.v3.0.0.yaml"))
    link.parent.mkdir(parents=True)
    link.symlink_to(target)
    inv = mg_inv(root)
    assert inv["verdict"] == "partial" and any("baz.v3.0.0" in u["path"] for u in inv["unreadable"])

    monkeypatch.setattr(ingest, "MAX_FILE_BYTES", 200)
    big = dict(BASE)
    big[G % ("b", "clusterserviceversions/bar.v2.0.0.yaml")] = y(csv("bar.v2.0.0", "b")) + "# " + "x" * 400 + "\n"
    inv = mg_inv(mgdir(tmp_path / "big", big))
    assert inv["verdict"] == "partial" and any("bar.v2.0.0" in u["path"] for u in inv["unreadable"])


def test_an_olm_file_outside_the_layout_oc_writes_is_a_gap(tmp_path: Path) -> None:
    files = dict(BASE)
    files[G % ("b", "ClusterServiceVersions/bar.yaml")] = y(csv("bar.v2.0.0", "b"))
    files[G % ("b", "clusterserviceversions/sub/deep.yaml")] = y(csv("deep.v2.0.0", "b"))
    inv = mg_inv(mgdir(tmp_path, files))
    assert inv["verdict"] == "partial"
    assert len([u for u in inv["unreadable"] if "layout" in u["reason"]]) == 2


@pytest.mark.parametrize(
    ("extra", "only"),
    [
        ({G % ("b", "clusterserviceversions/bar.v2.0.0.yaml"): b""}, False),
        ({G % ("a", "clusterserviceversions.yaml"): b"", G % ("a", "subscriptions.yaml"): b""}, True),
        ({G % ("b", "clusterserviceversions.yaml"): "Error from server (Forbidden): csvs is forbidden\n"}, False),
        (
            {
                G % ("a", "clusterserviceversions.yaml"): "apiVersion: v1\nkind: Status\ncode: 403\n",
                G % ("a", "subscriptions.yaml"): "kind: Status\ncode: 403\n",
            },
            True,
        ),
        (
            {
                G % ("a", "clusterserviceversions.yaml"): "kind: ClusterServiceVersionList\nitems:\n"
                "- metadata: {namespace: a}\n- 7\n- kind: Pod\n  metadata: {name: x}\n",
                G % ("a", "subscriptions.yaml"): "kind: SubscriptionList\nitems: null\n",
            },
            True,
        ),
        ({G % ("b", "clusterserviceversions/bar.yaml"): y(sub("bar", "b", "bar"))}, False),
    ],
)
def test_a_routed_file_with_no_usable_object_is_a_gap_not_zero_objects(
    tmp_path: Path, extra: dict[str, str | bytes], only: bool
) -> None:
    files: dict[str, str | bytes] = {} if only else dict(BASE)
    files.update(extra)
    inv = mg_inv(mgdir(tmp_path, files))
    assert inv["verdict"] in ("partial", "not-determined") and inv["complete"] is False
    assert inv["unreadable"], inv


def test_a_typed_list_holding_objects_it_cannot_use_is_partial_for_manifests() -> None:
    text = (
        "kind: ClusterServiceVersionList\nitems:\n- metadata: {name: foo.v1.0.0, namespace: a}\n- 7\n"
        "- kind: Pod\n  metadata: {name: p, namespace: a}\n---\nkind: SubscriptionList\nitems: []\n"
    )
    inv = ops.inventory(ops.from_manifests(text))
    assert inv["verdict"] == "partial"
    assert any("2 " in c and "ClusterServiceVersion" in c for c in inv["caveats"])


# -- 6: apiVersion ----------------------------------------------------------------------------------------------------


def test_an_object_of_another_api_group_is_not_an_olm_object() -> None:
    acm = sub("app", "apps", "my-app")
    acm["apiVersion"] = "apps.open-cluster-management.io/v1"
    inv = inv_of(csv("foo.v1.0.0", "a"), acm)
    assert inv["verdict"] == "partial"
    assert [o.get("csv") for o in inv["operators"]] == ["foo.v1.0.0"]
    assert inv["operators"][0]["state"] == "subscription-not-read"
    assert any("apps.open-cluster-management.io" in c for c in inv["caveats"])


# -- 7: list cap -------------------------------------------------------------------------------------------------------


def test_a_list_longer_than_the_cap_is_partial_with_the_count(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ops, "MAX_ITEMS", 3)
    items = [csv(f"op{i}.v1.0.0", "a") for i in range(5)]
    text = yaml.safe_dump({"kind": "ClusterServiceVersionList", "items": items}) + "---\nkind: SubscriptionList\nitems: []\n"
    inv = ops.inventory(ops.from_manifests(text))
    assert inv["verdict"] == "partial" and any("2 clusterserviceversions past the first 3" in c for c in inv["caveats"])


# -- 8, 9, 10, 11, 13: the join --------------------------------------------------------------------------------------


def test_a_copy_never_stands_in_for_a_missing_installed_csv() -> None:
    inv = inv_of(csv("foo.v1.0.0", "y", **{"labels": {"olm.copiedFrom": "x"}}), sub("foo", "x", "foo", "foo.v1.0.0"))
    (op,) = inv["operators"]
    assert op["state"] == "csv-missing" and inv["counts"]["installed"] == 0
    assert any("cop" in n for n in op["notes"])


@pytest.mark.parametrize(
    "marks",
    [{"labels": {"olm.copiedFrom": "b"}}, {"labels": {"olm.copiedFrom": "a"}}, {}],
)
def test_a_csv_that_differs_from_the_original_it_claims_to_copy_is_shown_on_its_own(marks: dict[str, Any]) -> None:
    other = csv("foo.v1.0.0", "b", version="9.9.9", phase="Failed", **marks)
    if not marks:
        other["status"]["reason"] = "Copied"
    inv = inv_of(csv("foo.v1.0.0", "a"), other)
    shown = by_csv(inv, "foo.v1.0.0")
    assert sorted(o["namespace"] for o in shown) == ["a", "b"], shown
    assert inv["counts"]["notSucceeded"] == 1


def test_a_subscription_without_status_is_its_own_state_and_does_not_orphan_its_csv() -> None:
    inv = inv_of(csv("foo.v1.0.0", "a"), sub("foo", "a", "foo"))
    states = sorted(o["state"] for o in inv["operators"])
    assert "not-installed" not in states and "no-subscription" not in states
    assert "status-not-read" in states and inv["verdict"] == "partial"
    csv_entry = next(o for o in inv["operators"] if o.get("csv"))
    assert not any("no Subscription" in n for n in csv_entry["notes"])
    bad = sub("bar", "a", "bar")
    bad["status"] = {"installedCSV": "bar v1; rm"}
    assert next(o for o in inv_of(bad)["operators"])["state"] == "status-not-read"


def test_the_join_follows_installed_csv_only_during_an_upgrade() -> None:
    installing = inv_of(csv("foo.v1.0.0", "a", phase="Failed"), sub("foo", "a", "foo", None, "foo.v1.0.0"))
    (op,) = installing["operators"]
    assert op["state"] == "not-installed" and installing["counts"]["installed"] == 0

    new_only = inv_of(csv("foo.v1.1.0", "a", "1.1.0", "Installing"), sub("foo", "a", "foo", "foo.v1.0.0", "foo.v1.1.0"))
    (op,) = new_only["operators"]
    assert op["state"] == "csv-missing" and op.get("version") is None and op["upgradeTo"] == "foo.v1.1.0"

    both = inv_of(
        csv("foo.v1.0.0", "a", "1.0.0", "Replacing"),
        csv("foo.v1.1.0", "a", "1.1.0", "Installing"),
        sub("foo", "a", "foo", "foo.v1.0.0", "foo.v1.1.0"),
    )
    (op,) = both["operators"]
    assert (op["state"], op["csv"], op["version"], op["upgradeTo"]) == (
        "upgrade-pending",
        "foo.v1.0.0",
        "1.0.0",
        "foo.v1.1.0",
    )


def test_two_subscriptions_naming_one_csv_give_one_operator() -> None:
    inv = inv_of(
        csv("foo.v1.0.0", "a"), sub("foo", "a", "foo", "foo.v1.0.0"), sub("foo2", "a", "foo", "foo.v1.0.0")
    )
    assert inv["counts"]["operators"] == 1 and inv["counts"]["installed"] == 1
    assert any("foo2" in n for n in inv["operators"][0]["notes"])


# -- 12: phase ---------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("phase", [None, "Install Failed", "Bogus"])
def test_an_unknown_or_missing_phase_is_not_counted_healthy(phase: Any) -> None:
    inv = inv_of(csv("foo.v1.0.0", "a", phase=phase), sub("foo", "a", "foo", "foo.v1.0.0"))
    (op,) = inv["operators"]
    assert op.get("phase") is None and inv["counts"]["notSucceeded"] == 1
    assert "phase unknown" in ops.render_text(inv)


# -- 14 ----------------------------------------------------------------------------------------------------------------


def test_a_namespace_with_csvs_and_no_subscription_in_a_file_set_is_not_read_there() -> None:
    inv = inv_of(csv("foo.v1.0.0", "a"), csv("bar.v2.0.0", "b"), sub("foo", "a", "foo", "foo.v1.0.0"))
    assert inv["verdict"] == "partial"
    assert by_csv(inv, "bar.v2.0.0")[0]["state"] == "subscription-not-read"
    other = sub("other", "b", "other", "other.v1.0.0")
    with_one = inv_of(csv("bar.v2.0.0", "b"), csv("other.v1.0.0", "b"), other)
    assert by_csv(with_one, "bar.v2.0.0")[0]["state"] == "no-subscription"


# -- 15 ----------------------------------------------------------------------------------------------------------------


def test_unusual_field_shapes_are_shown_or_noted_never_dropped() -> None:
    s = sub("foo", "a", "foo", "foo.v1.0.0", channel="Stable", source="Cat", installPlanApproval="manual")
    s["status"]["conditions"] = [
        {"type": "ResolutionFailed", "status": True, "message": "boom"},
        {"type": "InstallPlanPending", "status": True, "reason": "RequiresApproval"},
    ]
    inv = inv_of(csv("foo.v1.0.0", "a", "01.2.3"), s)
    (op,) = inv["operators"]
    assert any("ResolutionFailed" in p for p in op["problems"]) and op["awaitingApproval"] is True
    assert op["channel"] == "<Stable>" and op["catalog"] == "<Cat>"
    assert op["approval"] == "Automatic" and any("manual" in n for n in op["notes"])
    assert op["versionFrom"] == "derived-from-name"
    text = ops.render_text(inv)
    assert "channel unknown" not in text and "catalog unknown" not in text
    float_channel = sub("bar", "a", "bar", "bar.v1.0.0", channel=4.14)
    (op,) = inv_of(csv("bar.v1.0.0", "a"), float_channel)["operators"]
    assert op.get("channel") is None and any("channel" in n for n in op["notes"])


# -- 16 ----------------------------------------------------------------------------------------------------------------


def test_order_and_conflicting_duplicates_do_not_change_the_answer() -> None:
    docs = [csv(f"op{i}.v1.0.{i}", f"ns{i % 7}") for i in range(60)]
    docs += [sub(f"op{i}", f"ns{i % 7}", f"op{i}", f"op{i}.v1.0.{i}") for i in range(60)]
    first = json.dumps(ops.inventory(ops.from_documents(docs)))
    shuffled = docs[:]
    random.Random(3).shuffle(shuffled)
    assert json.dumps(ops.inventory(ops.from_documents(shuffled))) == first

    d1, d2 = csv("foo.v1.0.0", "a", "1.0.0"), csv("foo.v1.0.0", "a", "6.6.6", "Failed")
    one = ops.inventory(ops.from_documents([d1, d2]))
    two = ops.inventory(ops.from_documents([d2, d1]))
    assert json.dumps(one) == json.dumps(two)
    assert one["verdict"] == "partial" and any("conflict" in c or "different" in c for c in one["caveats"])
    assert one["sources"][0]["objects"] == 1


# -- 17 ----------------------------------------------------------------------------------------------------------------


def test_subscriptions_times_install_plans_in_one_namespace_is_linear() -> None:
    def run(n: int) -> float:
        subs = [
            {"apiVersion": API, "kind": "Subscription", "metadata": {"name": f"s{i}", "namespace": "a"},
             "spec": {"name": f"p{i}"}, "status": {"currentCSV": f"p{i}.v1.0.0"}}
            for i in range(n)
        ]
        plans = [
            {"apiVersion": API, "kind": "InstallPlan", "metadata": {"name": f"install-{i}", "namespace": "a"},
             "spec": {"clusterServiceVersionNames": [f"x{i}.v1.0.0"]}, "status": {"phase": "Complete"}}
            for i in range(n)
        ]
        c = ops.from_documents([*subs, *plans, csv("foo.v1.0.0", "a")])
        t = time.perf_counter()
        ops.inventory(c)
        return time.perf_counter() - t

    run(200)  # warm up
    small, large = run(1000), run(4000)
    assert large < 10.0  # a ceiling only a regression to quadratic could cross
    assert large / max(small, 1e-3) < 8, (small, large)  # four times the input: about four times the time


# -- 18 ----------------------------------------------------------------------------------------------------------------


def test_must_gather_analyze_carries_the_inventory_in_text_and_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = mgdir(tmp_path, BASE)
    assert main(["must-gather", "analyze", str(root), "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["operatorInventory"]["verdict"] == "listed"
    assert main(["must-gather", "analyze", str(root)]) == 0
    assert "operator inventory (must-gather): listed" in capsys.readouterr().out


def test_the_text_view_carries_what_the_json_carries() -> None:
    props = json.dumps({"properties": [{"type": "olm.package", "value": {"packageName": "loki", "version": "6.0.0"}}]})
    no_phase = csv("loki.v6.0.0", "a", version=None, phase=None, annotations={"operatorframework.io/properties": props})
    no_phase["status"] = {"reason": "InstallWaiting"}
    group = {"apiVersion": "operators.coreos.com/v1", "kind": "OperatorGroup", "metadata": {"name": "g", "namespace": "a"},
             "status": {"namespaces": ["a", "b"]}}
    inv = inv_of(no_phase, group, sub("loki", "a", "loki", "loki.v6.0.0"))
    text = ops.render_text(inv)
    for needle in (
        "6.0.0 (from the CSV's olm.package property)",
        "openshift-marketplace",
        "package loki (from the Subscription)",
        "(from the OperatorGroup)",
        "[InstallWaiting]",
        f"counts: {inv['counts']['operators']} operator",
    ):
        assert needle in text, needle

    many = ops.Collected("must-gather")
    many.unreadable = [{"path": f"f{i}.yaml", "reason": "bad"} for i in range(8)]
    many.reads = {r: ops.SourceRead(resource=r, state="read") for r in ops.RESOURCES}
    text = ops.render_text(ops.inventory(many))
    assert all(f"f{i}.yaml" in text for i in range(8))

    absent = ops.Collected("live")
    absent.reads = {r: ops.SourceRead(resource=r, state="read") for r in ops.RESOURCES}
    absent.reads["subscriptions"] = ops.SourceRead(resource="subscriptions", state="not-served", reason="404")
    absent.objects["clusterserviceversions"].append(ops.Obj(csv("x.v1.0.0", "a"), "live", "a", "x.v1.0.0"))
    assert any("Subscriptions" in c for c in ops.inventory(absent)["caveats"])


# -- 20 ----------------------------------------------------------------------------------------------------------------


def test_invisible_format_characters_are_removed_everywhere() -> None:
    from kube_noob import sanitize
    from kube_noob.mustgather import analyse

    hidden = "؜­\U000e0041 "
    msg = f"bad{hidden}thing"
    inv = inv_of(csv("foo.v1.0.0", "a", phase="Failed") | {"status": {"phase": "Failed", "message": msg}})
    blob = ops.render_text(inv) + json.dumps(inv, ensure_ascii=False)
    for ch in hidden:
        assert ch not in blob, hex(ord(ch))
        assert ch not in analyse._text(msg)
        assert ch not in sanitize.visible(msg)


# -- 21 ----------------------------------------------------------------------------------------------------------------


def test_package_property_problems_are_noted() -> None:
    def props(raw: str) -> dict[str, Any]:
        return inv_of(csv("foo", "a", annotations={"operatorframework.io/properties": raw}))["operators"][0]

    two = json.dumps(
        {
            "properties": [
                {"type": "olm.package", "value": {"packageName": "good", "version": "1.0.0"}},
                {"type": "olm.package", "value": {"packageName": "evil", "version": "2.0.0"}},
            ]
        }
    )
    assert props(two).get("package") is None and any("disagree" in n for n in props(two)["notes"])
    assert any("could not be read" in n for n in props("{not json")["notes"])
    late = json.dumps(
        {"properties": [{"type": "x", "value": 1}] * 600 + [{"type": "olm.package", "value": {"packageName": "p"}}]}
    )
    assert props(late)["package"] == "p"


def test_a_metadata_namespace_that_differs_from_its_path_is_noted(tmp_path: Path) -> None:
    files = dict(BASE)
    files[G % ("b", "clusterserviceversions/bar.v2.0.0.yaml")] = y(csv("bar.v2.0.0", "zzz"))
    inv = mg_inv(mgdir(tmp_path, files))
    (bar,) = by_csv(inv, "bar.v2.0.0")
    assert any("path" in n and "zzz" in n for n in bar["notes"])


def test_no_output_key_or_attribute_names_a_credential_word() -> None:
    """CodeQL keys its clear-text-logging check on identifier names: a count of dropped objects named for what was
    dropped reached print and was flagged. The count stays; its name says what it is without the word."""
    import re

    inv = inv_of(csv("foo.v1.0.0", "a"), {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "s"}})
    assert inv["droppedUnread"] == 1
    words = re.compile(r"(?i)secret|password|token|credential|key")
    assert not [k for k in inv if words.search(k)]
    assert not [f for f in ops.Collected.__dataclass_fields__ if words.search(f)]
