"""R5: look the installed operators up in the OpenShift release notes.

The bundled corpus keys every issue by OpenShift release and free text: no record carries a component, a package or
an operator version (measured in the first test, so a corpus that grows one fails here and the join gets upgraded
rather than silently ignoring it). The join is therefore package -> the names the release notes use, through an
explicit table in two tiers, narrowed by the cluster's OpenShift release, for Red Hat's builds only. A fix the notes
list is an OpenShift release, never an operator version. It is a lookup, not a vulnerability check. Every test is
named for a behaviour; most are about a miss, a gap or a guess not reading as "no reported issue".
"""

from __future__ import annotations

import importlib.util
import json
import random
import re
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import known_issues
from kube_noob import operator_issues as oi
from kube_noob import operators as ops
from kube_noob import toolkit as tk
from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.errors import ClusterAccessError
from kube_noob.mustgather import analyse, ingest, sample

ROOT = Path(__file__).resolve().parents[1]
API = "operators.coreos.com/v1alpha1"
RECORD_FIELDS = {"id", "ids", "kind", "minor", "version", "text", "source", "issued", "fixedIn"}
G = "namespaces/%s/operators.coreos.com/%s"
CV_PATH = "cluster-scoped-resources/config.openshift.io/clusterversions/%s.yaml"


def csv(name: str, ns: str, version: Any = "1.0.0") -> dict[str, Any]:
    d: dict[str, Any] = {
        "apiVersion": API,
        "kind": "ClusterServiceVersion",
        "metadata": {"name": name, "namespace": ns},
        "status": {"phase": "Succeeded"},
    }
    if version is not None:
        d["spec"] = {"version": version}
    return d


def sub(
    name: str,
    ns: str,
    pkg: str,
    installed: str | None = None,
    status: bool = True,
    source: str | None = "redhat-operators",
    source_ns: str | None = "openshift-marketplace",
) -> dict[str, Any]:
    spec: dict[str, Any] = {"name": pkg}
    if source is not None:
        spec["source"] = source
    if source_ns is not None:
        spec["sourceNamespace"] = source_ns
    d: dict[str, Any] = {"apiVersion": API, "kind": "Subscription", "metadata": {"name": name, "namespace": ns}}
    d["spec"] = spec
    if status:
        d["status"] = {"installedCSV": installed} if installed else {"state": "UpgradePending"}
    return d


def pair(pkg: str, ns: str, csv_name: str, version: Any = "1.0.0", **kw: Any) -> list[dict[str, Any]]:
    return [csv(csv_name, ns, version), sub(pkg, ns, pkg, csv_name, **kw)]


def y(*docs: Any) -> str:
    return "\n---\n".join(yaml.safe_dump(d) for d in docs)


def assess(*docs: Any, version: str | None = "4.22.3", **kw: Any) -> dict[str, Any]:
    return oi.assess(ops.from_manifests(y(*docs)), release=oi.Release(given=version), **kw)


def one(out: dict[str, Any], package: str | None = None, csv_name: str | None = None) -> dict[str, Any]:
    found = [o for o in out["operators"] if (package is None or o.get("package") == package)]
    found = [o for o in found if csv_name is None or o.get("csv") == csv_name]
    assert len(found) == 1, found
    return found[0]


def rows(out: dict[str, Any], package: str) -> list[dict[str, Any]]:
    return list(out["issues"][package]["rows"])


def row(out: dict[str, Any], package: str, issue_id: str) -> dict[str, Any]:
    return next(r for r in rows(out, package) if r["id"] == issue_id)


def mgdir(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "mg"
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(data)
    return root


def cv_doc(*history: tuple[str, str], desired: str | None = None, name: str = "version") -> dict[str, Any]:
    return {
        "apiVersion": "config.openshift.io/v1",
        "kind": "ClusterVersion",
        "metadata": {"name": name},
        "status": {
            "desired": {"version": desired or (history[0][0] if history else "")},
            "history": [{"version": v, "state": s} for v, s in history],
        },
    }


class FakeBackend:
    name = "fake"

    def __init__(self, data: dict[str, list[dict[str, Any]]], errors: dict[str, str] | None = None) -> None:
        self.data, self.errors = data, errors or {}

    def get(
        self,
        resource: str,
        name: str | None = None,
        namespace: str | None = None,
        selector: str | None = None,
        field_selector: str | None = None,
    ) -> dict[str, Any]:
        if resource in self.errors:
            raise ClusterAccessError(self.errors[resource])
        if resource == "clusterversions":
            return self.data["clusterversions"][0]
        items = [i for i in self.data.get(resource, []) if namespace is None or i["metadata"]["namespace"] == namespace]
        return {"kind": "List", "items": items}


def live(docs: list[dict[str, Any]], cv: Any = None, error: str | None = None, given: str | None = None) -> Any:
    data: dict[str, Any] = {
        "clusterserviceversions": [d for d in docs if d["kind"] == "ClusterServiceVersion"],
        "subscriptions": [d for d in docs if d["kind"] == "Subscription"],
    }
    if cv is not None:
        data["clusterversions"] = [cv]
    backend = FakeBackend(data, {"clusterversions": error} if error else None)
    rel = oi.live_release(backend)
    rel.given = given
    return oi.assess(ops.collect_live(backend, []), release=rel)


# -- what the corpus can support, and the table that joins it ----------------------------------------------------


def test_the_corpus_keys_issues_by_openshift_release_and_text_not_by_operator_version() -> None:
    issues, meta = known_issues.bundled()
    for f in sorted((ROOT / "src/kube_noob/data/known_issues").glob("*.json")):
        for r in json.loads(f.read_text(encoding="utf-8"))["records"]:
            assert set(r) <= RECORD_FIELDS, (f.name, sorted(set(r) - RECORD_FIELDS))
    ocp = re.compile(r"^4\.[0-9]+(\.[0-9]+)?\Z")
    assert all(ocp.match(i.version) and ocp.match(i.minor) for i in issues)
    assert all(i.fixed_in is None or ocp.match(i.fixed_in) for i in issues)
    assert meta["retrievedAt"] and "not a vulnerability check" in oi.method_note()


def test_every_alias_name_and_mention_is_used_by_the_bundled_release_notes() -> None:
    issues, _ = known_issues.bundled()
    assert oi.alias_problems(issues) == []
    for package, alias in oi.ALIASES.items():
        for term in (*alias.names, *alias.mentions):
            assert any(oi.name_pattern(term, alias.not_followed_by).search(i.text) for i in issues), (package, term)


def test_no_alias_name_matches_two_packages() -> None:
    owners: dict[str, str] = {}
    for package, alias in oi.ALIASES.items():
        for term in (*alias.names, *alias.mentions):
            assert owners.get(term, package) == package, (term, owners.get(term), package)
            owners[term] = package
    for a, pa in owners.items():
        for b, pb in owners.items():
            if pa != pb:
                assert not oi.name_pattern(a).search(b), (a, pa, b, pb)


def test_a_regenerated_corpus_missing_an_alias_target_is_reported() -> None:
    issues, _ = known_issues.bundled()
    without = [i for i in issues if not oi.name_pattern("NUMA Resources Operator").search(i.text)]
    problems = oi.alias_problems(without)
    assert any("numaresources-operator" in p and "NUMA Resources Operator" in p for p in problems)
    empty = oi.alias_problems([])
    assert any("holds no release-note issues" in p for p in empty)
    shared = dict(oi.ALIASES)
    shared["metallb-operator-copy"] = oi.Alias(("MetalLB Operator",), "test")
    assert any("two packages" in p for p in oi.alias_problems(issues, shared))


@pytest.mark.parametrize(
    ("name", "text", "hit"),
    [
        ("cert-manager", "with cert-manager installed", True),
        ("cert-manager", "the `cert-manager` Operator", True),
        ("cert-manager", "install cert-manager.", True),
        ("cert-manager", "cert-manager's webhook", True),
        ("cert-manager", "the openshift-cert-manager-operator namespace", False),
        ("cert-manager", "cert-manager-istio-csr is broken", False),
        ("cert-manager", "apiVersion cert-manager.io/v1 objects", False),
        ("cert-manager", "the image jetstack/cert-manager", False),
        ("cert-manager", "pods in the namespace cert-manager", False),
        ("cert-manager", "the cert-manager namespace", False),
        ("PTP Operator", "the XPTP Operator", False),
        ("PTP Operator", "the ptp operator", False),
        ("PTP Operator", "the PTP\nOperator", False),
        ("DPU Operator", "the DPU Operators", False),
        ("MetalLB Operator", "MetalLB Operator.", True),
    ],
)
def test_a_name_matches_only_as_a_whole_phrase(name: str, text: str, hit: bool) -> None:
    assert bool(oi.name_pattern(name).search(text)) is hit


@pytest.mark.parametrize(
    ("text", "hit"),
    [
        ("OpenShift Service Mesh 2.6 is affected", False),
        ("OpenShift Service Mesh (OSSM) 2.x cannot", False),
        ("OpenShift Service Mesh version 2 users", False),
        ("OpenShift Service Mesh 3.1 is affected", True),
        ("OpenShift Service Mesh (OSSM) 3.x provides", True),
    ],
)
def test_service_mesh_2_is_not_service_mesh_3(text: str, hit: bool) -> None:
    alias = oi.ALIASES["servicemeshoperator3"]
    assert (oi._hit(alias, text) is not None and oi._hit(alias, text)[1] == "name") is hit


def test_every_aliased_package_is_a_valid_package_name_with_a_cited_source() -> None:
    for package, alias in oi.ALIASES.items():
        assert ops._NAME.match(package), package
        assert alias.names and alias.source, package


def _vendor_script() -> Any:
    spec = importlib.util.spec_from_file_location("kn_vendor_known_issues", ROOT / "scripts/vendor_known_issues.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["kn_vendor_known_issues"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_the_vendor_check_fails_on_a_new_field_and_prints_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    mod = _vendor_script()
    src = ROOT / "src/kube_noob/data/known_issues"
    for f in src.glob("*.json"):
        (tmp_path / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(mod, "OUT", tmp_path)
    assert mod.check() == 0
    out = capsys.readouterr().out
    assert "ptp-operator: name 'PTP Operator' --" in out and "in 4.22" in out
    assert "shared: OCPBUGS-114054 (4.20) is matched for openshift-cert-manager-operator, " in out
    f = sorted(tmp_path.glob("*.json"))[0]
    doc = json.loads(f.read_text(encoding="utf-8"))
    doc["records"][0]["component"] = "Networking / ptp"
    f.write_text(json.dumps(doc), encoding="utf-8")
    assert mod.check() == 1
    assert "fields the loader does not know: component" in capsys.readouterr().out
    assert "a record has a field the loader does not know" in (mod.__doc__ or "")


# -- the join ----------------------------------------------------------------------------------------------------


def test_an_operator_named_in_a_fixed_issue_is_listed_with_its_source_and_the_corpus_date() -> None:
    out = assess(*pair("ptp-operator", "openshift-ptp", "ptp-operator.v4.22.0-202601010000", None))
    op = one(out, "ptp-operator")
    assert op["verdict"] == "named"
    r = row(out, "ptp-operator", "OCPBUGS-74358")
    assert r["releases"] == ["4.22"] and r["class"] == "fixed" and r["fixedInOpenShift"] == "4.22.0"
    assert r["tier"] == "named" and r["via"] in oi.ALIASES["ptp-operator"].names
    assert r["source"].startswith("https://github.com/openshift/openshift-docs/blob/")
    assert r["url"] == "https://redhat.atlassian.net/browse/OCPBUGS-74358"
    assert r["knownIssuesAsOf"] == out["knowledge"]["knownIssuesAsOf"] == "2026-10-27"


@pytest.mark.parametrize(
    ("cluster", "verdict"),
    [
        ("4.21.3", "after"),
        ("4.21.4", "at-or-before"),
        ("4.21.9", "at-or-before"),
        ("4.21", "unknown"),
        ("4.21.4-rc.1", "unknown"),
    ],
)
def test_a_fix_is_compared_only_with_the_cluster_release_never_with_the_operator_version(
    cluster: str, verdict: str
) -> None:
    for op_version in ("4.21.0-202601010000", "4.21.99", "0.1.0", None):
        out = assess(*pair("vertical-pod-autoscaler", "vpa", "vpa.v1", op_version), version=cluster)
        r = row(out, "vertical-pod-autoscaler", "OCPBUGS-76296")
        assert r["fixedInOpenShift"] == "4.21.4" and r["fixReleaseVsCluster"] == verdict
        assert r["installedHasFix"] == "not-determined"
    assert "not with the cluster" not in json.dumps(out["issues"])  # no row asserts where a fix ships
    assert "do not say whether it ships in the OpenShift payload or in the operator's own bundle" in out["fixNote"]


def test_a_known_issue_with_no_fix_says_no_fix_is_listed() -> None:
    out = assess(*pair("numaresources-operator", "n", "nro.v4.21.0"), version="4.21.5")
    r = row(out, "numaresources-operator", "OCPBUGS-77930")
    assert r["class"] == "open" and r["fixedInOpenShift"] is None and r["installedHasFix"] == "no-fix-listed"


def test_narrowing_keeps_the_release_the_cluster_runs_and_open_issues_from_before() -> None:
    out = assess(*pair("numaresources-operator", "n", "nro.v4.21.0"), version="4.21.5")
    assert [(r["id"], r["releases"]) for r in rows(out, "numaresources-operator")] == [
        ("OCPBUGS-77930", ["4.20", "4.21"])
    ]  # 4.22's records and the 4.22 fix (OCPBUGS-84690) are not this cluster's
    assert out["cluster"]["releasesSearched"] == ["4.21"] and out["cluster"]["versionFrom"] == "given"


def test_an_open_issue_from_an_earlier_release_stays_listed_at_the_next() -> None:
    docs = pair("netobserv-operator", "netobs", "network-observability-operator.v1.9.0")
    at_420 = assess(*docs, version="4.20.5")
    at_421 = assess(*docs, version="4.21.9")
    for out in (at_420, at_421):
        assert one(out)["verdict"] != "none-named"
        assert [r["id"] for r in rows(out, "netobserv-operator")] == ["OSSM-5407"]
    assert row(at_421, "netobserv-operator", "OSSM-5407")["listed"] == (
        "listed for OpenShift 4.20; no fix listed since"
    )
    assert "listed" not in row(at_420, "netobserv-operator", "OSSM-5407")


def test_component_names_are_a_separate_weaker_tier_and_open_issues_come_first() -> None:
    out = assess(*pair("ptp-operator", "openshift-ptp", "ptp-operator.v4.22.0"), version="4.22.3")
    got = rows(out, "ptp-operator")
    by_id = {r["id"]: r for r in got}
    for open_id in ("OCPBUGS-66413", "OCPBUGS-85586", "OCPBUGS-85092", "RHEL-93579"):
        assert by_id[open_id]["class"] == "open" and by_id[open_id]["tier"] == "mentioned", open_id
        assert "component name" in by_id[open_id]["tierWhy"]
    assert by_id["OCPBUGS-74358"]["tier"] == "named"
    classes = [r["class"] for r in got]
    assert classes == sorted(classes, key=lambda c: c != "open")
    block = out["issues"]["ptp-operator"]
    assert block["open"] >= 4 and block["fixed"] >= 4
    assert f"({block['open']} open, {block['fixed']} fixed issue(s))" in out["summary"]
    assert one(out)["verdict"] == "named" and "only mention it in" in one(out)["reason"]


@pytest.mark.parametrize(
    ("package", "issue_id", "why"),
    [
        ("openshift-cert-manager-operator", "OCPBUGS-114054", "openshift-external-secrets-operator"),
        ("openshift-external-secrets-operator", "OCPBUGS-114054", "openshift-cert-manager-operator"),
        ("servicemeshoperator3", "OCPBUGS-92038", "Cluster Ingress Operator"),
        ("servicemeshoperator3", "OCPBUGS-82147", "Cluster Ingress Operator"),
        ("cluster-logging", "OCPBUGS-77590", "Hub RDS"),
        ("netobserv-operator", "OSSM-5407", "servicemeshoperator3"),
    ],
)
def test_an_issue_that_also_names_another_product_or_the_platform_is_a_mention(
    package: str, issue_id: str, why: str
) -> None:
    out = assess(*pair(package, "x", "x.v1"), version=None)
    r = row(out, package, issue_id)
    assert r["tier"] == "mentioned" and why in r["tierWhy"]


def test_metallb_frr_bug_is_a_mention_of_the_platform() -> None:
    out = assess(*pair("metallb-operator", "metallb-system", "metallb-operator.v4.22.0"), version="4.22.3")
    r = row(out, "metallb-operator", "OCPBUGS-84960")
    assert r["tier"] == "mentioned" and "FRR-K8s" in r["tierWhy"]
    assert one(out)["verdict"] == "mentioned"


# -- the verdict and the gates -------------------------------------------------------------------------------------


def test_only_unaliased_operators_is_not_matched_and_fails_require_matched(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    docs = [d for n in range(30) for d in pair(f"op{n}", f"ns{n}", f"op{n}.v1.0.0")]
    out = assess(*docs, version="4.21.9", top=3)
    assert out["verdict"] == "not-matched" and out["complete"] is True and out["allMatched"] is False
    assert out["summary"].startswith("30 of 30 installed operator(s) were not matched against the release notes")
    assert "named in none" not in out["summary"]
    f = tmp_path / "ops.yaml"
    f.write_text(y(*docs))
    base = ["operators", "issues", "-f", str(f), "--openshift-version", "4.21.9", "--top", "3"]
    assert main([*base, "--require-complete"]) == 0  # complete keeps the inventory's meaning: the evidence was read
    capsys.readouterr()
    assert main([*base, "--require-matched"]) == 5
    assert "30 of 30 installed operator(s) were not matched" in capsys.readouterr().err


def test_some_unaliased_operators_is_partly_matched() -> None:
    out = assess(*pair("ptp-operator", "p", "ptp.v1"), *pair("my-operator", "m", "my.v1"))
    assert out["verdict"] == "partly-matched" and out["counts"]["notMatched"] == 1
    assert out["summary"].startswith("1 of 2 installed operator(s) were not matched")
    all_aliased = assess(*pair("ptp-operator", "p", "ptp.v1"), *pair("cluster-logging", "c", "c.v1"))
    assert all_aliased["verdict"] == "matched" and all_aliased["allMatched"] is True
    assert one(all_aliased, "cluster-logging")["verdict"] == "none-named"
    nothing = assess({"kind": "ClusterServiceVersionList", "items": []}, sub("ptp", "p", "ptp-operator"))
    assert nothing["verdict"] == "nothing-to-match" and one(nothing)["verdict"] == "not-installed"


@pytest.mark.parametrize("catalog", ["community-operators", "certified-operators", "redhat-marketplace"])
def test_an_operator_from_another_default_catalog_is_not_taken_for_red_hats_build(catalog: str) -> None:
    out = assess(*pair("openshift-cert-manager-operator", "cm", "cert-manager.v1.16.0", source=catalog))
    op = one(out)
    assert op["verdict"] == "not-determined" and op["catalogKind"] == "not-red-hat-build"
    assert catalog in op["reason"] and "Red Hat's build" in op["reason"]
    assert out["allMatched"] is False and out["counts"]["notMatched"] == 1
    assert catalog in oi.render_text(out)


@pytest.mark.parametrize(
    ("source", "source_ns"),
    [(None, None), ("cs-redhat-operator-index", "openshift-marketplace"), ("redhat-operators", "my-catalogs")],
)
def test_an_operator_from_an_unknown_catalog_keeps_its_matches_labelled_and_is_not_counted_matched(
    source: str | None, source_ns: str | None
) -> None:
    out = assess(*pair("metallb-operator", "m", "metallb-operator.v0.14.8", source=source, source_ns=source_ns))
    op = one(out)
    assert op["catalogKind"] == "unknown" and op["verdict"] in ("named", "mentioned")
    assert any("cannot tell whether this is it" in n for n in op["notes"])
    assert out["counts"]["catalogUnverified"] == 1 and out["allMatched"] is False
    assert out["verdict"] == "partly-matched" and out["complete"] is True


def test_a_cluster_that_does_not_serve_clusterversion_is_not_openshift() -> None:
    docs = pair(
        "metallb-operator", "operators", "metallb-operator.v0.14.8", source="operatorhubio-catalog", source_ns="olm"
    )
    for message in (
        'the server doesn\'t have a resource type "clusterversions"',
        'error: the server doesn\'t have a resource type "clusterversions.config.openshift.io"',
    ):
        out = live(docs, error=message)
        assert out["cluster"]["notOpenShift"] is True and out["verdict"] == "not-determined"
        assert out["complete"] is False and out["issues"] == {}
        assert {o["verdict"] for o in out["operators"]} == {"not-determined"}
        assert "not OpenShift" in out["summary"]
    for message in (
        'clusterversions.config.openshift.io "version" is forbidden',
        "Not found: GET /apis/config.openshift.io/v1/clusterversions/version",  # a missing object, not a missing type
        'Error from server (NotFound): clusterversions.config.openshift.io "version" not found',
    ):
        out = live(docs, error=message)
        assert out["cluster"]["notOpenShift"] is False and out["cluster"]["openshiftVersion"] is None, message
        assert out["verdict"] == "partial" and out["complete"] is False


def test_an_update_in_progress_searches_both_releases_and_is_incomplete() -> None:
    docs = pair("vertical-pod-autoscaler", "vpa", "vpa.v1")
    out = live(docs, cv_doc(("4.22.1", "Partial"), ("4.21.9", "Completed")))
    assert out["cluster"]["openshiftVersion"] == "4.21.9" and out["cluster"]["updatingTo"] == "4.22.1"
    assert out["cluster"]["releasesSearched"] == ["4.21", "4.22"]
    assert out["complete"] is False and any("updating to 4.22.1" in r for r in out["incompleteBecause"])
    assert {r for x in rows(out, "vertical-pod-autoscaler") for r in x["releases"]} == {"4.21", "4.22"}
    only_partial = live(docs, cv_doc(("4.22.1", "Partial"), ("4.22.0", "Partial")))
    assert only_partial["cluster"]["versionFrom"] == "clusterversion-desired" and only_partial["complete"] is False
    empty = live(docs, cv_doc(desired="4.22.1"))
    assert empty["cluster"]["versionFrom"] == "clusterversion-desired"
    assert any("status.desired" in c for c in empty["caveats"])
    settled = live(docs, cv_doc(("4.21.9", "Completed")))
    assert settled["complete"] is True and settled["cluster"]["versionFrom"] == "clusterversion"


def test_an_update_in_progress_in_a_must_gather_is_said(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    files = {
        G % ("vpa", "clusterserviceversions.yaml"): y({"kind": "List", "items": [csv("vpa.v1", "vpa")]}),
        G % ("vpa", "subscriptions.yaml"): y(
            {"kind": "List", "items": [sub("vpa", "vpa", "vertical-pod-autoscaler", "vpa.v1")]}
        ),
        CV_PATH % "version": y(cv_doc(("4.21.2", "Partial"), ("4.20.3", "Completed"))),
    }
    root = mgdir(tmp_path, files)
    assert main(["operators", "issues", "--must-gather", str(root), "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["cluster"]["openshiftVersion"] == "4.20.3" and out["cluster"]["updatingTo"] == "4.21.2"
    assert out["cluster"]["releasesSearched"] == ["4.20", "4.21"] and out["complete"] is False


def test_a_given_version_that_disagrees_with_the_cluster_is_said() -> None:
    docs = pair("vertical-pod-autoscaler", "vpa", "vpa.v1")
    out = live(docs, cv_doc(("4.22.1", "Completed")), given="4.20")
    assert out["cluster"]["openshiftVersion"] == "4.20" and out["cluster"]["versionFrom"] == "given"
    assert out["cluster"]["detectedVersion"] == "4.22.1"
    assert any("given version 4.20 disagrees with the ClusterVersion's 4.22.1" in c for c in out["caveats"])
    assert "the ClusterVersion says 4.22.1" in oi.render_text(out)
    agree = live(docs, cv_doc(("4.22.1", "Completed")), given="4.22")
    assert not any("disagrees" in c for c in agree["caveats"])


def test_a_clusterversion_not_named_version_is_not_used(tmp_path: Path) -> None:
    files = {
        CV_PATH % "aaa": y(cv_doc(("4.22.1", "Completed"), name="aaa")),
        CV_PATH % "bbb": y(cv_doc(("4.20.1", "Completed"), name="bbb")),
    }
    cluster = analyse.analyse(ingest.open_bundle(mgdir(tmp_path, files))).as_dict()["cluster"]
    assert cluster["version"] == "" and "none named version" in cluster["clusterVersionNote"]
    rel = oi.must_gather_release(cluster)
    assert rel.detected is None and "none named version" in rel.notes[0]


def test_an_unreadable_newest_completed_entry_does_not_fall_back() -> None:
    rel = oi.live_release(
        FakeBackend({"clusterversions": [cv_doc(("x4.22", "Completed"), ("4.20.1", "Completed"), desired="4.22.5")]})
    )
    assert rel.detected is None and "newest completed entry" in rel.notes[0]
    for shape in (
        {"status": {"history": 5, "desired": "4.22.1"}},
        {"status": [1, 2]},
        [],
        {"status": {"history": [{"version": "4.21.2", "state": True}, "x", None]}},
    ):
        rel = oi.live_release(FakeBackend({"clusterversions": [shape]}))  # type: ignore[list-item]
        assert rel.detected is None and rel.notes, shape


@pytest.mark.parametrize("bad", ["4.09", "04.21", "4.021", "٤.٢١", "v4.21", "4.21;", "4.21.1.1", ""])
def test_versions_take_ascii_digits_and_no_leading_zeros(bad: str) -> None:
    assert oi.parse_version(bad) is None and oi.parse_version(bad + "\n") is None
    with pytest.raises(ValueError):
        tk.OperatorKnownIssuesIn(manifests="x: 1", openshift_version=bad.strip() or "x")


@pytest.mark.parametrize("good", ["4.21", "4.21.0", "4.21.10", "4.21.0-rc.1", "4.0.0"])
def test_the_cli_and_the_tool_take_the_same_versions(good: str) -> None:
    assert oi.parse_version(good) == good
    assert tk.OperatorKnownIssuesIn(manifests="x: 1", openshift_version=good).openshift_version == good


def test_a_cluster_past_the_newest_indexed_update_is_said() -> None:
    out = assess(*pair("vertical-pod-autoscaler", "vpa", "vpa.v1"), version="4.22.99")
    assert any("past the newest 4.22 update in the index" in c for c in out["caveats"])
    assert not any("past the newest" in c for c in assess(*pair("x", "x", "x.v1"), version="4.22.1")["caveats"])


def test_a_cluster_version_outside_the_index_is_not_determined_for_every_operator() -> None:
    out = assess(*pair("ptp-operator", "p", "ptp.v4.18.0"), *pair("my-operator", "m", "my.v1"), version="4.18.5")
    assert out["verdict"] == "not-determined" and out["complete"] is False
    assert {o["verdict"] for o in out["operators"]} == {"not-determined"} and out["issues"] == {}
    assert out["cluster"]["indexed"] is False
    assert any("4.18" in c and "4.20, 4.21, 4.22" in c for c in out["caveats"])


def test_without_a_cluster_version_matches_are_not_narrowed_and_the_answer_is_incomplete() -> None:
    out = assess(*pair("numaresources-operator", "n", "n.v1"), version=None)
    assert out["complete"] is False and out["verdict"] == "partial"
    assert out["cluster"]["openshiftVersion"] is None and out["cluster"]["indexed"] is None
    assert row(out, "numaresources-operator", "OCPBUGS-77930")["releases"] == ["4.20", "4.21", "4.22"]
    assert any("was searched; pass --openshift-version" in c for c in out["caveats"])


def test_a_name_the_loaded_corpus_no_longer_uses_is_not_determined_not_none_named() -> None:
    issues, meta = known_issues.bundled()
    index = known_issues.Index([i for i in issues if "Vertical Pod Autoscaler" not in i.text], meta)
    c = ops.from_manifests(y(*pair("vertical-pod-autoscaler", "vpa", "vpa.v1")))
    out = oi.assess(c, release=oi.Release(given="4.21.9"), index=index)
    op = one(out)
    assert op["verdict"] == "not-determined" and "no longer use" in op["reason"]
    assert any("vertical-pod-autoscaler: the loaded release notes use none of" in c for c in out["caveats"])
    assert out["allMatched"] is False


def test_issue_rows_keep_open_and_newest_first_when_cut() -> None:
    issues, meta = known_issues.bundled()
    extra = [
        known_issues.Issue(
            id=f"OCPBUGS-{900000 + n}",
            ids=(f"OCPBUGS-{900000 + n}",),
            kind="fixed" if n % 2 else "known",
            minor="4.22",
            version=f"4.22.{n % 30}" if n % 2 else "4.22",
            text=f"Before this update the PTP Operator failed case {n}.",
            source="https://github.com/openshift/openshift-docs/blob/" + "a" * 40 + "/modules/x.adoc",
            issued=None,
            fixed_in=None,
        )
        for n in range(60)
    ]
    index = known_issues.Index(issues + extra, meta)
    c = ops.from_manifests(y(*pair("ptp-operator", "p", "ptp.v1")))
    out = oi.assess(c, release=oi.Release(given="4.22.3"), index=index, issues_per_package=5)
    block = out["issues"]["ptp-operator"]
    assert [r["class"] for r in block["rows"]] == ["open"] * 5
    assert [r["tier"] for r in block["rows"]] == ["named"] * 5
    numbers = [int(r["id"].split("-")[1]) for r in block["rows"]]
    assert numbers == sorted(numbers)  # numeric, not "OCPBUGS-128642" before "OCPBUGS-74358"
    assert block["withheld"] == {"open": block["open"] - 5, "fixed": block["fixed"]}
    assert out["counts"]["openIssues"] == block["open"]  # counted before the cut
    text = oi.render_text(out)
    assert f"and {block['open'] - 5} open and {block['fixed']} fixed more" in text
    wide = oi.assess(c, release=oi.Release(given="4.22.3"), index=index, issues_per_package=40)
    fixed = [r for r in wide["issues"]["ptp-operator"]["rows"] if r["class"] == "fixed"]
    fixes = [tuple(int(x) for x in r["fixedInOpenShift"].split(".")) for r in fixed if r["tier"] == "named"]
    assert fixes == sorted(fixes, reverse=True)


def test_the_must_gather_embedding_points_to_a_command_that_exists(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tgz = sample.write(tmp_path / "case")
    c = ops.from_manifests(y(*pair("ptp-operator", "p", "ptp.v1")))
    mg = oi.for_must_gather(c, {})
    assert mg["hints"]["issues"].startswith("run kube-noob operators issues --must-gather")
    assert any("run kube-noob operators issues --must-gather <path> --openshift-version" in x for x in mg["caveats"])
    text = oi.render_text(mg)
    assert "--format json" not in text and "pass --openshift-version" not in text
    mcp = oi.for_must_gather(c, {}, surface="mcp")
    assert any("pass openshift_version" in x for x in mcp["caveats"]) and "--" not in mcp["hints"]["issues"]
    assert len(mg["issues"]["ptp-operator"]["rows"]) == oi.MUST_GATHER_ISSUES_PER_PACKAGE
    # the command the hint names accepts what the hint says
    assert (
        main(["operators", "issues", "--must-gather", str(tgz), "--openshift-version", "4.20.3", "--issues", "200"])
        == 0
    )
    capsys.readouterr()


# -- inputs, safety, determinism -------------------------------------------------------------------------------


def test_a_partial_inventory_makes_the_answer_incomplete_and_names_the_operators_not_assessed() -> None:
    docs = [
        *pair("ptp-operator", "p", "ptp.v4.22.0"),
        csv("nro.v4.22.0", "n"),
        sub("nro", "n", "numaresources-operator", status=False),
    ]
    out = assess(*docs)
    assert out["inventory"]["verdict"] == "partial" and out["complete"] is False and out["verdict"] == "partial"
    assert any(c.startswith("inventory: ") for c in out["caveats"])
    nro = one(out, "numaresources-operator")
    assert nro["inventoryState"] == "status-not-read"
    assert any("installed" in n and "not determined" in n for n in nro["notes"])
    blind = oi.assess(
        ops.from_manifests(y({"kind": "ConfigMap", "metadata": {"name": "x"}})), release=oi.Release(given="4.22.1")
    )
    assert blind["verdict"] == "not-determined" and blind["operators"] == []
    assert "not determined" in blind["summary"]


def test_a_csv_that_was_not_read_is_not_determined_and_incomplete() -> None:
    out = assess(csv("other.v1", "a"), sub("vpa", "a", "vertical-pod-autoscaler", "vpa.v4.21.0"))
    op = one(out, "vertical-pod-autoscaler")
    assert op["inventoryState"] == "csv-missing" and op["verdict"] == "not-determined"
    assert out["complete"] is False and any("name a CSV that was not read" in r for r in out["incompleteBecause"])


def test_operators_past_the_cap_are_counted_with_a_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    out = assess(*pair("ptp-operator", "p", "ptp.v1"), *pair("my-operator", "m", "my.v1"), top=1)
    assert out["operatorsTotal"] == 2 and out["notShown"] == 1 and len(out["operators"]) == 1
    assert out["operators"][0]["verdict"] == "named"  # a named operator is not cut for an unaliased one
    monkeypatch.setattr(ops, "MAX_OPERATORS", 1)
    capped = assess(*pair("ptp-operator", "p", "ptp.v1"), *pair("my-operator", "m", "my.v1"))
    assert capped["counts"]["notAssessed"] == 1 and capped["complete"] is False
    assert "1 operator(s) not assessed" in capped["summary"]
    assert "were not assessed" in capped["summary"]


def test_one_package_on_many_operators_shares_one_issue_list() -> None:
    docs = [d for n in range(500) for d in pair("ptp-operator" if n % 2 else f"p{n}", f"n{n}", f"op{n}.v1")]
    out = assess(*docs, version="4.22.1", top=500)
    assert list(out["issues"]) == ["ptp-operator"]
    assert len(json.dumps(out)) < 450_000  # one issue list for 250 operators, not 250 copies of it
    assert oi.render_text(out).count("OCPBUGS-74358 [") == 1


def test_an_operator_whose_package_is_unknown_is_not_matched_by_its_csv_name() -> None:
    out = assess(csv("ptp-operator.v4.22.0", "openshift-ptp"), sub("other", "openshift-ptp", "unrelated", "x.v1"))
    op = one(out, None, "ptp-operator.v4.22.0")
    assert op["verdict"] == "package-unknown" and op["issues"]["open"] == 0
    assert out["counts"]["packageUnknown"] == 1


def test_hostile_strings_in_names_do_not_reach_the_output() -> None:
    hostile = "ptp-operator\x1b[31m\u202e\u200b\ue000"
    docs = [
        csv(f"evil{hostile}.v1", f"ns{hostile}"),
        sub(f"s{hostile}", "n", hostile, f"evil{hostile}.v1"),
        *pair("ptp-operator", "ok", "ptp.v4.22.0"),
    ]
    out = assess(*docs)
    blob = oi.render_text(out) + json.dumps(out, ensure_ascii=False)
    for ch in "\x1b\u202e\u200b\ue000":
        assert ch not in blob, hex(ord(ch))
    assert all(
        o["verdict"] not in ("named", "mentioned") for o in out["operators"] if o.get("package") != "ptp-operator"
    )


def _write_corpus(tmp_path: Path, doc: dict[str, Any]) -> Path:
    d = tmp_path / "data" / "known_issues"
    d.mkdir(parents=True)
    (d / "a.json").write_text(json.dumps(doc), encoding="utf-8")
    return tmp_path / "data"


GOOD = {
    "id": "OCPBUGS-1",
    "kind": "known",
    "minor": "4.22",
    "version": "4.22",
    "text": "The Vertical Pod Autoscaler does a thing.",
    "source": "modules/rn-ocp-release-notes-known-issues.adoc",
}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", "OCPBUGS-1](javascript:alert(1))"),
        ("id", "../../../etc/passwd?x=y#frag"),
        ("kind", "weird\nkind"),
        ("minor", "4.22\u200b"),
        ("minor", "٤.٢٢"),
        ("version", "4.21"),
        ("fixedIn", "not-a-version"),
        ("fixedIn", "4.22.1\nSAFE"),
        ("source", "http://evil.example/x?](javascript:alert(1))"),
        ("source", "httpjavascript:alert(1)"),
        ("source", "modules/../../x.adoc"),
        ("issued", "2026-13-45"),
        ("ids", ["OCPBUGS-1", "<b>"]),
    ],
)
def test_a_local_corpus_record_that_is_not_what_it_claims_is_left_out_and_counted(
    tmp_path: Path, field: str, value: Any
) -> None:
    data = _write_corpus(
        tmp_path,
        {
            "retrievedAt": "2027-01-01",
            "commits": {"4.22": "b" * 40},
            "records": [GOOD, {**GOOD, "id": "OCPBUGS-2", field: value}],
        },
    )
    index = known_issues.get_index(data)
    k = index.knowledge()
    assert [i.id for i in index.issues] == ["OCPBUGS-1"]
    assert k["recordsRejected"] == 1 and k["rejectedRecords"][0].startswith("a.json record 2: ")
    out = oi.assess(
        ops.from_manifests(y(*pair("vertical-pod-autoscaler", "v", "v.v1"))),
        release=oi.Release(given="4.22.1"),
        data_dir=data,
    )
    blob = oi.render_text(out) + json.dumps(out, ensure_ascii=False)
    assert "javascript" not in blob and "../" not in blob and "SAFE" not in blob
    assert any("1 record(s) of the loaded release notes were not usable" in c for c in out["caveats"])
    assert (
        known_issues.match("vertical pod autoscaler", "openshift", data_dir=data)["knowledge"]["recordsRejected"] == 1
    )


def test_a_local_corpus_whose_date_is_not_a_date_does_not_replace_the_bundled_one(tmp_path: Path) -> None:
    data = _write_corpus(tmp_path, {"retrievedAt": "2099-01-01\u202e<b>", "records": [GOOD]})
    index = known_issues.get_index(data)
    assert index.knowledge()["knownIssuesAsOf"] == "2026-10-27" and len(index.issues) == 957
    assert "not a date" in index.knowledge()["localCopyNote"]
    assert not known_issues.valid_date("2026-02-30") and known_issues.valid_date("2026-02-28")


def test_the_bundled_corpus_loads_every_record_unchanged() -> None:
    issues, meta = known_issues.bundled()
    assert len(issues) == 957 and "_rejected" not in meta
    assert "recordsRejected" not in known_issues.get_index().knowledge()


def test_the_answer_is_deterministic() -> None:
    docs = [
        *pair("ptp-operator", "p", "ptp.v1"),
        *pair("my-operator", "m", "my.v1"),
        *pair("metallb-operator", "x", "m.v1"),
        *pair("servicemeshoperator3", "o", "ossm.v3"),
    ]
    first = json.dumps(assess(*docs))
    rng = random.Random(7)
    for _ in range(5):
        shuffled = list(docs)
        rng.shuffle(shuffled)
        assert json.dumps(assess(*shuffled)) == first


def test_a_skipped_file_or_a_conflicting_duplicate_is_never_a_complete_answer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    d = tmp_path / "olm"
    d.mkdir()
    (d / "ptp.yaml").write_text(y(*pair("ptp-operator", "p", "ptp.v4.22.0")))
    (d / "broken.YAML").write_text("kind: [unclosed\n")
    argv = ["operators", "issues", "-f", str(d), "--openshift-version", "4.22.3"]
    assert main([*argv, "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["complete"] is False and out["inventory"]["verdict"] == "partial"
    assert main([*argv, "--require-complete"]) == 5
    capsys.readouterr()
    a, b = csv("ptp.v1", "p", "1.0.0"), csv("ptp.v1", "p", "2.0.0")
    first = assess(a, b, sub("ptp", "p", "ptp-operator", "ptp.v1"))
    assert first == assess(b, a, sub("ptp", "p", "ptp-operator", "ptp.v1")) and first["complete"] is False


def test_the_text_view_carries_what_the_json_carries() -> None:
    upgrading = {**sub("v", "v", "vertical-pod-autoscaler", "vpa.v1")}
    upgrading["status"] = {"installedCSV": "vpa.v1", "currentCSV": "vpa.v2"}
    docs = [*pair("ptp-operator", "p", "ptp.v1"), *pair("my-operator", "m", "my.v1"), csv("vpa.v1", "v"), upgrading]
    out = assess(*docs, version="4.20.5")
    text = oi.render_text(out)
    for needle in (
        out["knowledge"]["knownIssuesAsOf"],
        out["knowledge"]["source"],
        out["fixNote"],
        out["method"],
        "state upgrade-pending",
        "(from the subscription)",
        "(spec.version)",
        "(red-hat)",
        "(given)",
    ):
        assert needle in text, needle
    for op in out["operators"]:
        assert op["verdict"] in text and op["reason"] in text
    for block in out["issues"].values():
        for r in block["rows"]:
            assert r["id"] in text and r["source"] in text and r["url"] in text and r["tierWhy"] in text
            if r.get("workaround"):
                assert r["workaround"] in text
    for caveat in out["caveats"]:
        assert caveat in text
    for reason in out["incompleteBecause"]:
        assert reason in text


def test_named_is_worded_as_the_notes_name_it_not_as_affected() -> None:
    out = assess(*pair("ptp-operator", "p", "ptp.v1"))
    assert "not that it is affected" in out["method"]
    blob = json.dumps(out).lower()
    assert "affected" not in blob.replace("not that it is affected", "")


def test_no_output_key_names_a_credential_word() -> None:
    words = re.compile(r"(?i)secret|password|token|credential|key")
    out = assess(*pair("ptp-operator", "p", "ptp.v1"))

    def keys(x: Any) -> list[str]:
        if isinstance(x, dict):
            return [k for k, v in x.items() for k in [k, *keys(v)]]
        if isinstance(x, list):
            return [k for v in x for k in keys(v)]
        return []

    assert not [k for k in keys(out) if words.search(k)]


# -- the surfaces ------------------------------------------------------------------------------------------------


def test_the_cli_reads_the_same_three_inputs_and_exits_5_only_when_asked(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    full = tmp_path / "ops.yaml"
    full.write_text(y(*pair("ptp-operator", "p", "ptp.v4.22.0"), *pair("my-operator", "m", "my.v1")))
    argv = ["operators", "issues", "-f", str(full), "--openshift-version", "4.22.3"]
    assert main([*argv, "--require-complete"]) == 0
    text = capsys.readouterr().out
    assert "OCPBUGS-74358" in text and "no alias" in text and "2026-10-27" in text
    assert main([*argv, "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["complete"] is True and out["cluster"]["versionFrom"] == "given"
    assert main([*argv, "--format", "yaml"]) == 0
    assert yaml.safe_load(capsys.readouterr().out)["verdict"] == "partly-matched"
    assert main(["operators", "issues", "-f", str(full), "--require-complete"]) == 5
    assert "refusing" in capsys.readouterr().err

    tgz = sample.write(tmp_path / "case")
    assert main(["operators", "issues", "--must-gather", str(tgz), "--format", "json"]) == 0
    mg = json.loads(capsys.readouterr().out)
    assert mg["cluster"]["openshiftVersion"] == "4.20.3" and mg["cluster"]["detectedFrom"] == "must-gather"
    assert mg["cluster"]["updatingTo"] == "4.20.4" and mg["complete"] is False
    assert main(["operators", "issues", "--must-gather", str(tgz), "--require-complete"]) == 5
    capsys.readouterr()
    for bad in (
        ["operators", "issues"],
        ["operators", "issues", "-f", str(full), "--openshift-version", "4.22; rm"],
        ["operators", "issues", "-f", str(full), "--openshift-version", "v4.22"],
        ["operators", "issues", "-f", str(full), "--openshift-version", "4.09"],
        ["operators", "issues", "--live"],
        ["operators", "issues", "-f", str(full), "--top", "0"],
        ["operators", "issues", "-f", str(full), "--issues", "0"],
    ):
        assert main(bad) == 2, bad
        capsys.readouterr()


def test_the_tools_and_the_must_gather_analysis_carry_the_answer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    kit = tk.Toolkit(load_settings())
    names = {s.name for s in kit.specs()}
    assert "operator_known_issues" in names and "cluster_operator_known_issues" not in names
    manifests = y(*pair("ptp-operator", "p", "ptp.v1"))
    out = kit.operator_known_issues(tk.OperatorKnownIssuesIn(manifests=manifests, openshift_version="4.22.3"))
    assert out["complete"] is True and out["operators"][0]["verdict"] == "named"
    assert out["cluster"]["versionFrom"] == "given"
    f = tmp_path / "p.yaml"
    f.write_text(manifests)
    assert main(["operators", "issues", "-f", str(f), "--openshift-version", "4.22.3", "--format", "json"]) == 0
    cli = json.loads(capsys.readouterr().out)
    assert {k: v for k, v in cli.items() if k not in ("hints", "caveats")} == {
        k: v for k, v in out.items() if k not in ("hints", "caveats")
    }
    live_kit = tk.Toolkit(load_settings(overrides={"cluster": {"enabled": True}}))
    assert "cluster_operator_known_issues" in {s.name for s in live_kit.specs()}

    tgz = sample.write(tmp_path / "case")
    got = kit.analyze_must_gather(tk.MustGatherIn(path=str(tgz)))["operatorKnownIssues"]
    assert got["cluster"]["openshiftVersion"] == "4.20.3" and got["inventory"]["verdict"] == "partial"
    assert "openshift_version" in got["hints"]["version"]
    assert main(["must-gather", "analyze", str(tgz), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["operatorKnownIssues"]["complete"] is False
    assert main(["must-gather", "analyze", str(tgz)]) == 0
    assert "operator known issues (must-gather)" in capsys.readouterr().out


def test_the_plugin_ships_the_join() -> None:
    spec = importlib.util.spec_from_file_location("kn_sync_plugin_r5", ROOT / "scripts" / "sync_plugin_server.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["kn_sync_plugin_r5"] = mod
    spec.loader.exec_module(mod)
    assert "kube_noob.operator_issues" in mod.plugin_modules(ROOT)
