"""R5: which installed operators the OpenShift release notes name in a reported issue.

The bundled corpus keys every issue by OpenShift release and free text: no record carries a component, a package or
an operator version (measured in the first test, so a corpus that grows one fails here and the join gets upgraded
rather than silently ignoring it). The join is therefore package -> the product names the release notes use, through
an explicit alias table, narrowed by the cluster's OpenShift release. A fix the notes state is an OpenShift release,
never an operator version, so whether an installed operator carries it is never decided here. Every test is named for
a behaviour; most are about a miss or a gap not reading as "no reported issue".
"""

from __future__ import annotations

import json
import random
import re
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
from kube_noob.mustgather import sample

API = "operators.coreos.com/v1alpha1"
RECORD_FIELDS = {"id", "ids", "kind", "minor", "version", "text", "source", "issued", "fixedIn"}


def csv(name: str, ns: str, version: Any = "1.0.0", **meta: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "apiVersion": API,
        "kind": "ClusterServiceVersion",
        "metadata": {"name": name, "namespace": ns, **meta},
        "status": {"phase": "Succeeded"},
    }
    if version is not None:
        d["spec"] = {"version": version}
    return d


def sub(name: str, ns: str, pkg: str, installed: str | None = None, status: bool = True) -> dict[str, Any]:
    d: dict[str, Any] = {
        "apiVersion": API,
        "kind": "Subscription",
        "metadata": {"name": name, "namespace": ns},
        "spec": {"name": pkg, "source": "redhat-operators", "sourceNamespace": "openshift-marketplace"},
    }
    if status:
        d["status"] = {"installedCSV": installed} if installed else {"state": "UpgradePending"}
    return d


def pair(pkg: str, ns: str, csv_name: str, version: Any = "1.0.0") -> list[dict[str, Any]]:
    return [csv(csv_name, ns, version), sub(pkg, ns, pkg, csv_name)]


def y(*docs: Any) -> str:
    return "\n---\n".join(yaml.safe_dump(d) for d in docs)


def assess(*docs: Any, version: str | None = "4.22.3", **kw: Any) -> dict[str, Any]:
    return oi.assess(ops.from_manifests(y(*docs)), openshift_version=version, version_from="flag", **kw)


def one(out: dict[str, Any], package: str | None = None, csv_name: str | None = None) -> dict[str, Any]:
    found = [o for o in out["operators"] if (package is None or o.get("package") == package)]
    found = [o for o in found if csv_name is None or o.get("csv") == csv_name]
    assert len(found) == 1, found
    return found[0]


# -- what the corpus can support ---------------------------------------------------------------------------------


def test_the_corpus_keys_issues_by_openshift_release_and_text_not_by_operator_version() -> None:
    """The premise of the join, measured. If a regenerated corpus gains a component or an operator-version field,
    this fails: the join should then use it instead of names."""
    issues, meta = known_issues.bundled()
    root = Path(known_issues.__file__).parent / "data" / "known_issues"
    for f in sorted(root.glob("*.json")):
        for r in json.loads(f.read_text(encoding="utf-8"))["records"]:
            assert set(r) <= RECORD_FIELDS, (f.name, sorted(set(r) - RECORD_FIELDS))
    ocp = re.compile(r"^4\.\d+(\.\d+)?\Z")
    assert all(ocp.match(i.version) and ocp.match(i.minor) for i in issues)
    assert all(i.fixed_in is None or ocp.match(i.fixed_in) for i in issues)
    assert meta["retrievedAt"] and oi.method_note()


def test_every_alias_name_is_used_by_the_bundled_release_notes() -> None:
    """The table cannot rot silently when the corpus is regenerated: a name no record uses is a failure, here and in
    scripts/vendor_known_issues.py --check."""
    issues, _ = known_issues.bundled()
    assert oi.alias_problems(issues) == []
    for package, alias in oi.ALIASES.items():
        for name in alias.names:
            assert any(oi.name_pattern(name).search(i.text) for i in issues), (package, name)


def test_no_alias_name_matches_two_packages() -> None:
    owners: dict[str, str] = {}
    for package, alias in oi.ALIASES.items():
        for name in alias.names:
            assert name not in owners, (name, owners.get(name), package)
            owners[name] = package
    for a, pa in owners.items():
        for b, pb in owners.items():
            if pa != pb:
                assert not oi.name_pattern(a).search(b), (a, pa, b, pb)


def test_a_regenerated_corpus_missing_an_alias_target_is_reported() -> None:
    issues, _ = known_issues.bundled()
    without = [i for i in issues if not oi.name_pattern("NUMA Resources Operator").search(i.text)]
    problems = oi.alias_problems(without)
    assert any("numaresources-operator" in p and "NUMA Resources Operator" in p for p in problems)
    shared = dict(oi.ALIASES)
    shared["metallb-operator-copy"] = oi.Alias(("MetalLB Operator",), "test")
    assert any("two packages" in p for p in oi.alias_problems(issues, shared))


@pytest.mark.parametrize(
    ("name", "text", "hit"),
    [
        ("cert-manager", "with cert-manager installed", True),
        ("cert-manager", "the `cert-manager` Operator", True),
        ("cert-manager", "the openshift-cert-manager-operator namespace", False),
        ("cert-manager", "cert-manager-istio-csr is broken", False),
        ("PTP Operator", "the XPTP Operator", False),
        ("PTP Operator", "the ptp operator", False),  # case-sensitive: the notes write product names in capitals
        ("DPU Operator", "the DPU Operators", False),
        ("MetalLB Operator", "MetalLB Operator.", True),
    ],
)
def test_a_name_matches_only_as_a_whole_phrase(name: str, text: str, hit: bool) -> None:
    assert bool(oi.name_pattern(name).search(text)) is hit


def test_every_aliased_package_is_a_valid_package_name_with_a_cited_source() -> None:
    for package, alias in oi.ALIASES.items():
        assert ops._NAME.match(package), package
        assert alias.names and alias.source, package


# -- the join ----------------------------------------------------------------------------------------------------


def test_an_operator_named_in_a_fixed_issue_is_listed_with_its_source_and_the_corpus_date() -> None:
    out = assess(*pair("ptp-operator", "openshift-ptp", "ptp-operator.v4.22.0-202601010000", None), version="4.22.3")
    op = one(out, "ptp-operator")
    assert op["verdict"] == "named"
    ids = {i["id"] for i in op["issues"]}
    assert "OCPBUGS-74358" in ids
    row = next(i for i in op["issues"] if i["id"] == "OCPBUGS-74358")
    assert row["release"] == "4.22" and row["kind"] == "fixed" and row["fixedInOpenShift"] == "4.22.0"
    assert row["source"].startswith("https://github.com/openshift/openshift-docs/blob/")
    assert row["url"] == "https://redhat.atlassian.net/browse/OCPBUGS-74358"
    assert row["knownIssuesAsOf"] == out["knowledge"]["knownIssuesAsOf"] == "2026-10-27"
    assert row["matchedName"] in oi.ALIASES["ptp-operator"].names


@pytest.mark.parametrize(
    ("csv_name", "version", "label"),
    [
        # an OpenShift-versioned operator build: 4.y.0-<build>, which sorts BEFORE every 4.y.z fix
        ("ptp-operator.v4.22.0-202601010000", None, "derived-from-name"),
        # a version that looks comparable and AFTER the fix (4.22.0): still a different version space
        ("ptp-operator.v9", "4.22.99", "spec.version"),
        # and one that looks comparable and BEFORE it
        ("ptp-operator.v8", "4.21.0", "spec.version"),
        # not a version at all, and absent
        ("ptp-operator.v7", "latest", None),
        ("ptp-operator", None, None),
    ],
)
def test_a_fix_stated_as_an_openshift_release_is_never_compared_with_the_operator_version(
    csv_name: str, version: str | None, label: str | None
) -> None:
    out = assess(*pair("ptp-operator", "openshift-ptp", csv_name, version), version="4.22.3")
    op = one(out, "ptp-operator")
    assert op.get("versionFrom") == label
    fixed = [i for i in op["issues"] if i["fixedInOpenShift"]]
    assert fixed
    for row in fixed:
        assert row["installedHasFix"] == "not-determined", row
        assert "OpenShift release" in row["why"] and "not a version of ptp-operator" in row["why"]
    blob = json.dumps(out)
    for word in ('"installedHasFix": "yes"', '"installedHasFix": "no"', "affected", "is fixed in your"):
        assert word not in blob


def test_a_known_issue_with_no_fix_says_no_fix_is_listed() -> None:
    out = assess(
        *pair("numaresources-operator", "openshift-numaresources", "numaresources-operator.v4.21.0"), version="4.21.5"
    )
    row = next(i for i in one(out)["issues"] if i["id"] == "OCPBUGS-77930")
    assert row["kind"] == "known" and row["fixedInOpenShift"] is None and row["installedHasFix"] == "no-fix-listed"


def test_narrowing_keeps_only_the_release_the_cluster_runs() -> None:
    out = assess(*pair("numaresources-operator", "openshift-numaresources", "nro.v4.21.0"), version="4.21.5")
    op = one(out)
    assert [(i["id"], i["release"]) for i in op["issues"]] == [("OCPBUGS-77930", "4.21")]
    assert out["cluster"] == {"openshiftVersion": "4.21.5", "versionFrom": "flag", "release": "4.21", "indexed": True}


def test_an_aliased_operator_with_no_issue_for_this_release_is_none_named_not_clean() -> None:
    out = assess(*pair("clusterresourceoverride", "cro", "cro.v4.22.0"), version="4.22.3")
    op = one(out)
    assert op["verdict"] == "none-named" and op["issues"] == []
    assert "names this operator" in op["reason"] and "not that it has no" in op["reason"]
    assert out["complete"] is True and out["verdict"] == "assessed"
    assert out["counts"]["noneNamed"] == 1


def test_an_operator_without_an_alias_is_listed_and_counted_never_clean() -> None:
    out = assess(*pair("my-operator", "mine", "my-operator.v1.0.0"), *pair("ptp-operator", "ptp", "ptp.v4.22.0"))
    op = one(out, "my-operator")
    assert op["verdict"] == "no-alias" and op["issues"] == []
    assert "not matched against the release notes (no alias)" in op["reason"]
    assert out["counts"]["noAlias"] == 1 and out["counts"]["named"] == 1
    assert "1 operator(s) have no alias" in out["summary"]
    text = oi.render_text(out)
    assert "my-operator" in text and "not matched against the release notes (no alias)" in text


def test_an_operator_whose_package_is_unknown_is_not_matched_by_its_csv_name() -> None:
    out = assess(csv("ptp-operator.v4.22.0", "openshift-ptp"), sub("other", "openshift-ptp", "unrelated", "x.v1"))
    op = one(out, None, "ptp-operator.v4.22.0")
    assert op["verdict"] == "package-unknown" and op["issues"] == []
    assert out["counts"]["packageUnknown"] == 1


def test_a_cluster_version_outside_the_index_is_not_determined_for_every_operator() -> None:
    out = assess(*pair("ptp-operator", "p", "ptp.v4.18.0"), *pair("my-operator", "m", "my.v1.0.0"), version="4.18.5")
    assert out["verdict"] == "not-determined" and out["complete"] is False
    assert {o["verdict"] for o in out["operators"]} == {"not-determined"}
    assert all(o["issues"] == [] for o in out["operators"])
    assert out["cluster"]["indexed"] is False
    assert any("4.18" in c and "4.20, 4.21, 4.22" in c for c in out["caveats"])
    assert "no known issue" not in json.dumps(out).lower()


def test_without_a_cluster_version_matches_are_not_narrowed_and_the_answer_is_incomplete() -> None:
    docs = [*pair("clusterresourceoverride", "cro", "cro.v4.22.0"), *pair("numaresources-operator", "n", "n.v1")]
    out = assess(*docs, version=None)
    assert out["complete"] is False and out["verdict"] == "partial"
    assert out["cluster"]["openshiftVersion"] is None and out["cluster"]["indexed"] is None
    nro = one(out, "numaresources-operator")
    assert {i["release"] for i in nro["issues"]} == {"4.20", "4.21", "4.22"}
    assert any("not narrowed" in c for c in out["caveats"])


def test_with_no_version_an_aliased_operator_nothing_names_is_not_determined() -> None:
    issues, meta = known_issues.bundled()
    index = known_issues.Index([i for i in issues if "Cluster Resource Override" not in i.text], meta)
    c = ops.from_manifests(y(*pair("clusterresourceoverride", "cro", "cro.v4.22.0")))
    out = oi.assess(c, openshift_version=None, version_from=None, index=index)
    assert one(out)["verdict"] == "not-determined"


def test_a_partial_inventory_makes_the_answer_incomplete_and_names_the_operators_not_assessed() -> None:
    docs = [
        *pair("ptp-operator", "p", "ptp.v4.22.0"),
        csv("nro.v4.22.0", "n"),
        sub("nro", "n", "numaresources-operator", status=False),
    ]
    out = assess(*docs)
    assert out["inventory"]["verdict"] == "partial"
    assert out["complete"] is False and out["verdict"] == "partial"
    assert any(c.startswith("inventory: ") for c in out["caveats"])
    nro = one(out, "numaresources-operator")
    assert nro["inventoryState"] == "status-not-read"
    assert any("installed" in n and "not determined" in n for n in nro["notes"])

    blind = oi.assess(
        ops.from_manifests(y({"kind": "ConfigMap", "metadata": {"name": "x"}})),
        openshift_version="4.22.1",
        version_from="flag",
    )
    assert blind["verdict"] == "not-determined" and blind["operators"] == []
    assert "not determined" in blind["summary"] and "no reported issue" not in blind["summary"].lower()


def test_operators_the_inventory_did_not_show_are_counted_as_not_assessed(monkeypatch: pytest.MonkeyPatch) -> None:
    out = assess(*pair("ptp-operator", "p", "ptp.v1"), *pair("my-operator", "m", "my.v1"), top=1)
    assert out["operatorsTotal"] == 2 and out["notShown"] == 1 and len(out["operators"]) == 1
    monkeypatch.setattr(ops, "MAX_OPERATORS", 1)
    capped = assess(*pair("ptp-operator", "p", "ptp.v1"), *pair("my-operator", "m", "my.v1"))
    assert capped["complete"] is False and any("not assessed" in c for c in capped["caveats"])


def test_an_operator_that_is_not_installed_is_not_assessed() -> None:
    out = assess(sub("ptp", "p", "ptp-operator"), *pair("my-operator", "m", "my.v1"))
    op = one(out, "ptp-operator")
    assert op["verdict"] == "not-installed" and op["issues"] == []


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
    assert [o["package"] for o in out["operators"] if o.get("package") == "ptp-operator"] == ["ptp-operator"]
    assert all(o["verdict"] != "named" for o in out["operators"] if o.get("package") != "ptp-operator")


def test_hostile_text_in_a_local_corpus_copy_is_flattened(tmp_path: Path) -> None:
    _issues, meta = known_issues.bundled()
    evil = known_issues.Issue(
        id="OCPBUGS-1",
        ids=("OCPBUGS-1",),
        kind="known",
        minor="4.22",
        version="4.22",
        text="The PTP Operator \x1b]8;;http://x\x07 breaks \u202e here.",
        source="https://example.invalid/\x1b[2J",
        issued=None,
        fixed_in=None,
    )
    odd = known_issues.Issue(
        id="OCPBUGS-2\n caveat: forged",
        ids=("OCPBUGS-2",),
        kind="fixed\x1b[0m",
        minor="4.22\u2028\u061c",
        version="4.22.9\x1b[1m\ncaveat: forged",
        text="The PTP Operator did a thing.",
        source="modules/x.adoc",
        issued=None,
        fixed_in=None,
    )
    c = ops.from_manifests(y(*pair("ptp-operator", "p", "ptp.v1")))
    hostile_meta = {**meta, "retrievedAt": "2026-10-27\x1b[2J\ncaveat: forged"}
    index = known_issues.Index([evil, odd], hostile_meta)
    for version in ("4.22.1", None):
        out = oi.assess(c, openshift_version=version, version_from="flag", index=index)
        text = oi.render_text(out)
        blob = text + json.dumps(out, ensure_ascii=False)
        for ch in ("\x1b", "\u202e", "\x07", "\u2028", "\u061c"):
            assert ch not in blob, (version, hex(ord(ch)))
        assert not [line for line in text.splitlines() if line.startswith("caveat: forged")]
    assert {r["id"] for r in one(out)["issues"]} == {"OCPBUGS-1", "OCPBUGS-2 caveat: forged"}


def test_the_answer_is_deterministic() -> None:
    docs = [
        *pair("ptp-operator", "p", "ptp.v1"),
        *pair("my-operator", "m", "my.v1"),
        *pair("metallb-operator", "x", "m.v1"),
    ]
    first = json.dumps(assess(*docs), sort_keys=False)
    rng = random.Random(7)
    for _ in range(5):
        shuffled = list(docs)
        rng.shuffle(shuffled)
        assert json.dumps(assess(*shuffled), sort_keys=False) == first


def test_a_skipped_file_or_a_conflicting_duplicate_is_never_a_complete_answer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    d = tmp_path / "olm"
    d.mkdir()
    (d / "ptp.yaml").write_text(y(*pair("ptp-operator", "p", "ptp.v4.22.0")))
    (d / "broken.YAML").write_text("kind: [unclosed\n")
    (d / "empty.yml").write_text("")
    argv = ["operators", "issues", "-f", str(d), "--openshift-version", "4.22.3"]
    assert main([*argv, "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["complete"] is False and out["inventory"]["verdict"] == "partial"
    assert any("could not be read" in c for c in out["caveats"])
    assert main([*argv, "--require-complete"]) == 5
    capsys.readouterr()

    a, b = csv("ptp.v1", "p", "1.0.0"), csv("ptp.v1", "p", "2.0.0")
    first = assess(a, b, sub("ptp", "p", "ptp-operator", "ptp.v1"))
    again = assess(b, a, sub("ptp", "p", "ptp-operator", "ptp.v1"))
    assert first == again and first["complete"] is False
    assert any("different content" in c for c in first["caveats"])


def test_the_text_view_carries_what_the_json_carries() -> None:
    docs = [
        *pair("ptp-operator", "p", "ptp.v1"),
        *pair("my-operator", "m", "my.v1"),
        csv("nro.v1", "n"),
        sub("n", "n", "x", status=False),
    ]
    out = assess(*docs)
    text = oi.render_text(out)
    assert out["knowledge"]["knownIssuesAsOf"] in text
    for op in out["operators"]:
        assert op["verdict"] in text
        for row in op["issues"]:
            assert row["id"] in text and row["source"] in text and row["url"] in text
    for caveat in out["caveats"]:
        assert caveat in text
    assert out["method"] in text


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


def _cv(*history: tuple[str, str]) -> dict[str, Any]:
    return {
        "apiVersion": "config.openshift.io/v1",
        "kind": "ClusterVersion",
        "metadata": {"name": "version"},
        "status": {"desired": {"version": history[0][0]}, "history": [{"version": v, "state": s} for v, s in history]},
    }


def test_the_live_read_takes_the_running_version_from_the_cluster_version() -> None:
    data = {
        "clusterserviceversions": [csv("ptp.v4.21.0", "p")],
        "subscriptions": [sub("ptp", "p", "ptp-operator", "ptp.v4.21.0")],
        "clusterversions": [_cv(("4.22.1", "Partial"), ("4.21.9", "Completed"))],
    }
    version, note = oi.live_openshift_version(FakeBackend(data))
    assert (version, note) == ("4.21.9", "")
    failing = FakeBackend(data, {"clusterversions": 'clusterversions.config.openshift.io "version" is forbidden'})
    version, note = oi.live_openshift_version(failing)
    assert version is None and "forbidden" in note
    garbage = FakeBackend({"clusterversions": [_cv(("4.22.1\x1b[0m; rm", "Completed"))]})
    assert oi.live_openshift_version(garbage)[0] is None
    for shape in (
        {"status": {"history": 5, "desired": "4.22.1"}},
        {"status": {"history": "4.22.1", "desired": {"version": 4.22}}},
        {"status": [1, 2]},
        [],
        {"status": {"history": [{"version": "4.21.2", "state": True}, "x", None]}},
    ):
        version, note = oi.live_openshift_version(FakeBackend({"clusterversions": [shape]}))  # type: ignore[list-item]
        assert version is None and "no version" in note, shape
    # mid-update: the release that runs is the completed one, not the one it is moving to
    partial = FakeBackend({"clusterversions": [_cv(("4.22.1", "Partial"))]})
    assert oi.live_openshift_version(partial)[0] == "4.22.1"  # no completed entry yet: desired, as the analyser does


def test_a_live_cluster_version_that_cannot_be_read_leaves_the_answer_incomplete() -> None:
    data = {
        "clusterserviceversions": [csv("ptp.v1", "p")],
        "subscriptions": [sub("ptp", "p", "ptp-operator", "ptp.v1")],
    }
    backend = FakeBackend(data, {"clusterversions": "Error from server (Forbidden): forbidden"})
    version, note = oi.live_openshift_version(backend)
    out = oi.assess(ops.collect_live(backend, []), openshift_version=version, version_from=None, version_note=note)
    assert out["complete"] is False and out["cluster"]["openshiftVersion"] is None
    assert any("Forbidden" in c and "not narrowed" in c for c in out["caveats"])
    assert any("Forbidden" in line for line in oi.render_text(out).splitlines() if line.startswith("caveat:"))


def test_withheld_issues_and_operators_are_counted_in_every_format() -> None:
    docs = [*pair("servicemeshoperator3", "openshift-operators", "servicemeshoperator3.v3.1.0")]
    out = assess(*docs, version=None, issues_per_operator=2)
    op = one(out)
    assert op["issuesTotal"] > 2 and len(op["issues"]) == 2
    assert out["counts"]["issues"] == op["issuesTotal"]  # computed before the cut
    assert f"and {op['issuesTotal'] - 2} more issue(s)" in oi.render_text(out)
    many = [
        *pair("ptp-operator", "a", "ptp.v1"),
        *pair("zz-unaliased", "b", "zz.v1"),
        *pair("aa-unaliased", "c", "aa.v1"),
    ]
    cut = assess(*many, top=1)
    assert cut["operators"][0]["verdict"] == "named"  # a named operator is not cut for an unaliased one
    assert cut["counts"]["noAlias"] == 2 and cut["notShown"] == 2
    assert "and 2 more operator(s)" in oi.render_text(cut)


def test_the_cli_reads_the_same_three_inputs_and_exits_5_only_when_asked_and_incomplete(
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
    assert out["complete"] is True and out["cluster"]["versionFrom"] == "flag"
    assert main([*argv, "--format", "yaml"]) == 0
    assert yaml.safe_load(capsys.readouterr().out)["verdict"] == "assessed"
    assert main(["operators", "issues", "-f", str(full), "--require-complete"]) == 5
    assert "refusing" in capsys.readouterr().err

    tgz = sample.write(tmp_path / "case")
    assert main(["operators", "issues", "--must-gather", str(tgz), "--format", "json"]) == 0
    mg = json.loads(capsys.readouterr().out)
    assert mg["cluster"]["openshiftVersion"] == "4.20.3" and mg["cluster"]["versionFrom"] == "must-gather"
    assert mg["inventory"]["verdict"] == "partial" and mg["complete"] is False
    assert main(["operators", "issues", "--must-gather", str(tgz), "--require-complete"]) == 5
    capsys.readouterr()
    for bad in (
        ["operators", "issues"],
        ["operators", "issues", "-f", str(full), "--openshift-version", "4.22; rm"],
        ["operators", "issues", "-f", str(full), "--openshift-version", "v4.22"],
        ["operators", "issues", "--live"],
        ["operators", "issues", "-f", str(full), "--top", "0"],
    ):
        assert main(bad) == 2, bad
        capsys.readouterr()


def test_the_tools_and_the_must_gather_analysis_carry_the_answer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    kit = tk.Toolkit(load_settings())
    names = {s.name for s in kit.specs()}
    assert "operator_known_issues" in names and "cluster_operator_known_issues" not in names
    out = kit.operator_known_issues(
        tk.OperatorKnownIssuesIn(manifests=y(*pair("ptp-operator", "p", "ptp.v1")), openshift_version="4.22.3")
    )
    assert out["complete"] is True and out["operators"][0]["verdict"] == "named"
    with pytest.raises(ValueError):
        tk.OperatorKnownIssuesIn(manifests="x: 1", openshift_version="4.22; rm")
    live = tk.Toolkit(load_settings(overrides={"cluster": {"enabled": True}}))
    assert "cluster_operator_known_issues" in {s.name for s in live.specs()}

    tgz = sample.write(tmp_path / "case")
    mg = kit.analyze_must_gather(tk.MustGatherIn(path=str(tgz)))
    got = mg["operatorKnownIssues"]
    assert got["cluster"]["openshiftVersion"] == "4.20.3" and got["inventory"]["verdict"] == "partial"
    assert main(["must-gather", "analyze", str(tgz), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["operatorKnownIssues"]["complete"] is False
    assert main(["must-gather", "analyze", str(tgz)]) == 0
    assert "operator known issues (must-gather)" in capsys.readouterr().out


def test_the_plugin_ships_the_join() -> None:
    import importlib.util
    import sys

    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("kn_sync_plugin_r5", root / "scripts" / "sync_plugin_server.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["kn_sync_plugin_r5"] = mod
    spec.loader.exec_module(mod)
    assert "kube_noob.operator_issues" in mod.plugin_modules(root)
