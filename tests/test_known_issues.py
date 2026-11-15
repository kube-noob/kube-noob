"""Reported issues from the OpenShift release notes, the knowledge date on every answer, and the live cluster version.

The gate for 0.3: every match cites a Red Hat issue and the release-notes file, and generic errors that the
playbooks handle (OOMKilled, ImagePullBackOff, SCC denials, ...) never match a reported issue.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest

import kube_noob.net as net_mod
from kube_noob import known_issues as ki
from kube_noob import toolkit as tk
from kube_noob.config import load_settings
from kube_noob.debug.cluster import cluster_info
from kube_noob.knowledge_status import compare, status
from kube_noob.sources.release_notes import Release, clean, link_fixes, parse_attributes, parse_release

DATA = Path(ki.__file__).parent / "data" / "known_issues"

# Real errors and symptoms, each matched to the issue the release notes describe.
POSITIVE = {
    "OCPBUGS-57440": "Error syncing load balancer: failed to ensure load balancer: could not find any suitable subnets "
    "for creating the ELB. Gateway in AWS private cluster stuck pending",
    "OCPBUGS-56599": "service-ca operator hotloop with invalid serving-cert-secret-name annotation on my service",
    "OCPBUGS-62623": "DNS operator Progressing=True during node reboots, node-resolver pods not available in upgrade",
    "OCPBUGS-86872": "console crashed with React error #310 when opening Shipwright BuildRun detail page",
}

# Everyday errors the playbooks handle; none of them is a reported product bug.
NEGATIVE = [
    "Back-off restarting failed container api in pod api-7d9f. Last State: Terminated Reason: OOMKilled Exit Code: 137",
    "Failed to pull image quay.io/acme/api:latest: rpc error: code = Unknown desc = pull access denied",
    "0/3 nodes are available: 3 Insufficient cpu. preemption: 0/3 nodes are available",
    "Error from server (Forbidden): pods is forbidden: User system:serviceaccount:shop:default cannot list pods",
    "x509: certificate signed by unknown authority",
    "Readiness probe failed: HTTP probe failed with statuscode: 503",
    "Error creating: pods api-1 is forbidden: unable to validate against any security context constraint: provider "
    "restricted-v2: .spec.securityContext.runAsUser: Invalid value: 1000",
    "MountVolume.SetUp failed for volume pvc-1: mount failed: exit status 32 NFS permission denied",
    "Warning FailedScheduling persistentvolumeclaim not found",
    "route returns 503 Application is not available",
    "Error: UPGRADE FAILED: another operation (install/upgrade/rollback) is in progress",
    "CrashLoopBackOff",
]


# ---------------------------------------------------------------- the release-notes parser


def _release(tmp_path: Path) -> Release:
    (tmp_path / "_attributes").mkdir()
    (tmp_path / "_attributes" / "common-attributes.adoc").write_text(
        ":aws-first: Amazon Web Services (AWS)\n:rh-x-first: Red{nbsp}Hat X (RHX)\n"
    )
    mods = tmp_path / "modules"
    mods.mkdir()
    (mods / "rn-ocp-release-notes-known-issues.adoc").write_text(
        '= Known issues\n\n[role="_abstract"]\nIntro.\n\n'
        "* On {aws-first} private clusters the *gateway* load balancer stays `pending`.\n+\n"
        "To work around this problem, use a public subnet. (link:https://issues.redhat.com/browse/OCPBUGS-1001[OCPBUGS-1001])\n\n"
        "* A note without an issue link is not indexed because nobody can check it later on.\n\n"
        "* {rh-x-first} logs a warning at start up for no reason at all, which is harmless. "
        "(link:https://issues.redhat.com/browse/OCPBUGS-1002[OCPBUGS-1002])\n"
    )
    (mods / "zstream-4-20-3.adoc").write_text(
        "= RHSA-2026:1 - {product-title} {product-version}.3 bug fix update\n\nIssued: 5 March 2026\n\n"
        '[id="zstream-4-20-3-fixed-issues_{context}"]\n== Fixed issues\n\n'
        "* Before this update, the gateway load balancer stayed pending on private clusters. With this release, it "
        "is provisioned. (link:https://issues.redhat.com/browse/OCPBUGS-1001[OCPBUGS-1001])\n\n"
        '[id="zstream-4-20-3-updating_{context}"]\n== Updating\n\n* Not an issue: run oc adm upgrade.\n'
    )
    return Release("4.20", tmp_path, "c" * 40)


def test_parser_reads_known_and_fixed_issues_and_links_the_fix(tmp_path: Path) -> None:
    recs = link_fixes(parse_release(_release(tmp_path)))
    known = {r["id"]: r for r in recs if r["kind"] == "known"}
    fixed = [r for r in recs if r["kind"] == "fixed"]
    assert set(known) == {"OCPBUGS-1001", "OCPBUGS-1002"}, "items without an issue id are dropped"
    k = known["OCPBUGS-1001"]
    assert k["fixedIn"] == "4.20.3" and k["version"] == "4.20"
    assert "Amazon Web Services (AWS)" in k["text"] and "{aws-first}" not in k["text"]
    assert "gateway" in k["text"] and "*gateway*" not in k["text"]
    assert k["workaround"] == "To work around this problem, use a public subnet."
    assert "Red Hat X (RHX)" in known["OCPBUGS-1002"]["text"], "nested attributes and {nbsp} expand"
    assert known["OCPBUGS-1002"]["fixedIn"] is None
    assert [(r["id"], r["version"], r["issued"]) for r in fixed] == [("OCPBUGS-1001", "4.20.3", "2026-03-05")]
    assert all(r["source"].startswith("https://github.com/openshift/openshift-docs/blob/" + "c" * 40) for r in recs)


def test_clean_reduces_asciidoc_markup() -> None:
    attrs = parse_attributes(":a: Alpha\n:b: {a} Beta\n")
    assert attrs["b"] == "Alpha Beta"
    text = clean("See xref:../x.adoc#y[the guide] and link:https://e.com[E] for {b}.\n+\n----\n", attrs)
    assert text == "See the guide and E for Alpha Beta."


# ---------------------------------------------------------------- the bundled index


def test_bundled_index_cites_every_issue_and_fits_the_plugin_limits() -> None:
    files = sorted(DATA.glob("*.json"))
    assert files, "run scripts/vendor_known_issues.py"
    for f in files:
        raw = f.read_bytes()
        assert len(raw) < 256 * 1024, f.name
        json.loads(raw.decode("utf-8"))
    idx = ki.get_index()
    k = idx.knowledge()
    assert {"4.20", "4.21", "4.22"} <= set(k["openshiftReleases"])
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", k["knownIssuesAsOf"])
    assert len(idx.issues) > 500
    for issue in idx.issues:
        assert re.fullmatch(r"[A-Z][A-Z0-9]+-\d+", issue.id), issue.id
        assert issue.url == f"https://redhat.atlassian.net/browse/{issue.id}"
        assert re.match(
            r"https://github.com/openshift/openshift-docs/blob/[0-9a-f]{40}/modules/\S+\.adoc$", issue.source
        )
        assert not re.search(
            r"\{(product-title|product-version|nbsp|aws-first|azure-short|hcp|sno|op-system)\}", issue.text
        ), f"unexpanded AsciiDoc attribute in {issue.id}"


@pytest.mark.parametrize(("issue_id", "text"), sorted(POSITIVE.items()))
def test_real_errors_match_the_reported_issue(issue_id: str, text: str) -> None:
    out = ki.match(text, "openshift")
    assert out["matches"], text
    top = out["matches"][0]
    assert top["id"] == issue_id
    assert top["url"].startswith("https://redhat.atlassian.net/browse/") and "openshift-docs" in top["source"]
    # Three rare shared words, or two with a strong score: words the bundled docs explain ("serving", "cert") are
    # not evidence of one bug.
    shared = len(top["sharedTerms"])
    assert shared >= ki.MIN_RARE_TERMS or (shared >= 2 and top["score"] >= ki.STRONG_SCORE), top


@pytest.mark.parametrize("text", NEGATIVE)
def test_generic_errors_never_match_a_reported_issue(text: str) -> None:
    out = ki.match(text, "openshift")
    assert out["matches"] == [], (text, [m["id"] for m in out["matches"]])
    assert "No reported issue" in out["note"]


def test_an_error_quoted_word_for_word_from_a_known_issue_matches_it() -> None:
    """The docs' example: the cloud error exactly as a user sees it, with two rare words and no "openshift" in it. A
    run of seven words copied from the issue text, one of them rare, is evidence enough (red team, 2026-10-29)."""
    q = "could not find any suitable subnets for creating the ELB"
    out = ki.match(q, version="4.20.8")
    assert [m["id"] for m in out["matches"]][:1] == ["OCPBUGS-57440"], out.get("note")
    assert out["matches"][0]["exactError"] is True
    assert ki.match("could not find any suitable subnets", version="4.20.8")["matches"] == []  # too short to quote
    # Seven common words in a row are no quotation: every one of them is in many issues.
    common = "after you update the cluster to the latest version the pods are not running"
    assert ki.match(common, "openshift")["matches"] == []


def test_version_filter_and_status_messages() -> None:
    q = POSITIVE["OCPBUGS-56599"]
    issue = next(i for i in ki.get_index().issues if i.id == "OCPBUGS-56599")
    assert issue.kind == "fixed"
    older = ki.match(q, "openshift", issue.version.rsplit(".", 1)[0] + ".0")["matches"]
    assert older and older[0]["id"] == "OCPBUGS-56599"
    assert f"updating to {issue.version} or later fixes it" in older[0]["status"]
    newer = ki.match(q, "openshift", issue.version)["matches"]
    assert "OCPBUGS-56599" not in [m["id"] for m in newer], "already fixed in the version the user runs"
    open_issue = ki.match(POSITIVE["OCPBUGS-57440"], "rosa-hcp", "4.21.4")["matches"][0]
    assert open_issue["kind"] == "known" and open_issue["foundIn"] == "4.20"
    assert ki.match(POSITIVE["OCPBUGS-57440"], "openshift", "4.19.10")["matches"] == [], "issue starts in 4.20"


def test_plain_kubernetes_is_not_matched_against_openshift_issues() -> None:
    out = ki.match(POSITIVE["OCPBUGS-57440"], "kubernetes")
    assert out["matches"] == [] and "plain Kubernetes" in out["note"]


def test_a_newer_local_snapshot_replaces_the_bundled_one(tmp_path: Path) -> None:
    """`corpus known-issues --online` writes a full, newer snapshot; it wins over the bundled one."""
    records, commits = [], {}
    for f in sorted(DATA.glob("*.json")):
        doc = json.loads(f.read_text(encoding="utf-8"))
        records += doc["records"]
        commits.update(doc["commits"])
    records.append(
        {
            "id": "OCPBUGS-9999999",
            "kind": "known",
            "minor": "4.22",
            "version": "4.22",
            "text": "Zebra quokka marmoset frobnicator fails with error XQ-77 when the wibble controller restarts.",
            "source": "modules/rn-ocp-release-notes-known-issues.adoc",
        }
    )
    local = tmp_path / "known_issues"
    local.mkdir()
    doc = {"retrievedAt": "2099-01-01", "commits": commits, "records": records}
    (local / "openshift-release-notes.json").write_text(json.dumps(doc))
    out = ki.match("frobnicator error XQ-77 zebra quokka wibble controller", "openshift", data_dir=tmp_path)
    assert [m["id"] for m in out["matches"]] == ["OCPBUGS-9999999"]
    assert out["knowledge"]["knownIssuesAsOf"] == "2099-01-01"


# ---------------------------------------------------------------- tools, knowledge date and provenance


def test_diagnose_tool_adds_reported_issues_and_known_issues_tool_exists(tmp_path: Path) -> None:
    kit = tk.Toolkit(load_settings(overrides={"data_dir": str(tmp_path)}))
    assert "known_issues" in {s.name for s in kit.specs()}
    out = kit.diagnose(tk.DiagnoseIn(text=POSITIVE["OCPBUGS-57440"], platform="openshift", version="4.20.8"))
    assert [m["id"] for m in out["knownIssues"]] == ["OCPBUGS-57440"]
    plain = kit.diagnose(tk.DiagnoseIn(text=NEGATIVE[0], platform="openshift"))
    assert plain["knownIssues"] == [] and plain["diagnoses"][0]["id"] in {"DBG-OOM", "DBG-CRASHLOOP"}
    st = kit.config_status(tk.EmptyIn())["knowledgeStatus"]
    assert st["asOf"] and st["kubernetes"] == "1.35" and st["openshift"] == "4.22"


def test_every_mcp_result_carries_the_knowledge_date(tmp_path: Path) -> None:
    import anyio
    from mcp import Client

    from kube_noob.server.mcp_app import build_server

    server = build_server(load_settings(overrides={"data_dir": str(tmp_path)}))

    async def run() -> Any:
        async with Client(server) as c:
            return await c.call_tool("kubenoob_known_issues", {"text": POSITIVE["OCPBUGS-62623"]})

    res = anyio.run(run)
    assert not res.is_error
    data = res.structured_content or json.loads(res.content[0].text)
    payload = data.get("result", data)
    assert payload["knowledgeAsOf"].startswith("knowledge as of ")
    assert payload["matches"][0]["id"] == "OCPBUGS-62623"
    assert status()["note"].startswith("Built-in knowledge reviewed")


def test_web_results_are_labelled_external_and_after_the_cutoff(monkeypatch: pytest.MonkeyPatch) -> None:
    s = load_settings(overrides={"webEnabled": True})
    kit = tk.Toolkit(s)
    real = net_mod.http_client

    def fake(settings: Any, purpose: Any, **kw: Any) -> httpx.Client:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"content-type": "text/plain"}, content=iter([b"release notes"]))

        return real(settings, purpose, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(net_mod, "http_client", fake)
    out = kit.web_fetch(tk.WebFetchIn(url="https://kubernetes.io/docs/"))
    assert out["provenance"]["kind"] == "external" and out["provenance"]["afterKnowledgeCutoff"] is True


# ---------------------------------------------------------------- the live cluster version


class FakeBackend:
    name = "fake"

    def __init__(self, server: dict[str, Any], clusterversion: dict[str, Any] | None) -> None:
        self.server, self.cv = server, clusterversion

    def version(self) -> dict[str, Any]:
        return {"serverVersion": self.server}

    def get(self, resource: str, name: str | None = None, **_: Any) -> dict[str, Any]:
        from kube_noob.errors import ClusterAccessError

        assert resource == "clusterversions" and name == "version"
        if self.cv is None:
            # kubectl's own words (cli-runtime builder.go quotes the resource); unquoted is not recognised (G279)
            raise ClusterAccessError('error: the server doesn\'t have a resource type "clusterversions"')
        return self.cv

    def logs(self, *_: Any) -> str:
        return ""


def test_cluster_info_reads_openshift_and_flags_versions_newer_than_the_knowledge() -> None:
    ocp = FakeBackend(
        {"major": "1", "minor": "36+", "gitVersion": "v1.36.2"},
        {"spec": {"channel": "stable-4.23"}, "status": {"desired": {"version": "4.23.1"}}},
    )
    info = cluster_info(ocp)
    assert info["openshift"] == "4.23.1" and info["kubernetes"] == "1.36" and info["platform"] == "openshift"
    assert info["newerThanKnowledge"] is True and len(info["warnings"]) == 2
    vanilla = cluster_info(FakeBackend({"gitVersion": "v1.33.4"}, None))
    assert vanilla["platform"] == "kubernetes" and vanilla["kubernetes"] == "1.33"
    assert vanilla["newerThanKnowledge"] is False
    assert compare("1.35", "4.22") == {"newerThanKnowledge": False, "warnings": []}
