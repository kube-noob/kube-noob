"""Regression tests for the independent red team of VUL1: each test reproduces one reported finding (false negative,
crash, injection, gate bypass or blow-up) and pins the fix (guidance G57)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from kube_noob import attack_paths as ap
from kube_noob import gate
from kube_noob.cli import main
from kube_noob.vuln import assess, reports, threat, vex
from kube_noob.vuln.reports import gating_severity
from tests import bounds

#: Measured: `workload_reach` and `scan` over 16,000 objects. The cubic form took minutes at this size.
#: Re-measure with KUBE_NOOB_TEST_BOUNDS_REPORT=1 (tests/bounds.py).
HONEST_REACH_16000 = 1.2

R9 = ("red_hat_enterprise_linux_9", "Red Hat Enterprise Linux 9", "cpe:/o:redhat:enterprise_linux:9")
R8 = ("red_hat_enterprise_linux_8", "Red Hat Enterprise Linux 8", "cpe:/o:redhat:enterprise_linux:8")
AS9 = (
    "AppStream-9.3.0.Z.MAIN",
    "Red Hat Enterprise Linux AppStream (v. 9)",
    "cpe:/a:redhat:enterprise_linux:9::appstream",
)


def trivy(name: str, distro: str, vulns: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "SchemaVersion": 2,
        "Metadata": {"OS": {"Family": "redhat", "Name": distro}} if distro else {},
        "Results": [{"Target": name or "image", "Type": "redhat", "Vulnerabilities": vulns}],
    }
    if name:
        out["ArtifactName"] = name
    return out


def tv(cve: str, pkg: str, installed: str, fixed: str = "", sev: str = "CRITICAL", purl: str = "") -> dict[str, Any]:
    v: dict[str, Any] = {
        "VulnerabilityID": cve,
        "PkgName": pkg,
        "InstalledVersion": installed,
        "FixedVersion": fixed,
        "Severity": sev,
        "Status": "fixed" if fixed else "affected",
    }
    if purl:
        v["PkgIdentifier"] = {"PURL": purl}
    return v


def csaf(
    cve: str,
    products: list[tuple[str, str, str]],
    components: list[tuple[str, str]],
    status: dict[str, list[tuple[str, str]]],
) -> dict[str, Any]:
    """products: (id, name, cpe); components: (id, purl); status: {status: [(product id, component id)]}."""
    branches: list[dict[str, Any]] = [
        {
            "category": "product_name",
            "name": n,
            "product": {"name": n, "product_id": pid, "product_identification_helper": {"cpe": cpe}},
        }
        for pid, n, cpe in products
    ]
    branches += [
        {
            "category": "product_version",
            "name": cid,
            "product": {"name": cid, "product_id": cid, "product_identification_helper": {"purl": purl}},
        }
        for cid, purl in components
    ]
    rels: list[dict[str, Any]] = []
    ps: dict[str, list[str]] = {}
    for st, pairs in status.items():
        for prod, comp in pairs:
            fid = f"{prod}:{comp}"
            rels.append(
                {
                    "category": "default_component_of",
                    "full_product_name": {"name": fid, "product_id": fid},
                    "product_reference": comp,
                    "relates_to_product_reference": prod,
                }
            )
            ps.setdefault(st, []).append(fid)
    return {
        "document": {"category": "csaf_vex", "title": cve, "tracking": {"current_release_date": "2026-10-01"}},
        "product_tree": {
            "branches": [{"category": "vendor", "name": "Red Hat", "branches": branches}],
            "relationships": rels,
        },
        "vulnerabilities": [{"cve": cve, "product_status": ps}],
    }


def _assess(reps: list[dict[str, Any]], docs: list[dict[str, Any]], **kw: Any) -> dict[str, Any]:
    idx = vex.load(None, texts=[json.dumps(d) for d in docs], use_corpus=False)
    return assess.assess([reports.parse(json.dumps(r)) for r in reps], vex=idx, **kw)


# 1. Module streams: a statement for nodejs:18 must not speak for an installed nodejs:20 ------------------------------


def test_fixed_in_another_module_stream_does_not_drop_the_finding() -> None:
    doc = csaf(
        "CVE-2099-5001",
        [AS9],
        [
            ("nodejs-18", "pkg:rpm/redhat/nodejs@18.19.1-1.module%2Bel9.3.0?arch=src&epoch=1&rpmmod=nodejs:18"),
            ("nodejs-20", "pkg:rpm/redhat/nodejs@20.11.1-1.module%2Bel9.3.0?arch=src&epoch=1&rpmmod=nodejs:20"),
        ],
        {"fixed": [(AS9[0], "nodejs-18"), (AS9[0], "nodejs-20")]},
    )
    rep = trivy(
        "registry.example.com/app:1",
        "9.4",
        [tv("CVE-2099-5001", "nodejs", "1:20.5.0-1.module+el9.3.0", "1:20.11.1-1.module+el9.3.0")],
    )
    idx = vex.load(None, texts=[json.dumps(doc)], use_corpus=False)
    assert sorted(s.stream for s in idx.by_cve["CVE-2099-5001"]) == ["nodejs:18", "nodejs:20"]
    out = _assess([rep], [doc])
    assert [f["fixVersion"] for f in out["findings"]] == ["1:20.11.1-1.module+el9.3.0"]
    assert out["excluded"] == []


def test_not_affected_in_another_stream_does_not_drop_the_finding() -> None:
    doc = csaf(
        "CVE-2099-5002",
        [R9],
        [
            ("nodejs:18/nodejs", "pkg:rpm/redhat/nodejs?arch=src&rpmmod=nodejs:18"),
            ("nodejs:20/nodejs", "pkg:rpm/redhat/nodejs?arch=src&rpmmod=nodejs:20"),
        ],
        {"known_not_affected": [(R9[0], "nodejs:18/nodejs")], "known_affected": [(R9[0], "nodejs:20/nodejs")]},
    )
    rep = trivy("registry.example.com/app:1", "9.4", [tv("CVE-2099-5002", "nodejs", "1:20.5.0-1.module+el9.3.0")])
    out = _assess([rep], [doc])
    assert len(out["findings"]) == 1 and out["excluded"] == []


def test_conflicting_statements_keep_the_finding() -> None:
    doc = csaf(
        "CVE-2099-5009",
        [R9],
        [("a", "pkg:rpm/redhat/libfoo?arch=src"), ("b", "pkg:rpm/redhat/libfoo?arch=x86_64")],
        {"known_not_affected": [(R9[0], "a")], "known_affected": [(R9[0], "b")]},
    )
    rep = trivy("reg.example.com/a:1", "9.4", [tv("CVE-2099-5009", "libfoo", "1.0-1.el9")])
    assert len(_assess([rep], [doc])["findings"]) == 1


# 2. Image grouping: two different images must not share one VEX product scope ---------------------------------------


@pytest.mark.parametrize(
    ("n9", "n8", "d9", "d8"),
    [
        ("", "", "", ""),
        (
            "reg.example.com/app:latest",
            "reg.example.com/app:latest",
            "reg.example.com/app@sha256:" + "1" * 64,
            "reg.example.com/app@sha256:" + "2" * 64,
        ),
    ],
    ids=["both-unnamed", "same-tag-different-digests"],
)
def test_different_images_are_not_merged(n9: str, n8: str, d9: str, d8: str) -> None:
    doc = csaf(
        "CVE-2099-5003",
        [R9, R8],
        [("libfoo", "pkg:rpm/redhat/libfoo?arch=src")],
        {"known_not_affected": [(R9[0], "libfoo")], "known_affected": [(R8[0], "libfoo")]},
    )
    r9 = trivy(n9, "9.4", [tv("CVE-2099-5004", "bash", "5.1-1.el9", "5.1-2.el9")])
    r8 = trivy(n8, "8.10", [tv("CVE-2099-5003", "libfoo", "1.0-1.el8")])
    for r, d in ((r9, d9), (r8, d8)):
        if d:
            r["Metadata"]["RepoDigests"] = [d]
    out = _assess([r9, r8], [doc])
    assert len(out["images"]) == 2
    assert any(f["cve"] == "CVE-2099-5003" for f in out["findings"]), "the RHEL 9 statement must not drop RHEL 8's"
    assert out["excluded"] == []


def test_two_reports_of_one_image_are_still_merged() -> None:
    digest = "reg.example.com/app@sha256:" + "3" * 64
    a = trivy("reg.example.com/app:1", "9.4", [tv("CVE-2099-5010", "bash", "5.1-1.el9", "5.1-2.el9")])
    b = trivy("reg.example.com/app:1", "9.4", [tv("CVE-2099-5011", "zlib", "1.2-1.el9", "1.2-2.el9")])
    for r in (a, b):
        r["Metadata"]["RepoDigests"] = [digest]
    out = _assess([a, b], [])
    assert len(out["images"]) == 1 and len(out["findings"]) == 2


# 3. A vendor's own RPM (nginx.org's .ngx build) is not covered by Red Hat VEX -----------------------------------------


def test_vendor_rpm_is_not_dropped_by_red_hat_vex() -> None:
    doc = csaf(
        "CVE-2099-7004",
        [R9],
        [("nginx", "pkg:rpm/redhat/nginx?arch=src")],
        {"known_not_affected": [(R9[0], "nginx")]},
    )
    t = trivy(
        "reg.example.com/web:1",
        "9.4",
        [
            tv(
                "CVE-2099-7004",
                "nginx",
                "1:1.26.1-2.el9.ngx",
                "1:1.26.2-1.el9.ngx",
                purl="pkg:rpm/redhat/nginx@1.26.1-2.el9.ngx?arch=x86_64&epoch=1&distro=redhat-9.4",
            )
        ],
    )
    rh = {
        "id": "sha256:" + "c" * 64,
        "name": {"fullName": "reg.example.com/web:2"},
        "scan": {
            "operatingSystem": "rhel:9",
            "components": [
                {
                    "name": "nginx",
                    "version": "1:1.26.1-2.el9.ngx",
                    "source": "OS",
                    "vulns": [
                        {
                            "cve": "CVE-2099-7004",
                            "severity": "CRITICAL_VULNERABILITY_SEVERITY",
                            "fixedBy": "1:1.26.2-1.el9.ngx",
                        }
                    ],
                }
            ],
        },
    }
    for r in (t, rh):
        out = _assess([r], [doc])
        assert len(out["findings"]) == 1 and out["excluded"] == [], out["images"][0]["formats"]
    red_hat = trivy("reg.example.com/web:3", "9.4", [tv("CVE-2099-7004", "nginx", "1:1.20.1-14.el9_2.1")])
    assert len(_assess([red_hat], [doc])["excluded"]) == 1, "Red Hat's own build is still covered"


# 4. Unknown severity with a critical CVSS score, or known exploited, still fails the gate -----------------------------


def test_gating_severity() -> None:
    assert gating_severity("unknown", 9.8, False) == "critical"
    assert gating_severity("unknown", None, False) == "medium"
    assert gating_severity("unknown", None, True) == "high"
    assert gating_severity("low", 7.5, False) == "high"
    assert gating_severity("critical", 2.0, False) == "critical", "a report's own severity is never lowered"


def test_unknown_severity_fails_the_cli_and_the_gate(tmp_path: Path) -> None:
    v1 = tv("CVE-2099-7001", "requests", "2.0.0", "2.32.0", sev="UNKNOWN")
    v1["CVSS"] = {"nvd": {"V3Score": 9.8}}
    rep = trivy("reg.example.com/a:1", "9.4", [v1, tv("CVE-2099-7002", "urllib3", "1.0.0", "", sev="UNKNOWN")])
    rep["Results"][0]["Type"] = "python-pkg"
    path = tmp_path / "trivy.json"
    path.write_text(json.dumps(rep))
    kev_path = tmp_path / "kev.json"
    kev_path.write_text(json.dumps({"catalogVersion": "1", "vulnerabilities": [{"cveID": "CVE-2099-7002"}]}))
    assert main(["vuln", "report", "-r", str(path), "--no-corpus-vex", "--fail-on", "critical"]) == 1
    assert main(["vuln", "report", "-r", str(path), "--no-corpus-vex", "--fail-on", "never"]) == 0
    r = gate.run([], scanner_reports=[(str(path), path.read_text())], fail_on="critical")
    assert not r["passed"] and r["vulnerabilities"]["findings"] == 2
    only_kev = trivy("reg.example.com/a:1", "9.4", [tv("CVE-2099-7002", "urllib3", "1.0.0", "", sev="UNKNOWN")])
    r = gate.run(
        [],
        scanner_reports=[("r.json", json.dumps(only_kev))],
        kev_path=kev_path,
        fail_on="high",
    )
    assert not r["passed"], "an unfixable known-exploited finding of unknown severity counts as high"


# 5. Reachability is linear in the input, not cubic --------------------------------------------------------------------


def _many(n: int) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for i in range(n):
        labels = {"app": f"w{i}", "tier": "web"}
        items += [
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": f"w{i}", "namespace": "a"},
                "spec": {
                    "selector": {"matchLabels": labels},
                    "template": {
                        "metadata": {"labels": labels},
                        "spec": {"containers": [{"name": "c", "image": f"r.example.com/x:{i}"}]},
                    },
                },
            },
            {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {"name": f"sa{i}", "namespace": "a"},
                "automountServiceAccountToken": False,
            },
            {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {"name": f"s{i}", "namespace": "a"},
                "spec": {"selector": labels, "ports": [{"port": 80}]},
            },
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "Ingress",
                "metadata": {"name": f"i{i}", "namespace": "a"},
                "spec": {
                    "rules": [
                        {
                            "host": f"h{i}.example.com",
                            "http": {
                                "paths": [
                                    {
                                        "path": "/",
                                        "pathType": "Prefix",
                                        "backend": {"service": {"name": f"s{i}", "port": {"number": 80}}},
                                    }
                                ]
                            },
                        }
                    ]
                },
            },
        ]
    return items


def test_reach_looks_up_the_inventory_a_fixed_number_of_times() -> None:
    def calls(n: int) -> int:
        inv = ap.Inventory.from_documents(_many(n))
        count = [0]
        orig = inv.of

        def of(*kinds: str) -> list[dict[str, Any]]:
            count[0] += 1
            return orig(*kinds)

        inv.of = of  # type: ignore[method-assign]
        reach = ap.workload_reach(inv)
        assert len(reach) == n and all(len(r.entries) == 1 for r in reach.values())
        return count[0]

    assert calls(10) == calls(200), "no per-workload scan of the Services, entries or ServiceAccounts"


def test_reach_and_scan_of_16000_objects_take_seconds_not_hours() -> None:
    inv = ap.Inventory.from_documents(_many(4000))
    with bounds.bounded(bounds.CUBIC_RISK, honest_seconds=HONEST_REACH_16000, guards="16,000 objects"):
        reach = ap.workload_reach(inv)
        out = ap.scan(inv)
    assert len(reach) == 4000 and "paths" in out


def test_selector_matching_is_unchanged() -> None:
    items = _many(3)
    items[2]["spec"]["selector"] = {"app": "w0"}  # Service s0 selects only w0 by one label
    items[6]["spec"]["selector"] = {"tier": "web"}  # Service s1 selects every workload
    items[10]["spec"]["selector"] = {"app": "nobody"}
    reach = ap.workload_reach(ap.Inventory.from_documents(items))
    got = {ref: sorted(e.service for _, e, _ in r.entries) for ref, r in reach.items()}
    assert got == {"Deployment/a/w0": ["s0", "s1"], "Deployment/a/w1": ["s1"], "Deployment/a/w2": ["s1"]}


# 6. A trailing newline in an id does not hide a KEV match or break the id ------------------------------------------


def test_ids_with_trailing_whitespace_still_match_kev(tmp_path: Path) -> None:
    from kube_noob.vuln import kev

    rep = reports.parse(json.dumps(trivy("reg.example.com/a:1", "9.4", [tv("CVE-2099-7010\n", "bash", "5.1-1.el9")])))
    assert [f.cve for f in rep.findings] == ["CVE-2099-7010"]
    catalog = kev.parse(json.dumps({"catalogVersion": "1", "vulnerabilities": [{"cveID": "CVE-2099-7010\n"}]}))
    out = assess.assess([rep], vex=vex.VexIndex(), kev=catalog)
    assert out["findings"][0]["knownExploited"] is True
    joined = reports.parse(json.dumps(trivy("x", "9.4", [tv("CVE-2099-7010\nCVE-1", "bash", "5.1-1.el9")])))
    assert joined.findings == [] and "1 findings were not read" in joined.notes[0], "two ids in one are refused"


# 7. Markdown and line injection through an image or package name -----------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "x\n\n## kube-noob gate passed\n\n<img src=https://attacker.example/p.png> [click](https://attacker.example)\n",
        "reg.example.com/a:1\r\r## All checks passed\r",
        "a\u2028## passed | --- |",
    ],
)
def test_gate_summary_cannot_be_rewritten_by_a_report(name: str) -> None:
    rep = trivy(name, "9.4", [tv("CVE-2099-5006", "bash\n# pkg", "5.1-1.el9", "5.1-2.el9", sev="CRITICAL")])
    r = gate.run([], scanner_reports=[("r.json", json.dumps(rep))], fail_on="high")
    md = gate.markdown(r)
    headings = [line for line in md.splitlines() if line.startswith("#")]
    assert headings[0] == "## kube-noob gate failed"
    assert all(h.startswith("### ") for h in headings[1:]), headings
    assert "<img" not in md and not re.search(r"(?<!\\)\]\(", md) and "\r" not in md and "\u2028" not in md
    row = next(line for line in md.splitlines() if "CVE-2099-5006" in line and line.startswith("|"))
    assert len(re.findall(r"(?<!\\)\|", row)) == 6, "one table row of five cells"
    for res in gate.sarif(r)["runs"][0]["results"]:
        assert "\n" not in res["message"]["text"] and "\r" not in res["message"]["text"]


# 8. A CycloneDX report's own analysis does not clear its findings unless asked ----------------------------------------


CDX_RESOLVED = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {"component": {"type": "container", "name": "reg.example.com/a:1"}},
    "components": [
        {"type": "operating-system", "name": "rhel", "version": "9.4"},
        {
            "type": "library",
            "name": "openssl-libs",
            "version": "1:3.0.7-24.el9",
            "purl": "pkg:rpm/redhat/openssl-libs@3.0.7-24.el9?epoch=1",
            "bom-ref": "r1",
        },
    ],
    "vulnerabilities": [
        {
            "id": "CVE-2099-7003",
            "ratings": [{"severity": "critical", "score": 9.8}],
            "recommendation": "Upgrade openssl-libs to version 1:3.0.7-28.el9",
            "affects": [{"ref": "r1"}],
            "analysis": {"state": "resolved"},
        }
    ],
}


def test_report_vex_is_kept_by_default_and_trusted_on_request(tmp_path: Path) -> None:
    from kube_noob import toolkit as tk
    from kube_noob.config import load_settings

    out = assess.assess([reports.parse(json.dumps(CDX_RESOLVED))], vex=vex.VexIndex())
    assert len(out["findings"]) == 1 and "--trust-report-vex" in json.dumps(out)
    trusted = assess.assess([reports.parse(json.dumps(CDX_RESOLVED))], vex=vex.VexIndex(), trust_report_vex=True)
    assert trusted["findings"] == [] and len(trusted["excluded"]) == 1
    path = tmp_path / "cdx.json"
    path.write_text(json.dumps(CDX_RESOLVED))
    args = ["vuln", "report", "-r", str(path), "--no-corpus-vex", "--fail-on", "high"]
    assert main(args) == 1 and main([*args, "--trust-report-vex"]) == 0
    g = ["gate", "--scanner-report", str(path), "--fail-on", "high", "--format", "json"]
    assert main(g) == 1 and main([*g, "--trust-report-vex"]) == 0
    kit = tk.Toolkit(load_settings(overrides={"dataDir": str(tmp_path)}))
    assert kit.vuln_report(tk.VulnReportIn(reports=[json.dumps(CDX_RESOLVED)]))["counts"]["findings"] == 1
    got = kit.vuln_report(tk.VulnReportIn(reports=[json.dumps(CDX_RESOLVED)], trust_report_vex=True))
    assert got["counts"]["findings"] == 0


# 9. Malformed VEX shapes are skipped, never a crash -------------------------------------------------------------------


@pytest.mark.parametrize(
    "vuln, tree",
    [
        ({"flags": 5}, None),
        ({"remediations": 1}, None),
        ({"remediations": [{"product_ids": 3}]}, None),
        ({"scores": 7}, None),
        ({"flags": [{"product_ids": True}]}, None),
        ({"product_status": {"fixed": "x"}}, None),
        ({}, {"branches": 1}),
        ({}, {"relationships": 2}),
        ({}, {"branches": [{"branches": 9}]}),
        ({}, {"branches": [{"product": {"product_identification_helper": {"purl": 4}}}]}),
    ],
)
def test_malformed_vex_is_skipped(vuln: dict[str, Any], tree: dict[str, Any] | None) -> None:
    doc: dict[str, Any] = {"document": {"category": "csaf_vex"}, "vulnerabilities": [{"cve": "CVE-2099-0001", **vuln}]}
    if tree is not None:
        doc["product_tree"] = tree
    vex.load(None, texts=[json.dumps(doc)], use_corpus=False)


# 10. A product prefix without a release would let RHEL 8 statements speak for RHEL 9 ----------------------------------


def test_product_prefix_must_name_a_release(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from kube_noob import toolkit as tk

    with pytest.raises(vex.VexError, match="must name a release"):
        vex.validate_products(["cpe:/o:redhat:enterprise_linux"])
    assert vex.validate_products(["cpe:/o:redhat:enterprise_linux:9", "cpe:/a:redhat:openshift:4.20::el9"])
    with pytest.raises(Exception, match="String should match pattern"):
        tk.VulnReportIn(reports=["{}"], products=["cpe:/o:redhat:enterprise_linux"])
    rep = trivy("reg.example.com/a:1", "9.4", [tv("CVE-2099-5005", "libfoo", "1.0-1.el9", "1.0-2.el9")])
    with pytest.raises(assess.AssessError):
        assess.assess(
            [reports.parse(json.dumps(rep))], vex=vex.VexIndex(), products=("cpe:/o:redhat:enterprise_linux",)
        )
    path = tmp_path / "r.json"
    path.write_text(json.dumps(rep))
    assert main(["vuln", "report", "-r", str(path), "--product", "cpe:/o:redhat:enterprise_linux"]) == 2
    assert "must name a release" in capsys.readouterr().err


# 11. Every workload that runs a vulnerable image is counted, not the first 20 -----------------------------------------


def test_more_than_20_workloads_of_one_image_are_all_counted() -> None:
    from kube_noob.yamlio import load_documents

    docs = []
    for i in range(25):
        docs.append(
            f"""apiVersion: apps/v1
kind: Deployment
metadata: {{name: w{i:02d}, namespace: a}}
spec:
  selector: {{matchLabels: {{app: w{i}}}}}
  template:
    metadata: {{labels: {{app: w{i}}}}}
    spec: {{containers: [{{name: c, image: "reg.example.com/web:1"}}]}}
---
apiVersion: v1
kind: Service
metadata: {{name: s{i}, namespace: a}}
spec: {{type: LoadBalancer, selector: {{app: w{i}}}, ports: [{{port: 80}}]}}"""
        )
    text = "\n---\n".join(docs)
    rep = trivy("reg.example.com/web:1", "9.4", [tv("CVE-2099-8001", "bash", "5.1-1.el9", "5.1-2.el9")])
    reach = ap.workload_reach(ap.Inventory.from_documents(d.data for d in load_documents(text)))
    out = assess.assess([reports.parse(json.dumps(rep))], vex=vex.VexIndex(), reach=reach)
    vulnerable = assess.summary_for_workloads(out)
    assert len(vulnerable) == 25
    model = threat.model(text, vulnerable_images=vulnerable)
    e01 = [t for a in model["applications"] for t in a["threats"] if t["threat"] == "TM-E01"]
    assert len(e01) == 25 and all(t["status"] == "open" for t in e01)
    assert out["ranking"]["ranked"][0]["workloadsTotal"] == 25


# 12. Too many VEX files is an error, not a silent cut ----------------------------------------------------------------


def test_too_many_vex_documents_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vex, "MAX_DOCUMENTS", 3)
    for i in range(4):
        doc = {"document": {"category": "csaf_vex"}, "vulnerabilities": [{"cve": f"CVE-2099-000{i}"}]}
        (tmp_path / f"cve-2099-000{i}.json").write_text(json.dumps(doc))
    with pytest.raises(vex.VexError, match="more than 3"):
        vex.load(None, [tmp_path], use_corpus=False)
