"""The DISA Kubernetes STIG crosswalk (docs/stig.md, G437).

A crosswalk onto someone else's register fails in three ways, and each has a test here. It invents or loses a
control: every V-ID comes from the pinned snapshot and the count is asserted against it. It claims more than a
rule does: every `covered` and `partly` row is run on a fixture, the judged half AND the half the row says is not
judged, so the sentence in the document is a measurement. And it goes stale in the other direction: the CAT I
rows marked `not covered` are run too, and fail the day a rule starts reading that flag, because a row that says
"no rule" beside a rule that fires is as wrong as the reverse.

No status in the document is a pass. `covered` says a rule judges the check; it says nothing about a cluster.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
from collections import Counter
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Report
from kube_noob.audit.rules import RULES

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "stig.md"
SNAPSHOT = ROOT / "src" / "kube_noob" / "data" / "stig" / "kubernetes-stig.yaml"
CROSSWALK = ROOT / "src" / "kube_noob" / "data" / "stig" / "crosswalk.yaml"
STATUSES = ("covered", "partly", "not determinable from manifests", "not covered")
V_ID = re.compile(r"\AV-\d{6}\Z")
RULE_ID = re.compile(r"\ASV-(\d{6})r\d+_rule\Z")
STIG_ID = re.compile(r"\ACNTR-K8-\d{6}\Z")
CAT = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("stig_crosswalk", ROOT / "scripts" / "stig_crosswalk.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["stig_crosswalk"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def sx() -> ModuleType:
    return _load()


@pytest.fixture(scope="module")
def snapshot() -> dict[str, Any]:
    return yaml.safe_load(SNAPSHOT.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


@pytest.fixture(scope="module")
def rows() -> dict[str, dict[str, Any]]:
    return yaml.safe_load(CROSSWALK.read_text(encoding="utf-8"))["rows"]  # type: ignore[no-any-return]


def _rule_ids() -> set[str]:
    return {r.rule_id for r in (RULES.values() if isinstance(RULES, dict) else RULES)}


def _table_rows(doc: str) -> list[list[str]]:
    """The rows of the per-rule table: every line whose first cell is a V-ID link or id."""
    out = []
    section = doc.split("## Every rule", 1)[1]
    for line in section.splitlines():
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", line)[1:-1]]
        if cells and re.match(r"\[?V-\d{6}", cells[0]):
            out.append(cells)
    return out


# -- the snapshot ------------------------------------------------------------------------------------------------------


def test_the_snapshot_hashes_to_what_it_records(snapshot: dict[str, Any]) -> None:
    """The upstream hash cannot be recomputed offline; the hash of the list this repository ships can, and it is
    the list a reader is trusting. A snapshot nobody can verify is one anybody can add a control to."""
    canon = json.dumps(snapshot["rules"], indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    assert hashlib.sha256(canon.encode()).hexdigest() == snapshot["source"]["rules_sha256"]
    assert re.fullmatch(r"[0-9a-f]{64}", snapshot["source"]["parsed_sha256"])


def test_the_snapshot_pins_version_2_release_6_and_92_rules(snapshot: dict[str, Any]) -> None:
    """Pinned on purpose. The review that asked for this crosswalk quoted "V1R11, 91 controls", which was two
    major versions stale; a new release must change this test in the same commit that replaces the snapshot."""
    src = snapshot["source"]
    assert (src["stig_version"], src["stig_release"]) == (2, 6)
    assert src["published"] == "2026-02-12"
    assert src["rule_count"] == len(snapshot["rules"]) == 92
    assert Counter(r["severity"] for r in snapshot["rules"]) == {"high": 18, "medium": 74}


def test_the_snapshot_says_where_it_came_from_and_that_it_is_a_mirror(snapshot: dict[str, Any]) -> None:
    src = snapshot["source"]
    assert src["checklist"].startswith("https://ncp.nist.gov/checklist/")
    for profile, url in src["parsed_from"].items():
        assert re.fullmatch(rf"https://github\.com/mitre/k8s-{profile}-stig-baseline/tree/[0-9a-f]{{40}}/controls", url)
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", src["retrieved"])
    assert src["cross_checked"]
    head = SNAPSHOT.read_text(encoding="utf-8").split("version: 1", 1)[0]
    assert "Neither ncp.nist.gov" in head and "MITRE" in head, "the file must say it was not parsed from DISA's XCCDF"


def test_every_v_id_is_unique_and_well_formed(snapshot: dict[str, Any]) -> None:
    ids = [r["id"] for r in snapshot["rules"]]
    assert len(ids) == len(set(ids))
    assert ids == sorted(ids)
    for r in snapshot["rules"]:
        assert V_ID.match(r["id"]), r["id"]
        m = RULE_ID.match(r["rule_id"])
        assert m and m.group(1) == r["id"][2:], r["rule_id"]
        assert STIG_ID.match(r["stig_id"]), r["stig_id"]
        assert r["severity"] in CAT, r["severity"]
        assert r["title"].strip() and r["check"].strip()
        assert set(r["profiles"]) <= {"cluster", "node"} and r["profiles"]
    assert len({r["rule_id"] for r in snapshot["rules"]}) == len(ids)
    assert len({r["stig_id"] for r in snapshot["rules"]}) == len(ids)


def test_the_snapshot_carries_one_line_per_check_and_not_disa_text(snapshot: dict[str, Any]) -> None:
    """A summary in kube-noob's words, one line. The check, fix and discussion text is DISA's and is not shipped."""
    for r in snapshot["rules"]:
        assert "\n" not in r["check"] and len(r["check"]) < 330, r["id"]
        assert set(r) == {"id", "rule_id", "stig_id", "severity", "title", "check", "profiles"}, r["id"]
    text = SNAPSHOT.read_text(encoding="utf-8")
    for phrase in ("this is a finding", "Change to the /etc/kubernetes/manifests directory", "Fix Text"):
        assert phrase not in text, phrase


# -- the mapping -------------------------------------------------------------------------------------------------------


def test_every_row_is_a_snapshot_id_and_every_snapshot_id_has_a_row(
    snapshot: dict[str, Any], rows: dict[str, dict[str, Any]]
) -> None:
    """Neither direction is optional: a row with no snapshot entry is an invented control, and a snapshot entry
    with no row is a control the document would silently not list."""
    assert set(rows) == {r["id"] for r in snapshot["rules"]}
    assert len(rows) == 92


def test_no_status_other_than_the_four(rows: dict[str, dict[str, Any]], sx: ModuleType) -> None:
    assert sx.STATUSES == STATUSES
    for vid, row in rows.items():
        assert row["status"] in STATUSES, (vid, row["status"])
    for cells in _table_rows(DOC.read_text(encoding="utf-8")):
        assert cells[5] in STATUSES, cells


def test_every_rule_a_row_names_exists_and_only_judging_rows_name_one(rows: dict[str, dict[str, Any]]) -> None:
    """A rule id on a row reads as coverage, so a `not covered` or `not determinable` row may not carry one --
    the adjacent rule goes in the note, in a sentence that says it is not this check."""
    known = _rule_ids()
    for vid, row in rows.items():
        for rule_id in row["rules"]:
            assert rule_id in known, f"{vid} names {rule_id}, which is not in the catalogue"
        if row["status"] in {"covered", "partly"}:
            assert row["rules"], vid
            assert row["judged"].strip(), vid
        else:
            assert row["rules"] == [], vid
            assert "judged" not in row, vid


def test_each_status_says_the_thing_that_makes_it_honest(rows: dict[str, dict[str, Any]]) -> None:
    for vid, row in rows.items():
        if row["status"] == "partly":
            assert row["not_judged"].strip(), f"{vid} is partly covered and does not name the part not judged"
        if row["status"] == "covered":
            assert "not_judged" not in row, vid
        if row["status"] == "not determinable from manifests":
            assert row["evidence"].strip(), f"{vid} does not say what evidence would decide it"
            assert row["reads"] != "cluster-objects", vid
        if row["status"] == "not covered":
            assert row["backlog"].strip(), f"{vid} is a backlog row with no rule described"
            assert row["reads"] in {"static-pod-manifest", "cluster-objects"}, vid


def test_a_check_that_reads_a_node_is_never_called_determinable(
    rows: dict[str, dict[str, Any]], sx: ModuleType
) -> None:
    """File modes, service state, the kubelet's process and the PPSM list are in no manifest, so those rows can
    only be `not determinable` -- never `not covered`, which would promise a rule that cannot be written."""
    assert set(sx.READS) == {r["reads"] for r in rows.values()}
    for vid, row in rows.items():
        if row["reads"] in {"node-files", "node-state", "kubelet", "documentation"}:
            assert row["status"] == "not determinable from manifests", vid


def test_a_malformed_crosswalk_is_refused_not_rendered(
    sx: ModuleType, snapshot: dict[str, Any], rows: dict[str, dict[str, Any]], tmp_path: Path
) -> None:
    def refused(change: Any) -> str:
        data = {"version": 1, "rows": json.loads(json.dumps(rows))}
        change(data["rows"])
        path = tmp_path / "crosswalk.yaml"
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        with pytest.raises(sx.CrosswalkError) as err:
            sx.load_crosswalk(snapshot, path)
        return str(err.value)

    assert "V-999999" in refused(lambda r: r.update({"V-999999": dict(r["V-242376"])}))
    assert "V-242376" in refused(lambda r: r.pop("V-242376"))
    assert "passed" in refused(lambda r: r["V-242376"].update(status="passed"))
    assert "KN-S999" in refused(lambda r: r["V-242390"].update(rules=["KN-S999"]))
    assert "V-242376" in refused(lambda r: r["V-242376"].update(rules=["KN-S038"]))
    assert "V-242379" in refused(lambda r: r["V-242379"].pop("not_judged"))
    assert "V-242405" in refused(lambda r: r["V-242405"].pop("evidence"))
    assert "V-242390" in refused(lambda r: r["V-242390"].update(rules=[]))


def test_a_snapshot_that_was_edited_is_refused(sx: ModuleType, snapshot: dict[str, Any], tmp_path: Path) -> None:
    """An added control with the count bumped to match still fails: the hash is over the list."""
    data = json.loads(json.dumps(snapshot))
    data["rules"].append({**data["rules"][0], "id": "V-999999", "rule_id": "SV-999999r1_rule"})
    data["source"]["rule_count"] = 93
    path = tmp_path / "kubernetes-stig.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    with pytest.raises(sx.CrosswalkError, match="rules_sha256"):
        sx.load_snapshot(path)


# -- the document ------------------------------------------------------------------------------------------------------


def test_the_committed_document_matches_the_data(sx: ModuleType) -> None:
    assert sx.main(["--check"]) == 0, "run: python scripts/stig_crosswalk.py"
    snap = sx.load_snapshot()
    assert DOC.read_text(encoding="utf-8") == sx.render(snap, sx.load_crosswalk(snap))


def test_check_detects_drift_in_the_document_and_in_the_data(
    sx: ModuleType,
    snapshot: dict[str, Any],
    rows: dict[str, dict[str, Any]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = tmp_path / "stig.md"
    monkeypatch.setattr(sx, "DOC", out)
    assert sx.main(["--check"]) == 1, "a missing document is stale"
    out.write_text(DOC.read_text(encoding="utf-8").replace("| not covered |", "| covered |", 1), encoding="utf-8")
    assert sx.main(["--check"]) == 1, "a hand-edited status is drift"
    assert "python scripts/stig_crosswalk.py" in capsys.readouterr().err
    assert sx.main([]) == 0 and out.read_text(encoding="utf-8") == DOC.read_text(encoding="utf-8")
    assert sx.main(["--check"]) == 0
    # The data moves and the document does not: one row changes status, and the committed text is now stale.
    moved = {"version": 1, "rows": json.loads(json.dumps(rows))}
    moved["rows"]["V-242395"] = {
        "status": "not determinable from manifests",
        "reads": "node-state",
        "rules": [],
        "evidence": "x",
    }
    cw = tmp_path / "crosswalk.yaml"
    cw.write_text(yaml.safe_dump(moved, sort_keys=False), encoding="utf-8")
    monkeypatch.setattr(sx, "CROSSWALK", cw)
    assert sx.main(["--check"]) == 1
    # And data that does not validate is exit 1 with the reason, never a traceback and never a rendered table.
    moved["rows"]["V-242395"]["status"] = "compliant"
    cw.write_text(yaml.safe_dump(moved, sort_keys=False), encoding="utf-8")
    assert sx.main(["--check"]) == 1
    assert "compliant" in capsys.readouterr().err


def test_the_document_counts_match_the_snapshot_and_the_rows(
    snapshot: dict[str, Any], rows: dict[str, dict[str, Any]]
) -> None:
    doc = DOC.read_text(encoding="utf-8")
    table = _table_rows(doc)
    assert len(table) == len(snapshot["rules"]) == 92
    by_id = {r["id"]: r for r in snapshot["rules"]}
    seen = []
    for cells in table:
        vid = re.search(r"V-\d{6}", cells[0]).group(0)  # type: ignore[union-attr]
        seen.append(vid)
        assert cells[1] == by_id[vid]["stig_id"]
        assert cells[2] == CAT[by_id[vid]["severity"]]
        assert cells[5] == rows[vid]["status"]
        assert re.findall(r"KN-[A-Z]+\d{3}", cells[6]) == rows[vid]["rules"], vid
    assert seen == sorted(by_id)
    assert "**Version 2, Release 6**" in doc and "2026-02-12" in doc
    assert f"**{len(table)} rules**" in doc
    status = Counter(r["status"] for r in rows.values())
    cat = Counter(CAT[r["severity"]] for r in snapshot["rules"])
    cross = Counter((rows[r["id"]]["status"], CAT[r["severity"]]) for r in snapshot["rules"])
    for name in STATUSES:
        line = next(ln for ln in doc.splitlines() if ln.startswith(f"| {name} |"))
        cells = [c.strip() for c in line.split("|")[1:-1]]
        assert cells[1:] == [
            str(cross[name, "CAT I"]),
            str(cross[name, "CAT II"]),
            str(cross[name, "CAT III"]),
            str(status[name]),
        ]
    total = next(ln for ln in doc.splitlines() if ln.startswith("| **All** |"))
    assert [c.strip() for c in total.split("|")[1:-1]][1:] == [
        str(cat["CAT I"]),
        str(cat["CAT II"]),
        str(cat["CAT III"]),
        "92",
    ]
    assert sum(status.values()) == 92


def test_the_document_says_it_is_not_an_assessment(sx: ModuleType) -> None:
    doc = DOC.read_text(encoding="utf-8")
    assert sx.NOT_AN_ASSESSMENT in doc
    low = sx.NOT_AN_ASSESSMENT.lower()
    assert "not a stig assessment" in low and "not an ato artifact" in low
    assert "cluster or node evidence" in low
    assert sx.MANAGED_CONTROL_PLANE in doc
    assert "Do not edit" in doc.splitlines()[2]


def test_the_document_never_calls_a_row_a_pass(rows: dict[str, dict[str, Any]]) -> None:
    """`covered` is about the rule. The words an assessor reads as a result do not appear as a status or a count."""
    doc = DOC.read_text(encoding="utf-8")
    for word in ("compliant |", "| pass", "| passed", "Not a Finding |", "satisfied |"):
        assert word.lower() not in doc.lower(), word
    assert "No status on this page is a pass" in doc


def test_every_cat_i_rule_is_listed_with_its_status(snapshot: dict[str, Any], rows: dict[str, dict[str, Any]]) -> None:
    doc = DOC.read_text(encoding="utf-8")
    section = doc.split("## The 18 CAT I rules", 1)[1].split("\n## ", 1)[0]
    for r in snapshot["rules"]:
        if r["severity"] == "high":
            line = next(ln for ln in section.splitlines() if r["id"] in ln)
            assert f"| {rows[r['id']]['status']} |" in line, r["id"]


def test_the_generator_is_wired_into_the_gates_and_the_compliance_page() -> None:
    assert "scripts/stig_crosswalk.py --check" in (ROOT / "scripts" / "check.sh").read_text(encoding="utf-8")
    assert "python scripts/stig_crosswalk.py --check" in (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    compliance = (ROOT / "docs" / "compliance.md").read_text(encoding="utf-8")
    assert "(stig.md)" in compliance and "not a STIG assessment" in compliance
    assert "src/kube_noob/data/stig/kubernetes-stig.yaml" in (ROOT / "THIRD_PARTY_NOTICES.md").read_text(
        encoding="utf-8"
    )


def test_the_numbers_the_compliance_page_quotes_are_the_crosswalks_own(
    snapshot: dict[str, Any], rows: dict[str, dict[str, Any]]
) -> None:
    """The compliance page states six counts in a sentence. They are guarded by scripts/doc_numbers.py, which
    measures them from the same two data files, so the sentence and docs/stig.md cannot disagree."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import doc_numbers as dn

    measured = dn.counted()
    status = Counter(r["status"] for r in rows.values())
    cat_i = {r["id"] for r in snapshot["rules"] if r["severity"] == "high"}
    want = {
        "stig_rules": 92,
        "stig_covered": status["covered"],
        "stig_partly": status["partly"],
        "stig_not_determinable": status["not determinable from manifests"],
        "stig_not_covered": status["not covered"],
        "stig_not_covered_cat1": sum(1 for v in cat_i if rows[v]["status"] == "not covered"),
    }
    assert {k: measured[k] for k in want} == want
    guarded = {key for path, _p, key, _w in dn.GUARDS if path.name == "compliance.md"}
    assert set(want) <= guarded
    path = ROOT / "docs" / "compliance.md"
    text = path.read_text(encoding="utf-8")
    stale = text.replace(f"and {want['stig_not_covered']} could be decided", "and 3 could be decided", 1)
    assert stale != text and dn.guarded({path: stale})[path] == text


# -- the rows, measured ------------------------------------------------------------------------------------------------


def _pod(name: str, command: list[str], namespace: str = "kube-system", **container: Any) -> str:
    body = {"name": name, "image": f"registry.k8s.io/{name}:v1.35.0", "command": command, **container}
    doc = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"hostNetwork": True, "containers": [body]},
    }
    return yaml.safe_dump(doc, sort_keys=False)


def _app(namespace: str = "shop", labels: dict[str, str] | None = None, **container: Any) -> str:
    meta: dict[str, Any] = {"name": "web", "namespace": namespace}
    if labels:
        meta["labels"] = labels
    doc = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": meta,
        "spec": {"containers": [{"name": "web", "image": "registry.example/web:1.0", **container}]},
    }
    return yaml.safe_dump(doc, sort_keys=False)


def _report(text: str, platform: str = "kubernetes") -> Report:
    return analyze(text, platform, "1.35")


def _fires(text: str, rule_id: str, platform: str = "kubernetes") -> bool:
    return any(f.rule_id == rule_id for f in _report(text, platform).findings)


def _clean(text: str, rule_id: str) -> bool:
    report = _report(text)
    return rule_id in report.evaluated_rules and not any(f.rule_id == rule_id for f in report.findings)


def _declined(text: str, rule_id: str, platform: str = "kubernetes") -> bool:
    report = _report(text, platform)
    return rule_id not in report.evaluated_rules and not any(f.rule_id == rule_id for f in report.findings)


API = ["kube-apiserver"]
SAFE_API = [*API, "--authorization-mode=Node,RBAC", "--anonymous-auth=false"]
ETCD = [
    "etcd",
    "--listen-client-urls=https://10.0.0.1:2379",
    "--listen-peer-urls=https://10.0.0.1:2380",
    "--advertise-client-urls=https://10.0.0.1:2379",
    "--initial-advertise-peer-urls=https://10.0.0.1:2380",
]
CLIENT_PAIR = ["--cert-file=/pki/server.crt", "--key-file=/pki/server.key"]
PEER_PAIR = ["--peer-cert-file=/pki/peer.crt", "--peer-key-file=/pki/peer.key"]
CLIENT_AUTH = ["--client-cert-auth=true", "--trusted-ca-file=/pki/ca.crt"]
PEER_AUTH = ["--peer-client-cert-auth=true", "--peer-trusted-ca-file=/pki/ca.crt"]
SAFE_ETCD = [*ETCD, *CLIENT_PAIR, *PEER_PAIR, *CLIENT_AUTH, *PEER_AUTH]
LOOPBACK_ETCD = ["etcd", "--listen-client-urls=https://127.0.0.1:2379", "--listen-peer-urls=https://127.0.0.1:2380"]


def _v242382_authorization_mode() -> None:
    """Covered. The check: `--authorization-mode` absent, or AlwaysAllow."""
    assert _fires(_pod("kube-apiserver", [*API, "--anonymous-auth=false"]), "KN-S038")
    assert _fires(
        _pod("kube-apiserver", [*API, "--authorization-mode=AlwaysAllow", "--anonymous-auth=false"]), "KN-S038"
    )
    assert _fires(
        _pod("kube-apiserver", [*API, "--authorization-mode=RBAC,AlwaysAllow", "--anonymous-auth=false"]), "KN-S038"
    )
    assert _clean(_pod("kube-apiserver", SAFE_API), "KN-S038")
    # What the rule cannot read it declines; it never counts it clean.
    config = [*API, "--authorization-config=/etc/kubernetes/authz.yaml", "--anonymous-auth=false"]
    assert _declined(_pod("kube-apiserver", config), "KN-S038")


def _v242390_anonymous_auth() -> None:
    """Covered, CAT I. The check: `--anonymous-auth` set to true."""
    assert _fires(_pod("kube-apiserver", [*API, "--authorization-mode=Node,RBAC", "--anonymous-auth=true"]), "KN-S038")
    assert _clean(_pod("kube-apiserver", SAFE_API), "KN-S038")
    # Stricter than the check, as the row says: an absent flag is the upstream default, which is true.
    assert _fires(_pod("kube-apiserver", [*API, "--authorization-mode=Node,RBAC"]), "KN-S038")
    # With AlwaysAllow in effect it is one finding, and the rule still fires on the object.
    assert _fires(_pod("kube-apiserver", [*API, "--anonymous-auth=true"]), "KN-S038")
    # An authentication configuration file is not in the input: declined, never clean.
    config = [*API, "--authorization-mode=Node,RBAC", "--authentication-config=/etc/kubernetes/authn.yaml"]
    assert _declined(_pod("kube-apiserver", config), "KN-S038")


def _v242379_etcd_auto_tls() -> None:
    """Partly. Judged: auto-tls on with no certificate pair. Not judged: an absent flag, and on beside a pair."""
    assert _fires(_pod("etcd", [*ETCD, *PEER_PAIR, *CLIENT_AUTH, *PEER_AUTH, "--auto-tls=true"]), "KN-S039")
    assert _clean(_pod("etcd", SAFE_ETCD), "KN-S039"), "absent --auto-tls is the check's finding and not the rule's"
    assert _clean(_pod("etcd", [*SAFE_ETCD, "--auto-tls=true"]), "KN-S039"), "on beside a pair: etcd ignores it"
    assert _clean(_pod("etcd", [*SAFE_ETCD, "--auto-tls=false"]), "KN-S039")


def _v242380_etcd_peer_auto_tls() -> None:
    """Partly, the peer side of V-242379."""
    assert _fires(_pod("etcd", [*ETCD, *CLIENT_PAIR, *CLIENT_AUTH, *PEER_AUTH, "--peer-auto-tls=true"]), "KN-S039")
    assert _clean(_pod("etcd", SAFE_ETCD), "KN-S039")
    assert _clean(_pod("etcd", [*SAFE_ETCD, "--peer-auto-tls=true"]), "KN-S039")


def _v242423_etcd_client_cert_auth() -> None:
    """Partly. Judged: absent or false with no CA file. Not judged: absent beside a CA file, and loopback."""
    assert _fires(_pod("etcd", [*ETCD, *CLIENT_PAIR, *PEER_PAIR, *PEER_AUTH]), "KN-S039")
    assert _fires(_pod("etcd", [*ETCD, *CLIENT_PAIR, *PEER_PAIR, *PEER_AUTH, "--client-cert-auth=false"]), "KN-S039")
    assert _clean(_pod("etcd", SAFE_ETCD), "KN-S039")
    with_ca = [*ETCD, *CLIENT_PAIR, *PEER_PAIR, *PEER_AUTH, "--trusted-ca-file=/pki/ca.crt"]
    assert _clean(_pod("etcd", with_ca), "KN-S039"), "the check's finding (flag absent), and not the rule's"
    assert _clean(_pod("etcd", LOOPBACK_ETCD), "KN-S039"), "loopback only: the check's finding, not the rule's"


def _v242426_etcd_peer_client_cert_auth() -> None:
    """Partly, the peer side of V-242423."""
    assert _fires(_pod("etcd", [*ETCD, *CLIENT_PAIR, *PEER_PAIR, *CLIENT_AUTH]), "KN-S039")
    assert _clean(_pod("etcd", SAFE_ETCD), "KN-S039")
    with_ca = [*ETCD, *CLIENT_PAIR, *PEER_PAIR, *CLIENT_AUTH, "--peer-trusted-ca-file=/pki/ca.crt"]
    assert _clean(_pod("etcd", with_ca), "KN-S039")


def _v242414_host_ports() -> None:
    """Partly. Judged: every hostPort. Not judged: which are privileged, which namespace, and hostNetwork."""
    assert _fires(_app(ports=[{"containerPort": 80, "hostPort": 80}]), "KN-S011")
    assert _clean(_app(ports=[{"containerPort": 80}]), "KN-S011")
    # Broader than the check, as the row says: an unprivileged port and a system namespace fire the same way.
    assert _fires(_app(ports=[{"containerPort": 8080, "hostPort": 8080}]), "KN-S011")
    assert _fires(_app(namespace="kube-system", ports=[{"containerPort": 80, "hostPort": 80}]), "KN-S011")
    hit = next(
        f for f in _report(_app(ports=[{"containerPort": 80, "hostPort": 80}])).findings if f.rule_id == "KN-S011"
    )
    assert "80" in hit.message, "the port is in the finding, which is what lets a reader apply the check"
    # And narrower: a hostNetwork pod on a privileged port declares no hostPort. KN-S009 has that one.
    host = yaml.safe_load(_app(ports=[{"containerPort": 80}]))
    host["spec"]["hostNetwork"] = True
    text = yaml.safe_dump(host, sort_keys=False)
    assert _clean(text, "KN-S011") and _fires(text, "KN-S009")


def _v274883_sensitive_information() -> None:
    """Partly, CAT I. Judged: what looks like a credential. Not judged: anything else a person calls sensitive."""
    assert _fires(_app(env=[{"name": "DB_PASSWORD", "value": "correct-horse-battery"}]), "KN-S013")
    config = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "c", "namespace": "shop"}}
    assert _fires(yaml.safe_dump({**config, "data": {"DB_PASSWORD": "correct-horse-battery"}}), "KN-S026")
    assert _clean(_app(env=[{"name": "LOG_LEVEL", "value": "info"}]), "KN-S013")
    assert _clean(yaml.safe_dump({**config, "data": {"LOG_LEVEL": "info"}}), "KN-S026")
    # A personal identifier is sensitive and is not a credential: neither rule sees it.
    assert _clean(_app(env=[{"name": "CUSTOMER_SSN", "value": "078-05-1120"}]), "KN-S013")
    assert _clean(yaml.safe_dump({**config, "data": {"customer_ssn": "078-05-1120"}}), "KN-S026")


def _role(rules: list[dict[str, Any]]) -> str:
    doc = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "reader", "namespace": "shop"},
        "rules": rules,
    }
    return yaml.safe_dump(doc, sort_keys=False)


def _v274884_secret_access() -> None:
    """Partly. Judged: which roles read Secrets. Not judged: the documented requirement, and a named `get`."""
    assert _fires(_role([{"apiGroups": [""], "resources": ["secrets"], "verbs": ["list"]}]), "KN-S017")
    assert _fires(_role([{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]), "KN-S017")
    assert _fires(_role([{"apiGroups": [""], "resources": ["*"], "verbs": ["get"]}]), "KN-S015")
    assert _clean(_role([{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}]), "KN-S017")
    named = _role([{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"], "resourceNames": ["db"]}])
    assert _clean(named, "KN-S017"), "least privilege to the rule; still a grant the check wants documented"


PROOFS = {
    "V-242379": _v242379_etcd_auto_tls,
    "V-242380": _v242380_etcd_peer_auto_tls,
    "V-242382": _v242382_authorization_mode,
    "V-242390": _v242390_anonymous_auth,
    "V-242414": _v242414_host_ports,
    "V-242423": _v242423_etcd_client_cert_auth,
    "V-242426": _v242426_etcd_peer_client_cert_auth,
    "V-274883": _v274883_sensitive_information,
    "V-274884": _v274884_secret_access,
}


def test_every_covered_and_partly_row_has_a_fixture_proof(
    snapshot: dict[str, Any], rows: dict[str, dict[str, Any]]
) -> None:
    """The list is exhaustive in both directions: a row cannot claim a rule without a proof here, and a proof
    cannot outlive the row it was written for."""
    judged = {vid for vid, row in rows.items() if row["status"] in {"covered", "partly"}}
    assert judged == set(PROOFS)
    cat_i = {r["id"] for r in snapshot["rules"] if r["severity"] == "high"}
    assert {v for v in judged & cat_i if rows[v]["status"] == "covered"} == {"V-242390"}


@pytest.mark.parametrize("vid", sorted(PROOFS))
def test_a_judged_row_is_proved_on_a_fixture(vid: str, rows: dict[str, dict[str, Any]]) -> None:
    PROOFS[vid]()
    # The proof exercises the rules the row names, and no others.
    source = PROOFS[vid].__code__.co_consts
    named = {c for c in source if isinstance(c, str) and re.fullmatch(r"KN-[A-Z]+\d{3}", c)}
    assert set(rows[vid]["rules"]) <= named, (vid, named)


def test_a_static_pod_row_is_undetermined_when_no_static_pod_is_in_the_input() -> None:
    """A managed control plane, or simply an application bundle: there is no kube-apiserver or etcd manifest to
    read, so the two rules behind the six static-pod rows decline. They are not evaluated and not clean."""
    app = _app()
    for rule_id in ("KN-S038", "KN-S039"):
        assert _declined(app, rule_id)
    # And where the platform runs the control plane itself, a manifest that names it is declined too.
    assert _declined(_pod("kube-apiserver", [*API, "--anonymous-auth=true"]), "KN-S038", platform="openshift")


#: CAT I rows marked `not covered`: the fixture that IS the STIG's finding, beside the one that is not. No rule
#: tells them apart today, which is what the status says. When a rule starts to, this fails and the row moves.
UNCOVERED_CAT_I: dict[str, tuple[str, str]] = {
    "V-242381": (
        _pod("kube-controller-manager", ["kube-controller-manager", "--use-service-account-credentials=false"]),
        _pod("kube-controller-manager", ["kube-controller-manager", "--use-service-account-credentials=true"]),
    ),
    "V-242383": (_app(namespace="default"), _app(namespace="shop")),
    "V-242415": (
        _app(env=[{"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db", "key": "password"}}}]),
        _app(volumeMounts=[]),
    ),
    "V-242436": (
        _pod("kube-apiserver", [*SAFE_API, "--enable-admission-plugins=NodeRestriction"]),
        _pod("kube-apiserver", [*SAFE_API, "--enable-admission-plugins=NodeRestriction,ValidatingAdmissionWebhook"]),
    ),
    "V-245542": (
        _pod("kube-apiserver", [*SAFE_API, "--basic-auth-file=/etc/kubernetes/basic.csv"]),
        _pod("kube-apiserver", SAFE_API),
    ),
    "V-245543": (
        _pod("kube-apiserver", [*SAFE_API, "--token-auth-file=/etc/kubernetes/tokens.csv"]),
        _pod("kube-apiserver", SAFE_API),
    ),
    "V-245544": (
        _pod("kube-apiserver", SAFE_API),
        _pod(
            "kube-apiserver",
            [*SAFE_API, "--kubelet-client-certificate=/pki/kubelet.crt", "--kubelet-client-key=/pki/kubelet.key"],
        ),
    ),
    "V-254800": (
        _pod("kube-apiserver", SAFE_API),
        _pod("kube-apiserver", [*SAFE_API, "--admission-control-config-file=/etc/kubernetes/admission.yaml"]),
    ),
    "V-254801": (
        _pod("kube-apiserver", [*SAFE_API, "--feature-gates=PodSecurity=false"]),
        _pod("kube-apiserver", [*SAFE_API, "--feature-gates=PodSecurity=true"]),
    ),
    "V-274882": (
        _pod("kube-apiserver", SAFE_API),
        _pod("kube-apiserver", [*SAFE_API, "--encryption-provider-config=/etc/kubernetes/encryption.yaml"]),
    ),
}


def test_every_uncovered_cat_i_row_that_a_fixture_can_show_is_measured(
    snapshot: dict[str, Any], rows: dict[str, dict[str, Any]]
) -> None:
    cat_i = {r["id"] for r in snapshot["rules"] if r["severity"] == "high"}
    uncovered = {v for v in cat_i if rows[v]["status"] == "not covered"}
    # V-242437 is a PodSecurityPolicy check for clusters below 1.25, where the API still exists; its fixture
    # would only measure KN-V005, which reports the kind as removed, and the row's note says that instead.
    assert uncovered - set(UNCOVERED_CAT_I) == {"V-242437"}
    assert set(UNCOVERED_CAT_I) <= uncovered


@pytest.mark.parametrize("vid", sorted(UNCOVERED_CAT_I))
def test_no_rule_tells_an_uncovered_cat_i_finding_from_its_absence(vid: str) -> None:
    finding, fine = UNCOVERED_CAT_I[vid]
    fired = {f.rule_id for f in _report(finding).findings}
    baseline = {f.rule_id for f in _report(fine).findings}
    assert fired <= baseline, (
        f"{vid} is marked `not covered`, and {sorted(fired - baseline)} now fires on its finding and not beside "
        "it: move the row to `partly` or `covered` in crosswalk.yaml, with a proof"
    )


def test_the_rule_whose_remedy_is_this_checks_finding_is_named_in_the_row(rows: dict[str, dict[str, Any]]) -> None:
    """V-242415 counts an environment variable set from a Secret as a finding; KN-S013's remediation recommends
    exactly that. A reader who follows one into the other deserves to be told on the row, so the row says it,
    and this holds the remediation text that makes the sentence true."""
    rule = next(r for r in (RULES.values() if isinstance(RULES, dict) else RULES) if r.rule_id == "KN-S013")
    assert "secretKeyRef" in rule.remediation
    assert "KN-S013" in rows["V-242415"]["note"] and "secretKeyRef" in rows["V-242415"]["note"]
    assert rows["V-242415"]["rules"] == []
