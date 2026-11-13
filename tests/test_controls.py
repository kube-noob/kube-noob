"""Every audit rule names the NIST SP 800-53 controls it gives evidence for, and crypto stays FIPS-friendly."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from kube_noob.audit.controls import RULE_CONTROLS, TITLES, summary
from kube_noob.audit.engine import analyze, explain_rule, list_rules
from kube_noob.cli import main
from kube_noob.config import load_settings
from kube_noob.posture import crypto_posture, posture

ROOT = Path(__file__).resolve().parents[1]
CONTROL_ID = re.compile(r"^(AC|AT|AU|CA|CM|CP|IA|IR|MA|MP|PE|PL|PM|PS|PT|RA|SA|SC|SI|SR)-\d{1,2}(\(\d{1,2}\))?$")


def test_every_rule_maps_to_titled_800_53_controls() -> None:
    ids = {r["ruleId"] for r in list_rules()}
    assert len(ids) == 98 and set(RULE_CONTROLS) == ids
    for rid, controls in RULE_CONTROLS.items():
        assert controls, rid
        for c in controls:
            assert CONTROL_ID.match(c) and c in TITLES, (rid, c)
    assert set(TITLES) == {c for cs in RULE_CONTROLS.values() for c in cs}  # no stale titles
    assert explain_rule("KN-S013")["controls"] == [
        {"id": "IA-5(7)", "title": "Authenticator Management | No Embedded Unencrypted Static Authenticators"},
        {"id": "SC-28", "title": "Protection of Information at Rest"},
    ]


def test_findings_and_reports_carry_controls(capsys: pytest.CaptureFixture[str]) -> None:
    report = analyze((ROOT / "examples" / "insecure-deployment.yaml").read_text(), "openshift", "4.22").as_dict()
    secret = next(f for f in report["findings"] if f["ruleId"] == "KN-S013")
    assert secret["controls"] == ["IA-5(7)", "SC-28"]
    # The summary now also names controls whose rules ran and found nothing, so compare the findings
    # side against the findings side: a control at zero is coverage, not a finding (G191).
    touched = {c["id"]: c["findings"] for c in report["controlSummary"]["controls"] if c["findings"]}
    expected = summary([f["ruleId"] for f in report["findings"]])
    assert touched == {c["id"]: c["findings"] for c in expected["controls"]} and touched["AC-6"] >= 1
    clean = [c for c in report["controlSummary"]["controls"] if c["findings"] == 0]
    assert clean and all("clean" in c and "notEvaluated" in c for c in clean), (
        "a control that was checked and found nothing must be named, not absent"
    )
    assert "assessment" in report["controlSummary"]["note"]
    main(["audit", "-f", str(ROOT / "examples" / "insecure-deployment.yaml"), "--platform", "openshift"])
    assert "NIST SP 800-53 controls with findings: " in capsys.readouterr().out


def test_crypto_is_fips_friendly_and_reported() -> None:
    weak = re.compile(r"hashlib\.(md5|sha1|new\(\s*['\"](md5|sha1)['\"])|\bfrom Crypto\b|\bimport Crypto\b")
    offenders = [
        str(p.relative_to(ROOT))
        for p in (ROOT / "src" / "kube_noob").rglob("*.py")
        if weak.search(p.read_text(encoding="utf-8"))
    ]
    assert offenders == []
    c = crypto_posture()
    assert c["fipsMode"] in {"on", "off", "unknown"} and "SHA-256" in c["algorithms"]
    assert posture(load_settings())["crypto"]["fipsMode"] == c["fipsMode"]
