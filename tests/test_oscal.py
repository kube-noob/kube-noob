"""OSCAL assessment-results: the document NIST's own schema accepts, and the claims it refuses to make (G197)."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from kube_noob import __version__, oscal
from kube_noob.audit.controls import TITLES
from kube_noob.audit.engine import analyze
from kube_noob.cli import main

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "oscal"
SCHEMA = FIX / "oscal_assessment-results_schema.json"
IDS = json.loads((FIX / "nist-800-53-rev5-ids.json").read_text(encoding="utf-8"))
WHEN = datetime(2026, 11, 5, 12, 0, 0, tzinfo=UTC)
# OSCAL UUIDDatatype: a type 4 or type 5 UUID. Every uuid kube-noob emits is a v5, so the nibble is 5.
UUID5 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
# TokenDatatype, with \p{L} and \p{N} narrowed to what a control id can actually contain.
TOKEN = re.compile(r"^[A-Za-z_][A-Za-z0-9.\-_]*$")


def _report(platform: str = "openshift", version: str | None = "4.22", path: str = "insecure-deployment.yaml") -> dict:
    return analyze((ROOT / "examples" / path).read_text(encoding="utf-8"), platform, version).as_dict()


@pytest.fixture(scope="module")
def doc() -> dict[str, Any]:
    return oscal.assessment_results(_report(), timestamp=WHEN)


@pytest.fixture(scope="module")
def result(doc: dict[str, Any]) -> dict[str, Any]:
    return doc["assessment-results"]["results"][0]


# -- the shape NIST requires ---------------------------------------------------------------------------


def test_the_required_members_are_present(doc: dict[str, Any], result: dict[str, Any]) -> None:
    ar = doc["assessment-results"]
    assert set(ar) >= {"uuid", "metadata", "import-ap", "results"}
    assert set(ar["metadata"]) >= {"title", "last-modified", "version", "oscal-version"}
    assert set(result) >= {"uuid", "title", "description", "start", "reviewed-controls"}
    for f in result["findings"]:
        assert set(f) >= {"uuid", "title", "description", "target"}
        assert set(f["target"]) >= {"type", "target-id", "status"}
    for o in result["observations"]:
        assert set(o) >= {"uuid", "description", "methods", "collected"}


def test_the_document_states_the_oscal_release_it_was_written_against(doc: dict[str, Any]) -> None:
    assert doc["assessment-results"]["metadata"]["oscal-version"] == "1.2.3" == oscal.OSCAL_VERSION
    assert doc["assessment-results"]["metadata"]["version"] == __version__
    assert IDS["_oscalVersion"] == "1.2.3", "the catalogue the ids came from is the same release"


def test_every_uuid_is_a_version_5_uuid(doc: dict[str, Any], result: dict[str, Any]) -> None:
    ids = [doc["assessment-results"]["uuid"], result["uuid"]]
    ids += [f["uuid"] for f in result["findings"]] + [o["uuid"] for o in result["observations"]]
    assert ids and all(UUID5.match(u) for u in ids), [u for u in ids if not UUID5.match(u)]


def test_the_document_is_reproducible_byte_for_byte() -> None:
    a = oscal.assessment_results(_report(), timestamp=WHEN)
    b = oscal.assessment_results(_report(), timestamp=WHEN)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True), "CI could not diff this"


def test_the_timestamp_carries_a_timezone() -> None:
    """DateTimeWithTimezoneDatatype requires one; a naive stamp fails the schema."""
    stamp = oscal.assessment_results(_report(), timestamp=WHEN)["assessment-results"]["metadata"]["last-modified"]
    assert stamp == "2026-11-05T12:00:00Z"


def test_a_finding_targets_an_objective_because_the_schema_forbids_a_control(result: dict[str, Any]) -> None:
    for f in result["findings"]:
        assert f["target"]["type"] == "objective-id", "statement-id and objective-id are the only members"
        assert f["target"]["target-id"].endswith("_obj")


def test_observations_say_the_evidence_was_examined_not_tested(result: dict[str, Any]) -> None:
    """kube-noob reads configuration: it interviews nobody and exercises no running system."""
    assert result["observations"] and all(o["methods"] == ["EXAMINE"] for o in result["observations"])


# -- the control ids ----------------------------------------------------------------------------------


def test_control_ids_are_catalogue_ids_not_the_labels() -> None:
    assert oscal.control_id("AC-6(10)") == "ac-6.10"
    assert oscal.objective_id("AC-6(10)") == "ac-6.10_obj"
    assert oscal.control_id("SC-4") == "sc-4"


def test_every_control_resolves_to_the_pinned_nist_catalogue_id() -> None:
    assert set(IDS["controls"]) == set(TITLES), "a control was added or removed without refreshing the mapping"
    for label, want in IDS["controls"].items():
        assert oscal.control_id(label) == want["controlId"], label
        assert oscal.objective_id(label) == want["objectiveId"], label


def test_no_emitted_id_would_break_the_token_pattern() -> None:
    """`AC-6(10)` is not a legal OSCAL token: emitting the label would produce an unvalidatable document."""
    assert not TOKEN.match("ac-6(10)")
    for label in TITLES:
        assert TOKEN.match(oscal.control_id(label)), label
        assert TOKEN.match(oscal.objective_id(label)), label


# -- the claims it refuses to make --------------------------------------------------------------------


def test_a_control_no_rule_evaluated_is_excluded_and_never_satisfied() -> None:
    report = _report()
    # A stage filter leaves most controls unevaluated, which is the case P1 made visible.
    narrow = analyze(
        (ROOT / "examples" / "insecure-deployment.yaml").read_text(encoding="utf-8"),
        "openshift",
        "4.22",
        stages={__import__("kube_noob.audit.model", fromlist=["Stage"]).Stage.VALIDATE},
    ).as_dict()
    doc = oscal.assessment_results(narrow, timestamp=WHEN)
    sel = doc["assessment-results"]["results"][0]["reviewed-controls"]["control-selections"][0]
    excluded = {e["control-id"] for e in sel.get("exclude-controls", [])}
    assert excluded, "a stage filter must leave controls excluded"
    satisfied = {
        f["target"]["target-id"]
        for f in doc["assessment-results"]["results"][0].get("findings", [])
        if f["target"]["status"]["state"] == "satisfied"
    }
    assert not (satisfied & {f"{c}_obj" for c in excluded}), "an unevaluated control was reported satisfied"
    assert len(excluded) < len(TITLES) or not report  # sanity: not everything is excluded in the full run


def test_a_clean_control_is_satisfied_only_because_the_coverage_record_says_its_rules_ran(
    result: dict[str, Any],
) -> None:
    satisfied = [f for f in result["findings"] if f["target"]["status"]["state"] == "satisfied"]
    assert satisfied, "the full audit has controls that were checked and are clean"
    assert all("ran over this input and produced no finding" in f["description"] for f in satisfied)


def test_without_a_coverage_record_nothing_is_reported_satisfied() -> None:
    report = _report()
    for c in report["controlSummary"]["controls"]:
        c.pop("clean", None)
        c.pop("notEvaluated", None)
    doc = oscal.assessment_results(report, timestamp=WHEN)
    result = doc["assessment-results"]["results"][0]
    states = {f["target"]["status"]["state"] for f in result.get("findings", [])}
    assert "satisfied" not in states, "no coverage record means no earned pass"
    sel = result["reviewed-controls"]["control-selections"][0]
    assert "no coverage record" in sel["description"] or "no coverage record" in sel.get("remarks", "")


def test_every_finding_says_it_is_not_a_compliance_claim(result: dict[str, Any]) -> None:
    assert result["findings"]
    for f in result["findings"]:
        assert "not a claim of compliance" in f["description"], f["title"]


def test_the_missing_assessment_plan_is_stated_rather_than_faked(doc: dict[str, Any]) -> None:
    block = doc["assessment-results"]["import-ap"]
    assert block["href"] == oscal.NO_PLAN
    assert "No assessment plan was imported" in block["remarks"]


def test_a_real_assessment_plan_replaces_the_placeholder_and_its_remark() -> None:
    doc = oscal.assessment_results(_report(), timestamp=WHEN, import_ap="https://grc.example.com/ap.json")
    block = doc["assessment-results"]["import-ap"]
    assert block["href"] == "https://grc.example.com/ap.json" and "remarks" not in block


def test_an_empty_report_reviews_nothing_rather_than_everything() -> None:
    doc = oscal.assessment_results({}, timestamp=WHEN)
    sel = doc["assessment-results"]["results"][0]["reviewed-controls"]["control-selections"][0]
    assert "include-controls" not in sel and sel["include-all"] == {}
    assert "No control was reviewed" in sel["description"]
    assert doc["assessment-results"]["results"][0].get("findings") in (None, [])


# -- the CLI ------------------------------------------------------------------------------------------


def test_the_flag_replaces_the_report_and_keeps_the_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    args = ["audit", "-f", str(ROOT / "examples" / "insecure-deployment.yaml"), "--platform", "openshift"]
    plain = main(args)
    capsys.readouterr()
    with_flag = main([*args, "--oscal"])
    out = capsys.readouterr().out
    assert plain == with_flag == 1, "a gate must read the same verdict with the flag as without"
    doc = json.loads(out)
    assert "assessment-results" in doc, "the OSCAL document is the whole output, with no report above it"
    assert "kube-noob audit |" not in out


def test_the_cli_passes_the_assessment_plan_through(capsys: pytest.CaptureFixture[str]) -> None:
    main(
        [
            "audit",
            "-f",
            str(ROOT / "examples" / "insecure-deployment.yaml"),
            "--oscal",
            "--oscal-import-ap",
            "https://grc.example.com/ap.json",
        ]
    )
    doc = json.loads(capsys.readouterr().out)
    assert doc["assessment-results"]["import-ap"]["href"] == "https://grc.example.com/ap.json"


# -- NIST's own schema --------------------------------------------------------------------------------


def _ajv() -> str | None:
    node = shutil.which("node")
    if node is None:
        return None
    probe = subprocess.run(
        [node, "-e", "import('ajv').then(()=>process.exit(0),()=>process.exit(1))"],
        capture_output=True,
        check=False,
        cwd=ROOT,
    )
    return node if probe.returncode == 0 else None


def test_the_document_validates_against_nists_published_schema(tmp_path: Path) -> None:
    node = _ajv()
    if node is None:
        pytest.skip("ajv is not installed: npm install --no-save ajv@8.17.1 ajv-formats@3.0.1 ajv-draft-04@1.0.0")
    out = tmp_path / "ar.json"
    out.write_text(json.dumps(oscal.assessment_results(_report(), timestamp=WHEN)), encoding="utf-8")
    done = subprocess.run(
        [node, str(ROOT / "scripts" / "json_schema_validate.mjs"), str(SCHEMA), str(out)],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert "VALID" in done.stdout


def test_python_jsonschema_cannot_validate_this_schema_at_all() -> None:
    """Why ajv. OSCAL's TokenDatatype uses \\p{L}, which Python's `re` cannot compile.

    An earlier note claimed jsonschema SKIPS the pattern and would call an invalid document valid. It does
    not: it raises on every document, valid or not. The conclusion (use ajv) stands; the mechanism was wrong,
    and this test pins the real one so the claim cannot drift back.
    """
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    token = schema["definitions"]["TokenDatatype"]["pattern"]
    assert "\\p{L}" in token
    with pytest.raises(re.error):
        re.compile(token)
    jsonschema = pytest.importorskip("jsonschema")
    validator = jsonschema.Draft7Validator(schema)
    # A document complete enough to be worth checking reaches a token and blows up.
    with pytest.raises(Exception, match="bad escape"):
        list(validator.iter_errors(oscal.assessment_results(_report(), timestamp=WHEN)))
    # So does one whose only fault is an illegal token -- the very thing the pattern exists to catch.
    bad = oscal.assessment_results(_report(), timestamp=WHEN)
    bad["assessment-results"]["results"][0]["findings"][0]["target"]["target-id"] = "ac-6(10)_obj"
    with pytest.raises(Exception, match="bad escape"):
        list(validator.iter_errors(bad))
    # Only a document that fails earlier never reaches the pattern, which is no use as a check.
    assert len(list(validator.iter_errors({"assessment-results": "nonsense"}))) == 1


# -- red team, 2026-11-05 (G200) -----------------------------------------------------------------------


def _ajv_ok(tmp_path: Path, doc: dict[str, Any], name: str = "d.json") -> None:
    node = _ajv()
    if node is None:
        pytest.skip("ajv is not installed: npm install --no-save ajv@8.17.1 ajv-formats@3.0.1 ajv-draft-04@1.0.0")
    out = tmp_path / name
    out.write_text(json.dumps(doc), encoding="utf-8")
    done = subprocess.run(
        [node, str(ROOT / "scripts" / "json_schema_validate.mjs"), str(SCHEMA), str(out)],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert done.returncode == 0, done.stdout + done.stderr


def test_a_name_with_whitespace_does_not_break_the_property_pattern(tmp_path: Path) -> None:
    """A YAML folded scalar yields `Deployment/shop/orders-api\\n`, which StringDatatype refuses."""
    text = (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: >\n    orders-api\n  namespace: shop\n"
        "spec:\n  replicas: 1\n  selector: {matchLabels: {app: o}}\n"
        "  template:\n    metadata: {labels: {app: o}}\n    spec:\n      containers: [{name: c, image: i}]\n"
    )
    doc = oscal.assessment_results(analyze(text, "kubernetes").as_dict(), timestamp=WHEN)
    for o in doc["assessment-results"]["results"][0]["observations"]:
        for prop in o["props"]:
            assert prop["value"] == prop["value"].strip() and "\n" not in prop["value"]
            assert prop["value"], prop
    _ajv_ok(tmp_path, doc, "folded.json")


def test_a_field_path_with_a_trailing_space_does_not_break_it_either(tmp_path: Path) -> None:
    """The typo KN-V007 exists to report produced the path `spec.bad field `, which the schema refuses."""
    text = (
        'apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web, namespace: shop}\nspec:\n  "bad field ": y\n'
        "  replicas: 1\n  selector: {matchLabels: {app: w}}\n"
        "  template:\n    metadata: {labels: {app: w}}\n    spec:\n      containers: [{name: c, image: i}]\n"
    )
    doc = oscal.assessment_results(analyze(text, "kubernetes").as_dict(), timestamp=WHEN)
    _ajv_ok(tmp_path, doc, "badfield.json")


def test_two_containers_failing_one_pod_level_check_get_two_observation_uuids() -> None:
    """The finding fingerprint excludes the message by design, so it alone is not an observation identity."""
    text = (
        "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: n}\nspec:\n  containers:\n"
        "  - {name: alpha, image: i}\n  - {name: beta, image: i}\n"
    )
    obs = oscal.assessment_results(analyze(text, "kubernetes").as_dict(), timestamp=WHEN)["assessment-results"][
        "results"
    ][0]["observations"]
    uuids = [o["uuid"] for o in obs]
    assert len(uuids) == len(set(uuids)), "a consumer resolving related-observations would miss one container"


def test_the_uuid_changes_when_the_verdict_changes() -> None:
    """Keying on the objects alone gave a clean run and a failing run the same uuid."""
    from kube_noob.audit.model import Severity

    def ids(**kw: Any) -> tuple[str, str]:
        rep = analyze(
            (ROOT / "examples" / "insecure-deployment.yaml").read_text(encoding="utf-8"), "openshift", "4.22", **kw
        ).as_dict()
        ar = oscal.assessment_results(rep, timestamp=WHEN)["assessment-results"]
        return ar["uuid"], ar["results"][0]["uuid"]

    default, filtered = ids(), ids(min_severity=Severity.CRITICAL)
    assert default != filtered, "two opposite verdicts shared one identity"
    assert ids() == default, "and the same input still produces the same identity"


def test_the_import_ap_is_part_of_the_identity() -> None:
    a = oscal.assessment_results(_report(), timestamp=WHEN)["assessment-results"]["uuid"]
    b = oscal.assessment_results(_report(), timestamp=WHEN, import_ap="./ap.json")["assessment-results"]["uuid"]
    assert a != b


def test_the_document_does_not_depend_on_the_order_the_documents_arrived_in() -> None:
    dep = (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d, namespace: n}\nspec:\n  replicas: 1\n"
        "  selector: {matchLabels: {a: b}}\n  template:\n    metadata: {labels: {a: b}}\n"
        "    spec:\n      containers: [{name: c, image: i}]\n"
    )
    svc = (
        "apiVersion: v1\nkind: Service\nmetadata: {name: s, namespace: n}\n"
        "spec:\n  selector: {a: b}\n  ports: [{port: 80, targetPort: 8080}]\n"
    )
    one = oscal.assessment_results(analyze(dep + "---\n" + svc, "kubernetes").as_dict(), timestamp=WHEN)
    two = oscal.assessment_results(analyze(svc + "---\n" + dep, "kubernetes").as_dict(), timestamp=WHEN)
    assert json.dumps(one, sort_keys=True) == json.dumps(two, sort_keys=True)


@pytest.mark.parametrize("href", ["ap plan.json", "C:\\plans\\ap.json", "  https://x/y  ", ""])
def test_an_import_ap_that_is_not_a_uri_reference_is_refused(href: str) -> None:
    from kube_noob.errors import ConfigError

    with pytest.raises(ConfigError, match="not a URI reference"):
        oscal.check_import_ap(href)


@pytest.mark.parametrize("href", ["./ap.json", "https://grc.example.com/ap.json", "#no-assessment-plan", None])
def test_a_real_uri_reference_is_accepted(href: str | None) -> None:
    oscal.check_import_ap(href)


def test_skipped_files_are_named_in_the_document_not_only_on_stderr() -> None:
    """--oscal replaces the report, so the partial-audit warning has to be inside the document."""
    report = _report()
    report["unreadable"] = [{"path": "broken.yaml", "why": "not readable as UTF-8 text"}]
    remarks = oscal.assessment_results(report, timestamp=WHEN)["assessment-results"]["results"][0]["remarks"]
    assert "broken.yaml" in remarks and "could not be read" in remarks
    assert "covers only the files that were read" in remarks


def test_a_check_that_maps_to_no_control_is_declared_rather_than_silently_dropped() -> None:
    """Schema-validation observations belong to no control, so no control's verdict reflects them."""
    text = "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: web, namespace: shop}\nspec: {imagePullPolice: x}\n"
    report = analyze(text, "kubernetes").as_dict()
    assert any(not f.get("controls") for f in report["findings"]), "this input has an uncontrolled finding"
    remarks = oscal.assessment_results(report, timestamp=WHEN)["assessment-results"]["results"][0]["remarks"]
    assert "map to no control" in remarks


def test_a_control_is_never_both_given_a_finding_and_excluded() -> None:
    """The include/exclude lists and the findings all read one predicate, so they cannot disagree."""
    report = _report()
    for c in report["controlSummary"]["controls"]:
        c.pop("clean", None)
        c.pop("notEvaluated", None)
        c.pop("withheld", None)
        if c["id"] == "CM-2":
            c["findings"], c["excepted"] = 0, 2
    doc = oscal.assessment_results(report, timestamp=WHEN)
    result = doc["assessment-results"]["results"][0]
    sel = result["reviewed-controls"]["control-selections"][0]
    included = {e["control-id"] for e in sel.get("include-controls", [])}
    excluded = {e["control-id"] for e in sel.get("exclude-controls", [])}
    assert not (included & excluded)
    for f in result.get("findings", []):
        cid = f["target"]["target-id"].removesuffix("_obj")
        assert cid not in excluded, f"{cid} has a finding and is excluded"
        assert cid in included, f"{cid} has a finding and is not included"
