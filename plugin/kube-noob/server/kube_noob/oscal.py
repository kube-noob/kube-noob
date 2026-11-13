"""OSCAL assessment-results for an audit report (roadmap P3).

Pure serialisation of what the audit already computed. It reads the report's public dict -- the same shape
`kube-noob audit --format json` prints -- so an exceptions file that rebuilds the control summary is reflected
without this module knowing about exceptions at all. Only `audit` is wired to it; `gate` has no `--oscal` flag,
because the gate report carries findings but no coverage record (roadmap P3).

The coverage record is what makes this honest. `controlSummary` reports `findings`, `clean` and `notEvaluated`
per control (G191), so a control whose rules ran and found nothing is `satisfied`, a control with findings is
`not-satisfied`, and a control NO rule evaluated is named under `exclude-controls` and given no finding at all.
Without that record the document would have claimed satisfaction from silence, which is the failure FedRAMP's
own guidance names; when the record is absent (an older caller) this module degrades to reporting only the
controls that have findings and says so in the remarks, rather than inventing coverage.

Every field was written against NIST's published schema and catalogue, not from recollection:

* `oscal_assessment-results_schema.json` from the OSCAL **v1.2.3** release gives the required members:
  `assessment-results` needs `uuid`, `metadata`, `import-ap`, `results`; a `result` needs `uuid`, `title`,
  `description`, `start`, `reviewed-controls`; a `finding` needs `uuid`, `title`, `description`, `target`; an
  `observation` needs `uuid`, `description`, `methods`, `collected`.
* `finding-target.type` is an enum of exactly `statement-id` and `objective-id`, so a finding may NOT target a
  control directly. It targets the control's objective id, `ac-6.10_obj`, which the catalogue defines.
* Control ids are catalogue ids, not the labels in `controls.py`: `AC-6(10)` is `ac-6.10`. Parentheses are not
  legal in OSCAL's `TokenDatatype` (``^(\\p{L}|_)(\\p{L}|\\p{N}|[.\\-_])*$``), so emitting the label would
  produce a document that cannot validate. All 28 of kube-noob's controls and their `_obj` ids resolve in
  `NIST_SP-800-53_rev5_catalog.json`, and a test holds that mapping.
* That same ``\\p{L}`` is why CI validates with ajv rather than Python's `jsonschema`: Python's `re`
  cannot compile a Unicode property escape, so `jsonschema` raises `PatternError` the moment validation
  reaches a token -- which any document complete enough to be worth checking does, including one whose
  only fault is an illegal control id. It cannot check this schema at all. (An earlier note here said it
  SKIPS the pattern and would call an invalid document valid. That was wrong: it fails loudly rather than
  quietly. The conclusion stands, the stated mechanism did not, and the test now pins the real behaviour.)

`import-ap` is required by the schema and kube-noob has no assessment plan, so it defaults to a local fragment
whose remarks say plainly that no plan was imported and that this is evidence about controls rather than an
assessment against a plan. A pipeline that has one passes `import_ap`.

Determinism: every uuid is a v5 uuid over stable content, so two runs over the same bundle produce the same
document and CI can diff it. The timestamp is the one value that moves, and the caller supplies it.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from kube_noob import __version__
from kube_noob.errors import ConfigError

# A fixed namespace for this project's v5 uuids, itself derived (a uuid5 of the project homepage in the DNS
# namespace) rather than invented, so anyone can recompute it.
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "kube-noob.com")
OSCAL_VERSION = "1.2.3"
NO_PLAN = "#no-assessment-plan"
PROP_NS = "https://kube-noob.com/ns/oscal"
_ENHANCEMENT = re.compile(r"\((\d+)\)")

_NOT_A_COMPLIANCE_CLAIM = (
    "kube-noob produces evidence from configuration; it does not assess a control in full, and a control "
    "named here is not a claim of compliance."
)


def control_id(control: str) -> str:
    """``AC-6(10)`` -> ``ac-6.10``: the id the NIST OSCAL catalogue uses for that control."""
    return _ENHANCEMENT.sub(r".\1", control).lower()


def objective_id(control: str) -> str:
    """The catalogue id for a control's objective, which is what an OSCAL finding is allowed to target."""
    return f"{control_id(control)}_obj"


def _uuid(*parts: str) -> str:
    return str(uuid.uuid5(NAMESPACE, "\x1f".join(parts)))


def _identity(f: dict[str, Any]) -> str:
    """A finding's stable identity. `gate` builds its findings by hand and carries no fingerprint, so the
    fallback has to be more than the rule id or two gate runs with different findings would share a uuid."""
    fp = f.get("fingerprint")
    if isinstance(fp, str) and fp:
        return fp
    return "|".join(str(f.get(k, "")) for k in ("ruleId", "resource", "path", "uri", "line"))


def _scope(report: dict[str, Any], import_ap: str | None) -> str:
    """A stable identity for this ASSESSMENT, not merely for the objects it looked at.

    Keying on platform, version and resource names alone meant `--min-severity critical` and a default run --
    one reporting every control satisfied, the other fifteen not-satisfied -- produced the same
    `assessment-results` uuid, the same `result` uuid, and fifteen `finding` uuids that flipped verdict without
    changing identity. Any store keyed on the uuid, which is what a uuid is for, would treat those as one
    record. So the verdict-bearing content is in the key: every finding's identity, every control's buckets,
    and the imported plan.
    """
    controls = report.get("controlSummary", {}).get("controls") or []
    parts = [
        str(report.get("platform") or "kubernetes"),
        str(report.get("kubernetesVersion") or ""),
        *sorted(str(r) for r in report.get("resources") or []),
        *sorted(_identity(f) for f in report.get("findings") or [] if isinstance(f, dict)),
        *sorted(
            "{}={},{},{},{},{}".format(
                c.get("id"),
                c.get("findings"),
                c.get("excepted"),
                c.get("clean"),
                c.get("withheld"),
                c.get("notEvaluated"),
            )
            for c in controls
            if isinstance(c, dict)
        ),
        import_ap or NO_PLAN,
    ]
    return "\x1f".join(parts)


def check_import_ap(href: str | None) -> None:
    """Refuse an `import-ap` href that is not a URI reference, before a document is built around it.

    `import-ap.href` is OSCAL's ``URIReferenceDatatype``, which a validator enforces as `format:
    uri-reference`. Taking the value verbatim meant an ordinary mistake -- a path with a space, a Windows
    path, a value with stray surrounding whitespace -- produced a document that validates nowhere, while the
    exit code stayed the audit's and the pipeline read it as a success.
    """
    if href is None:
        return
    if not href or href != href.strip() or any(ch.isspace() for ch in href):
        raise ConfigError(
            f"--oscal-import-ap {href!r} is not a URI reference: it must not be empty or contain whitespace. "
            "Use a URL (https://grc.example.com/ap.json), a relative path (./ap.json) or a fragment (#id)."
        )
    if "\\" in href:
        raise ConfigError(
            f"--oscal-import-ap {href!r} is not a URI reference: a backslash is not a path separator in a URI. "
            "Use forward slashes, or a file:// URL."
        )


def _prop(name: str, value: object) -> dict[str, str] | None:
    """A property whose value satisfies OSCAL's ``StringDatatype``, or None when nothing is left of it.

    The pattern is ``^\\S(.*\\S)?$``: no leading or trailing whitespace, not empty, and in ECMAScript ``.``
    does not match a newline, so an interior newline is invalid too. A Kubernetes name can carry all three --
    a YAML folded scalar yields ``Deployment/shop/orders-api\\n``, and an unknown field whose key has a
    trailing space (exactly the typo KN-V007 exists to report) yields the path ``spec.bad field ``. Emitting
    those verbatim produced a document no OSCAL tool will ingest, so every run of whitespace collapses to one
    space and the result is stripped.
    """
    text = " ".join(str(value).split())
    return {"name": name, "ns": PROP_NS, "value": text} if text else None


def _stamp(when: datetime) -> str:
    """RFC 3339 with a timezone, which the schema's ``DateTimeWithTimezoneDatatype`` requires."""
    return when.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _has_coverage(controls: list[dict[str, Any]]) -> bool:
    """True when the report carried a coverage record, so `clean` means checked rather than unknown."""
    return any("clean" in c and "notEvaluated" in c for c in controls)


def _reviewed(c: dict[str, Any]) -> bool:
    """A control at least one rule actually looked at."""
    return bool(c.get("findings") or c.get("excepted") or c.get("clean") or c.get("withheld"))


def _observations(findings: list[dict[str, Any]], collected: str, scope: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for i, f in enumerate(findings):
        props = [
            p
            for p in (
                _prop("rule-id", f.get("ruleId", "")),
                _prop("severity", f.get("severity", "")),
                _prop("resource", f.get("resource", "")),
                _prop("path", f["path"]) if f.get("path") else None,
                # The file, when the caller audited files rather than a pasted string: an assessment result
                # that names a resource and a field but no path leaves the assessor to find it (G251). The
                # LINE is deliberately not here: it depends on where a document sits inside its file, and
                # `test_the_document_does_not_depend_on_the_order_the_documents_arrived_in` holds this
                # document to being identical for a reordered bundle. The line is in the JSON report.
                _prop("file", str(f["file"])) if f.get("file") else None,
            )
            if p is not None
        ]
        # The finding's fingerprint is its cross-run identity (G190) and deliberately excludes the message, so
        # two containers failing one pod-level check share it. An OBSERVATION is a thing that was seen, and two
        # different observations may not share a uuid -- a consumer resolving `related-observations` would reach
        # one of them and never the other -- so the message joins the key here. It is stable for a given input,
        # which is what reproducibility needs.
        key = "\x1f".join([_identity(f), str(f.get("message", "")), str(i)])
        entry: dict[str, Any] = {
            "uuid": _uuid("observation", scope, key),
            "title": f"{f.get('ruleId', '')} {f.get('title', '')}".strip(),
            "description": f"{f.get('resource', '<bundle>')}: {f.get('message', '')}",
            # EXAMINE, of the four the schema allows: kube-noob reads configuration. It interviews nobody and
            # exercises no running system, so TEST would overstate what happened.
            "methods": ["EXAMINE"],
            "props": props,
            "collected": collected,
        }
        if f.get("remediation"):
            entry["remarks"] = str(f["remediation"])
        out.append(entry)
    return out


def _is_reviewed(c: dict[str, Any], coverage: bool) -> bool:
    """The ONE predicate for whether this document reviews a control.

    `include-controls`, `exclude-controls` and whether a finding is emitted all have to agree. When they did
    not, a control could be given a `not-satisfied` finding and named under `exclude-controls` in the same
    document, beside a description saying no control was reviewed.
    """
    if coverage:
        return _reviewed(c)
    # Without a coverage record, "no findings" is not evidence of anything, so only findings count.
    return bool(c.get("findings") or c.get("excepted"))


def _findings(
    controls: list[dict[str, Any]], scope: str, obs_by_control: dict[str, list[str]], coverage: bool
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for c in controls:
        cid, title = str(c["id"]), str(c.get("title", ""))
        n, excepted = int(c.get("findings") or 0), int(c.get("excepted") or 0)
        if not _is_reviewed(c, coverage):
            continue  # not reviewed: it gets an exclusion, never a finding
        withheld = int(c.get("withheld") or 0)
        if n:
            state, reason = "not-satisfied", "fail"
            description = f"{n} finding(s) bear on {cid} {title}."
        elif withheld:
            # The rules ran and reported; this report's severity filter removed their findings. Emitting
            # `satisfied` here is how `--min-severity critical` turned a privileged container into a clean
            # compliance record (G199).
            state, reason = "not-satisfied", "other"
            description = (
                f"{withheld} rule(s) giving evidence about {cid} {title} ran and reported findings that this "
                "report's severity filter withheld. The objective is not satisfied; re-run without the filter "
                "to see what they found."
            )
        elif excepted:
            # An exception is a reviewed, owned, expiring decision about a control. It is not a pass.
            state, reason = "not-satisfied", "other"
            description = (
                f"{excepted} finding(s) bearing on {cid} {title} were accepted by an exception list. "
                "An accepted finding is a recorded decision, not a satisfied objective."
            )
        else:
            state, reason = "satisfied", "pass"
            description = (
                f"{int(c.get('clean') or 0)} rule(s) giving evidence about {cid} {title} ran over this input "
                "and produced no finding."
            )
        if coverage and int(c.get("notEvaluated") or 0):
            description += (
                f" {int(c['notEvaluated'])} further rule(s) for this control were not evaluated, so this "
                "covers part of the control's evidence, not all of it."
            )
        entry: dict[str, Any] = {
            "uuid": _uuid("finding", scope, cid),
            "title": f"{cid} {title}",
            "description": f"{description} {_NOT_A_COMPLIANCE_CLAIM}",
            "target": {
                "type": "objective-id",
                "target-id": objective_id(cid),
                "status": {"state": state, "reason": reason},
            },
        }
        related = obs_by_control.get(cid, [])
        if related:
            entry["related-observations"] = [{"observation-uuid": u} for u in sorted(set(related))]
        out.append(entry)
    return out


def assessment_results(
    report: dict[str, Any], *, timestamp: datetime | None = None, import_ap: str | None = None
) -> dict[str, Any]:
    """An OSCAL 1.2.3 assessment-results document for a `kube-noob audit` report dict."""
    when = timestamp or datetime.now(UTC)
    collected = _stamp(when)
    resources = [str(r) for r in report.get("resources") or []]
    platform = str(report.get("platform") or "kubernetes")
    k8s = str(report.get("kubernetesVersion") or "")
    scope = _scope(report, import_ap)

    findings_in = [f for f in report.get("findings") or [] if isinstance(f, dict)]
    summary = report.get("controlSummary") or {}
    controls = [c for c in summary.get("controls") or [] if isinstance(c, dict) and c.get("id")]
    coverage = _has_coverage(controls)

    observations = _observations(findings_in, collected, scope)
    obs_by_control: dict[str, list[str]] = {}
    for f, o in zip(findings_in, observations, strict=True):
        for cid in f.get("controls") or []:
            obs_by_control.setdefault(str(cid), []).append(o["uuid"])

    reviewed = [c for c in controls if _is_reviewed(c, coverage)]
    excluded = [c for c in controls if not _is_reviewed(c, coverage)]
    selection: dict[str, Any] = {
        "description": (
            f"Controls for which at least one kube-noob rule ran over this input. {_NOT_A_COMPLIANCE_CLAIM}"
            if coverage
            else "Controls with at least one finding from this input. This report carried no coverage record, "
            f"so a control without findings here is not reported as reviewed. {_NOT_A_COMPLIANCE_CLAIM}"
        )
    }
    if reviewed:
        selection["include-controls"] = [{"control-id": control_id(str(c["id"]))} for c in reviewed]
    else:
        # The schema requires a non-empty include-controls, and there is nothing honest to put in it.
        selection["include-all"] = {}
        selection["description"] = (
            "No control was reviewed by this document: no rule is recorded as having run over this input."
        )
    if excluded:
        selection["exclude-controls"] = [{"control-id": control_id(str(c["id"]))} for c in excluded]
        selection["remarks"] = (
            "Excluded controls had no rule run over this input -- a stage filter, an object kind no rule "
            "covers, or a partial bundle. They are neither satisfied nor unsatisfied here, and the absence of "
            "a finding for them is not evidence."
            if coverage
            else "This report carried no coverage record, so these controls cannot be distinguished between "
            "checked and clean, and not checked at all. They are excluded rather than reported satisfied."
        )

    result: dict[str, Any] = {
        "uuid": _uuid("result", scope),
        "title": f"kube-noob configuration audit, {platform} {k8s}".rstrip(),
        "description": (
            f"Deterministic offline configuration audit of {len(resources)} object(s) by kube-noob "
            f"{__version__}. {len(findings_in)} finding(s); {len(reviewed)} control(s) reviewed, "
            f"{len(excluded)} excluded."
        ),
        "start": collected,
        "end": collected,
        "reviewed-controls": {"control-selections": [selection]},
    }
    if observations:
        # Sorted by uuid, which is a digest of the finding rather than of its position. `report["findings"]` is
        # ordered by (severity, docIndex, line), so listing the same two files in the other order produced the
        # same uuids and different bytes -- an identity that says "unchanged" over a document that is not.
        result["observations"] = sorted(observations, key=lambda o: o["uuid"])
    oscal_findings = _findings(controls, scope, obs_by_control, coverage)
    if oscal_findings:
        result["findings"] = oscal_findings
    remarks = [str(a) for a in report.get("assumptions") or []]
    unreadable = [u for u in report.get("unreadable") or [] if isinstance(u, dict)]
    if unreadable:
        # `--skip-unreadable` promises the skipped files are listed "so a gate never reads a partial audit as a
        # clean one". With --oscal the document IS the whole report, so the list has to be in it.
        names = ", ".join(sorted(str(u.get("path") or "?") for u in unreadable))
        remarks.append(
            f"{len(unreadable)} input file(s) could not be read and were skipped: {names}. This assessment "
            "covers only the files that were read."
        )
    orphans = sum(1 for f in findings_in if not (f.get("controls") or []))
    if orphans:
        remarks.append(
            f"{orphans} observation(s) come from checks that map to no control in this catalogue (schema "
            "validation among them), so they are recorded as observations and no control's verdict reflects "
            "them."
        )
    if summary.get("note"):
        remarks.append(str(summary["note"]))
    if remarks:
        result["remarks"] = " ".join(remarks)

    import_block: dict[str, Any] = {"href": import_ap or NO_PLAN}
    if not import_ap:
        import_block["remarks"] = (
            "No assessment plan was imported. OSCAL requires this field and kube-noob has no plan to point "
            "at: this document is machine-readable evidence about the controls named in it, produced from "
            "configuration, and not an assessment against a plan. Pass your own plan to replace this."
        )
    return {
        "assessment-results": {
            "uuid": _uuid("assessment-results", scope),
            "metadata": {
                "title": f"kube-noob audit: {platform} {k8s}".rstrip(),
                "last-modified": collected,
                "version": __version__,
                "oscal-version": OSCAL_VERSION,
            },
            "import-ap": import_block,
            "results": [result],
        }
    }
