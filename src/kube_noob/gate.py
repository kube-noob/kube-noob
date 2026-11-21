"""The CI gate before deploy (requirements R4.3): one command over manifests, rendered charts and Containerfiles.

``kube-noob gate`` runs the audit rules (with an exception list when given), says for every finding whether the
generated admission policy would refuse it in enforce mode, lists open reported issues in the target OpenShift
release that mention a kind the manifests deploy, audits Containerfiles, and fails at ``--fail-on``. It writes SARIF
2.1.0 (GitHub code scanning), a Markdown summary (``$GITHUB_STEP_SUMMARY``, merge request notes) and GitLab's code
quality JSON. Findings in a rendered Helm chart point at the template file (``# Source:`` comments) when
``--chart-path`` names the chart in the repository.

Everything is offline: no cluster, no network, no model. Vulnerability checks need scanner input and are listed as
not run until the scanner reader (requirements R5.1) is built.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from kube_noob import __version__, sanitize
from kube_noob.audit.controls import coverage_line, grouped_reasons
from kube_noob.audit.model import Severity, open_not_audited
from kube_noob.yamlio import json_document

MAX_FILES = 2_000
MAX_TOTAL = 5_000_000
SEVERITIES = ("info", "low", "medium", "high", "critical")
#: GitHub displays "10 warning annotations, 10 error annotations, and 10 notice annotations per step" and
#: "50 annotations per job" (actions/toolkit, docs/problem-matchers.md, retrieved 2026-11-05). The eleventh
#: of a kind is dropped without a word, so the tenth is spent saying how many are not shown.
MAX_ANNOTATIONS_PER_TYPE = 10
_SOURCE = re.compile(r"^# Source: ([\w.-]{1,200})/(.{1,400})$")
_KIND = re.compile(r"^kind:\s{0,5}([A-Z][A-Za-z0-9]{1,62})\s*$", re.M)
# Kinds whose names are distinctive enough to search release notes for (Route, Service or Pod are everyday words).
_DISTINCT_KIND = re.compile(r"^[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+\Z")
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/kube-noob/kube-noob"


class GateError(ValueError):
    """Nothing to check, too much input, or a file that cannot be read."""


@dataclass
class Source:
    uri: str
    text: str
    chart: str | None = None  # the chart directory this was rendered from (findings point at its templates)
    skip: str | None = None  # why the file is not audited (not a manifest, a Helm template)
    unreadable: str | None = None  # why the file could not be read at all (bytes YAML refuses, a parse error)
    start: int = 0  # first line of this file in the combined input (1-based)
    lines: int = 0


#: The keys every Kubernetes document must carry, spelled the way the API server spells them.
REQUIRED_KEYS = ("apiVersion", "kind")
#: What a reason for a key spelled differently from one of those starts with. One string, so the report, the exit
#: code, the renderers and `verify` all read the same marker rather than keeping a second list of files (class 9).
NEAR_MISS_PREFIX = "a Kubernetes manifest whose key "
#: Every reason `_classify` gives for not auditing a YAML file found in a directory walk, and whether that reason
#: forbids a verdict. A reason that forbids one makes the gate fail, report `incomplete`, and exit 5: the walk
#: declined to read the file, which is neither a policy violation (1) nor a clean result (0). A reason that does
#: not is a file that was read and understood and holds no Kubernetes object -- a workflow, a values file -- and
#: saying so must stay silent, or every repository scanned with `gate -f .` turns red (G325).
#: `tests/test_near_miss_manifest.py::test_every_skip_reason_decides_whether_it_forbids_a_verdict` fails when a
#: reason reaches `_classify` without an entry here.
SKIP_REASONS: tuple[tuple[str, bool], ...] = (
    ("a Helm template:", False),
    ("not a Kubernetes manifest", False),
    (NEAR_MISS_PREFIX, True),
    # Raised by the bounded loader, returned by `_classify`: the file was not read at all, so it cannot be the
    # ground of a verdict either. It keeps `skipped`'s exit code rather than `unreadable`'s only because the two
    # answers must stay distinct (`unreadable_reason`'s docstring); both are incomplete evidence.
    ("YAML nested too deeply", True),
)


def forbids_verdict(why: str | None) -> bool:
    """Whether a file skipped for this reason makes the gate incomplete rather than clean."""
    if not why:
        return False
    return any(why.startswith(prefix) for prefix, forbids in SKIP_REASONS if forbids)


def _fold(key: str) -> str:
    """A key reduced to what a case-, whitespace- or separator-only typo leaves unchanged."""
    return key.strip().replace("-", "").replace("_", "").lower()


def _near_miss_reason(docs: list[Any]) -> str | None:
    """A required key spelled differently from the way the API server spells it, or None.

    Deliberately narrow, and narrower than "a required key is missing": the document must be a mapping that lacks
    the key EXACTLY, carries a spelling that folds onto it, and carries both required keys when folded that way.
    A kustomization, a Helm values file or a CRD fragment with a `kind` and no `apiVersion` at all is therefore
    not a near miss -- it is a file that is no manifest, which is the answer it already gets.
    """
    for d in docs:
        if not isinstance(d, dict):
            continue
        keys = [k for k in d if isinstance(k, str)]
        folded = {_fold(k): k for k in reversed(keys)}  # the first spelling wins, so the reason is deterministic
        if not all(_fold(r) in folded for r in REQUIRED_KEYS):
            continue
        for required in REQUIRED_KEYS:
            if required in d:
                continue
            written = folded[_fold(required)]
            return (
                f"{NEAR_MISS_PREFIX}`{written}` is spelled differently from `{required}`: Kubernetes keys are "
                "case-sensitive, so the API server would reject this document too"
            )
    return None


def _classify(path: Path | None, text: str) -> str | None:
    """Why a YAML file found in a directory is not a manifest to audit, or None when it is one.

    Only files picked up from a directory are classified; a file named on the command line is always audited, so a
    broken manifest cannot slip through as "not a manifest"."""
    if path is not None and any(_in_chart_templates(path, parent) for parent in path.parents):
        return "a Helm template: render the chart with --chart"
    try:
        docs = [d for d in sanitize.safe_load_all_bounded(text) if d is not None]
    except sanitize.YamlTooDeep as exc:
        return str(exc)
    except (yaml.YAMLError, RecursionError):
        return None  # audited, so the parse error is reported
    if not any(isinstance(d, dict) and "apiVersion" in d and "kind" in d for d in docs):
        # A key that differs from `apiVersion` or `kind` only in shape is a typo in a manifest, not a file that is
        # no manifest: the two answers shared one sentence and one exit code, so `apiversion: v1` on a privileged
        # pod read exactly like a CI workflow and the gate passed (G325). The document is NOT normalised and
        # audited: the API server would reject it as it stands, so auditing it as valid would be the same false
        # answer pointing the other way. The honest answer is that it was not read, which makes this incomplete.
        return _near_miss_reason(docs) or "not a Kubernetes manifest (no document with apiVersion and kind)"
    return None


def unreadable_reason(text: str) -> str | None:
    """Why YAML cannot read this text at all, or None. Separate from ``_classify``: a file that is not a manifest was
    read and understood, while this one was not read, which is not the same answer and must not share its exit code.
    Collecting it per file keeps one bad file in a directory from deciding the outcome for every other file, and keeps
    the reason attached to a path the user can open instead of a line of the combined input."""
    try:
        sanitize.safe_load_all_bounded(text)
    except sanitize.YamlTooDeep as exc:
        # Not read, and the reason is the depth rather than a syntax error, so say that and name no line.
        return str(exc)
    except yaml.YAMLError as exc:
        first = str(exc).strip().splitlines()[0] if str(exc).strip() else exc.__class__.__name__
        mark = getattr(exc, "problem_mark", None)
        where = f" (line {mark.line + 1})" if mark is not None else ""
        return f"{first}{where}"
    except RecursionError:
        return "YAML nesting is too deep to read safely"
    return None


def _in_chart_templates(path: Path, parent: Path) -> bool:
    return parent.name == "templates" and (parent.parent / "Chart.yaml").is_file() and path.is_relative_to(parent)


def render(
    charts: list[str],
    values: list[str],
    namespace: str,
    platform: str = "kubernetes",
    version: str | None = None,
) -> list[Source]:
    """``helm template`` each chart (the helm binary must be on PATH)."""
    from kube_noob.generate.helm_render import kube_version_arg, render_chart

    kube_version = kube_version_arg(platform, version)
    out = []
    for chart in charts:
        text = render_chart(chart, values, namespace=namespace, release="kube-noob-gate", kube_version=kube_version)
        out.append(Source(f"{chart.rstrip('/')}/(rendered)", text, chart=chart.rstrip("/")))
    return out


def _uri(path: Path) -> str:
    """Relative to the working directory (the repository root in CI) when the file is under it."""
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def collect(paths: list[str], read: Any) -> list[Source]:
    """Manifest files from paths (directories: their *.yaml and *.yml, sorted), ``-`` for stdin."""
    out: list[Source] = []
    total = 0
    bad: dict[str, str | None] = {}
    for raw in paths:
        items: list[tuple[str, str, str | None]]
        if raw == "-":
            items = [("stdin", read("-"), None)]
        else:
            p = Path(raw)
            if p.is_dir():
                files = sorted(
                    f
                    for f in p.rglob("*")
                    if f.suffix in {".yaml", ".yml"}
                    and not any(part.startswith(".") for part in f.relative_to(p).parts)  # .git, .github, ..data
                    and f.is_file()
                )
                items = []
                for f in files:
                    text = f.read_text(encoding="utf-8", errors="replace")
                    items.append((_uri(f), text, _classify(f, text)))
                for uri, text, why in items:
                    if why is None:
                        bad[uri] = unreadable_reason(text)
            elif p.is_file():
                items = [(_uri(p), p.read_text(encoding="utf-8", errors="replace"), None)]
            else:
                raise GateError(f"{raw}: no such file or directory")
        for uri, text, why in items:
            total += len(text)
            out.append(Source(uri, text, skip=why, unreadable=bad.get(uri)))
            if len(out) > MAX_FILES or total > MAX_TOTAL:
                raise GateError(f"more than {MAX_FILES} files or {MAX_TOTAL:,} characters: gate one release at a time")
    return out


def _combine(sources: list[Source]) -> str:
    parts: list[str] = []
    line = 1
    for s in sources:
        text = s.text if s.text.endswith("\n") else s.text + "\n"
        s.start, s.lines = line, text.count("\n")
        parts.append(text)
        line += s.lines + 1  # the separator line
    return "---\n".join(parts)


def _where(sources: list[Source], line: int | None, chart_path: str | None) -> tuple[str, int | None]:
    if line is None:
        return (sources[0].uri if len(sources) == 1 else "manifests"), None
    for s in sources:
        if s.start <= line < s.start + s.lines:
            local = line - s.start + 1
            chart = s.chart or chart_path
            if chart:
                tpl = _template_for(s.text, local, chart)
                if tpl:
                    return tpl, None
            return s.uri, local
    return sources[-1].uri, None


def _template_for(text: str, line: int, chart_path: str) -> str | None:
    """The chart template a rendered line came from (``helm template`` writes ``# Source: <chart>/<path>``)."""
    source = None
    for n, raw in enumerate(text.splitlines()[:line], 1):
        m = _SOURCE.match(raw.strip())
        if m:
            source = m.group(2)
        if n == line:
            break
    if source is None or ".." in source.split("/"):
        return None
    return f"{chart_path.rstrip('/')}/{source}"


def _admission(platform: str, version: str | None) -> tuple[dict[str, str], dict[str, str]]:
    """Rules generated as admission policies (with their limitation, if any) and the reasons for the others."""
    from kube_noob.generate import policies

    checks, skipped = policies._checks(platform, version)
    return {r: c.limitation for r, c in checks.items()}, {**policies.NOT_GENERATED, **skipped}


def _admission_text(rule: str, severity: str, enforced: dict[str, str], not_generated: dict[str, str]) -> str:
    if rule not in enforced:
        return f"not an admission policy: {not_generated.get(rule, 'needs other objects')}"
    if severity == "info":
        return "not refused: the admission policies refuse low severity and above"
    return "refused in enforce mode" + (f" (partly: {enforced[rule]})" if enforced[rule] else "")


def _known(kinds: set[str], platform: str, version: str | None, data_dir: Path | None) -> list[dict[str, Any]]:
    """Open reported issues in the target release whose text names a kind these manifests deploy."""
    from kube_noob.catalog import OPENSHIFT_FAMILY
    from kube_noob.known_issues import get_index, vkey
    from kube_noob.versions import read_version

    cv = read_version(version)
    if platform not in OPENSHIFT_FAMILY or cv is None:
        return []
    index = get_index(data_dir)
    # The same reading of the version as the coverage statement beside it (G277): " 4.20.0" once matched nothing
    # here while the statement said "determined".
    advise = index.coverage(version)["status"] == "determined"
    out: list[dict[str, Any]] = []
    for issue in index.issues:
        if issue.kind != "known" or issue.minor != cv.minor:
            continue
        if issue.fixed_in and vkey(cv.numeric) >= vkey(issue.fixed_in):
            continue
        named = sorted(k for k in kinds if _DISTINCT_KIND.match(k) and re.search(rf"\b{k}s?\b", issue.text))
        if named:
            out.append({**issue.as_dict(cv.numeric, 1.0, advise, cv.shown), "kinds": named})
    return out[:20]


def _known_coverage(platform: str, version: str | None, data_dir: Path | None) -> dict[str, Any] | None:
    """Whether ``_known`` could answer for ``version``; ``None`` for a platform the index does not describe. With an
    OpenShift platform and no version nothing was looked up, and that is said, not left as an empty list (G277)."""
    from kube_noob.catalog import OPENSHIFT_FAMILY
    from kube_noob.known_issues import coverage

    if platform not in OPENSHIFT_FAMILY:
        return None
    if not version:
        return {
            "status": "not-determined",
            "why": "No --version was given, so reported issues in the target OpenShift release were not looked up "
            "(the audit assumed a default release). Give --version to look them up.",
        }
    return coverage(version, data_dir)


def run(
    sources: list[Source],
    *,
    containerfiles: list[tuple[str, str]] | None = None,
    platform: str = "kubernetes",
    version: str | None = None,
    exceptions: str | None = None,
    fail_on: str = "high",
    chart_path: str | None = None,
    data_dir: Path | None = None,
    scanner_reports: list[tuple[str, str]] | None = None,
    vex_paths: list[Path] | None = None,
    kev_path: Path | None = None,
    trust_report_vex: bool = False,
    sarif_reports: list[tuple[str, str]] | None = None,
    source_roots: list[str] | None = None,
    code_builds: list[Any] | None = None,
    unknown_builds: list[str] | None = None,
    repo: Path | None = None,
    cni: str | None = None,
    default_namespace: str | None = None,
) -> dict[str, Any]:
    """``code_builds``: Containerfiles read with their context (``kube_noob.code.builds``); without them each
    Containerfile's directory is its context. ``unknown_builds``: Containerfiles given but not readable as builds
    (shipping is then unknown, which fails like shipped code). ``repo``: the checkout, to tell a SARIF path that is
    no file of the repository (scanned elsewhere) from one no image ships."""
    from kube_noob.audit import exceptions as exc
    from kube_noob.audit.engine import analyze, refuse_if_not_manifests
    from kube_noob.errors import ConfigError

    containerfiles = containerfiles or []
    scanner_reports = scanner_reports or []
    sarif_reports = sarif_reports or []
    # One list, one marker: `forbidsVerdict` on the entry rather than a second list of files that could disagree
    # with this one (docs/review-classes.md class 9). Everything below derives from it.
    skipped = [
        {"file": s.uri, "why": s.skip, **({"forbidsVerdict": True} if forbids_verdict(s.skip) else {})}
        for s in sources
        if s.skip
    ]
    blocking = [s for s in skipped if s.get("forbidsVerdict")]
    unreadable = [{"file": s.uri, "why": s.unreadable} for s in sources if s.unreadable and not s.skip]
    sources = [s for s in sources if not s.skip and not s.unreadable]
    if not sources and not containerfiles and not scanner_reports and not sarif_reports:
        if unreadable:
            raise GateError("nothing could be read: " + "; ".join(f"{u['file']}: {u['why']}" for u in unreadable))
        if blocking:
            # Beside the `unreadable` refusal, for the same reason: there is nothing to report a verdict on, and
            # an empty clean report would be the defect this fixes with the files removed.
            raise GateError(
                "nothing was read as a manifest: " + "; ".join(f"{s['file']}: {s['why']}" for s in blocking)
            )
        raise GateError(
            "nothing to check: pass manifests with -f, Containerfiles with --containerfile, --scanner-report or "
            "--sarif-report"
        )
    findings: list[dict[str, Any]] = []
    failures: list[str] = []
    if blocking:
        shown_blocking = "; ".join(f"{s['file']}: {s['why']}" for s in blocking[:5])
        failures.append(
            f"{len(blocking)} file(s) were not read as manifests, so this gate reached no verdict: {shown_blocking}"
            + (f"; and {len(blocking) - 5} more under `skipped`" if len(blocking) > 5 else "")
        )
    combined = _combine(sources) if sources else ""
    if sources:
        # A path named with -f used to be audited even when it was a Helm values file, so `gate -f values.yaml`
        # reported KN-V001 (missing apiVersion) and could fail the job. `audit` already refuses that input.
        # A directory walk still classifies the same file as skipped, and a real manifest in the same command
        # still proceeds: refuse_if_not_manifests returns as soon as one document has apiVersion and kind.
        try:
            refuse_if_not_manifests(combined)
        except ConfigError as err:
            raise GateError(str(err)) from err
    review = exc.review(exceptions) if exceptions else None
    enforced, not_generated = _admission(platform, version)
    excepted = 0
    kinds: set[str] = set()
    # The gate already runs `analyze`, so it HAS the coverage record; it just never published it, and a
    # compliance document built from the gate could therefore only ever say not-satisfied (G201).
    coverage: dict[str, Any] = {}
    assumptions: list[str] = []
    if sources:
        report = analyze(combined, platform, version, cni=cni)
        # What the audit declined or could not read inside the files it was given (a pod spec in a kind with no
        # reader, a group it does not know, an assumed version). The gate dropped these, so a gate that passed on a
        # privileged container nobody read said nothing about it; `kube-noob verify` reads its verdict from here.
        assumptions = list(report.assumptions)
        kept_rules: list[str] = []
        excepted_rules: list[str] = []
        kinds = set(_KIND.findall(combined))
        for f in report.findings:
            if review is not None and exc.match(review, f.rule_id, f.resource) is not None:
                excepted += 1
                excepted_rules.append(f.rule_id)
                continue
            kept_rules.append(f.rule_id)
            uri, line = _where(sources, f.line, chart_path)
            findings.append(
                {
                    "ruleId": f.rule_id,
                    "title": f.title,
                    "severity": f.severity.name.lower(),
                    "message": f.message,
                    "resource": f.resource,
                    "path": f.path,
                    "uri": uri,
                    "line": line,
                    "remediation": f.remediation,
                    "admission": _admission_text(f.rule_id, f.severity.name.lower(), enforced, not_generated),
                    "helpUri": next((c.url for c in f.citation_objects()), INFO_URI),
                }
            )
        from kube_noob.audit.controls import summary as control_summary

        if review is not None:
            exc.accept_not_audited(review, report.not_audited)
        # ONE call of the one predicate, and ONE failure line from it. The merge of G272 and G281 left this
        # computed twice and appended twice, so a gate that reached no verdict listed the same fact as two
        # failures (class 9).
        undetermined = report.undetermined()
        if undetermined:
            # Not a verdict: the gate is incomplete, never passed, whatever --fail-on says (G272, seventh
            # review). Objects the rules did not read (an apiVersion that is not a string, not shaped like an
            # API, or in a group the kind is not known under; a kind that is not a kind name; a pod spec in a
            # kind with no reader) and no exception accepted are not findings and not absences: a typo in
            # apiVersion turned a failing gate into a passing one whose every output said no workload was
            # present (G281, review 4, R1). The reason carries the counts and the names; this line adds the
            # per-object `why`, which the reason does not have.
            open_rows = open_not_audited(report.not_audited)
            named = "; ".join(f"{r['object']} ({r['why']})" for r in open_rows[:MAX_NOT_AUDITED_NAMED])
            if len(open_rows) > MAX_NOT_AUDITED_NAMED:
                named += f"; and {len(open_rows) - MAX_NOT_AUDITED_NAMED} more"
            failures.append(f"the audit is undetermined: {undetermined}" + (f" -- {named}" if named else ""))
        coverage = {
            "kubernetesVersion": report.kubernetes_version,
            "resources": report.resources,
            # What the audit could not decide, as `audit` reports it: without these the gate passed a bundle whose
            # API server the audit had declined, and said nothing anywhere (G272). The rows carry the file and
            # line of the object they name, as the findings do (G281) -- the raw rows beside them would have
            # overwritten exactly that.
            "assumptions": list(report.assumptions),
            "notAudited": [_located_row(r, sources, chart_path) for r in report.not_audited],
            # ONE key for the reason: `verdict_word`, the Markdown headline, the HTML masthead and the SARIF
            # invocation all read `incomplete`, which is this key being present.
            **({"undetermined": undetermined} if undetermined else {}),
            "controlSummary": control_summary(
                kept_rules,
                excepted_rules or None,
                report.evaluated_rules or None,
                report.fired_rules or None,
                not_evaluated=report.not_evaluated or None,
                absent_subjects=report.absent_subjects or None,
                partly_evaluated=report.partly_evaluated or None,
            ),
            **({"declined": report.declined} if report.declined else {}),
            **({"notEvaluated": report.not_evaluated} if report.not_evaluated else {}),
        }
        if review is not None and not review.summary()["gate"]:
            failures.append("the exception list has expired or refused entries (kube-noob exceptions check)")
    for uri, text in containerfiles:
        from kube_noob.build import containerfile as cf
        from kube_noob.build import image

        try:
            rep = image.audit(text, manifests=combined or None)
        except cf.ContainerfileError as err:
            failures.append(f"{uri}: {err}")
            continue
        for f in rep["findings"]:
            findings.append(
                {
                    "ruleId": f["ruleId"],
                    "title": f["title"],
                    "severity": f["severity"],
                    "message": f["message"],
                    "resource": "Containerfile",
                    "path": "",
                    "uri": uri,
                    "line": f.get("line"),
                    "remediation": f["fix"],
                    "admission": "a build check, not an admission policy",
                    "helpUri": (f.get("sources") or [{"url": INFO_URI}])[0]["url"],
                }
            )
    vulns = _vulnerabilities(
        scanner_reports,
        combined,
        vex_paths or [],
        kev_path,
        data_dir,
        fail_on,
        trust_report_vex,
        default_namespace=default_namespace,
    )
    findings.extend(vulns["findings"])
    if vulns["failing"]:
        failures.append(
            f"{vulns['failing']} vulnerability finding(s) at {fail_on} or above that are fixable or known exploited"
        )
    code = _code_findings(
        sarif_reports, containerfiles, source_roots or [], fail_on, code_builds, unknown_builds or [], repo
    )
    findings.extend(code["findings"])
    if code["failing"]:
        unknown_n = (code["summary"] or {}).get("shippingUnknown") or 0
        where = (
            ("in shipped code or code whose shipping is not known" if unknown_n else "in shipped code")
            if containerfiles
            else "(no --containerfile: shipping not known)"
        )
        failures.append(f"{code['failing']} code finding(s) at {fail_on} or above {where}")
    failures.extend(code["errors"])
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda r: (-order[r["severity"]], r["uri"], r.get("line") or 0, r["ruleId"]))
    counts = {s: sum(1 for r in findings if r["severity"] == s) for s in reversed(SEVERITIES)}
    if fail_on != "never":
        floor = Severity.parse(fail_on)
        over = [
            r
            for r in findings
            if Severity.parse(r["severity"]) >= floor and not r.get("vulnerability") and not r.get("code")
        ]
        for r in over:
            r["failsGate"] = True
        if over:
            failures.append(f"{len(over)} finding(s) at {fail_on} or above")
    known = _known(kinds, platform, version, data_dir)
    ki_coverage = _known_coverage(platform, version, data_dir)
    return {
        "tool": {"name": "kube-noob", "version": __version__},
        "platform": platform,
        "version": version,
        "failOn": fail_on,
        "passed": not failures,
        # True while the audit under the gate reached no verdict (`undetermined` says why): then `passed` is
        # false and the headline says "incomplete", not "failed" (G272).
        # ... or a file the walk declined to read: that is evidence the gate does not have, exactly as an
        # undetermined audit is, and it must not render as "failed" either (G325).
        "incomplete": "undetermined" in coverage or bool(blocking),
        "failures": failures,
        "files": [s.uri for s in sources],
        "skipped": skipped,
        "unreadable": unreadable,
        "containerfiles": [u for u, _ in containerfiles],
        "counts": counts,
        "excepted": excepted,
        "findings": findings,
        # Empty when the gate audited no manifests (Containerfiles or scanner reports only), in which case
        # there is no coverage to claim and the OSCAL emitter degrades on its own.
        **coverage,
        "admission": {
            "refusedInEnforceMode": sum(1 for r in findings if r["admission"].startswith("refused in enforce mode")),
            "command": f"kube-noob policy generate --platform {platform}"
            + (f" --version {version}" if version else "")
            + " --mode enforce",
        },
        "knownIssues": known,
        "assumptions": assumptions,
        **({"knownIssuesCoverage": ki_coverage} if ki_coverage else {}),
        "vulnerabilities": vulns["summary"],
        "code": code["summary"],
        "notRun": [
            # The two biggest omissions were missing: a pipeline whose manifest glob stopped matching passed its
            # reports, exited 0, and rendered an empty "Not run" section, which asserts that nothing was skipped.
            *(
                []
                if sources
                else [
                    "manifest and chart audit: no manifests were read, so no policy, RBAC, SCC or NetworkPolicy "
                    "rule ran. Pass them with -f, or render a chart with --chart"
                ]
            ),
            *(
                []
                if containerfiles
                else ["Containerfile audit: pass a build file with --containerfile (Dockerfile or Containerfile)"]
            ),
            *(
                []
                if scanner_reports
                else [
                    "vulnerability checks: pass the images' scanner output with --scanner-report (Trivy or Grype "
                    "JSON, a CycloneDX or SPDX SBOM, or an RHACS image scan)"
                ]
            ),
            *(
                []
                if sarif_reports
                else [
                    "code checks: pass your SAST tools' SARIF with --sarif-report (Semgrep, Bandit, SpotBugs, ESLint, "
                    "CodeQL)"
                ]
            ),
            # An empty knownIssues for a release the index does not hold is a lookup not made, not "none" (G277).
            *(
                [f"reported issues: {ki_coverage['why']}"]
                if ki_coverage and ki_coverage["status"] == "not-determined"
                else []
            ),
            # A file the walk found and did not audit -- a Helm template that was never rendered, a YAML file that
            # is not a manifest -- is a gap in the answer, not a footnote: pod.yaml beside an unrendered chart passed
            # as `complete` while `skipped` carried the template (G291, review). Listed here so every consumer of
            # the report (the CI wrappers read `notRun`) sees it, after the four standing entries.
            *(f"{s['file']}: {s['why']} (skipped, not audited)" for s in skipped),
        ],
    }


def _code_findings(
    reports: list[tuple[str, str]],
    containerfiles: list[tuple[str, str]],
    roots: list[str],
    fail_on: str,
    code_builds: list[Any] | None = None,
    unknown_builds: list[str] | None = None,
    repo: Path | None = None,
) -> dict[str, Any]:
    """SAST findings from SARIF as gate findings. With Containerfiles, a finding in a file no image ships (tests,
    tools, files the .dockerignore leaves out) is reported but does not fail the gate. Shipping that cannot be
    known fails closed: a path outside the source root, a path that is no file of the repository, or a Containerfile
    that could not be read as a build."""
    if not reports:
        return {"findings": [], "failing": 0, "errors": [], "summary": None}
    from kube_noob.code import sarif, ship

    errors: list[str] = []
    parsed = []
    for uri, text in reports:
        try:
            parsed.append(sarif.parse(text, uri, roots=roots, max_depth=sanitize.MAX_JSON_DEPTH_FILE))
        except sarif.SarifError as err:
            raise GateError(str(err)) from err
    unknown = list(unknown_builds or [])
    if code_builds is not None:
        builds = list(code_builds)
    else:
        builds = []
        for uri, text in containerfiles:
            try:
                builds.append(ship.parse_build(ship.Build(uri, text, "", str(Path(uri).parent))))
            except ship.ShipError as err:
                errors.append(str(err))
                unknown.append(str(err))
    given = bool(containerfiles) or bool(builds) or bool(unknown)
    merged = sarif.merge([f for r in parsed for f in r.findings])
    floor = Severity.parse(fail_on) if fail_on != "never" else None
    findings: list[dict[str, Any]] = []
    failing = 0
    not_shipped = 0
    unknown_count = 0
    for f in merged:
        why = ""
        if given:
            if not f.location.resolved:
                why = "the path is outside the source root (pass --source-root with the directory the scanner ran in)"
            elif repo is not None and not (repo / f.location.path).is_file():
                why = "no such file in the repository (scan from the repository root, or pass --source-root)"
            elif unknown:
                why = f"a Containerfile could not be read as a build ({unknown[0]})"
        shipped = ship.where(builds, f.location.path) if builds and not why else []
        unshipped = given and not shipped and not why
        not_shipped += int(unshipped)
        unknown_count += int(bool(why))
        cwe = ", ".join(f"CWE-{c}" for c in f.cwe)
        tools = ", ".join(sorted({s["tool"] for s in f.sources}))
        findings.append(
            {
                "ruleId": f.sources[0]["ruleId"],
                "title": f.title,
                "severity": f.severity,
                "message": (f"{cwe}: " if cwe else "")
                + f"{f.message} ({tools})"
                + (" - not shipped in any image" if unshipped else f" - shipping unknown: {why}" if why else ""),
                "resource": ", ".join(sorted({s.image for s in shipped})) or "code",
                "path": "",
                "uri": f.location.path,
                "line": f.location.line,
                "remediation": f"fix {f.location.path}:{f.location.line or '?'} as the {tools} rule describes",
                "admission": "a code finding, not an admission policy",
                "code": True,
                "helpUri": f.help_uri
                or (f"https://cwe.mitre.org/data/definitions/{f.cwe[0]}.html" if f.cwe else INFO_URI),
            }
        )
        if floor is not None and not unshipped and Severity.parse(f.severity) >= floor:
            findings[-1]["failsGate"] = True
            failing += 1
    summary = {
        "tools": sorted({t for r in parsed for t in r.tools}),
        "findings": len(merged),
        "excluded": sum(len(r.excluded) for r in parsed),
        "quality": sum(len(r.quality) for r in parsed),
        "notShipped": not_shipped if given else None,
        "shippingUnknown": unknown_count if given else None,
        "notes": list(dict.fromkeys(n for r in parsed for n in r.notes))[:20],
    }
    return {"findings": findings, "failing": failing, "errors": errors, "summary": summary}


_VULN_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "negligible": "info"}


def _vulnerabilities(
    reports: list[tuple[str, str]],
    manifests: str,
    vex_paths: list[Path],
    kev_path: Path | None,
    data_dir: Path | None,
    fail_on: str,
    trust_report_vex: bool = False,
    default_namespace: str | None = None,
) -> dict[str, Any]:
    """Scanner findings as gate findings: VEX applied, KEV marked, ranked against the manifests. A finding fails the
    gate at ``fail_on`` only when it is fixable or known exploited (an unfixable finding is reported, not blocked)."""
    if not reports:
        return {"findings": [], "failing": 0, "summary": None}
    from kube_noob.attack_paths import Inventory as PathInventory
    from kube_noob.attack_paths import workload_reach
    from kube_noob.vuln import assess
    from kube_noob.vuln import kev as kevmod
    from kube_noob.vuln import reports as rep
    from kube_noob.vuln import vex as vexmod
    from kube_noob.yamlio import load_documents

    try:
        parsed = [rep.parse(text, uri) for uri, text in reports]
        index = vexmod.load(data_dir, vex_paths)
        kev = kevmod.load(kev_path) if kev_path else None
        reach = (
            workload_reach(
                PathInventory.from_documents(
                    (d.data for d in load_documents(manifests)), default_namespace=default_namespace
                )
            )
            if manifests
            else None
        )
        out = assess.assess(parsed, vex=index, kev=kev, reach=reach, top=200, trust_report_vex=trust_report_vex)
    except (rep.ReportError, vexmod.VexError, kevmod.KevError, assess.AssessError) as exc:
        raise GateError(str(exc)) from exc
    uri_of: dict[str, str] = {}
    for (uri, _), one in zip(reports, parsed, strict=True):
        uri_of.setdefault(one.image.label, uri)
    ranked = {(x["image"], x["finding"]["id"]): x for x in out["ranking"]["ranked"]}
    findings: list[dict[str, Any]] = []
    failing = 0
    floor = Severity.parse(fail_on) if fail_on != "never" else None
    from kube_noob.vuln.reports import gating_severity

    for f in out["findings"]:
        sev = _VULN_SEVERITY.get(gating_severity(f["severity"], f["cvss"], f["knownExploited"]), "medium")
        r = ranked.get((f["image"], f["id"]))
        where = f"; ranked {r['rank']} (score {r['score']}): {r['attackPath']['summary']}" if r else ""
        fix = f["fixVersion"] or "no fix yet"
        findings.append(
            {
                "ruleId": f["cve"],
                "title": f"{f['cve']} in {f['package']['name']}",
                "severity": sev,
                "message": f"{f['cve']} in {f['package']['name']} {f['package']['version']} (fix: {fix}) in image "
                f"{f['image']}" + (" - known exploited (CISA KEV)" if f["knownExploited"] else "") + where,
                "resource": ", ".join(r["workloads"][:3]) if r and r["workloads"] else f["image"],
                "path": "",
                "uri": uri_of.get(f["image"], reports[0][0]),
                "line": None,
                "remediation": f"update {f['package']['name']} to {f['fixVersion']} and rebuild the image"
                if f["fixVersion"]
                else "no fixed version yet: reduce exposure and privileges of the workloads that run it",
                "admission": "a vulnerability in the image, not an admission policy",
                "vulnerability": True,
                "helpUri": f"https://access.redhat.com/security/cve/{f['cve']}"
                if f["package"]["ecosystem"] == "rpm"
                else f"https://www.cve.org/CVERecord?id={f['cve']}",
            }
        )
        if floor is not None and Severity.parse(sev) >= floor and (f["fixVersion"] or f["knownExploited"]):
            # Marked on the finding, not re-derived later. A vulnerability at or above the floor with no fix and
            # no KEV entry does NOT fail the gate, so an annotation that called it an error would show a red
            # cross on a green step -- the same "publish what you computed" lesson as G201.
            findings[-1]["failsGate"] = True
            failing += 1
    summary = {
        **out["counts"],
        "images": [i["image"]["name"] for i in out["images"]],
        "vex": out["vex"]["sources"],
        "kev": out["kev"]["catalog"],
        # A name two different objects carry: each copy placed with its own images and rights (G273).
        "ambiguous": list(out["ranking"].get("ambiguous") or []),
    }
    return {"findings": findings, "failing": failing, "summary": summary}


# -- output formats ----------------------------------------------------------------------------------------------

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}
_CODEQUALITY = {"critical": "blocker", "high": "critical", "medium": "major", "low": "minor", "info": "info"}


def _fingerprint(r: dict[str, Any]) -> str:
    key = "\x1f".join(str(r.get(k) or "") for k in ("ruleId", "uri", "resource", "path", "message"))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


#: How many refused objects the gate's failure line names before it gives a count.
MAX_NOT_AUDITED_NAMED = 5
#: The SARIF rule id under which a refused object is reported: a `note`, not a finding, with no severity score.
NOT_AUDITED_RULE = "KN-NOT-AUDITED"
NOT_EVALUATED_RULE = "KN-NOT-EVALUATED"
NOT_READ_RULE = "KN-NOT-READ"


def _located_row(row: dict[str, Any], sources: list[Source], chart_path: str | None) -> dict[str, Any]:
    """A `notAudited` row with the file and line of the object it names, as the findings carry theirs."""
    line = row.get("line")
    uri, local = _where(sources, line if isinstance(line, int) else None, chart_path)
    out = {k: v for k, v in row.items() if k != "line"}
    out["uri"] = uri
    if local is not None:
        out["line"] = local
    return out


def _artifact(uri: str) -> dict[str, Any]:
    """A SARIF artifactLocation. An absolute path becomes a file URI; anything else is relative to the checkout,
    which is what a code-scanning upload needs to anchor the result to a file in the repository."""
    return {"uri": Path(uri).as_uri()} if uri.startswith("/") else {"uri": uri, "uriBaseId": "%SRCROOT%"}


def _not_audited_results(report: dict[str, Any], rules: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """One `note`-level result per object the rules refused to read, so a SARIF consumer sees the object that was
    not audited beside the findings, and the run's invocation carries the list too (review 4, R1)."""
    rows = [r for r in report.get("notAudited") or [] if isinstance(r, dict)]
    if not rows:
        return []
    rules[NOT_AUDITED_RULE] = {
        "id": NOT_AUDITED_RULE,
        "name": "ObjectNotAudited",
        "shortDescription": {"text": "Object not audited"},
        "fullDescription": {"text": "The rules refused to read this object, so the verdict is undetermined."},
        "help": {
            "text": (
                "The rules did not read this object (its apiVersion or kind is not one they know, or its pods are "
                "in a kind with no reader), so the verdict is undetermined. To accept it as reviewed, add a "
                "notAudited entry to the ExceptionList (kind, apiGroup, namespace, name, with owner, reason and "
                "expiry); the row stays listed with acceptedBy."
            )
        },
        "helpUri": INFO_URI,
        "defaultConfiguration": {"level": "note"},
        "properties": {"tags": ["kubernetes", "coverage"]},
    }
    out = []
    for r in rows:
        accepted = f" (accepted by {r['acceptedBy']})" if r.get("acceptedBy") else ""
        uri = str(r.get("uri") or "manifests")
        artifact = _artifact(uri)
        loc: dict[str, Any] = {"artifactLocation": artifact}
        if isinstance(r.get("line"), int) and r["line"] >= 1:
            loc["region"] = {"startLine": int(r["line"])}
        key = "\x1f".join([NOT_AUDITED_RULE, uri, str(r.get("object") or ""), str(r.get("why") or "")])
        out.append(
            {
                "ruleId": NOT_AUDITED_RULE,
                "ruleIndex": list(rules).index(NOT_AUDITED_RULE),
                "level": "note",
                # SARIF's word for "a reviewer should look, it is not a defect"; with the object's location and a
                # fingerprint, so code scanning lists it in the file view and tracks it (review 5, item 10).
                "kind": "review",
                "message": {"text": f"{r.get('object')}: not audited, {r.get('why')}{accepted}"},
                "locations": [{"physicalLocation": loc}],
                "partialFingerprints": {"kubeNoob/v1": hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]},
            }
        )
    return out


def sarif(report: dict[str, Any], invocation: dict[str, Any] | None = None) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for r in report["findings"]:
        if r["ruleId"] not in rules:
            rules[r["ruleId"]] = {
                "id": r["ruleId"],
                "name": re.sub(r"[^A-Za-z0-9]+", "", r["title"].title())[:100] or r["ruleId"],
                "shortDescription": {"text": r["title"]},
                "fullDescription": {"text": r["remediation"][:1000]},
                "help": {"text": r["remediation"][:2000]},
                "helpUri": r["helpUri"],
                "defaultConfiguration": {"level": _LEVEL[r["severity"]]},
                "properties": _rule_properties(r),
            }
        uri = str(r["uri"])
        artifact = _artifact(uri)
        loc: dict[str, Any] = {"artifactLocation": artifact}
        if r.get("line"):
            loc["region"] = {"startLine": int(r["line"])}
        results.append(
            {
                "ruleId": r["ruleId"],
                "ruleIndex": list(rules).index(r["ruleId"]),
                "level": _LEVEL[r["severity"]],
                "message": {"text": f"{r['resource']}: {r['message']}" if r["resource"] else r["message"]},
                "locations": [{"physicalLocation": loc}],
                "partialFingerprints": {"kubeNoob/v1": _fingerprint(r)},
            }
        )
    results += _not_audited_results(report, rules)
    # `coverage`: what this run did not evaluate and did not read, as results rather than only as notifications.
    # Absent (the gate's own report) means this builder adds none, so that path is unchanged.
    cov = report.get("coverage") or {}
    results += _coverage_results(cov, rules, str(cov.get("uri") or "manifests"))
    if report.get("notAudited"):
        invocation = {
            **(invocation or {"executionSuccessful": True}),
            "properties": {**((invocation or {}).get("properties") or {}), "notAudited": list(report["notAudited"])},
        }
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "kube-noob",
                        "version": report["tool"]["version"],
                        "informationUri": INFO_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "columnKind": "unicodeCodePoints",
                **({"invocations": [invocation]} if invocation else {}),
            }
        ],
    }


def _rule_properties(r: dict[str, Any]) -> dict[str, Any]:
    """Severity and tags, and the NIST SP 800-53 controls the catalogue maps this rule to.

    The controls go in twice on purpose: `tags` is what a code-scanning UI shows and filters on, and the
    `nist-800-53` list is what a program reads without parsing a tag's prefix. A rule the catalogue maps to no
    control (and every finding that is not an audit rule: a CVE, a SAST result) has NO `nist-800-53` property --
    an empty list would read as "checked, and it maps to nothing".
    """
    from kube_noob.audit.controls import RULE_CONTROLS

    controls = list(RULE_CONTROLS.get(r["ruleId"], ()))
    props: dict[str, Any] = {
        "security-severity": _SCORE[r["severity"]],
        "tags": ["security", "kubernetes", *(f"NIST-800-53/{c}" for c in controls)],
    }
    if controls:
        props["nist-800-53"] = controls
    return props


def _caveat_notes(rep: dict[str, Any]) -> list[dict[str, Any]]:
    """The audit's assumptions and the rules that reached no verdict, as SARIF warnings (G269, G272)."""
    from kube_noob.audit.caveats import caveat_lines

    notes = [{"level": "warning", "message": {"text": str(a)}} for a in rep.get("assumptions") or []]
    notes += [{"level": "warning", "message": {"text": ln}} for ln in caveat_lines(rep.get("controlSummary") or {})]
    return notes


def _coverage_results(rep: dict[str, Any], rules: dict[str, dict[str, Any]], uri: str) -> list[dict[str, Any]]:
    """The rules that reached no verdict, and the files that were not read, as SARIF **results**.

    They were already on the run's invocation as ``toolExecutionNotifications``, which is where the SARIF spec puts
    what the tool wants to say about its own run. The trouble is that a notification is not a result, and the
    consumers this file is written for read ``runs[].results``: GitHub code scanning shows alerts, DefectDojo and
    the scanner operators import findings. A file carrying twelve findings and "forty-one rules were not evaluated"
    only in a notification arrives at the other end as twelve findings and nothing else -- the honest part of the
    answer destroyed at the first hop, which is the defect this product exists to refuse, one layer out from the
    verdict.

    So each one is also a result, exactly as ``notAudited`` already is (``_not_audited_results``): ``kind:
    "review"``, SARIF's word for "a reviewer should look, this is not a defect in the input". The notifications
    stay, because a reader of the invocation should still see them and because removing them would be a second
    change; a consumer that reads both sees the same statement twice, which is the right failure of the two.

    Grouped by reason, not one per rule, for the reason ``grouped_reasons`` exists: a Deployment-only input leaves
    about forty rules unevaluated for six reasons, and forty near-identical alerts would be noise a reviewer mutes,
    which is how an honest signal gets switched off.
    """
    from kube_noob.audit.controls import grouped_reasons

    groups = grouped_reasons(rep.get("controlSummary") or {})
    unreadable = [u for u in rep.get("unreadable") or [] if isinstance(u, dict)]
    if not groups and not unreadable:
        return []
    out: list[dict[str, Any]] = []
    if groups:
        rules[NOT_EVALUATED_RULE] = {
            "id": NOT_EVALUATED_RULE,
            "name": "RulesNotEvaluated",
            "shortDescription": {"text": "Rules not evaluated"},
            "fullDescription": {
                "text": "These rules reached no verdict on this input: neither clean nor findings. Their controls "
                "are not evidenced by this run."
            },
            "help": {
                "text": "A rule that was not evaluated has not passed. Give the audit the objects the reason names "
                "(a whole namespace rather than one file, the Service beside the Deployment) and run it again, or "
                "accept the gap deliberately with an ExceptionList entry that records who accepted it and why. "
                "Counting these as clean is what makes a compliance score higher than the evidence supports."
            },
            "helpUri": INFO_URI,
            "defaultConfiguration": {"level": "note"},
            "properties": {"tags": ["kubernetes", "coverage"]},
        }
        # ONE result, not one per reason. A Deployment-only input leaves about forty rules unevaluated under
        # thirty-odd reasons, and thirty-three near-identical alerts are what gets a rule muted in code scanning --
        # which would switch off the honest signal more thoroughly than the notification did. The claim is about
        # this run as a whole ("it did not evaluate these"), not about thirty-three places in the file, so it is
        # one alert carrying every reason, and its fingerprint covers the whole set: the alert changes when
        # coverage changes and closes when nothing is left unevaluated.
        total = sum(len(ids) for _, ids in groups)
        detail = "; ".join(f"{why}: {', '.join(ids)}" for why, ids in groups)
        key = "\x1f".join([NOT_EVALUATED_RULE, detail])
        out.append(
            {
                "ruleId": NOT_EVALUATED_RULE,
                "ruleIndex": list(rules).index(NOT_EVALUATED_RULE),
                "level": "note",
                "kind": "review",
                "message": {
                    "text": f"{total} rules reached no verdict on this input, so their controls are not "
                    f"evidenced by this run -- {detail}"
                },
                "locations": [{"physicalLocation": {"artifactLocation": _artifact(uri)}}],
                "partialFingerprints": {"kubeNoob/v1": hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]},
            }
        )
    if unreadable:
        rules[NOT_READ_RULE] = {
            "id": NOT_READ_RULE,
            "name": "FileNotRead",
            "shortDescription": {"text": "File not read"},
            "fullDescription": {"text": "This file was not read, so nothing in it was audited."},
            "help": {
                "text": "The file could not be parsed or decoded. Nothing in it was audited, so a clean run over "
                "the rest of the input says nothing about it: fix the file or remove it from the input, and do not "
                "read the absence of findings for it as a pass."
            },
            "helpUri": INFO_URI,
            "defaultConfiguration": {"level": "warning"},
            "properties": {"tags": ["kubernetes", "coverage"]},
        }
        for u in unreadable:
            path = str(u.get("path") or uri)
            key = "\x1f".join([NOT_READ_RULE, path, str(u.get("why") or "")])
            out.append(
                {
                    "ruleId": NOT_READ_RULE,
                    "ruleIndex": list(rules).index(NOT_READ_RULE),
                    "level": "warning",
                    "kind": "review",
                    "message": {"text": f"not read: {path} ({u.get('why')})"},
                    "locations": [{"physicalLocation": {"artifactLocation": _artifact(path)}}],
                    "partialFingerprints": {"kubeNoob/v1": hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]},
                }
            )
    return out


def sarif_of_audit(rep: dict[str, Any]) -> dict[str, Any]:
    """SARIF for `kube-noob audit`: the same document the gate writes, plus what this run could not see.

    A SARIF run is a list of results, and the only way a list says "nothing found" is by being empty. An audit that
    declined its cross-object rules because it was given part of a namespace, or that skipped a file it could not
    parse, produces a shorter list and nothing else -- an absence a consumer reads as a pass. So the report's
    `assumptions` and `unreadable` entries become `toolExecutionNotifications` on the run's invocation: warnings for
    what was not evaluated, errors for what was not read. `executionSuccessful` stays true, because the tool ran;
    what it could not decide is a notification, not a crash.
    """
    findings = [
        {
            "ruleId": f["ruleId"],
            "title": f["title"],
            "severity": f["severity"],
            "message": f["message"],
            "resource": f.get("resource") or "",
            "path": f.get("path") or "",
            "uri": f.get("file") or "stdin",
            "line": f.get("line"),
            "remediation": f.get("remediation") or "",
            "helpUri": next((c["url"] for c in f.get("citations") or [] if c.get("url")), INFO_URI),
        }
        for f in rep["findings"]
    ]
    notes = _caveat_notes(rep)
    # The coverage record, one notification per reason: a consumer of the SARIF alone can see that the Service
    # rules never ran rather than passed (G281). Grouped, so a Deployment-only file is a few lines, not seventy.
    notes += [
        {"level": "warning", "message": {"text": f"not evaluated, {why}: {', '.join(ids)}"}}
        for why, ids in grouped_reasons(rep.get("controlSummary") or {})
    ]
    notes += [
        {"level": "error", "message": {"text": f"not read: {u['path']} ({u['why']})"}}
        for u in rep.get("unreadable") or []
    ]
    return sarif(
        {
            "findings": findings,
            "tool": {"version": __version__},
            # `_locate` put the file and line on each row as on each finding; `uri` is what the result reads.
            "notAudited": [{**r, "uri": r.get("file") or "stdin"} for r in rep.get("notAudited") or []],
            # The same two absences the notifications above carry, so they also reach `results`, which is the
            # array every SARIF consumer reads. Anchored to the audited file when there is exactly one, because a
            # code-scanning alert with no location is shown against the repository root or not at all.
            "coverage": {
                "controlSummary": rep.get("controlSummary") or {},
                "unreadable": rep.get("unreadable") or [],
                "uri": _one_input_uri(rep),
            },
        },
        invocation={"executionSuccessful": True, "toolExecutionNotifications": notes},
    )


def _one_input_uri(rep: dict[str, Any]) -> str:
    """The file to anchor a coverage result to: the single file this audit read, or ``manifests``.

    A rule that was not evaluated is about the input as a whole and not about a place in it, so there is no honest
    line number. With one file there is still an honest FILE, which is what a reviewer needs to find it; with
    several, naming one of them would say the gap belongs to that one.
    """
    uris = {str(f.get("file") or "") for f in rep.get("findings") or []} | {
        str(r.get("file") or "") for r in rep.get("notAudited") or []
    }
    uris.discard("")
    return next(iter(uris)) if len(uris) == 1 else "manifests"


def codequality(report: dict[str, Any]) -> list[dict[str, Any]]:
    """GitLab's code quality report (a list of CodeClimate issues)."""
    return [
        {
            "description": f"{r['ruleId']} {r['resource']}: {r['message']}"[:2000],
            "check_name": r["ruleId"],
            "fingerprint": _fingerprint(r),
            "severity": _CODEQUALITY[r["severity"]],
            "location": {"path": r["uri"], "lines": {"begin": int(r.get("line") or 1)}},
        }
        for r in report["findings"]
    ]


_MD_ESCAPE = {"&": "&amp;", "<": "&lt;", ">": "&gt;", "|": "\\|"} | {c: "\\" + c for c in "\\`*_[]!#~"}


def _cell(text: Any, limit: int = 300) -> str:
    """One line of Markdown text from untrusted input (an image name or package from a scanner report, a manifest
    path): control characters and line breaks become spaces so nothing starts a new heading or table row, HTML
    is entity-escaped and link, image, emphasis and code syntax is backslash-escaped, so a report cannot render as
    a different verdict, an image or a link in the job summary (red team, VUL1)."""
    flat = sanitize.visible_squeezed(str(text))[:limit]
    return "".join(_MD_ESCAPE.get(c, c) for c in flat)


def _annotation_data(text: Any) -> str:
    """Text for a workflow command: cleaned first (``sanitize.visible_lines``, so what the runner shows is what
    the escaping meant -- escaping first made ``%`` into ``%25`` and the cleaner then took ``ESC %2`` for an escape
    sequence), then escaped per the toolkit's rules (``%``, CR, LF), with every ``##...[`` service message broken by
    the same marker the output boundary uses (G279)."""
    out = sanitize.visible_lines(str(text), mark=True)
    out = out.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return sanitize.defuse_service_messages(out)


def _annotation(level: str, finding: dict[str, Any]) -> str:
    """One GitHub workflow command. `file`, `line`, `title` and the message are escaped per the toolkit's rules."""

    def esc(text: str, *, prop: bool = False) -> str:
        # A raw newline ends the command and an unescaped % corrupts the next escape. In a property, a comma or a
        # colon ends the property list, so those go too.
        out = _annotation_data(text)
        # In a property a comma ends the property and a colon ends the property LIST, so both go -- every colon,
        # not just a pair of them: a value ending in ":" produced `title=x:::[KN-X] ...`, and the runner then cut
        # the title and moved the colon into the message.
        return out.replace(",", "%2C").replace(":", "%3A") if prop else out

    rule = str(finding.get("ruleId") or "kube-noob")
    heading = f"{rule} {finding.get('title') or ''}".strip()
    props = [f"title={esc(heading, prop=True)}"]
    uri = str(finding.get("uri") or "")
    # Only anchor the annotation to a path a checkout could actually have. Reading from stdin gives every
    # finding the uri "-", and `file=-` asks GitHub to anchor 11 annotations to a file named "-": the runner
    # either drops them from the diff or puts them somewhere meaningless, which is worse than a repository-level
    # annotation, because the finding looks reported and is not.
    if uri and uri not in {"-", "<stdin>", "(stdin)"} and not uri.startswith("<"):
        props.insert(0, f"file={esc(uri, prop=True)}")
        line = finding.get("line")
        if isinstance(line, int) and line > 0:
            props.insert(1, f"line={line}")
    resource = str(finding.get("resource") or "")
    message = " ".join(
        part
        for part in (
            f"[{rule}]",
            resource,
            str(finding.get("message") or ""),
            f"Fix: {finding['remediation']}" if finding.get("remediation") else "",
        )
        if part
    )
    return f"::{level} {','.join(props)}::{esc(message)}"


def github_annotations(report: dict[str, Any]) -> list[str]:
    """Gate findings as GitHub workflow commands, so they appear on the pull request rather than in a log.

    Not named `annotations`: this module starts with `from __future__ import annotations`, so that name is
    already bound and a function with it shadows the feature flag -- mypy refuses it, and rightly.

    A finding is an error when it is one the gate FAILED on (`failsGate`, set where that decision was made) and a
    warning otherwise. The first version read the severity instead, which annotated an unfixable critical CVE as
    an error on a step that passed -- the gate fails on a vulnerability only when it is fixable or known
    exploited, and on a code finding only when an image ships the file. The reasons in `failures` are annotated
    too: a gate can fail with no finding at all (an expired exception, a Containerfile that would not parse), and
    those left the step red with nothing on the pull request.

    GitHub's caps decide the shape: 10 of each type per step and 50 per job (actions/toolkit,
    docs/problem-matchers.md). The eleventh annotation of a kind is dropped with no message, so a developer who
    saw ten would reasonably believe there were ten. The last slot of each kind therefore carries the count that
    was not shown and points at the SARIF and the job summary, which have all of them.
    """
    rows = [f for f in report.get("findings") or () if isinstance(f, dict)]
    reasons = [str(x) for x in report.get("failures") or () if str(x).strip()]
    if not rows and not reasons:
        return []

    def rank(f: dict[str, Any]) -> tuple[int, str, str]:
        sev = str(f.get("severity") or "info")
        order = SEVERITIES.index(sev) if sev in SEVERITIES else 0
        return (-order, str(f.get("ruleId") or ""), str(f.get("resource") or ""))

    buckets: dict[str, list[dict[str, Any]]] = {"error": [], "warning": []}
    for f in sorted(rows, key=rank):
        # `failsGate` is set where the gate DECIDED, so the annotation level matches the exit code. Deriving it
        # from severity here instead put a red cross on a green step: an unfixable critical CVE with no KEV entry
        # is at or above the floor and does not fail the gate, and nor does a code finding in an image that
        # ships nothing.
        buckets["error" if f.get("failsGate") else "warning"].append(f)
    out: list[str] = []
    # A gate can fail with no finding at all -- an expired exception, a Containerfile that would not parse, a
    # SARIF file that could not be read. Those went unannotated, so the step was red and the pull request said
    # nothing. They come first, because they are why the step failed.
    for reason in reasons[:MAX_ANNOTATIONS_PER_TYPE]:
        out.append(f"::error title=kube-noob gate::{_annotation_data(reason)}")
    if len(reasons) > MAX_ANNOTATIONS_PER_TYPE:
        out[-1] = (
            f"::error title=kube-noob gate::{len(reasons) - MAX_ANNOTATIONS_PER_TYPE + 1} more reason(s) this "
            "gate failed are not annotated; the job summary has all of them."
        )
    for level in ("error", "warning"):
        found = buckets[level]
        room = MAX_ANNOTATIONS_PER_TYPE - sum(1 for line in out if line.startswith(f"::{level} "))
        if not found or room <= 0:
            continue
        if len(found) <= room:
            out += [_annotation(level, f) for f in found]
            continue
        shown = found[: room - 1]
        out += [_annotation(level, f) for f in shown]
        hidden = len(found) - len(shown)
        out.append(
            f"::{level} title=kube-noob::{hidden} more {level}-level finding(s) are not annotated: GitHub shows "
            f"{MAX_ANNOTATIONS_PER_TYPE} of each kind per step. All of them are in the SARIF file and the job summary."
        )
    return out


def verdict_word(report: dict[str, Any]) -> str:
    """ "passed", "failed", or "incomplete" while the audit under the gate is undetermined."""
    if report.get("incomplete"):
        return "incomplete"
    return "passed" if report["passed"] else "failed"


def markdown(report: dict[str, Any], top: int = 25) -> str:
    # Three words, one predicate, called and never re-derived: undetermined is neither passed nor failed, and
    # the headline says which.
    verdict = verdict_word(report)
    target = _cell(report["platform"] + (f" {report['version']}" if report["version"] else ""), 60)
    lines = [
        f"## kube-noob gate {verdict}",
        "",
        f"{len(report['files'])} manifest file(s) and {len(report['containerfiles'])} Containerfile(s) checked for "
        f"{target}, failing at {report['failOn']}. kube-noob {report['tool']['version']}, offline.",
        "",
        "| Severity | Findings |",
        "|---|---|",
        *[f"| {sev} | {n} |" for sev, n in report["counts"].items()],
        "",
    ]
    if report.get("notAudited"):
        open_rows = [r for r in report["notAudited"] if not r.get("acceptedBy")]
        lines += [
            f"### Not passed: {len(open_rows)} object(s) not audited"
            if open_rows
            else f"### {len(report['notAudited'])} object(s) not audited, accepted by the exception list",
            "",
            "The rules did not read these objects"
            + (", so the verdict is undetermined, not a pass." if open_rows else "; every one is accepted."),
            "",
            *[
                f"- {_cell(str(r.get('object')), 120)}: {_cell(str(r.get('why')), 200)}"
                + (f" (accepted by {_cell(str(r['acceptedBy']), 64)})" if r.get("acceptedBy") else "")
                for r in report["notAudited"]
            ],
            "",
        ]
    if report["failures"]:
        why = "### Why it is incomplete" if verdict == "incomplete" else "### Why it failed"
        lines += [why, "", *[f"- {_cell(f)}" for f in report["failures"]], ""]
    if report["findings"]:
        lines += ["### Findings", "", "| Severity | Rule | Where | Finding | Admission |", "|---|---|---|---|---|"]
        for r in report["findings"][:top]:
            where = f"{r['uri']}:{r['line']}" if r.get("line") else r["uri"]
            lines.append(
                f"| {r['severity']} | {_cell(r['ruleId'], 80)} | {_cell(where)} "
                f"| {_cell(r['resource'] + ': ' + r['message'])} | {_cell(r['admission'])} |"
            )
        if len(report["findings"]) > top:
            lines.append(f"\n{len(report['findings']) - top} more in the SARIF file.")
        lines.append("")
    adm = report["admission"]
    lines += [
        f"{adm['refusedInEnforceMode']} of {len(report['findings'])} findings would be refused at admission by "
        f"`{adm['command']}`.",
        "",
    ]
    if report["excepted"]:
        lines += [f"{report['excepted']} finding(s) accepted by the exception list.", ""]
    summary = report.get("controlSummary")
    if isinstance(summary, dict) and (line := coverage_line(summary)):
        # The gate's own coverage record, in the summary a reviewer reads: a clean gate over a Deployment-only
        # change must not read as "every Service rule passed" (G281, G221).
        lines += [line, ""]
    c = report.get("code")
    if c:
        shipped = "" if c["notShipped"] is None else f", {c['notShipped']} in files no image ships"
        if c.get("shippingUnknown"):
            shipped += f", {c['shippingUnknown']} whose shipping is not known (gated as shipped)"
        lines += [
            f"Code findings from {_cell(', '.join(c['tools']), 300)}: {c['findings']} security findings{shipped}, "
            f"{c['excluded']} excluded (suppressed or fixed), {c['quality']} lint or quality results not gated.",
            "",
        ]
        lines += [f"Note: {_cell(n, 400)}" for n in c.get("notes") or []]
        if c.get("notes"):
            lines.append("")
    v = report.get("vulnerabilities")
    if v:
        lines += [
            f"Vulnerabilities in {_cell(', '.join(v['images']), 600)}: {v['reported']} reported, "
            f"{v['excludedByVex']} excluded by VEX, {v['findings']} findings, {v['fixable']} fixable, "
            f"{v['knownExploited']} known exploited.",
            "",
        ]
        lines += [f"Note: {_cell(n, 400)}" for n in v.get("ambiguous") or []]
        if v.get("ambiguous"):
            lines.append("")
    if report["knownIssues"]:
        lines += ["### Reported issues in this release (informational)", ""]
        for k in report["knownIssues"]:
            lines.append(f"- [{_cell(k['id'], 40)}]({k['url']}) ({', '.join(k['kinds'])}): {_cell(k['summary'])}")
        lines.append("")
    if report.get("skipped"):
        lines += ["### Skipped", "", *[f"- {_cell(x['file'])}: {_cell(x['why'])}" for x in report["skipped"][:50]], ""]
    if report.get("assumptions"):
        lines += ["### Assumed, or not evaluated", "", *[f"- {_cell(a, 600)}" for a in report["assumptions"]], ""]
    lines += ["### Not run", "", *[f"- {_cell(n)}" for n in report["notRun"]], ""]
    # Two sections, not one: "assumed 1.35" is how the audit read the input, and everything else is something it
    # did not read. "Assumptions" is an ALLOWLIST -- the assumed-version lines -- because a split by "is this a
    # declined rule" put a RayCluster's unaudited pods and a kind with no bundled schema under "Assumptions", as if
    # they had been read (G272).
    from kube_noob.audit.caveats import caveat_lines
    from kube_noob.audit.engine import ASSUMED_VERSION_PREFIXES

    caveats = [str(a) for a in report.get("assumptions") or []]
    assumed = [a for a in caveats if a.startswith(ASSUMED_VERSION_PREFIXES)]
    gaps = [a for a in caveats if not a.startswith(ASSUMED_VERSION_PREFIXES)]
    gaps += caveat_lines(report.get("controlSummary") or {})
    for heading, items in (("### Assumptions", assumed), ("### Not evaluated in full", gaps)):
        if not items:
            continue
        shown = items[:MD_CAVEATS]
        more = [f"- and {len(items) - MD_CAVEATS} more in the JSON report"] if len(items) > MD_CAVEATS else []
        lines += [heading, "", *[f"- {_cell(a, 1200)}" for a in shown], *more, ""]
    return sanitize.visible_lines("\n".join(lines))  # nothing that does not print reaches the file (G279)


#: How many audit caveats the Markdown summary lists before pointing at the JSON report.
MD_CAVEATS = 20


def sarif_of_gate(report: dict[str, Any]) -> dict[str, Any]:
    """The gate's SARIF: its results, and what the audit under it could not decide, as the audit's SARIF carries.

    The gate runs the same audit and dropped its caveats on the way out: a static pod the audit declined left the
    gate's SARIF, Markdown and HTML silent, and `passed: true` (G272).
    """
    notes = _caveat_notes(report)
    notes += [
        {"level": "error", "message": {"text": f"not read: {u['file']} ({u['why']})"}}
        for u in report.get("unreadable") or []
    ]
    blocked = [s for s in report.get("skipped") or [] if s.get("forbidsVerdict")]
    notes += [
        {"level": "error", "message": {"text": f"not read as a manifest: {s['file']} ({s['why']})"}} for s in blocked
    ]
    undetermined = report.get("undetermined")
    if blocked:
        # Through the same channel as an undetermined audit, so a consumer that reads only `results` or only the
        # invocation's properties sees the gap either way (G272, G325).
        named = "; ".join(f"{s['file']}: {s['why']}" for s in blocked[:5])
        gap = f"{len(blocked)} file(s) were not read as manifests: {named}"
        undetermined = f"{undetermined}; {gap}" if undetermined else gap
    if not notes and not undetermined:
        return sarif(report)
    invocation: dict[str, Any] = {"executionSuccessful": True, "toolExecutionNotifications": notes}
    if undetermined:
        # The incomplete state as a property of the invocation AND one note-level result, so a consumer that
        # reads only results sees it (G272, seventh review).
        invocation["properties"] = {"incomplete": True, "undetermined": undetermined}
    out = sarif(report, invocation=invocation)
    if undetermined:
        run = out["runs"][0]
        run["tool"]["driver"].setdefault("rules", []).append(
            {
                "id": "kube-noob/undetermined",
                "name": "AuditUndetermined",
                "shortDescription": {"text": "The audit reached no verdict on part of the input"},
                "fullDescription": {
                    "text": "Something was not read: a rule declined on an object, or an object no rule audited. "
                    "The gate is incomplete, not passed."
                },
                "helpUri": INFO_URI,
                "defaultConfiguration": {"level": "note"},
            }
        )
        run["results"].append(
            {
                "ruleId": "kube-noob/undetermined",
                "ruleIndex": len(run["tool"]["driver"]["rules"]) - 1,
                "level": "note",
                "message": {"text": f"gate incomplete: {undetermined}"},
            }
        )
    return out


def write(report: dict[str, Any], *, sarif_path: str | None, summary: str | None, quality: str | None) -> None:
    if sarif_path:
        # json_document: a CI step that prints the file must not run a workflow command from it (G279); the gate's
        # SARIF carries the audit's caveats and the undetermined state (G272), and goes through the same boundary.
        Path(sarif_path).write_text(json_document(sarif_of_gate(report), indent=1) + "\n", encoding="utf-8")
    if summary:
        Path(summary).write_text(markdown(report), encoding="utf-8", errors="replace")
    if quality:
        Path(quality).write_text(json_document(codequality(report), indent=1) + "\n", encoding="utf-8")
