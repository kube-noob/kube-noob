"""kube-noob command line.

Exit codes: 0 ok | 1 findings at/above --fail-on | 2 usage/config error | 3 clarification needed | 4 runtime error.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

from kube_noob import __version__, completion, sanitize
from kube_noob.config import Settings, load_settings
from kube_noob.errors import ClarificationNeeded, ConfigError, KubeNoobError, ManifestError

PLATFORMS = ["kubernetes", "openshift", "rosa-classic", "rosa-hcp"]


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    p = Path(path)
    if p.is_dir():
        return "\n---\n".join(text for _, text in _dir_yaml(p)[0])
    return p.read_text(encoding="utf-8")


def _dir_yaml(d: Path) -> tuple[list[tuple[str, str]], list[dict[str, str]]]:
    """Every ``*.yaml``/``*.yml`` under ``d``, and the ones that could not be read.

    Read per file, because the files used to be concatenated before anything looked at them: one file that was not
    UTF-8 or not YAML then decided the outcome for every other file in the directory, and said so against a line of
    the combined text rather than against a path anyone could open.
    """
    from kube_noob.gate import unreadable_reason

    ok: list[tuple[str, str]] = []
    bad: list[dict[str, str]] = []
    for f in sorted(d.rglob("*")):
        if f.suffix not in {".yaml", ".yml"} or not f.is_file():
            continue
        rel = str(f.relative_to(d))
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError) as exc:
            bad.append({"path": rel, "why": f"not readable as UTF-8 text: {exc}"})
            continue
        why = unreadable_reason(text)
        if why:
            bad.append({"path": rel, "why": why})
        else:
            ok.append((rel, text))
    return ok, bad


def _manifest_input(a: argparse.Namespace) -> tuple[str, list[dict[str, str]]]:
    """The manifest text for the audit family, with the files in a directory that could not be read."""
    text, bad, _sources = _manifest_sources(a)
    return text, bad


def _manifest_sources(a: argparse.Namespace) -> tuple[str, list[dict[str, str]], list[tuple[str, int]]]:
    """The same text, plus where each file starts in it: (path, its first line of the combined text).

    The audit reads one string, so a directory is concatenated -- and every line number after the first file
    was then a line of a document nobody can open. `_locate` uses these ranges to put a finding back in the
    file it came from, which is what `_dir_yaml`'s own docstring says an unreadable file deserved (G251).
    """
    p = Path(a.file) if a.file != "-" else None
    if p is None or not p.is_dir():
        return _read(a.file), [], ([] if p is None else [(str(a.file), 1)])
    ok, bad = _dir_yaml(p)
    if not ok:
        named = "; ".join(f"{b['path']}: {b['why']}" for b in bad)
        raise ConfigError(
            f"{a.file}: no readable manifest here" + (f" ({named})" if named else " (no .yaml or .yml files)")
        )
    sep = "\n---\n"
    parts: list[str] = []
    sources: list[tuple[str, int]] = []
    for path, text in ok:
        # Counted off the text that will precede this file, separator included: whether a file ends with a
        # newline changes the arithmetic, and a line number that is right for most inputs is the defect this
        # replaces. `sep.join(parts)` alone is not that text -- joining one part inserts no separator.
        before = (sep.join(parts) + sep) if parts else ""
        sources.append((path, before.count("\n") + 1))
        parts.append(text)
    return sep.join(parts), bad, sources


def _locate(report: dict[str, Any], sources: Sequence[tuple[str, int]]) -> None:
    """Put every finding back in the file it came from, in place.

    `line` becomes the line of THAT file and `file` names it. Without this, `kube-noob audit -f dir/` reported
    a finding in the second file of a directory at a line of the concatenation -- often past the end of the
    file it was in, and against no path at all. A finding with no line keeps none, and with several files and
    no line nothing is claimed about which file it was in (G251).
    """
    if not sources:
        return
    for key in ("findings", "excepted"):
        for f in report.get(key) or []:
            if not isinstance(f, dict):
                continue
            line = f.get("line")
            if not isinstance(line, int) or line < 1:
                if len(sources) == 1:
                    f["file"] = sources[0][0]
                continue
            path, start = next((p, s) for p, s in reversed(sources) if s <= line)
            f["file"] = path
            f["line"] = line - start + 1


def _partial_input(a: argparse.Namespace) -> bool:
    """True when the caller named one file or stdin rather than a directory.

    A directory is taken to be the whole namespace, so rules that fire on an absent object are evaluated.
    One file is not: `audit -f deployment.yaml` cannot tell "this namespace has no NetworkPolicy" from
    "you did not pass it", and reporting the first would be a finding on every correct repository.
    """
    f = getattr(a, "file", None)
    return not (isinstance(f, str) and f != "-" and Path(f).is_dir())


def _refuse_unreadable(bad: list[dict[str, str]], flag: str = "--skip-unreadable") -> None:
    for b in bad:
        print(f"error: {b['path']}: {b['why']}", file=sys.stderr)
    print(
        f"error: {len(bad)} file(s) could not be read, so this is not a clean result; pass {flag} to audit the rest "
        "and list these in the report",
        file=sys.stderr,
    )


_PATHLIKE = re.compile(r"[/\\]|\.[A-Za-z0-9]{1,5}$")


def _read_text_or_file(value: str, command: str = "diagnose") -> str:
    """For `diagnose`: '-' reads stdin, an existing path is read, anything else is the pasted text itself.

    A single token that looks like a missing file (``events.txt``, ``logs/pod.log``) is an error rather than text, so a
    typo in a file name is reported instead of being diagnosed as the words "events.txt".
    """
    if value == "-":
        if sys.stdin.isatty():
            print("Paste events, describe output or logs, then press Ctrl-D:", file=sys.stderr)
        return sys.stdin.read()
    try:
        is_path = "\n" not in value and Path(value).exists()
    except (OSError, ValueError):  # too long or not a valid path: it is text
        is_path = False
    if is_path:
        return _read(value)
    if not any(c.isspace() for c in value) and _PATHLIKE.search(value):
        raise ConfigError(
            f"no such file: {value}. To read text instead, pass it in quotes: kube-noob {command} '<text>'"
        )
    return value


def _emit(obj: Any, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(obj, indent=2, default=str))
    else:
        print(yaml.safe_dump(obj, sort_keys=False, width=120, allow_unicode=True), end="")


_REMARK_LABELS = {"cause": "cause", "expected": "why closed", "fix": "fix note"}


def _print_insight(res: dict[str, Any]) -> None:
    _tprint("input: " + "; ".join(f"{k['kind']} ({k['evidence']})" for k in res["kinds"]))
    if res.get("ran"):
        _tprint("ran: " + ", ".join(res["ran"]))
    for f in res["findings"]:
        extra = f.get("verdict") or f.get("severity") or f.get("confidence") or f.get("cite") or ""
        source = "related doc" if f.get("related") else f["source"]
        _tprint(f"  {source:15} {f.get('id')!s:28} {str(f.get('title') or '')[:90]}  {extra}")
        if f.get("cause"):
            _tprint(f"  {'':15} cause: {f['cause'][:150]}")
        if f.get("fix"):
            _tprint(f"  {'':15} fix: {f['fix'][:150]}")
        if f.get("escalate"):
            _tprint(f"  {'':15} escalate: {f['escalate'][:400]}")
        for c in f.get("diagnosticCommands", [])[:2]:
            _tprint(f"  {'':15} in the toolbox (needs approval): {c['command']}")
    if res.get("answeredBy"):
        _tprint("kube-noob answers this directly:")
        for st in res["answeredBy"]:
            _tprint(f"  {st['command']}")
            _tprint(f"      {st['why']}")
    if res.get("readOnlyNextSteps"):
        _tprint("read-only next steps:")
        for st in res["readOnlyNextSteps"]:
            _tprint(f"  {st.get('command') or st.get('step') or st}")
    for sk in res.get("skipped", []):
        _tprint(f"not analysed ({sk['kind']}): {sk['why']}")


def _print_ticket_changes(res: dict[str, Any], opened: dict[str, Any]) -> None:
    counts = ", ".join(f"{n} {k}" for k, n in res["counts"].items()) or "none"
    _tprint(f"changes since {res['since']} (last sync {res['lastSync'] or 'never'}): {counts}")
    for c in res["changes"]:
        before = (c.get("from") or {}).get("verdict")
        after = (c.get("to") or {}).get("verdict")
        fix = ", ".join((c.get("to") or {}).get("fixVersions") or [])
        move = f"{before} -> {after}" if before else after
        _tprint(f"  {c['key']:16} {c['kind']:16} {move}{f' (fix {fix})' if fix else ''}  {c['title'][:70]}")
    if res.get("truncated"):
        _tprint(f"  ... {res['truncated']} more (--limit)")
    if res.get("note"):
        _tprint(res["note"])
    if opened.get("available"):
        per = "; ".join(
            f"{proj} " + ", ".join(f"{n} {v}" for v, n in sorted(vs.items()))
            for proj, vs in opened["byProject"].items()
        )
        _tprint(f"open tickets: {opened['open']} ({per or 'none'})")
        if opened["topComponents"]:
            _tprint("busiest components: " + ", ".join(f"{c} {n}" for c, n in opened["topComponents"][:5]))
    else:
        _tprint(opened["note"])


def _print_ticket_lines(m: dict[str, Any]) -> None:
    if m.get("workaround"):
        _tprint(f"  workaround: {m['workaround']}")
    for r in m.get("remarks") or []:
        if r["kind"] in _REMARK_LABELS:
            _tprint(f"  {_REMARK_LABELS[r['kind']]} ({r.get('date') or r['from']}): {r['text']}")


def _write_html(path: str | None, report: dict[str, Any]) -> None:
    """Write the self-contained HTML report, when one was asked for (U1)."""
    if not path:
        return
    from kube_noob import report_html

    Path(path).write_text(report_html.render(report), encoding="utf-8", errors="replace")


def _ksi_markdown(out: dict[str, Any], audited: bool) -> str:
    """The KSI view as text. Every indicator keeps a row, including the ones kube-noob cannot see at all: a
    column of zeros reads as a pass, and an indicator with no rule behind it has passed nothing (G217)."""

    d = out["dataset"]
    lines = [
        f"FedRAMP 20x Key Security Indicators -- {d['name']} {d['version']} (updated {d['lastUpdated']})",
        "",
        out["note"],
        "",
        out["applicability"],
        "",
    ]
    if out.get("unmappedControls"):
        lines += [
            "Controls kube-noob maps that no indicator cites, so no finding reaches an indicator through them: "
            + ", ".join(out["unmappedControls"]),
            "",
        ]
    for note in out.get("assumptions") or []:
        lines += [f"assumed: {note}", ""]
    if limit := out.get("notCheckedBeyond"):
        # Before the rows, as `audit` does it: a reader has to see the limit before reading an empty finding
        # count as a clean result.
        lines += [f"not checked: {limit['why']}", ""]
    for bad in out.get("unreadable") or []:
        lines += [f"not read: {bad['path']}: {bad['why']}"]
    if out.get("unreadable"):
        lines += ["", "This is not a complete audit, so no row below is a clean result.", ""]
    for miss in out.get("findingsNotMapped") or []:
        lines += [f"{miss['findings']} finding(s) from {miss['ruleId']} reach no indicator: {miss['why']}"]
    if out.get("findingsNotMapped"):
        lines.append("")
    f = out.get("filtered")
    if f:
        lines += [
            f"showing {f['shown']} of {f['of']} indicators"
            + (f"; --evidenced-only hid {f['evidencedOnly']}" if f.get("evidencedOnly") else ""),
            "",
        ]
        if f.get("why"):
            lines += [f["why"], ""]
    lines += [out["sharedControlCaveat"], ""]
    # `excepted` only when an exception list was actually read. `ksi` takes none, so printing a column of zeros
    # asserted that nothing was excepted when nothing was even looked at (G199).
    excepted = any("excepted" in r for r in out["indicators"])
    counted = ""
    if audited:
        counted = "  findings" + ("  excepted" if excepted else "") + "  clean  not evaluated  withheld"
    lines.append(f"{'INDICATOR':<14}{'FAM':<5}{'NAME':<36}{counted}")
    for r in out["indicators"]:
        name = r["name"][:34]
        if not r["evidenced"]:
            lines.append(f"{r['id']:<14}{r['family']:<5}{name:<36}  -- {r['why']}")
            continue
        if audited:
            tail = f"  {r['findings']:>8}"
            if excepted:
                tail += f"  {r['excepted']:>8}"
            tail += f"  {r.get('clean', 0):>5}  {r.get('notEvaluated', 0):>13}  {r.get('withheld', 0):>8}"
        else:
            tail = f"  {r['rulesBehind']} rule(s), controls {', '.join(r['controls'])}"
        lines.append(f"{r['id']:<14}{r['family']:<5}{name:<36}{tail}")
        if r["variesByClass"]:
            lines.append(
                f"{'':<14}{'':<5}varies by service class {', '.join(r['variesByClass'])}"
                + (f"; optional for {', '.join(r['optionalFor'])}" if r["optionalFor"] else "")
            )
        if r.get("notEvaluatedRules"):
            more = f" and {r['moreNotEvaluated']} more" if r.get("moreNotEvaluated") else ""
            lines.append(f"{'':<19}not evaluated: {', '.join(r['notEvaluatedRules'])}{more}")
        # From the row, not from EVIDENCE: one source, so the text and the JSON cannot drift apart.
        if r.get("warning"):
            lines.append(f"{'':<19}WARNING: {r['warning']}")
        ev = r.get("evidence")
        if ev:
            lines.append(f"{'':<19}shows: {ev['shows']}")
            lines.append(f"{'':<19}does NOT show: {ev['doesNotShow']}")
    return "\n".join(lines)


def _print_known_issues(out: dict[str, Any]) -> None:
    for m in out["matches"]:
        _tprint(f"{m['id']}  {m['status']}")
        _tprint(f"  {m['summary']}")
        if m.get("kind") == "ticket":
            _print_ticket_lines(m)
            _tprint(f"  ticket: {m['url']}  ({m['source']})")
            continue
        if m.get("workaround"):
            _tprint(f"  workaround: {m['workaround']}")
        if m.get("ticket"):
            _tprint(f"  ticket now: {m['ticket']['status']}")
        _tprint(f"  issue: {m['url']}")
        _tprint(f"  release notes: {m['source']}")
    if out.get("note"):
        _tprint(out["note"])
    k = out["knowledge"]
    print(f"index: release-note issues as of {k['knownIssuesAsOf']} for OpenShift {', '.join(k['openshiftReleases'])}")
    jt = k.get("jiraTickets")
    if jt:
        names = ", ".join(jt["projects"][:6]) + ("..." if len(jt["projects"]) > 6 else "")
        print(f"index: {jt['tickets']} Red Hat Jira tickets ({names}) retrieved {jt['asOf']}")
    elif out.get("ticketsNote"):
        _tprint(f"index: no Red Hat Jira tickets: {out['ticketsNote']}")


def _print_upgrade_risks(out: dict[str, Any]) -> None:
    from kube_noob.upgrade_risks import CANNOT_EVALUATE

    edge, counts = out["edge"], out["counts"]
    arch = f" ({edge['architecture']})" if edge["architecture"] else ""
    summary = ", ".join(f"{n} {v}" for v, n in counts.items() if n) or "none"
    _tprint(f"Update {edge['from']} -> {edge['to']}{arch}: {len(out['risks'])} declared risks ({summary})")
    for r in out["risks"]:
        _tprint()
        _tprint(f"{r['verdict'].upper()}  {r['name']}")
        if r.get("message"):
            _tprint(f"  {' '.join(str(r['message']).split())}")
        if r.get("appliesWhen"):
            _tprint(f"  applies when: {r['appliesWhen']}")
            _tprint(f"  decided by: {r['decidedBy']}")
        for c in r.get("readOnlyCommands", []):
            _tprint(f"  check (read-only): {c}")
        for path in r.get("mustGather", []):
            _tprint(f"  in a must-gather: {path}")
        if r["verdict"] != "check" and r.get("reason") and r["reason"] != CANNOT_EVALUATE:
            _tprint(f"  why: {r['reason']}")
        if r.get("promql") and r["verdict"] != "check":
            _tprint("  promql:")
            for q in str(r["promql"]).splitlines():
                _tprint(f"    {q}")
        if r.get("architectures"):
            _tprint(f"  architectures: {', '.join(r['architectures'])}")
        if r.get("fixedIn"):
            _tprint(f"  fixed in: {r['fixedIn']}")
        _tprint(f"  link: {r['url']}")
        _tprint(f"  declared in: {r['source']}")
    _tprint()
    if any(r.get("reason") == CANNOT_EVALUATE for r in out["risks"]):
        _tprint(f"cannot evaluate offline: {CANNOT_EVALUATE}")
    if out.get("note"):
        _tprint(out["note"])
    _tprint(out["channelNote"])
    k = out["knowledge"]
    _tprint(
        f"index: update risks as of {k['upgradeRisksAsOf']} (cincinnati-graph-data {str(k['commit'] or '')[:12]}) "
        f"for targets {k['minTarget']} to {k['newestTarget']}"
    )


def _print_report(rep: dict[str, Any]) -> None:
    s = rep["summary"]
    print(
        f"kube-noob audit | platform={rep['platform']} k8s={rep['kubernetesVersion']} | score={s['score']} | "
        + " ".join(f"{k}={v}" for k, v in s["counts"].items() if v)
    )
    for a in rep.get("assumptions", []):
        print(f"  note: {a}")
    if limit := rep.get("notCheckedBeyond"):
        # Print it before the findings, not after: somebody reading a short report in a terminal has to see the
        # limit before they read an empty finding list as a clean one.
        print(f"  not checked: {limit['why']}")
    for f in rep["findings"]:
        # `file:line` when the caller gave files, `L<n>` when the input was stdin and there is nothing to
        # name. A bare line number against a directory audit was a line of the concatenation (G251).
        where = f"{f['file']}:{f['line']}" if f.get("file") and f.get("line") else ""
        if not where:
            where = f.get("file") or (f"L{f['line']}" if f.get("line") else "")
        print(f"[{f['severity'].upper():8}] {f['ruleId']:9} {f['resource']} {where} {f['path']}")
        print(f"           {f['message']}")
        print(f"           fix: {f['remediation']}")
        if f.get("stackroxPolicies"):
            print(f"           RHACS: {', '.join(f['stackroxPolicies'])}")
    touched = (rep.get("controlSummary") or {}).get("controls") or []
    if touched:
        print("NIST SP 800-53 controls with findings: " + ", ".join(f"{c['id']} ({c['findings']})" for c in touched))
    if cov := rep.get("detectionCoverage"):
        from kube_noob.audit.detection import render_text

        print()
        print(render_text(cov), end="")
    for sc in rep.get("redTeam", []):
        if sc["verdict"] == "exposed":
            print(f"[RED-TEAM {sc['severity'].upper()}] {sc['scenarioId']}: {sc['question']}")
            for e in sc["evidence"][:4]:
                print(f"           - {e}")


def _print_exceptions(rep: dict[str, Any]) -> None:
    ex = rep.get("exceptions")
    if not ex:
        return
    c = ex["counts"]
    print(f"exceptions: {c['active']} active, {c['expired']} expired, {c['refused']} refused")
    for e in ex["entries"]:
        if e["status"] != "active":
            print(f"  [{e['status'].upper()}] {e['id']} ({e['rule']}): {e['reason']}")
    for f in rep.get("excepted", []):
        x = f["exception"]
        print(f"  excepted {f['ruleId']} {f['resource']} by {x['id']} (owner {x['owner']}, until {x['expires']})")
    for eid in ex.get("unused", []):
        print(f"  unused {eid}: covers no finding; delete it if the object is gone")
    if not ex["gate"]:
        print("gate: failed (an exception is expired or refused)")


def _exceptions_cmd(a: argparse.Namespace, fmt: str) -> int:
    import datetime as dt

    from kube_noob.audit import exceptions as exc

    try:
        today = dt.date.fromisoformat(a.today) if a.today else None
    except ValueError as err:
        raise ConfigError("--today must be a date: YYYY-MM-DD") from err
    try:
        rev = exc.review(_read(a.file), today)
    except exc.ExceptionsError as err:
        raise ConfigError(f"{a.file}: {err}") from err
    out = rev.summary()
    if a.format == "text":
        c = out["counts"]
        print(f"{a.file}: {c['active']} active, {c['expired']} expired, {c['refused']} refused")
        for e in out["entries"]:
            print(f"  [{e['status'].upper():7}] {e['id']} {e['rule']}: {e['reason']}")
    else:
        _emit(out, fmt)
    return 0 if out["gate"] else 1


def _check_cni(raw: str | None) -> None:
    """--cni is NAME or NAME:VERSION; anything else is a configuration error (exit 2) for gate and verify alike."""
    if raw:
        from kube_noob.debug.cni import parse_cni

        try:
            parse_cni(raw)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc


def _gate_cmd(a: argparse.Namespace, s: Settings, fmt: str) -> int:
    _check_cni(getattr(a, "cni", None))
    from kube_noob import gate
    from kube_noob.audit.exceptions import ExceptionsError
    from kube_noob.code import builds as cb

    repo = Path.cwd()
    containerfiles: list[tuple[str, str]] = []
    code_builds = []
    unknown: list[str] = []
    for spec in a.containerfile:
        try:
            b = cb.load_one(spec, repo)
        except cb.BuildSpecError as err:  # still audited; code shipping through it is unknown
            try:
                path = cb.parse_spec(spec, repo).path
            except cb.BuildSpecError:
                path = spec
            containerfiles.append((path, _read(path)))
            unknown.append(str(err))
            continue
        containerfiles.append((b.containerfile, b.text))
        code_builds.append(b)
    try:
        sources = gate.collect(a.file, _read) + gate.render(
            a.chart, a.values, a.namespace, platform=a.platform or s.default_platform, version=a.pversion
        )
        report = gate.run(
            sources,
            containerfiles=containerfiles,
            code_builds=code_builds,
            unknown_builds=unknown,
            repo=repo,
            platform=a.platform or s.default_platform,
            version=a.pversion,
            exceptions=_read(a.exceptions) if a.exceptions else None,
            fail_on=a.fail_on,
            chart_path=a.chart_path,
            data_dir=s.data_dir,
            scanner_reports=[(p, _read(p)) for p in a.scanner_report],
            vex_paths=[Path(v) for v in a.vex],
            kev_path=Path(a.kev) if a.kev else None,
            trust_report_vex=a.trust_report_vex,
            sarif_reports=[(p, _read(p)) for p in a.sarif_report],
            source_roots=[str(Path.cwd().resolve()), *(r.rstrip("/") for r in a.source_root if r.startswith("/"))],
            cni=a.cni,
        )
    except (gate.GateError, ExceptionsError) as exc:
        raise ConfigError(str(exc)) from exc
    gate.write(report, sarif_path=a.sarif, summary=a.summary, quality=a.codequality)
    _write_html(a.html, report)
    if getattr(a, "github_annotations", False):
        # Before the report, and on stdout: Actions reads workflow commands from the step's output, and a caller
        # parsing --format json filters the `::` lines (the test does exactly that).
        for line in gate.github_annotations(report):
            print(line)
    quiet_pass = getattr(a, "quiet", False) and report["passed"]
    if getattr(a, "oscal", False):
        from kube_noob.oscal import assessment_results, check_import_ap

        # The flag REPLACES the gate report, the same way it does for `audit`. SARIF and the Markdown summary
        # are still written to their files, because those are paths the caller asked for.
        check_import_ap(a.oscal_import_ap)
        if not quiet_pass:
            _emit(assessment_results(report, import_ap=a.oscal_import_ap), "json" if a.format == "text" else fmt)
    elif a.format == "text":
        if not quiet_pass:
            _tprint(gate.markdown(report, top=50))
    elif not quiet_pass:
        _emit(report, fmt)
    if report.get("unreadable") and not a.skip_unreadable:
        _refuse_unreadable([{"path": u["file"], "why": u["why"]} for u in report["unreadable"]])
        return 5
    return 0 if report["passed"] else 1


def tolerant_streams() -> None:
    """stdout and stderr write under any terminal encoding: a character the encoding lacks (the « » around text
    from the repository, under `PYTHONIOENCODING=ascii` or `LC_ALL=POSIX`) is written as an escape such as `\\xab`
    rather than raising, which turned an allow into exit 4 and a harness that refuses on non-zero refused every
    command. The hook does the same (G280)."""
    import contextlib

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(OSError, ValueError, TypeError):  # a stream that cannot be reconfigured
                reconfigure(errors="backslashreplace")


def _verify_cmd(a: argparse.Namespace, s: Settings, fmt: str) -> int:
    from kube_noob import gate, verify
    from kube_noob.audit.exceptions import ExceptionsError

    tolerant_streams()
    if bool(a.file) == (a.change_command is not None):
        raise ConfigError("pass the change as manifests (-f) or as a command line (--command), one of the two")
    platform = a.platform or s.default_platform
    common: dict[str, Any] = {
        "platform": platform,
        "version": a.pversion,
        "fail_on": a.fail_on,
        "exceptions": _read(a.exceptions) if a.exceptions else None,
        "cni": a.cni,
    }
    _check_cni(a.cni)
    try:
        # /dev/null is the empty baseline: every finding of the change is new.
        named = [p for p in a.against if p != os.devnull]
        against = verify.collect(named, _read) if named else ([] if a.against else None)
        if a.change_command is not None:
            plan = verify.plan(a.change_command, cwd=Path.cwd(), platform=platform, version=a.pversion)
            result = verify.evaluate(plan.sources, against=against, command=plan, from_command=True, **common)
        else:
            result = verify.evaluate(verify.collect(a.file, _read), against=against, **common)
    except (gate.GateError, verify.VerifyError, ExceptionsError) as exc:
        raise ConfigError(str(exc)) from exc
    if a.format == "text":
        _tprint(verify.text(result))
    else:
        _emit(result, fmt)
    return verify.exit_code(result, a.allow_undetermined)


def _hook_install(a: argparse.Namespace, fmt: str) -> int:
    from kube_noob import hook

    scope = a.scope or "project"
    path = hook.settings_path(scope, Path.cwd(), Path.home())
    options = hook.Options(
        platform=a.platform, version=a.pversion, fail_on=a.fail_on, executable=hook.current_executable()
    )
    try:
        flags = options.args()
    except hook.InstallError as exc:
        raise ConfigError(str(exc)) from exc
    if not a.write:
        out = {
            "file": str(path),
            "merge": hook.settings_snippet(options),
            "write": f"kube-noob hook install --claude-code --{scope}{flags} --write",
        }
        if a.format == "text":
            _tprint(f"Merge this into {path} (keep any hooks already there), or let kube-noob merge it:")
            _tprint(f"  {out['write']}")
            _tprint(json.dumps(out["merge"], indent=2))
            _tprint("Needs Claude Code v2.1.295 or later for onFailure; the hook itself blocks with exit 2 on error.")
        else:
            _emit(out, fmt)
        return 0
    try:
        changed = hook.write_settings(path, options)
    except hook.InstallError as exc:
        raise ConfigError(str(exc)) from exc
    msg = f"added the kube-noob PreToolUse hook to {path}" if changed else f"{path} already has the hook; unchanged"
    _tprint(msg) if a.format == "text" else _emit({"file": str(path), "changed": changed}, fmt)
    return 0


def _build_cmd(a: argparse.Namespace, kit: Any, fmt: str) -> int:
    from kube_noob import toolkit as tk
    from kube_noob.build import containerfile as cf
    from kube_noob.build import image, oci

    if a.build_cmd == "diagnose":
        text = _read(a.file)
        out = kit.build_diagnose(
            tk.BuildDiagnoseIn(log=text[-tk.MAX_BUILD_LOG :], platform=a.platform, version=a.pversion)
        )
        if a.format == "text":
            step = out["failingStep"]
            cause = out["cause"]
            _tprint(f"system: {out['system']}, {out['steps']} steps")
            _tprint(f"failing step: {step['name']} ({step['why']})" if step else f"failing step: {out.get('note')}")
            if step and step.get("command"):
                _tprint(f"  command: {step['command']}")
            if cause:
                _tprint(f"cause: {cause['class']} ({cause['confidence']}): {cause['meaning']}")
            else:
                _tprint(f"cause: not recognised. {out.get('causeNote', '')}")
            for e in out["evidence"]:
                _tprint(f"  line {e['line']}: {e['text']}")
            if out["errorTemplate"]:
                _tprint(f"error template {out['errorTemplate']['id']}: {out['errorTemplate']['text'][:200]}")
            for m in out.get("knownIssues", []):
                _tprint(f"reported issue {m.get('id')}: {m.get('title')}")
            for m in out.get("memory", []):
                _tprint(f"team memory {m.get('citation') or m.get('id')}: {m.get('symptom')}")
            for f in out["fix"]:
                _tprint(f"fix: {f}")
            for r in out["readOnlyNextSteps"]:
                _tprint(f"read-only: {r}")
        else:
            _emit(out, fmt)
        return 0
    if a.build_cmd == "analytics":
        from kube_noob.build import analytics

        if not 1 <= a.top <= 200:
            raise ConfigError("--top must be 1-200")
        try:
            out = analytics.analyse(analytics.load_history(Path(a.history)), top=a.top)
        except analytics.HistoryError as exc:
            raise ConfigError(str(exc)) from exc
        if a.format == "text":
            _tprint(
                f"{out['runs']} runs of {out['commits']} commits, {out['from'][:10]} to {out['to'][:10]}: "
                + ", ".join(f"{n} {k}" for k, n in sorted(out["conclusions"].items()))
            )
            _tprint(f"flaky tests ({len(out['flakyTests'])}):")
            for f in out["flakyTests"]:
                how = "rerun within a run" if f["rerunInRun"] and not f["commits"] else f"{len(f['commits'])} commit(s)"
                _tprint(f"  {f['test']}  ({how}, {f['failures']} failures)")
            for f in out["failingTests"]:
                _tprint(f"failing, not flaky: {f['test']} ({f['failures']} failures)")
            if out["flakyRuns"]:
                _tprint(f"commits with a failed and a successful run: {len(out['flakyRuns'])}")
            _tprint("slowest steps (mean, p90, trend):")
            for r in out["slowestSteps"]:
                trend = f"{r['trendPercent']:+.1f}%" if r["trendPercent"] is not None else "n/a"
                _tprint(f"  {r['job']} / {r['step']}: {r['meanSeconds']} s, p90 {r['p90Seconds']} s, {trend}")
            for week, counts in out["failureClasses"].items():
                _tprint(f"failures {week}: " + ", ".join(f"{n} {c}" for c, n in counts.items()))
        else:
            _emit(out, fmt)
        return 0
    if a.build_cmd == "history":
        from kube_noob.build import github_history

        try:
            done = github_history.fetch(
                kit.settings, a.github, Path(a.output), workflow=a.workflow, branch=a.branch, max_runs=a.max_runs
            )
        except github_history.HistoryFetchError as exc:
            raise ConfigError(str(exc)) from exc
        _emit(done, fmt) if a.format != "text" else _tprint(
            f"wrote {done['attempts']} run attempts of {done['runs']} runs to {done['folder']} ({done['requests']} "
            "requests)"
        )
        return 0
    if not a.file and not a.image_layout:
        raise ConfigError("pass the Containerfile with -f, an image with --image-layout, or both")
    try:
        rep = image.audit(
            _read(a.file) if a.file else None,
            context=Path(a.context) if a.context else None,
            manifests=_read(a.manifests) if a.manifests else None,
            layout=Path(a.image_layout) if a.image_layout else None,
            platform=a.image_platform,
        )
    except (cf.ContainerfileError, oci.LayoutError) as exc:
        raise ConfigError(str(exc)) from exc
    if a.format == "text":
        c = rep["counts"]
        _tprint(", ".join(f"{n} {sev}" for sev, n in c.items() if n) or "no findings")
        for f in rep["findings"]:
            where = f"line {f['line']}" if f.get("line") else (f"layer {f['layer']}" if f.get("layer") else "image")
            _tprint(f"  [{f['severity'].upper():8}] {f['ruleId']} {where}: {f['message']}")
            _tprint(f"      fix: {f['fix']}")
        for n in rep["notChecked"]:
            _tprint(f"not checked: {n}")
        for n in (rep.get("image") or {}).get("notRead", []):
            _tprint(f"not read: {n}")
    else:
        _emit(rep, fmt)
    return 1 if cf.failed(rep, a.fail_on) else 0


def _rhacs_cmd(a: argparse.Namespace, s: Settings, fmt: str) -> int:
    from kube_noob import rhacs

    try:
        if a.live:
            if a.file:
                raise ConfigError("pass -f with an export or --live, not both")
            from kube_noob import rhacs_central

            policies, source = rhacs_central.read_central(s)
        else:
            if not a.file:
                raise ConfigError(
                    "pass the policy export with -f (the portal's Export policy to JSON, or POST "
                    "/v1/policies/export), or --live"
                )
            if a.file != "-" and Path(a.file).is_file() and Path(a.file).stat().st_size > rhacs.MAX_BYTES:
                raise ConfigError(f"{a.file}: larger than {rhacs.MAX_BYTES} bytes")
            policies, source = rhacs.load(_read(a.file)), {"file": a.file}
    except rhacs.RhacsError as exc:
        raise ConfigError(f"rhacs: {exc}") from exc
    out = {"source": source, **rhacs.compare(policies)}
    if a.format == "text":
        c = out["counts"]
        _tprint(
            f"{out['total']} RHACS policies: {c['overlap']} overlap, {c['related']} related, {c['gap']} gap, "
            f"{c['outside']} outside kube-noob's scope, {c['unexplained']} unexplained"
        )
        for row in out["policies"]:
            if a.outcome and row["outcome"] not in a.outcome:
                continue
            rules = f" -> {', '.join(row['rules'])}" if row["rules"] else ""
            off = " (disabled in RHACS)" if row["disabled"] else ""
            _tprint(f"  [{row['outcome']:11}] {row['name']}{rules}{off}")
            _tprint(f"      {row['reason']}")
            for n in row.get("notes", []):
                _tprint(f"      note: {n}")
        if out["disagreements"]:
            _tprint("disagree: " + "; ".join(out["disagreements"]))
        if out["disabledButCheckedByKubeNoob"]:
            _tprint("disabled in RHACS, checked by kube-noob: " + "; ".join(out["disabledButCheckedByKubeNoob"]))
        _tprint(
            f"kube-noob rules no imported policy covers ({len(out['kubeNoobOnly'])}): " + ", ".join(out["kubeNoobOnly"])
        )
    else:
        _emit(out, fmt)
    return 1 if out["unexplained"] else 0


def _vuln_cmd(a: argparse.Namespace, s: Settings, fmt: str) -> int:
    from kube_noob.attack_paths import Inventory as PathInventory
    from kube_noob.attack_paths import workload_reach
    from kube_noob.vuln import assess, threat
    from kube_noob.vuln import kev as kevmod
    from kube_noob.vuln import reports as rep
    from kube_noob.vuln import vex as vexmod
    from kube_noob.yamlio import load_documents

    def parse_reports(paths: list[str]) -> list[rep.ScanReport]:
        out = []
        for path in paths:
            if path != "-" and Path(path).is_file() and Path(path).stat().st_size > rep.MAX_BYTES:
                raise ConfigError(f"{path}: larger than {rep.MAX_BYTES} bytes")
            out.append(rep.parse(_read(path), path, sanitize.MAX_JSON_DEPTH_FILE))
        return out

    try:
        if a.vuln_cmd == "threat":
            text = "\n---\n".join(_read(f) for f in a.file)
            vulnerable = None
            if a.report:
                index = vexmod.load(s.data_dir)
                reach = workload_reach(PathInventory.from_documents(d.data for d in load_documents(text)))
                vulnerable = assess.summary_for_workloads(
                    assess.assess(parse_reports(a.report), vex=index, reach=reach)
                )
            out = threat.model(
                text, platform=a.platform or s.default_platform, version=a.pversion, vulnerable_images=vulnerable
            )
            if a.format == "text":
                _tprint(threat.render_markdown(out))
            else:
                _emit(out, fmt)
            return 0
        if not 1 <= a.top <= 200:
            raise ConfigError("--top must be 1-200")
        reports = parse_reports(a.report)
        if a.rhacs_image:
            from kube_noob import rhacs, rhacs_central

            try:
                docs, _source = rhacs_central.read_images(s, list(a.rhacs_image))
            except rhacs.RhacsError as exc:
                raise ConfigError(f"rhacs: {exc}") from exc
            reports += [rep.parse(json.dumps(d), f"RHACS {d.get('id', '')}") for d in docs]
        if not reports:
            raise ConfigError(
                "pass scanner output with -r (Trivy, Grype, CycloneDX, SPDX, RHACS JSON) or --rhacs-image"
            )
        index = vexmod.load(
            s.data_dir, [Path(v) for v in a.vex], products=list(a.product), use_corpus=not a.no_corpus_vex
        )
        kev = kevmod.load(Path(a.kev)) if a.kev else None
        placed: dict[str, Any] | None = None
        if a.manifests:
            text = "\n---\n".join(_read(m) for m in a.manifests)
            placed = dict(workload_reach(PathInventory.from_documents(d.data for d in load_documents(text))))
        out = assess.assess(
            reports,
            vex=index,
            kev=kev,
            reach=placed,
            products=tuple(a.product),
            image=a.image,
            top=a.top,
            trust_report_vex=a.trust_report_vex,
        )
    except (rep.ReportError, vexmod.VexError, kevmod.KevError, assess.AssessError, threat.ThreatError) as exc:
        raise ConfigError(str(exc)) from exc
    if a.format == "text":
        _tprint(assess.render_text(out, top=a.top))
    else:
        _emit(out, fmt)
    if a.fail_on == "never":
        return 0
    from kube_noob.vuln.reports import SEVERITY_RANK, gating_severity

    floor = SEVERITY_RANK[a.fail_on]
    bad = [
        f
        for f in out["findings"]
        if SEVERITY_RANK[gating_severity(f["severity"], f["cvss"], f["knownExploited"])] >= floor
        and (f["fixVersion"] or f["knownExploited"])
    ]
    return 1 if bad else 0


def _code_builds(specs: list[str], repo: Path) -> list[Any]:
    from kube_noob.code import builds

    try:
        return builds.load(specs, repo)
    except builds.BuildSpecError as exc:
        raise ConfigError(f"-c {exc}") from exc


def _dependency_files(repo: Path) -> dict[str, str]:
    import os

    from kube_noob.code import deps

    out: dict[str, str] = {}
    root = repo.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in deps.SKIP_DIRS and not d.startswith("."))
        for fn in sorted(filenames):
            if not deps.is_dependency_file(fn):
                continue
            f = Path(dirpath) / fn
            if f.is_symlink() or f.stat().st_size > deps.MAX_FILE_BYTES:
                continue
            out[f.relative_to(root).as_posix()] = f.read_text(encoding="utf-8", errors="replace")
            if len(out) >= deps.MAX_FILES:
                return out
    return out


def _code_cmd(a: argparse.Namespace, s: Settings, fmt: str) -> int:
    from kube_noob.attack_paths import Inventory as PathInventory
    from kube_noob.attack_paths import workload_reach
    from kube_noob.code import assess, sarif
    from kube_noob.vuln import reports as vr
    from kube_noob.yamlio import load_documents

    if not a.sarif and not a.scanner_report:
        raise ConfigError("pass SARIF with -s (Semgrep, Bandit, SpotBugs, ESLint, CodeQL) or scanner reports with -r")
    if not 1 <= a.top <= 200:
        raise ConfigError("--top must be 1-200")
    repo = Path(a.repo)
    if not repo.is_dir():
        raise ConfigError(f"--repo {a.repo}: not a directory")
    roots = [str(repo.resolve()), *(r.rstrip("/") for r in a.source_root)]
    bad = [r for r in roots if not r.startswith("/")]
    if bad:
        raise ConfigError(f"--source-root must be absolute: {', '.join(bad)}")
    try:
        sarifs = []
        for path in a.sarif:
            if path != "-" and Path(path).is_file() and Path(path).stat().st_size > sarif.MAX_BYTES:
                raise ConfigError(f"{path}: larger than {sarif.MAX_BYTES} bytes")
            sarifs.append(sarif.parse(_read(path), path, roots=roots, max_depth=sanitize.MAX_JSON_DEPTH_FILE))
        builds = _code_builds(list(a.containerfile), repo)
        reach = None
        if a.manifests:
            text = "\n---\n".join(_read(m) for m in a.manifests)
            reach = dict(workload_reach(PathInventory.from_documents(d.data for d in load_documents(text))))
        scans = []
        for path in a.scanner_report:
            if Path(path).is_file() and Path(path).stat().st_size > vr.MAX_BYTES:
                raise ConfigError(f"{path}: larger than {vr.MAX_BYTES} bytes")
            scans.append(vr.parse(_read(path), path))
        files = _dependency_files(repo) if scans else None
        root = repo.resolve()
        out = assess.assess(
            sarifs,
            builds,
            reach,
            scans,
            files,
            top=a.top,
            include_quality=a.include_quality,
            exists=lambda rel: (root / rel).is_file() and root in (root / rel).resolve().parents,
        )
    except (sarif.SarifError, vr.ReportError) as exc:
        raise ConfigError(str(exc)) from exc
    if a.format == "text":
        _tprint(assess.render_text(out, top=a.top))
    else:
        _emit(out, fmt)
    why = assess.failing(out, a.fail_on)
    for w in why:
        print(f"fail: {w}", file=sys.stderr)
    return 1 if why else 0


def _admission_cmd(a: argparse.Namespace, s: Settings, fmt: str) -> int:
    from kube_noob import admission

    ad = s.admission
    try:
        cfg = admission.Config.build(
            enforce=list(a.enforce) if getattr(a, "enforce", None) is not None else list(ad.enforce),
            excluded=list(ad.excluded_namespaces),
            platform=s.default_platform,
            version=ad.version,
            max_warnings=ad.max_warnings,
            exceptions_text=ad.exceptions_file.read_text(encoding="utf-8") if ad.exceptions_file else None,
            lookups=ad.lookups,
            # KN-S036's allowlist lives with the audit's, in one place: the webhook and `kube-noob audit` read
            # the same configuration file and must give the same verdict (R3c, G243).
            allowed_registries=tuple(s.audit.allowed_registries),
        )
    except (admission.AdmissionConfigError, OSError, ValueError) as exc:
        raise ConfigError(str(exc)) from exc
    if a.admission_cmd == "review":
        out = admission.review_bytes(_read(a.file).encode("utf-8"), cfg)
        if a.format == "yaml":
            _emit(out, fmt)
        else:  # the AdmissionReview the API server would receive
            print(json.dumps(out, indent=1))
        return 0 if out["response"]["allowed"] else 1
    context = None
    if ad.lookups:
        if not s.cluster.enabled:
            raise ConfigError("admission.lookups reads the namespace's other objects: set cluster.enabled (read-only)")
        from kube_noob.debug.cluster import get_backend

        lookups = admission.Lookups(get_backend(s))
        lookups.start()
        context = lookups
    import os
    import signal

    import uvicorn

    for path in (a.tls_cert, a.tls_key):
        if not Path(path).is_file():
            raise ConfigError(f"{path}: no such file (mount the serving certificate Secret)")
    admission.watch_certificate([a.tls_cert, a.tls_key], lambda: os.kill(os.getpid(), signal.SIGTERM))
    mode = f"enforcing {', '.join(sorted(cfg.enforce))}" if cfg.enforce else "warn mode (nothing is denied)"
    print(f"kube-noob-admission: {mode}; lookups {'on' if context else 'off'}", file=sys.stderr)
    uvicorn.run(
        admission.app(cfg, context),
        host=a.host,
        port=a.port,
        ssl_certfile=a.tls_cert,
        ssl_keyfile=a.tls_key,
        log_level="warning",
        proxy_headers=False,
        server_header=False,
        limit_concurrency=200,
        timeout_keep_alive=30,
    )
    return 0


def _blueprint_from_args(a: argparse.Namespace) -> dict[str, Any]:
    if a.blueprint:
        data = yaml.safe_load(_read(a.blueprint)) or {}
        if not isinstance(data, dict):
            raise ConfigError("blueprint file must contain a mapping")
        return data
    if not (a.name and a.namespace and a.image):
        raise ConfigError("provide --blueprint FILE or at least --name, --namespace and --image")
    bp: dict[str, Any] = {
        "name": a.name,
        "namespace": a.namespace,
        "image": a.image,
        "platform": a.platform,
        "replicas": a.replicas,
        "port": a.port,
        "workload": a.workload,
    }
    if a.platform_version:
        bp["platformVersion"] = a.platform_version
    if a.expose != "none":
        bp["exposure"] = {"type": a.expose, **({"host": a.host} if a.host else {})}
    if a.storage_size:
        bp["storage"] = {
            "size": a.storage_size,
            "accessMode": a.access_mode,
            **({"storageClass": a.storage_class} if a.storage_class else {}),
        }
    return bp


def _patch(subparsers: Any, common: argparse.ArgumentParser) -> None:
    original = subparsers.add_parser

    def add_parser(name: str, **kw: Any) -> argparse.ArgumentParser:
        return original(name, parents=[common], **kw)  # type: ignore[no-any-return]

    subparsers.add_parser = add_parser


GLOBAL_DEFAULTS: dict[str, Any] = {"config": None, "web_enabled": False, "cluster_enabled": False, "format": "text"}


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--config", default=argparse.SUPPRESS, help="Path to kube-noob.yaml (default: lookup chain, see docs)"
    )
    common.add_argument(
        "--web-enabled",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Override webEnabled: true for this invocation",
    )
    common.add_argument(
        "--cluster-enabled",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Override cluster.enabled: true (read-only)",
    )
    common.add_argument(
        "--format",
        choices=["text", "json", "yaml", "sarif"],
        default=argparse.SUPPRESS,
        help="output format. `sarif` (SARIF 2.1.0) is for `audit` only: it is a format for findings, and a command "
        "with none to put in it refuses rather than print something else under that name",
    )
    p = argparse.ArgumentParser(
        prog="kube-noob",
        description="Kubernetes/OpenShift/ROSA/Helm/RHACS audit, debugging and learning tools. No AI inside.",
        parents=[common],
    )
    # No set_defaults here: the global options' actions are shared with every subcommand (parents=[common]), so a
    # parser-level default would reset a value given before the subcommand (`kube-noob --config X doctor`).
    # Defaults are filled in after parsing (GLOBAL_DEFAULTS).
    p.add_argument("--version", action="version", version=f"kube-noob {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    _add = sub.add_parser

    def add_parser(name: str, **kw: Any) -> argparse.ArgumentParser:
        return _add(name, parents=[common], **kw)

    sub.add_parser = add_parser  # type: ignore[method-assign]

    def manifests_cmd(name: str, help_: str) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("-f", "--file", required=True, help="YAML file, directory or '-' for stdin")
        sp.add_argument("--platform", choices=PLATFORMS, default=None)
        sp.add_argument("--version", dest="pversion", help="OpenShift (4.22) or Kubernetes (1.35) version")
        return sp

    a = manifests_cmd("audit", "Validate + audit + calibrate + red-team manifests")
    a.add_argument("--min-severity", default="low", choices=["info", "low", "medium", "high", "critical"])
    a.add_argument(
        "--skip-unreadable",
        action="store_true",
        help="audit the files that could be read and list the rest under 'unreadable' in the report; without it a "
        "directory holding a file that is not UTF-8 or not YAML exits 5, so a gate never reads a partial audit as a "
        "clean one (exit 1 stays findings at or above --fail-on)",
    )
    a.add_argument(
        "--compact",
        action="store_true",
        help="in json/yaml output, collect each rule's constant fields (title, severity, remediation, citations, "
        "controls and the rest) once into a 'ruleInfo' map keyed by rule id instead of repeating them on every "
        "finding: the same report, losslessly, about a third smaller where a rule fires more than once. The exit "
        "code is unchanged, so a gate reads the same verdict either way",
    )
    a.add_argument(
        "--cni",
        default=None,
        help="the cluster's CNI as NAME or NAME:VERSION (calico:3.32, ovn-kubernetes, cilium:1.18). No manifest "
        "states it, so KN-N014 -- an AdminNetworkPolicy or BaselineAdminNetworkPolicy the CNI stopped enforcing, "
        "which Calico did in 3.32 without reporting an error -- is reported as NOT EVALUATED until you name it, "
        "rather than counted clean",
    )
    a.add_argument("--fail-on", default="high", choices=["info", "low", "medium", "high", "critical", "never"])
    a.add_argument(
        "--exceptions",
        default=None,
        help="exception list (kube-noob.io/v1 ExceptionList): active entries hide the findings they cover; an expired "
        "or refused entry fails the gate (exit 1)",
    )
    a.add_argument(
        "--oscal",
        action="store_true",
        help="emit an OSCAL 1.2.3 assessment-results document instead of the report: the findings as observations, "
        "and one finding per control, satisfied only where that control's rules actually ran and found nothing. A "
        "control no rule evaluated is named under exclude-controls and never reported satisfied. Every uuid is a v5 "
        "uuid over the input, so two runs over the same bundle produce the same document and CI can diff it. The "
        "exit code is unchanged, so a gate reads the same verdict with the flag as without",
    )
    a.add_argument(
        "--oscal-import-ap",
        default=None,
        metavar="HREF",
        help="the assessment plan this document is assessed against. OSCAL requires the field; without it the "
        "document points at a local fragment and says plainly that no plan was imported",
    )
    exc_p = sub.add_parser(
        "exceptions",
        help="Check an exception list: owner, reason, expiry and scope of every entry",
        description="Refuses entries with no owner or reason, an unknown rule, a scope wider than a namespace (or a "
        "named cluster-scoped object), or an expiry more than 400 days ahead; reports expired ones. Exit 1 when any "
        "entry is refused or expired. Example: kube-noob exceptions check kube-noob-exceptions.yaml",
    )
    exc_sub = exc_p.add_subparsers(dest="exceptions_cmd", required=True)
    _patch(exc_sub, common)
    exc_chk = exc_sub.add_parser("check", help="Check every entry and say why one is refused or expired")
    exc_chk.add_argument("file", help="the exception list (YAML)")
    exc_chk.add_argument("--today", default=None, help="check as of this date (YYYY-MM-DD), for planning renewals")
    gt = sub.add_parser(
        "gate",
        help="CI gate before deploy: audit, admission policy, reported issues and Containerfiles; SARIF and a summary",
        description="Audits manifests and rendered charts (with an exception list when given), says which findings the "
        "generated admission policies would refuse, lists open reported issues in the target OpenShift release that "
        "name a deployed kind, audits Containerfiles, and exits 1 at --fail-on. Writes SARIF 2.1.0, a Markdown "
        "summary and GitLab code quality JSON. Offline. Example: helm template app chart/ > rendered.yaml && "
        "kube-noob gate -f rendered.yaml --chart-path chart --platform openshift --version 4.20 --sarif out.sarif",
    )
    gt.add_argument("-f", "--file", action="append", default=[], help="manifests: a file, a directory, or -; repeat")
    gt.add_argument("--chart", action="append", default=[], help="a Helm chart directory to render; repeat")
    gt.add_argument("--values", action="append", default=[], help="values file for --chart; repeat")
    gt.add_argument("--namespace", default="default", help="namespace to render charts into")
    gt.add_argument(
        "--containerfile",
        action="append",
        default=[],
        metavar="PATH[=IMAGE][,context=DIR][,target=STAGE]",
        help="a Containerfile to audit and, with --sarif-report, the build that ships code (context defaults to "
        "its directory: context=. for docker build -f deploy/Containerfile .); repeat",
    )
    gt.add_argument("--platform", choices=PLATFORMS)
    gt.add_argument("--version", dest="pversion", help="OpenShift (4.20) or Kubernetes (1.33) version")
    gt.add_argument("--exceptions", default=None, help="exception list (kube-noob.io/v1 ExceptionList)")
    gt.add_argument(
        "--github-annotations",
        action="store_true",
        help="also print the findings as GitHub Actions workflow commands, so they appear on the pull request "
        "instead of in a log. GitHub shows ten of each kind per step, so the tenth says how many are not shown",
    )
    gt.add_argument(
        "--cni",
        default=None,
        help="the cluster's CNI as NAME or NAME:VERSION (calico:3.32, ovn-kubernetes, cilium:1.18). No manifest "
        "states it, so KN-N014 -- an AdminNetworkPolicy or BaselineAdminNetworkPolicy the CNI stopped enforcing, "
        "which Calico did in 3.32 without reporting an error -- is reported as NOT EVALUATED until you name it, "
        "rather than counted clean",
    )
    gt.add_argument(
        "--oscal",
        action="store_true",
        help="emit an OSCAL 1.2.3 assessment-results document instead of the gate report: the same document "
        "`kube-noob audit --oscal` writes, from the gate's own coverage record. The exit code is unchanged, so "
        "the gate verdict is the same with the flag as without",
    )
    gt.add_argument(
        "--oscal-import-ap",
        default=None,
        metavar="HREF",
        help="the assessment plan this document is assessed against; without it the document says plainly that "
        "no plan was imported",
    )
    gt.add_argument("--fail-on", default="high", choices=["info", "low", "medium", "high", "critical", "never"])
    gt.add_argument(
        "--quiet",
        action="store_true",
        help="print nothing when the gate passes (a failing gate still reports in full). For pre-commit hooks and "
        "other places where a silent success is the point; the exit code carries the verdict either way",
    )
    gt.add_argument(
        "--skip-unreadable",
        action="store_true",
        help="gate the files that could be read and list the rest under 'unreadable' in the report; without it a "
        "file that is not UTF-8 or not YAML exits 5, which a pipeline can tell apart from 1 (findings at or above "
        "--fail-on)",
    )
    gt.add_argument("--chart-path", default=None, help="the chart in the repository: findings point at its templates")
    gt.add_argument("--sarif", default=None, help="write SARIF 2.1.0 here (GitHub code scanning)")
    gt.add_argument("--summary", default=None, help="write the Markdown summary here ($GITHUB_STEP_SUMMARY)")
    gt.add_argument(
        "--html",
        default=None,
        help="write a self-contained HTML report here: one file, no network, nothing the browser "
        "fetches -- for forwarding to a reviewer who will not read JSON",
    )
    gt.add_argument("--codequality", default=None, help="write GitLab code quality JSON here")
    gt.add_argument(
        "--scanner-report",
        action="append",
        default=[],
        help="Trivy or Grype JSON, CycloneDX or SPDX SBOM, or RHACS image JSON of a deployed image; repeat. Fixable "
        "or known-exploited findings at --fail-on fail the gate",
    )
    gt.add_argument("--vex", action="append", default=[], help="Red Hat CSAF VEX for --scanner-report; repeat")
    gt.add_argument("--kev", default=None, help="the CISA KEV catalog JSON for --scanner-report")
    gt.add_argument(
        "--sarif-report",
        action="append",
        default=[],
        help="SARIF 2.1.0 from Semgrep, Bandit, SpotBugs, ESLint or CodeQL; repeat. Security findings at --fail-on "
        "fail the gate unless no --containerfile ships the file",
    )
    gt.add_argument(
        "--source-root",
        action="append",
        default=[],
        help="an absolute directory the SAST tools ran in (the current directory always is one); repeat",
    )
    gt.add_argument(
        "--trust-report-vex",
        action="store_true",
        help="honour a CycloneDX report's own analysis (not_affected, resolved, false_positive); off by default: "
        "whoever wrote the report could otherwise clear its findings",
    )

    vf = sub.add_parser(
        "verify",
        help="Check a change BEFORE it is applied: manifests (-f) or a command (--command); allow, deny or "
        "not-determined",
        description="One verdict for a change: allow, deny (it adds findings at or above --fail-on, or a command "
        "grants cluster-admin, the privileged SCC or wildcard RBAC) or not-determined (what it does cannot be read "
        "from its text and the local files: a URL, exec, a delete, a strategic-merge patch, a program or wrapper "
        "verify does not model that is given a kube command). In --command, kubectl apply -f - with nothing on stdin "
        "is not determined; verify -f - with nothing on stdin is a usage error (exit 2). A command is never run: its "
        "files are read inside the working directory, no link followed, no network. Uses the gate's own audit, so "
        "`verify -f X` and `gate -f X` agree on every finding. --against /dev/null is an empty baseline. Exit codes: "
        "0 allow, 1 deny, 2 a usage or configuration error (a missing file, a bad --cni), 4 an internal error or "
        "refused input, 5 not determined (0 with --allow-undetermined; a deny stays 1). Example: kube-noob verify "
        "--command 'kubectl apply -f k8s/ -n shop'",
    )
    vf.add_argument("-f", "--file", action="append", default=[], help="proposed manifests: a file, a directory or -")
    vf.add_argument(
        "--command",
        dest="change_command",
        default=None,
        help="the command line to check (kubectl, oc, helm, kustomize; through sh -c, env, sudo, xargs and the "
        "rest). Its files are read relative to the current directory",
    )
    vf.add_argument(
        "--against",
        action="append",
        default=[],
        help="the current state of the same objects (a file or directory); only findings the change ADDS count",
    )
    vf.add_argument("--platform", choices=PLATFORMS)
    vf.add_argument("--version", dest="pversion", help="OpenShift (4.20) or Kubernetes (1.33) version")
    vf.add_argument("--fail-on", default="high", choices=["info", "low", "medium", "high", "critical", "never"])
    vf.add_argument("--exceptions", default=None, help="exception list (kube-noob.io/v1 ExceptionList)")
    vf.add_argument("--cni", default=None, help="the cluster's CNI as NAME or NAME:VERSION, as for `gate`")
    vf.add_argument(
        "--allow-undetermined",
        action="store_true",
        help="exit 0 instead of 5 when the verdict is not-determined (the reasons are still printed). Off by "
        "default: a check before an action fails closed",
    )
    hk = sub.add_parser(
        "hook",
        help="Make a coding agent pass `kube-noob verify` before a command that changes a cluster",
        description="`hook claude-code` is a Claude Code PreToolUse hook: it reads the hook JSON on stdin, passes "
        "commands that start no cluster change, and blocks (exit 2) a kubectl, oc or helm change that verify does "
        "not allow -- including not-determined, and its own errors. `hook install --claude-code` prints the "
        "settings to add; with --write it merges them into the settings file. A client-side hook can be bypassed "
        "by an agent with shell access; the admission webhook is the server-side control (SECURITY.md).",
    )
    hk_sub = hk.add_subparsers(dest="hook_cmd", required=True)
    _patch(hk_sub, common)
    hc = hk_sub.add_parser("claude-code", help="Answer one Claude Code PreToolUse call (hook JSON on stdin)")
    hi = hk_sub.add_parser("install", help="Print (or with --write, merge) the settings that enable the hook")
    for p_ in (hc, hi):
        p_.add_argument("--platform", choices=PLATFORMS, default="kubernetes")
        p_.add_argument("--version", dest="pversion", help="OpenShift (4.20) or Kubernetes (1.33) version")
        p_.add_argument("--fail-on", default="high", choices=["info", "low", "medium", "high", "critical", "never"])
    hi.add_argument("--claude-code", action="store_true", required=True, help="the harness: Claude Code")
    scope = hi.add_mutually_exclusive_group()
    scope.add_argument("--user", dest="scope", action="store_const", const="user", help="~/.claude/settings.json")
    scope.add_argument(
        "--project", dest="scope", action="store_const", const="project", help=".claude/settings.json (default)"
    )
    scope.add_argument(
        "--local", dest="scope", action="store_const", const="local", help=".claude/settings.local.json (not committed)"
    )
    hi.add_argument(
        "--write",
        action="store_true",
        help="merge the hook into that file (existing hooks kept, atomic, never through a symbolic link)",
    )

    bd = sub.add_parser(
        "build",
        help="Build insight: why a build failed, and a Containerfile and image audit",
        description="diagnose reads a failed GitHub Actions, Jenkins, Tekton or OpenShift build log and names the "
        "failing step, the error, the cause class and the fix. audit checks a Containerfile (and, with --context, "
        "what COPY takes from the build context; with --image-layout, the built image's config and layers). "
        "Examples: kube-noob build diagnose -f build.log; kube-noob build audit -f Containerfile --context .",
    )
    bd_sub = bd.add_subparsers(dest="build_cmd", required=True)
    _patch(bd_sub, common)
    bdd = bd_sub.add_parser("diagnose", help="Name the failing step, the cause class and the fix of a build log")
    bdd.add_argument("-f", "--file", required=True, help="the build log, - for stdin")
    bdd.add_argument("--platform", choices=PLATFORMS)
    bdd.add_argument("--version", dest="pversion", help="the cluster's OpenShift version, for reported issues")
    bda = bd_sub.add_parser(
        "audit",
        help="Audit a Containerfile, the build context and an image on disk (static, offline)",
        description="Exit 1 when a finding is at or above --fail-on. An OCI layout comes from skopeo copy "
        "docker://<image> oci:<dir>, podman save --format oci-dir or buildah push <image> oci:<dir>; nothing is "
        "pulled or extracted.",
    )
    bda.add_argument("-f", "--file", help="the Containerfile or Dockerfile")
    bda.add_argument("--context", help="the build context directory: check what COPY takes from it")
    bda.add_argument("--image-layout", help="an OCI image layout directory of the built image")
    bda.add_argument("--image-platform", default=None, help="os/arch to read from a multi-arch layout (linux/amd64)")
    bda.add_argument("--manifests", help="the workload YAML that runs the image: its probes satisfy KN-B007")
    bda.add_argument("--fail-on", default="high", choices=["info", "low", "medium", "high", "critical", "never"])
    ban = bd_sub.add_parser(
        "analytics",
        help="Flaky tests, slow steps and their trend, failure classes over time, from a CI history folder",
        description="Reads one folder per run: run.json (the GitHub Actions run with its jobs and steps), JUnit XML "
        "reports and optional build logs. Example: kube-noob build analytics --history ci-history/",
    )
    ban.add_argument("--history", required=True, help="the folder of run folders")
    ban.add_argument("--top", type=int, default=20, help="rows per table (1-200)")
    bhi = bd_sub.add_parser(
        "history",
        help="Write a CI history folder from the GitHub Actions API (read-only; needs ci.githubEnabled)",
        description="GET only, to ci.githubApiUrl only, with a random pause between requests and every attempt of "
        "every run. Test reports and logs are not fetched: add JUnit artifacts with gh run download. Example: "
        "GITHUB_TOKEN=<token> kube-noob build history --github acme/shop --workflow ci.yml -o ci-history",
    )
    bhi.add_argument("--github", required=True, help="owner/repo")
    bhi.add_argument("--workflow", default=None, help="the workflow file (ci.yml) or id; default: every workflow")
    bhi.add_argument("--branch", default=None, help="only runs on this branch")
    bhi.add_argument("--max-runs", type=int, default=None, help="attempts to read (default ci.maxRuns, 200)")
    bhi.add_argument("-o", "--output", required=True, help="the history folder to write")
    rh = sub.add_parser(
        "rhacs",
        help="Compare RHACS (StackRox) policies with kube-noob's rules: overlap, related, gaps, outside its scope",
        description="Maps every policy in an RHACS export (the portal's Export policy to JSON, or POST "
        "/v1/policies/export) to kube-noob rules by name and criteria, and says why the rest differ: image and "
        "vulnerability data, runtime events, API events, label conventions, or a deploy-time setting kube-noob has no "
        "rule for. Exit 1 when a policy is unexplained. "
        "Example: kube-noob rhacs compare -f policies.json",
    )
    rh_sub = rh.add_subparsers(dest="rhacs_cmd", required=True)
    _patch(rh_sub, common)
    rhc = rh_sub.add_parser("compare", help="Compare an export (-f) or Central's policies (--live, read-only)")
    rhc.add_argument("-f", "--file", default=None, help="policy export (JSON), - for stdin")
    rhc.add_argument(
        "--live",
        action="store_true",
        help="read Central's policies (GET only; needs rhacs.enabled, rhacs.endpoint and $ROX_API_TOKEN)",
    )
    rhc.add_argument(
        "--outcome",
        action="append",
        default=[],
        choices=["overlap", "related", "gap", "outside", "unexplained"],
        help="with --format text: only these outcomes; repeat",
    )
    vu = sub.add_parser(
        "vuln",
        help="Vulnerabilities from scanner output: normalise, apply Red Hat VEX, rank by reachability; threat model",
        description="report reads Trivy or Grype JSON, CycloneDX or SPDX JSON SBOMs and RHACS image scans into one "
        "finding per package, version and CVE, drops what Red Hat VEX says is not affected or already fixed (citing "
        "the statement), marks CISA KEV entries, and with the manifests ranks findings by exposure, privileges and "
        "RBAC reach with their attack path. threat writes a STRIDE threat model with the rules, policies and MITRE "
        "ATT&CK techniques for each threat. Offline unless --rhacs-image. Examples: trivy image -f json "
        "--list-all-pkgs -o trivy.json <image> && kube-noob vuln report -r trivy.json -m deploy/ --kev "
        "known_exploited_vulnerabilities.json; kube-noob vuln threat -f deploy/ --platform openshift",
    )
    vu_sub = vu.add_subparsers(dest="vuln_cmd", required=True)
    _patch(vu_sub, common)
    vr = vu_sub.add_parser(
        "report",
        help="Normalise scanner output, apply VEX and KEV, rank by reachability",
        description="Exit 1 when a fixable or known-exploited finding is at or above --fail-on (default never).",
    )
    vr.add_argument(
        "-r",
        "--report",
        action="append",
        default=[],
        help="Trivy or Grype JSON, a CycloneDX or SPDX 2 JSON SBOM, or an RHACS image (GET /v1/images/{id}); repeat",
    )
    vr.add_argument(
        "--rhacs-image",
        action="append",
        default=[],
        help="read this image's scan from RHACS Central (sha256:<digest>; GET only, needs rhacs.enabled); repeat",
    )
    vr.add_argument(
        "--vex",
        action="append",
        default=[],
        help="Red Hat CSAF VEX: a file, a folder of <year>/cve-*.json or the csaf_vex archive; repeat. The "
        "redhat-vex corpus shard (kube-noob corpus advisories) is read too",
    )
    vr.add_argument("--no-corpus-vex", action="store_true", help="do not read the redhat-vex corpus shard")
    vr.add_argument(
        "--product",
        action="append",
        default=[],
        help="Red Hat product CPE prefix (default: from the report's RHEL release, cpe:/o:redhat:enterprise_linux:9)",
    )
    vr.add_argument("--kev", default=None, help="the CISA KEV catalog (known_exploited_vulnerabilities.json, CC0)")
    vr.add_argument(
        "--trust-report-vex",
        action="store_true",
        help="honour a CycloneDX report's own analysis (not_affected, resolved, false_positive); off by default: "
        "the findings it marks are kept, with a note",
    )
    vr.add_argument(
        "-m",
        "--manifests",
        action="append",
        default=[],
        help="YAML that runs the images (a file or a directory); ranks findings by exposure and privileges; repeat",
    )
    vr.add_argument("--image", default=None, help="treat every report as this image (registry/repo:tag or digest)")
    vr.add_argument("--top", type=int, default=20, help="ranked findings to show (1-200)")
    vr.add_argument(
        "--fail-on",
        default="never",
        choices=["low", "medium", "high", "critical", "never"],
        help="exit 1 when a fixable or known-exploited finding is at or above this severity",
    )
    vt = vu_sub.add_parser(
        "threat",
        help="STRIDE threat model of the applications in manifests",
        description="Entry points, trust boundaries, data stores and identities from the manifests; each threat with "
        "its status, evidence, mitigating rules and policies, and ATT&CK technique ids. With -r, public-facing "
        "exploits (TM-E01) are assessed from the images' reports.",
    )
    vt.add_argument("-f", "--file", action="append", required=True, help="manifests: a file or a directory; repeat")
    vt.add_argument("--platform", choices=PLATFORMS)
    vt.add_argument("--version", dest="pversion", help="OpenShift (4.20) or Kubernetes (1.33) version")
    vt.add_argument("-r", "--report", action="append", default=[], help="a scanner report of an image; repeat")
    cd = sub.add_parser(
        "code",
        help="Code findings from SAST tools (SARIF), the images that ship them, the pods that run them",
        description="report reads the SARIF 2.1.0 that Semgrep, Bandit, SpotBugs/FindSecBugs, ESLint and CodeQL "
        "write (kube-noob has no analysis engine of its own), merges the same file, line and CWE across tools, drops "
        "suppressed and fixed results with the reason, follows each file through the Containerfiles into the images "
        "that ship it (copied or built), and with the manifests ranks findings by exposure and privileges with their "
        "attack path. With scanner reports of the images (-r), each language-package vulnerability points at the "
        "dependency file and line to change. Offline. Example: kube-noob code report -s semgrep.sarif -s codeql.sarif "
        "-c web/Containerfile=quay.io/acme/web -m deploy/ -r trivy-web.json",
    )
    cd_sub = cd.add_subparsers(dest="code_cmd", required=True)
    _patch(cd_sub, common)
    cr = cd_sub.add_parser(
        "report",
        help="Normalise SARIF, map files to images and workloads, rank; dependency fixes from scanner reports",
        description="Exit 1 when a security finding in shipped code, or a fixable or known-exploited dependency "
        "vulnerability, is at or above --fail-on (default never). Without -c every finding counts as shipped.",
    )
    cr.add_argument("-s", "--sarif", action="append", default=[], help="a SARIF 2.1.0 file; repeat")
    cr.add_argument(
        "-c",
        "--containerfile",
        action="append",
        default=[],
        help="PATH[=IMAGE][,context=DIR][,target=STAGE]: a Containerfile in the repository and the image it builds "
        "(context defaults to the Containerfile's directory); repeat",
    )
    cr.add_argument("--repo", default=".", help="the repository on disk (default: the current directory)")
    cr.add_argument(
        "--source-root",
        action="append",
        default=[],
        help="an absolute directory the scanners ran in (CI checkout path), so absolute paths in SARIF map to the "
        "repository; the --repo path is always one; repeat",
    )
    cr.add_argument(
        "-m", "--manifests", action="append", default=[], help="YAML that runs the images (file or directory); repeat"
    )
    cr.add_argument(
        "-r",
        "--scanner-report",
        action="append",
        default=[],
        help="Trivy or Grype JSON or a CycloneDX report of an image, for dependency fixes; repeat",
    )
    cr.add_argument("--include-quality", action="store_true", help="list lint and quality results too")
    cr.add_argument("--top", type=int, default=20, help="ranked findings to show (1-200)")
    cr.add_argument(
        "--fail-on",
        default="never",
        choices=["low", "medium", "high", "critical", "never"],
        help="exit 1 at or above this severity (shipped code findings; fixable or exploited dependencies)",
    )
    mg = sub.add_parser(
        "must-gather",
        help="Read an OpenShift must-gather safely, offline (nothing extracted or run; Secrets never read)",
        description="analyze opens a must-gather directory or a .tar, .tar.gz or .tgz archive of one (oc adm "
        "must-gather, oc adm inspect) without extracting or executing anything. An archive member with an absolute "
        "path or .. is refused; links, devices and nested archives are not followed or opened; files named like "
        "Secrets are never read. Prints what was gathered, for which version and when, then what is wrong: the "
        "cluster version and update, cluster operators, nodes, machine config pools, OLM operators, pods, warning "
        "events and etcd log hints, ranked, each with its file, its signals and read-only next steps. Example: "
        "kube-noob must-gather analyze must-gather.tar.gz --fail-on high",
    )
    mg_sub = mg.add_subparsers(dest="mg_cmd", required=True)
    _patch(mg_sub, common)
    mga = mg_sub.add_parser(
        "analyze",
        help="Open a must-gather safely and say what is wrong: cluster version, operators, nodes, machine config "
        "pools, OLM operators, pods, events and etcd logs, ranked, with read-only next steps",
    )
    mga.add_argument("path", help="a must-gather directory, or a .tar, .tar.gz or .tgz archive of one")
    mga.add_argument(
        "--fail-on",
        default="never",
        choices=["low", "medium", "high", "critical", "never"],
        help="exit 1 when a finding is at or above this severity",
    )
    mga.add_argument(
        "--require-complete",
        action="store_true",
        help="exit 5 when the must-gather was missing analysers or held files that could not be read, so a gate "
        "never reads a blind run as a clean one (exit 1 stays findings at or above --fail-on)",
    )
    mga.add_argument(
        "--report",
        metavar="DIR",
        help="write report.md and report.json here: findings with the known issues and team memory that match them",
    )
    mga.add_argument(
        "--case-draft",
        action="store_true",
        help="with --report, also write case-draft.md: a support case with the facts filled in and placeholders "
        "for what only you know",
    )
    ad = sub.add_parser(
        "admission",
        help="The kube-noob-admission webhook: admission warnings for every rule, denials only for enforced rules",
        description="serve answers AdmissionReview requests over HTTPS (POST /validate; /healthz, /readyz, /metrics). "
        "Warn mode by default: nothing is denied. admission.enforce lists the rules that deny; on UPDATE an enforced "
        "rule denies only a finding the old object did not have. System namespaces are excluded and nothing is "
        "mutated. review evaluates one AdmissionReview JSON offline. Install with the chart (admission.enabled). "
        "Examples: kube-noob admission review -f review.json; kube-noob admission serve --tls-cert tls.crt --tls-key "
        "tls.key",
    )
    ad_sub = ad.add_subparsers(dest="admission_cmd", required=True)
    _patch(ad_sub, common)
    ads = ad_sub.add_parser("serve", help="Serve the webhook over HTTPS")
    ads.add_argument("--host", default="0.0.0.0", help="address to listen on (default 0.0.0.0)")  # noqa: S104
    ads.add_argument("--port", type=int, default=8443)
    ads.add_argument("--tls-cert", required=True, help="the serving certificate (PEM)")
    ads.add_argument("--tls-key", required=True, help="its private key (PEM)")
    adr = ad_sub.add_parser("review", help="Evaluate one AdmissionReview (JSON) offline and print the response")
    adr.add_argument("-f", "--file", required=True, help="the AdmissionReview JSON, - for stdin")
    adr.add_argument("--enforce", action="append", default=None, help="a rule to enforce (overrides the config)")
    manifests_cmd("validate", "Schema/API/platform validation only")
    manifests_cmd("redteam", "Red-team scenarios only")
    fx = manifests_cmd("fix", "Apply safe mechanical fixes")
    fx.add_argument("-o", "--output", help="Write fixed YAML here (default: stdout)")
    fx.add_argument("--no-harden", action="store_true")

    pr = sub.add_parser("protocol", help="Run the 7-step protocol on a request")
    pr.add_argument("request")
    pr.add_argument("-f", "--file", help="Manifests to review")
    pr.add_argument("--blueprint", help="Blueprint YAML to generate from")
    pr.add_argument("--platform", choices=PLATFORMS)
    pr.add_argument("--version", dest="pversion")
    pr.add_argument("--no-fix", action="store_true")

    for name in ("generate", "helm-chart"):
        g = sub.add_parser(name, help="Generate audited manifests" if name == "generate" else "Generate a Helm chart")
        g.add_argument("--blueprint", help="Blueprint YAML file")
        g.add_argument("--name")
        g.add_argument("--namespace")
        g.add_argument("--image")
        g.add_argument("--platform", choices=PLATFORMS, default="kubernetes")
        g.add_argument("--platform-version")
        g.add_argument("--replicas", type=int, default=3)
        g.add_argument("--port", type=int, default=8080)
        g.add_argument("--workload", choices=["deployment", "statefulset"], default="deployment")
        g.add_argument("--expose", choices=["none", "route", "ingress", "gateway", "loadbalancer"], default="none")
        g.add_argument("--host")
        g.add_argument("--storage-size")
        g.add_argument(
            "--access-mode", default="ReadWriteOnce", choices=["ReadWriteOnce", "ReadWriteMany", "ReadWriteOncePod"]
        )
        g.add_argument("--storage-class")
        g.add_argument("-o", "--output", help="Output file (generate) or directory (helm-chart)")

    ha = sub.add_parser("helm-audit", help="Render a chart with helm and audit the output")
    ha.add_argument("chart")
    ha.add_argument("-f", "--values", action="append", default=[])
    ha.add_argument("--platform", choices=PLATFORMS, default="kubernetes")
    ha.add_argument("--version", dest="pversion")
    ha.add_argument("--namespace", default="default")

    d = sub.add_parser(
        "diagnose",
        help="Diagnose pasted events/logs/errors offline",
        description="Diagnose events, describe output, logs or errors. Pass the text in quotes, a file with -f, or "
        "pipe it in. Examples: kube-noob diagnose 'Back-off restarting failed container' | kube-noob diagnose -f "
        "events.txt | pbpaste | kube-noob diagnose",
    )
    d.add_argument("text", nargs="*", help="the error text; quote multi-line text (single quotes avoid $ expansion)")
    d.add_argument("-f", "--file", default=None, help="a file, '-' for stdin, or the text itself")
    d.add_argument("--platform", choices=PLATFORMS)
    d.add_argument(
        "--version", dest="pversion", help="your OpenShift version, e.g. 4.20.8: leaves out issues already fixed there"
    )

    ins = sub.add_parser(
        "insight",
        help="Paste anything (events, logs, an alert, a denial, a ticket, manifests, a question): it names what it is "
        "and runs every analyser that applies",
        description="Recognises what the input is and merges the diagnosis, reported issues, team memory, policy "
        "explanations, audit findings and documentation that apply. Text in quotes, a file with -f, or stdin.",
    )
    ins.add_argument("text", nargs="*", help="the input; quote multi-line text (single quotes avoid $ expansion)")
    ins.add_argument("-f", "--file", default=None, help="a file (a .pcap is recognised by its header), or '-'")
    ins.add_argument("--platform", choices=PLATFORMS)
    ins.add_argument("--version", dest="pversion", help="your OpenShift version, e.g. 4.20.8")

    kis = sub.add_parser(
        "known-issues",
        help="Is this a reported OpenShift issue? Match an error against the release notes",
        description="Match an error or symptom against the known and fixed issues in the OpenShift release notes. "
        "Example: kube-noob known-issues 'could not find any suitable subnets for creating the ELB' --version 4.20.8",
    )
    kis.add_argument("text", nargs="*", help="the error text or symptom, in quotes")
    kis.add_argument("-f", "--file", default=None, help="a file, '-' for stdin, or the text itself")
    kis.add_argument("--platform", choices=PLATFORMS, default="openshift")
    kis.add_argument("--version", dest="pversion", help="your OpenShift version, e.g. 4.20.8")
    kis.add_argument("--limit", type=int, default=3)

    ksi = sub.add_parser(
        "ksi",
        help="FedRAMP 20x Key Security Indicators: which ones a kube-noob finding is evidence for",
        description="Join kube-noob's findings to the FedRAMP 20x Key Security Indicators through the NIST "
        "controls both sides name. With no input it prints the crosswalk; with -f it audits the manifests first "
        "and reports, per indicator, what was found. A mapping is evidence, never a compliance claim. "
        "Example: kube-noob ksi -f deploy/ --format json",
    )
    ksi.add_argument("-f", "--file", default=None, help="manifest, directory or '-' for stdin")
    ksi.add_argument(
        "--skip-unreadable",
        action="store_true",
        help="audit the readable files and list the rest in the report instead of refusing",
    )
    ksi.add_argument("--platform", choices=PLATFORMS, default=None)
    ksi.add_argument("--version", dest="pversion", help="target OpenShift or Kubernetes version")
    ksi.add_argument(
        "--cni",
        default=None,
        help="the cluster's CNI as NAME or NAME:VERSION (calico:3.32); without it the rule that decides whether "
        "an AdminNetworkPolicy is inert cannot decide, and the row says so",
    )
    ksi.add_argument(
        "--exceptions",
        default=None,
        help="the exception list `audit --exceptions` takes: active entries move their findings to 'excepted' on "
        "the indicators they reach, so this page reconciles with the audit report; an expired or refused entry "
        "fails the gate (exit 1), as it does for `audit`",
    )
    ksi.add_argument(
        "--min-severity",
        default="low",
        choices=["info", "low", "medium", "high", "critical"],
        help="hide findings below this severity; the default is `audit`'s default, because this view is a "
        "projection of one audit and a rule a threshold hid is reported as withheld rather than clean",
    )
    ksi.add_argument("--indicator", default=None, help="one indicator by id, e.g. KSI-IAM-ELP")
    ksi.add_argument("--control", default=None, help="the indicators citing one NIST control, e.g. AC-6")
    ksi.add_argument("--evidenced-only", action="store_true", help="hide indicators no kube-noob rule can see")
    ksi.add_argument(
        "--html",
        default=None,
        help="write a self-contained HTML report here: one file, no network, nothing the browser "
        "fetches -- for forwarding to a reviewer who will not read JSON",
    )

    upr = sub.add_parser(
        "upgrade-risks",
        help="Known risks for an OpenShift update, from the public update graph (offline)",
        description="List the risks Red Hat declares for updating from one OpenShift version to another (conditional "
        "updates in github.com/openshift/cincinnati-graph-data), from a bundled snapshot: whether each applies, the "
        "read-only check that decides it, or its PromQL when that cannot be evaluated offline. "
        "Example: kube-noob upgrade-risks --from 4.20.3 --to 4.21.4",
    )
    upr.add_argument("--from", dest="from_version", required=True, help="the version the cluster runs, e.g. 4.20.3")
    upr.add_argument("--to", dest="to_version", required=True, help="the version to update to, e.g. 4.21.4")
    upr.add_argument(
        "--arch",
        choices=["amd64", "arm64", "multi", "ppc64le", "s390x"],
        default=None,
        help="the release architecture; without it every architecture is checked",
    )

    tik = sub.add_parser(
        "ticket",
        help="Look up a Red Hat Jira ticket in the local copy: what became of it, fix versions, workaround",
        description="Show one ticket from the local copy of Red Hat's public Jira (kube-noob corpus jira --online). "
        "Example: kube-noob ticket OCPBUGS-12345 --version 4.21.1",
    )
    sig = sub.add_parser(
        "signals",
        help="Extract signals: alert names, event and condition reasons, container reasons, admission rules, "
        "components and error templates",
        description="Find the canonical names in an alert payload, events, ClusterOperators, pod status or pasted "
        "text. Example: oc get events -o json | kube-noob signals",
    )
    sig.add_argument("text", nargs="*", help="text to read; or -f FILE; or pipe it in")
    sig.add_argument("-f", "--file", default=None, help="a file, '-' for stdin, or the text itself")
    tik.add_argument("key", help="a Jira key such as OCPBUGS-12345 or ROX-30000")
    tik.add_argument("--version", dest="pversion", help="your OpenShift version: says whether the fix is in it")

    pol = sub.add_parser(
        "policy",
        help="Why was this denied? Would a NetworkPolicy allow this traffic?",
        description="Explain admission denials (Kyverno, Gatekeeper, ValidatingAdmissionPolicy, Pod Security, "
        "OpenShift SCC, RHACS, quota, LimitRange, RBAC), check NetworkPolicy reachability, generate admission policies "
        "and check legacy Kyverno policies for their CEL form. Read-only and offline unless --live is given.",
    )
    psub = pol.add_subparsers(dest="policy_cmd", required=True)
    _patch(psub, common)
    pex = psub.add_parser(
        "explain",
        help="Explain an admission denial, policy by policy",
        description="Pass the error in quotes, a file with -f, or pipe it in. Example: kubectl apply -f deploy.yaml "
        "2>&1 | kube-noob policy explain",
    )
    pex.add_argument("text", nargs="*", help="the denial text; quote it (single quotes avoid $ expansion)")
    pex.add_argument("-f", "--file", default=None, help="a file, '-' for stdin, or the text itself")
    pex.add_argument("--platform", choices=PLATFORMS)
    prc = psub.add_parser(
        "reach",
        help="Would NetworkPolicies let the source reach the destination on a port? (exit 1 when denied)",
        description="Endpoints: namespace/name, namespace/kind/name, namespace:key=value,... or an IP/CIDR. Example: "
        "kube-noob policy reach --from web/frontend --to shop/orders-api --port 8080 -f k8s/",
    )
    prc.add_argument("--from", dest="source", required=True, help="source endpoint")
    prc.add_argument("--to", dest="destination", required=True, help="destination endpoint")
    prc.add_argument("--port", required=True, help="port number or named container port")
    prc.add_argument("--protocol", default="TCP", choices=["TCP", "UDP", "SCTP"])
    prc.add_argument("-f", "--file", action="append", default=[], help="YAML file or directory; repeat for several")
    prc.add_argument("--namespace", dest="default_namespace", default="default", help="for objects without one")
    prc.add_argument("--live", action="store_true", help="read the policies from the cluster (read-only)")
    prc.add_argument("--platform", choices=PLATFORMS)
    prc.add_argument(
        "--cni",
        default=None,
        help="the cluster's CNI as NAME or NAME:VERSION (calico:3.32, ovn-kubernetes, cilium:1.18). Calico ignores "
        "AdminNetworkPolicy and BaselineAdminNetworkPolicy from 3.32 onward, so with it those policies are reported "
        "as inert instead of deciding; an undocumented CNI makes the verdict undetermined",
    )
    pgen = psub.add_parser(
        "generate",
        help="Turn kube-noob's audit rules into ValidatingAdmissionPolicy and Kyverno ValidatingPolicy YAML",
        description="One policy per rule that can be decided from one object at admission; the others are listed "
        "with the reason. Audit mode warns and records, enforce refuses. Example: kube-noob policy generate "
        "--platform openshift --version 4.20 --mode audit -o kube-noob-policies.yaml",
    )
    pgen.add_argument("--platform", choices=PLATFORMS)
    pgen.add_argument("--version", dest="pversion", help="OpenShift (4.20) or Kubernetes (1.33) version")
    pgen.add_argument(
        "--engine",
        dest="engines",
        action="append",
        choices=["vap", "kyverno"],
        default=[],
        help="vap (ValidatingAdmissionPolicy, built in) or kyverno (ValidatingPolicy, Kyverno 1.18+); repeat for "
        "both (default: both)",
    )
    pgen.add_argument("--mode", choices=["audit", "enforce"], default="audit", help="audit (default) or enforce")
    pgen.add_argument("--rule", dest="rules", action="append", default=[], help="a rule id such as KN-S001; repeat")
    pgen.add_argument(
        "--exclude-namespace",
        dest="exclude_namespaces",
        action="append",
        default=[],
        help="a namespace the policies skip, besides kube-system, kube-public and kube-node-lease; repeat",
    )
    pgen.add_argument(
        "--exceptions",
        default=None,
        help="exception list (kube-noob.io/v1 ExceptionList): active entries become exemptions in their rule's policy",
    )
    pgen.add_argument("-o", "--output", help="write the YAML here (default: stdout)")
    pmc = psub.add_parser(
        "migrate-check",
        help="Lint legacy Kyverno policies (removed in Kyverno 1.20) rule by rule for their CEL policy form",
        description="For each rule of a kyverno.io ClusterPolicy, Policy, ClusterCleanupPolicy, CleanupPolicy or "
        "PolicyException: direct, inverted, manual or blocked, with the field path, the policies.kyverno.io target "
        "kind, the reason and the Kyverno documentation section. Rules that map directly get a draft CEL policy and a "
        "kyverno test fixture skeleton to prove it. Lint only: nothing is applied or rewritten. Example: kube-noob "
        "policy migrate-check -f policies/ --fail-on blocked",
    )
    pmc.add_argument("-f", "--file", action="append", required=True, help="policy YAML, a directory or -; repeat")
    pmc.add_argument(
        "--fail-on",
        default="never",
        choices=["never", "manual", "blocked"],
        help="exit 1 when a finding is at or above this verdict (default never)",
    )
    pmc.add_argument("--no-drafts", action="store_true", help="findings only: no draft policies or test fixtures")
    pmc.add_argument(
        "-o",
        "--output-dir",
        default=None,
        help="write the drafts and kyverno test fixtures under this directory (refuses to overwrite a file)",
    )

    pos = sub.add_parser(
        "posture",
        help="Attack paths: from what is exposed to what a compromised pod could do (read-only)",
        description="Ranks paths from a Route, Ingress, LoadBalancer or NodePort Service to the pods it reaches and "
        "what they can do: node access (privileged, hostPath, host namespaces) or Kubernetes API rights through "
        "the ServiceAccount token (read Secrets, exec, create workloads, escalate). Score = exposure x blast radius. "
        "Secrets are never read. Example: kube-noob posture scan -f k8s/",
    )
    posub = pos.add_subparsers(dest="posture_cmd", required=True)
    _patch(posub, common)
    psc = posub.add_parser("scan", help="Rank the attack paths in manifests (-f) or the live cluster (--live)")
    psc.add_argument("-f", "--file", action="append", default=[], help="YAML file or directory; repeat for several")
    psc.add_argument("--live", action="store_true", help="read the cluster (read-only, never Secrets)")
    psc.add_argument(
        "-n", "--namespace", dest="namespaces", action="append", default=[], help="with --live: only these; repeat"
    )
    psc.add_argument("--top", type=int, default=20, help="paths to show (1-200, default 20)")
    psc.add_argument(
        "--fail-above", type=int, default=None, help="exit 1 when a path scores above this (CI gate; max score 30)"
    )

    opr = sub.add_parser(
        "operators",
        help="Operators installed through OLM: which, at what version, from which catalog and channel (read-only)",
        description="inventory lists the operators OLM installed: package, version, catalog, channel, approval mode, "
        "namespace and the namespaces each serves, phase, a pending upgrade or a Manual approval waiting. It reads "
        "manifests (-f), a must-gather (--must-gather) or the live cluster (--live: ClusterServiceVersions and "
        "Subscriptions only, never Secrets). What it could not read is part of the answer: with no "
        "ClusterServiceVersions it says not determined, never zero operators. Example: kube-noob operators inventory "
        "--must-gather must-gather.tar.gz",
    )
    opsub = opr.add_subparsers(dest="operators_cmd", required=True)
    _patch(opsub, common)
    opi = opsub.add_parser(
        "inventory",
        help="List the OLM-installed operators in manifests (-f), a must-gather (--must-gather) or the cluster "
        "(--live), and say what could not be read",
    )
    opi.add_argument("-f", "--file", action="append", default=[], help="YAML file or directory; repeat for several")
    opi.add_argument("--must-gather", default=None, help="a must-gather directory, or a .tar, .tar.gz or .tgz of one")
    opi.add_argument("--live", action="store_true", help="read the cluster (read-only, never Secrets)")
    opi.add_argument(
        "-n", "--namespace", dest="namespaces", action="append", default=[], help="with --live: only these; repeat"
    )
    opi.add_argument("--top", type=int, default=200, help="operators to show (1-500, default 200)")
    opi.add_argument(
        "--require-complete",
        action="store_true",
        help="exit 5 unless every OLM object the answer needs was read, so a gate never reads a blind or partial "
        "inventory as a complete one",
    )

    def snap_source(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("-f", "--file", action="append", default=[], help="YAML file or directory; repeat for several")
        sp.add_argument("--live", action="store_true", help="read the cluster (read-only, never Secrets)")
        sp.add_argument(
            "-n", "--namespace", dest="namespaces", action="append", default=[], help="with --live: only these; repeat"
        )
        sp.add_argument("--platform", choices=PLATFORMS)
        sp.add_argument("--version", dest="pversion", help="OpenShift (4.20) or Kubernetes (1.33) version")
        sp.add_argument("--exceptions", default=None, help="exception list: excepted findings are not counted open")

    pss = posub.add_parser("snapshot", help="Record the objects' hashes and today's findings (no values) to a file")
    snap_source(pss)
    pss.add_argument("-o", "--output", required=True, help="the snapshot file (JSON)")
    pdf = posub.add_parser("diff", help="What changed between two snapshots: objects, new and fixed findings, owners")
    pdf.add_argument("old", help="the earlier snapshot")
    pdf.add_argument("new", help="the later snapshot")
    pdf.add_argument("--markdown", default=None, help="also write the report as Markdown here")
    pdf.add_argument(
        "--html",
        default=None,
        help="write a self-contained HTML report here: one file, no network, nothing the browser "
        "fetches -- for forwarding to a reviewer who will not read JSON",
    )
    prp = posub.add_parser(
        "report",
        help="Snapshot now, compare with the newest snapshot kept, write the report (the daily job)",
        description="Keeps snapshots and reports in --state-dir (default <dataDir>/posture), the newest --keep of "
        "them. Example: kube-noob --cluster-enabled posture report --live",
    )
    snap_source(prp)
    prp.add_argument(
        "--html",
        default=None,
        help="write a self-contained HTML report here: one file, no network, nothing the browser "
        "fetches -- for forwarding to a reviewer who will not read JSON",
    )
    prp.add_argument("--state-dir", default=None, help="where snapshots and reports are kept")
    prp.add_argument("--keep", type=int, default=None, help="snapshots to keep (default posture.keep, 14)")

    wt = sub.add_parser(
        "watch",
        help="Watch namespaces read-only: open, explain and remember incidents (needs cluster access)",
        description="Polls pods, events, deployments and replicasets (get/list only, never Secrets), groups problems "
        "into incidents, explains each new one and records it in the local incident ledger. Example: kube-noob "
        "--cluster-enabled watch -n shop --once",
    )
    wt.add_argument("-n", "--namespace", dest="namespaces", action="append", default=[], help="repeat for several")
    wt.add_argument("--once", action="store_true", help="poll once and exit")
    wt.add_argument("--interval", type=int, default=None, help="seconds between polls (default watch.intervalSeconds)")

    inc = sub.add_parser("incidents", help="Incidents the watch recorded: list, show, or confirm the fix")
    isub = inc.add_subparsers(dest="incidents_cmd")
    _patch(isub, common)
    il = isub.add_parser("list", help="Open incidents (default), or --all")
    il.add_argument("--all", action="store_true", help="include resolved incidents")
    il.add_argument("-n", "--namespace", default=None)
    ish = isub.add_parser("show", help="One incident in full")
    ish.add_argument("incident_id")
    icf = isub.add_parser("confirm", help="Remember the cause and fix that worked (summaries only)")
    icf.add_argument("incident_id")
    icf.add_argument("--cause", required=True)
    icf.add_argument("--fix", required=True)

    dbg = sub.add_parser("debug", help="Collect live read-only evidence for a workload and diagnose it")
    dbg.add_argument("target", help="kind/name, e.g. deployment/orders-api")
    dbg.add_argument("-n", "--namespace", required=True)
    dbg.add_argument("--platform", choices=PLATFORMS)

    bun = sub.add_parser(
        "bundle", help="Write a redacted, read-only diagnostic bundle (Markdown + JSON) for a workload"
    )
    bun.add_argument("target", help="kind/name, e.g. deployment/orders-api")
    bun.add_argument("-n", "--namespace", required=True)
    bun.add_argument("-o", "--out", default="kube-noob-bundle", help="output directory (default: ./kube-noob-bundle)")
    bun.add_argument("--platform", choices=PLATFORMS)

    s = sub.add_parser("search", help="Search local knowledge")
    s.add_argument("query")
    s.add_argument("-n", "--limit", type=int, default=5)
    s.add_argument("--source")

    sub.add_parser("rules", help="List audit rules")
    ex = sub.add_parser("explain", help="Explain a rule")
    ex.add_argument("rule_id")

    lr = sub.add_parser("learn", help="Learning tracks, lessons, exercises, quizzes")
    lsub = lr.add_subparsers(dest="learn_cmd", required=True)
    learner_common = argparse.ArgumentParser(add_help=False, parents=[common])
    learner_common.add_argument("--learner", default=argparse.SUPPRESS, help="Learner id for progress/credits")
    _patch(lsub, learner_common)
    lsub.add_parser("tracks")
    lsn = lsub.add_parser("lesson")
    lsn.add_argument("lesson_id")
    lex = lsub.add_parser("exercise")
    lex.add_argument("exercise_id")
    lsu = lsub.add_parser("submit")
    lsu.add_argument("exercise_id")
    lsu.add_argument("-f", "--file", required=True)
    lq = lsub.add_parser("quiz")
    lq.add_argument("question_id")
    lq.add_argument("--choice", type=int)
    lsub.add_parser("progress")
    lr.set_defaults(learner="local")

    lg = sub.add_parser("learning", help="What kube-noob remembers locally (profile, confirmed notes, counters)")
    lgs = lg.add_subparsers(dest="learning_cmd", required=True)
    _patch(lgs, common)
    lgs.add_parser("show", help="Profile, recent notes and the most frequent playbooks/rules")
    ln = lgs.add_parser("note", help="Save a confirmed symptom -> cause -> fix (summaries only, no secrets)")
    ln.add_argument("--symptom", required=True)
    ln.add_argument("--cause", required=True)
    ln.add_argument("--fix", required=True)
    ln.add_argument("--platform", choices=PLATFORMS)
    ln.add_argument("--tag", action="append", default=[], dest="tags")
    lgf = lgs.add_parser("forget", help="Delete a note by id (local-N)")
    lgf.add_argument("note_id")
    lgp = lgs.add_parser("profile", help="Set your platform, versions and team conventions")
    lgp.add_argument("--platform", choices=PLATFORMS)
    for key in ("kubernetes", "openshift", "helm", "rhacs", "rosa"):
        lgp.add_argument(f"--{key}", metavar="X.Y", help=f"{key} version")
    lgp.add_argument("--convention", action="append", dest="conventions", help="repeat for several")

    mem = sub.add_parser(
        "memory",
        help="Your team's fixes as code: reviewed entries in your own repository, validated and matched",
        description="A memory repository holds entries/MEM-<n>.yaml, one per lesson. kube-noob reads it locally and "
        "never uploads, bundles or exports it. Example: kube-noob memory match 'etcd leader changed' --dir ./memory",
    )
    msub = mem.add_subparsers(dest="memory_cmd", required=True)
    _patch(msub, common)
    mi = msub.add_parser("init", help="Scaffold a repository: README, schema, entries/, CI templates (keeps files)")
    mi.add_argument("dir")
    madd = msub.add_parser("add", help="Write a proposed entry (never commits; review it in a pull request)")
    madd.add_argument("dir")
    madd.add_argument("--symptom", required=True)
    madd.add_argument("--cause", required=True)
    madd.add_argument("--fix", required=True)
    madd.add_argument("--kind", choices=["fix", "negative", "runbook"], default="fix")
    madd.add_argument("--signal", action="append", default=[], help="kind:name, e.g. alert:etcdNoLeader (repeat)")
    madd.add_argument("--command", action="append", default=[], dest="commands", help="one command (repeat)")
    madd.add_argument("--platform", choices=PLATFORMS)
    madd.add_argument("--introduced", metavar="X.Y[.Z]")
    madd.add_argument("--fixed-in", dest="fixed_in", metavar="X.Y[.Z]")
    madd.add_argument("--owner", action="append", default=[], dest="owners", help="team or person (repeat)")
    madd.add_argument("--source", action="append", default=[], dest="sources", help="https URL (repeat)")
    mval = msub.add_parser("validate", help="Schema, duplicates, review dates, credentials and the fix verifier")
    mval.add_argument("dir")
    mval.add_argument("--strict", action="store_true", help="passed review dates are errors")
    mm = msub.add_parser("match", help="Entries for an error, an alert payload or a symptom (approved only)")
    mm.add_argument("text", nargs="*", help="the error or symptom, in quotes")
    mm.add_argument("-f", "--file", default=None, help="a file (e.g. an Alertmanager payload), or '-' for stdin")
    mm.add_argument(
        "--dir", action="append", default=[], dest="dirs", help="memory repository (repeat); default: memory.paths"
    )
    mm.add_argument("--version", dest="pversion", help="your OpenShift version: entries fixed there show as retired")
    mm.add_argument("--platform", choices=PLATFORMS)
    mm.add_argument("--operator", action="append", default=[], help="name=version of an installed operator (repeat)")
    mm.add_argument("--include-proposed", action="store_true")
    mm.add_argument("--limit", type=int, default=5)
    mo = msub.add_parser("outcome", help="Record that an entry was applied, and how it went")
    mo.add_argument("dir")
    mo.add_argument("entry_id", metavar="MEM-N")
    mo.add_argument("--result", required=True, choices=["resolved", "partial", "not-resolved"])
    mo.add_argument("--ticket", help="an opaque ticket reference, e.g. INC-4211")
    mo.add_argument("--cluster", help="a cluster label, e.g. prod-east")
    mo.add_argument("--date", dest="when", metavar="YYYY-MM-DD")
    mst = msub.add_parser("stats", help="Entries and outcomes, optionally per cluster, signal or component")
    mst.add_argument("dir")
    mst.add_argument("--by", choices=["cluster", "signal", "component"])
    mimp = msub.add_parser(
        "import",
        help="Turn resolved tickets from a ServiceNow or Jira export into proposed entries (people removed)",
    )
    mimp.add_argument("dir")
    mimp.add_argument(
        "--from",
        dest="ticket_format",
        required=True,
        choices=["servicenow-json", "servicenow-csv", "jira-json", "jira-csv"],
        help="the export's format (--format stays the output format)",
    )
    mimp.add_argument("-f", "--file", required=True, help="the export file, or '-' for stdin")
    mimp.add_argument("--platform", choices=PLATFORMS)
    mimp.add_argument("--owner", default="unassigned")
    mimp.add_argument("--cluster", help="a cluster label for every imported outcome, e.g. prod-east")
    mimp.add_argument("--dry-run", action="store_true", help="show what would be written; write nothing")
    mrp = msub.add_parser(
        "replay",
        help="Would memory have helped? Replay tickets in date order and report hits, misses and useful matches",
    )
    mrp.add_argument("--memory", required=True, help="the memory repository")
    mrp.add_argument("--tickets", required=True, help="the ticket export to replay")
    mrp.add_argument(
        "--from",
        dest="ticket_format",
        required=True,
        choices=["servicenow-json", "servicenow-csv", "jira-json", "jira-csv"],
        help="the export's format (--format stays the output format)",
    )
    mrp.add_argument("--labels", help="YAML: ticket ref -> true/false (was the match useful?)")
    mrp.add_argument("--as-of-ticket-date", action="store_true", help="only entries created before each ticket count")
    mrp.add_argument("--approved-only", action="store_true", help="ignore proposed entries")
    mrp.add_argument("--out", help="directory for report.md and report.json")
    mmig = msub.add_parser("migrate-learning", help="Turn confirmed learning notes into proposed entries (once)")
    mmig.add_argument("dir")
    mmig.add_argument("--owner", default="unassigned")

    ask = sub.add_parser("ask", help="Optional: ask a model you configure, which calls these tools")
    ask.add_argument("question")

    sub.add_parser("mcp", help="Run the MCP server over stdio")
    sv = sub.add_parser("serve", help="Run the MCP server over streamable HTTP (sidecar/service)")
    sv.add_argument("--host")
    sv.add_argument("--port", type=int)
    sv.add_argument("--allow-unauthenticated", action="store_true")
    sv.add_argument("--watch", action="store_true", help="also run the incident watch (watch.enabled)")

    c = sub.add_parser("corpus", help="Build / inspect the local corpus (network: maintainers & CI)")
    csub = c.add_subparsers(dest="corpus_cmd", required=True)
    _patch(csub, common)
    cb = csub.add_parser("build", help="Ingest public Git sources")
    cb.add_argument("--sources", default="all", help="comma-separated source ids or 'all'")
    cb.add_argument("--limit-per-source", type=int)
    cb.add_argument("--online", action="store_true", help="Required: confirm network ingestion")
    cj = csub.add_parser(
        "jira",
        help="Keep a local copy of Red Hat's public Jira tickets (every status), through its REST API",
        description="Copy every ticket of the chosen projects, whatever its status, into the data folder and index "
        "it for known-issues, diagnose and the incident watch. Paced at one request per second or slower; "
        "--max-requests caps a run and the next run resumes. The copy is not redistributable and never leaves "
        "this machine.",
    )
    cj.add_argument(
        "--projects", help="default (Kubernetes, OpenShift, ROSA, ACM, RHACS), all, or keys such as OCPBUGS,ROX"
    )
    cj.add_argument("--max-requests", type=int, help="request budget for this run (default jira.maxRequests)")
    cj.add_argument("--online", action="store_true")
    cjs = csub.add_parser(
        "jira-snapshot",
        help="Pack the local Jira copy (tickets, sync state, change log) into one file other installs import",
    )
    cjs.add_argument("-o", "--out", default="jira-snapshot.tgz", help="output file (keep it inside your organisation)")
    cjc = csub.add_parser(
        "jira-changes",
        help="Reconcile: tickets fixed, closed, reopened or opened since a date, and the open tickets by project",
    )
    cjc.add_argument("--since", default="2d", help="2d, 36h, 90m or a date such as 2026-10-25 (default 2d)")
    cjc.add_argument("--project", help="one project key, e.g. OCPBUGS")
    cjc.add_argument("--kind", action="append", default=[], help="fixed, not-a-bug, reopened, opened... (repeat)")
    cjc.add_argument("--limit", type=int, default=100)
    cja = csub.add_parser(
        "jira-audit",
        help="What the local Jira copy holds: tickets, comments kept, cut or older tickets, key coverage, and a check "
        "that no people are left in it",
    )
    cja.add_argument("--project", help="one project key, e.g. OCPBUGS")
    cjp = csub.add_parser("jira-projects", help="List the projects on Red Hat's public Jira, marking the default set")
    cjp.add_argument("--online", action="store_true")
    ch = csub.add_parser("history", help="Release timelines from Git tags")
    ch.add_argument("--online", action="store_true")
    cav = csub.add_parser(
        "advisories",
        help="Red Hat CSAF VEX statements (CC BY 4.0) for OpenShift, RHACS, ACM, layered products and RHEL 8/9",
        description="Per CVE: severity, CVSS and each component's status per product (fixed with the erratum, "
        "affected, not affected with the VEX justification, under investigation). Paced one request a second plus "
        "jitter. Examples: kube-noob corpus advisories --online --cves CVE-2023-44487; kube-noob corpus advisories "
        "--online --since 2026-10-27; kube-noob corpus advisories --from-archive csaf_vex.tar.zst",
    )
    cav.add_argument("--online", action="store_true")
    cav.add_argument("--cves", help="comma-separated CVE ids")
    cav.add_argument("--since", help="every CVE whose VEX changed after this date or time (from changes.csv)")
    cav.add_argument("--from-archive", help="a downloaded VEX archive (.tar.zst, .tar.gz or a folder), read offline")
    cav.add_argument("--max-requests", type=int, default=3000)
    cav.add_argument("--replace", action="store_true", help="start the shard over instead of merging")
    cki = csub.add_parser("known-issues", help="Refresh reported OpenShift issues from the release notes (Git)")
    cki.add_argument("--minors", default="4.20,4.21,4.22", help="comma-separated OpenShift minor releases")
    cki.add_argument("--online", action="store_true")
    csub.add_parser("stats")
    csub.add_parser("verify")
    cad = csub.add_parser("add-docs", help="Index your own runbooks (Markdown/AsciiDoc/text folder), offline")
    cad.add_argument("path", help="folder with .md, .adoc, .txt or .rst files (for example a cloned wiki)")
    cad.add_argument("--source", required=True, help="short name, e.g. platform-runbooks")
    cad.add_argument("--base-url", help="link prefix for citations, e.g. https://git.example.com/runbooks/blob/main")
    ci = csub.add_parser(
        "import", help="Import a corpus directory or .tgz (the corpus-refresh artifact, a Jira snapshot, kube-noob-db)"
    )
    ci.add_argument("path")
    ci.add_argument("--key-file", help="the key of a sealed snapshot (default: $KUBE_NOOB_SEED_KEY_FILE)")
    for name, what in (("seal", "Seal"), ("unseal", "Open")):
        cs = csub.add_parser(
            name,
            help=f"{what} a Jira snapshot with your organisation's key (AES-256-GCM, a key file of 16+ characters)",
            description="Example: openssl rand -base64 32 > seed.key && kube-noob corpus seal jira-snapshot.tgz -o "
            "jira-snapshot.tgz.enc --key-file seed.key",
        )
        cs.add_argument("path")
        cs.add_argument("-o", "--output", required=True)
        cs.add_argument("--key-file", help="default: $KUBE_NOOB_SEED_KEY_FILE")
    cdb = csub.add_parser(
        "db-bundle",
        help="Pack what may be shared (redistributable docs, release history, known issues) into kube-noob-db.tgz",
        description="Shards marked not redistributable and every Jira shard are left out; the archive is checked "
        "before it is written. Example: kube-noob corpus db-bundle -o dist/kube-noob-db.tgz",
    )
    cdb.add_argument("-o", "--output", default="kube-noob-db.tgz", help="the archive to write")
    cdc = csub.add_parser(
        "db-check",
        help="Check a kube-noob-db archive or folder: redistributable records on allowed licenses only, no Jira data, "
        "every file listed with its checksum (exit 1 on any problem)",
    )
    cdc.add_argument("path")

    t = sub.add_parser("train", help="Training enforcer, credit system and dataset export")
    tsub = t.add_subparsers(dest="train_cmd", required=True)
    _patch(tsub, common)
    te = tsub.add_parser("export", help="Export SFT + GRPO datasets")
    te.add_argument("--out", default="dataset")
    te.add_argument(
        "--include-restricted",
        action="store_true",
        help="Include non-redistributable corpus records (local/private training only)",
    )
    te.add_argument("--synthetic-limit", type=int)
    tg = tsub.add_parser("grade", help="Grade a completion against a benchmark task")
    tg.add_argument("--task", required=True)
    tg.add_argument("-f", "--file", required=True)
    tb = tsub.add_parser("bench", help="Run the benchmark through the configured LLM")
    tb.add_argument("--tasks", help="comma-separated task ids")
    tb.add_argument("--no-tools", action="store_true")
    tb.add_argument("--out")
    tsub.add_parser("tasks", help="List benchmark tasks")

    sub.add_parser("config", help="Show the effective configuration")
    cmp_p = sub.add_parser(
        "completion",
        help="Print a shell completion script (bash, zsh or fish), generated from this CLI",
        description="Print a completion script for your shell. It is walked off the parser at the moment you run "
        "it, so it lists the commands this build actually has. bash: source <(kube-noob completion bash). "
        'zsh: kube-noob completion zsh > "${fpath[1]}/_kube-noob". fish: kube-noob completion fish > '
        "~/.config/fish/completions/kube-noob.fish",
    )
    cmp_p.add_argument("shell", choices=list(completion.SHELLS))
    sub.add_parser("doctor", help="Show what kube-noob can reach (network, cluster, model); exit 1 on conflicts")
    st = sub.add_parser("selftest", help="Answer a battery of real questions offline and score the results")
    st.add_argument("--category", choices=["kubernetes", "helm", "openshift", "rosa-hcp", "rhacs", "everyday"])
    st.add_argument(
        "--cases",
        help="your own problems instead of the built-in battery: YAML, JSONL, CSV, or plain text (one per line, "
        "or blocks separated by ---)",
    )
    st.add_argument("--gate", type=float, help="with --cases: fail (exit 1) when the pass rate is below this, 0-1")
    st.add_argument("--out", help="with --cases: write report.md and report.json to this folder")
    dm = sub.add_parser("demo", help="Offline walkthroughs of common use cases (no network, no cluster)")
    dm.add_argument("scenario", nargs="?", help="scenario name or 'all' (see --list)")
    dm.add_argument("--list", action="store_true", dest="list_demos")
    return p


def _settings(a: argparse.Namespace) -> Settings:
    overrides: dict[str, Any] = {}
    if a.web_enabled:
        overrides["webEnabled"] = True
    if a.cluster_enabled:
        overrides["cluster"] = {"enabled": True}
    return load_settings(a.config, overrides)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    a = parser.parse_args(argv)
    if a.cmd == "hook" and a.hook_cmd == "claude-code":
        # Before the configuration is read and outside the error handling below: the hook answers in Claude Code's
        # protocol, where 2 blocks and every other non-zero code lets the command through. A configuration error
        # mapped to 4 here would have been a pass.
        try:
            from kube_noob import hook

            return hook.main(options=hook.Options(platform=a.platform, version=a.pversion, fail_on=a.fail_on))
        except BaseException:  # noqa: BLE001 - any failure here is a blocked command, never exit 1 (a pass)
            import contextlib

            with contextlib.suppress(OSError, ValueError):
                sys.stderr.write("kube-noob hook failed; the command is blocked.\n")
            return 2
    for key, value in GLOBAL_DEFAULTS.items():
        if not hasattr(a, key):
            setattr(a, key, value)
    if a.format == "sarif" and a.cmd != "audit":
        # `--format` is shared by every command, so argparse accepts this. Printing YAML under the name would hand
        # a caller a file called .sarif that is not SARIF; the gate writes its own with `gate --sarif PATH`.
        print(
            f"error: --format sarif is for `kube-noob audit`; `{a.cmd}` has no findings to put in a SARIF document "
            "(the gate writes one with `kube-noob gate --sarif PATH`)",
            file=sys.stderr,
        )
        return 2
    if a.format == "sarif" and getattr(a, "oscal", False):
        print("error: --oscal and --format sarif each replace the report; ask for one document", file=sys.stderr)
        return 2
    try:
        s = _settings(a)
        return _dispatch(a, s)
    except ClarificationNeeded as exc:
        _emit({"status": "needs-clarification", "questions": exc.questions}, "yaml" if a.format == "text" else a.format)
        return 3
    except (ConfigError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (KubeNoobError, KeyError, ValueError) as exc:
        msg = exc.args[0] if isinstance(exc, KeyError) and exc.args else exc
        print(f"error: {msg}", file=sys.stderr)
        return 4
    except BrokenPipeError:
        # `kube-noob ... | head`: the reader went away; exit quietly like other CLI tools.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 141


def _dispatch(a: argparse.Namespace, s: Settings) -> int:
    from kube_noob import toolkit as tk
    from kube_noob.signals import alertmanager

    kit = tk.Toolkit(s)
    fmt = "yaml" if a.format == "text" else a.format
    platform = getattr(a, "platform", None) or s.default_platform

    if a.cmd == "completion":
        print(completion.script(a.shell, build_parser()), end="")
        return 0
    if a.cmd in {"audit", "validate", "redteam", "fix"}:
        text, unreadable, sources = _manifest_sources(a)
        if unreadable and not getattr(a, "skip_unreadable", False):
            _refuse_unreadable(unreadable)
            return 5
        if a.cmd in {"audit", "validate", "redteam"}:
            from kube_noob.audit.engine import refuse_if_not_manifests

            refuse_if_not_manifests(text)
        if a.cmd == "audit":
            from kube_noob.audit.exceptions import ExceptionsError

            exceptions = _read(a.exceptions) if a.exceptions else None
            try:
                rep = kit.audit(
                    tk.AuditIn(
                        manifests=text,
                        platform=platform,
                        version=a.pversion,
                        min_severity=a.min_severity,
                        exceptions=exceptions,
                        partial_bundle=_partial_input(a),
                        cni=a.cni,
                    )
                )
            except ExceptionsError as exc:
                raise ConfigError(f"{a.exceptions}: {exc}") from exc
            rep["unreadable"] = unreadable
            # Before anything is printed or emitted, and before OSCAL and the compact form are built from it:
            # they all carry the line numbers (G251).
            _locate(rep, sources)
            if a.oscal:
                from kube_noob.oscal import assessment_results, check_import_ap

                # The flag REPLACES the report: a caller asking for OSCAL wants a document it can hand to a
                # tool, not a document with a human report printed above it. The exit code is unchanged, so a
                # gate reads the same verdict with the flag as without.
                check_import_ap(a.oscal_import_ap)
                _emit(assessment_results(rep, import_ap=a.oscal_import_ap), "json" if a.format == "text" else fmt)
                # The document names the skipped files in its remarks, and the operator still gets the notice
                # on stderr: a partial audit must not look clean on either channel.
                for b in unreadable:
                    print(f"not read: {b['path']} ({b['why']})", file=sys.stderr)
            elif a.format == "sarif":
                from kube_noob.gate import sarif_of_audit

                # The document carries what was not read and not evaluated as notifications, and the operator
                # still gets the notice on stderr: a partial audit must not look clean on either channel.
                print(json.dumps(sarif_of_audit(rep), indent=2))
                for b in unreadable:
                    print(f"not read: {b['path']} ({b['why']})", file=sys.stderr)
            elif a.format == "text":
                _print_report(rep)
                _print_exceptions(rep)
                for b in unreadable:
                    print(f"not read: {b['path']} ({b['why']})", file=sys.stderr)
            elif a.compact:
                from kube_noob.audit.compact import compact_report

                # Compact the emitted copy only. The exit code below is computed from `rep`, where every finding
                # still carries its severity -- a gate must read the same verdict whether or not this flag is on.
                _emit(compact_report(rep), fmt)
            else:
                _emit(rep, fmt)
            if rep.get("exceptions") and not rep["exceptions"]["gate"]:
                return 1
            if a.fail_on == "never":
                return 0
            from kube_noob.audit.model import Severity

            limit = Severity.parse(a.fail_on)
            return 1 if any(Severity.parse(f["severity"]) >= limit for f in rep["findings"]) else 0
        if a.cmd == "validate":
            rep = kit.validate(tk.ManifestsIn(manifests=text, platform=platform, version=a.pversion))
            _locate(rep, sources)
            _print_report(rep) if a.format == "text" else _emit(rep, fmt)
            return 1 if rep["summary"]["counts"]["high"] + rep["summary"]["counts"]["critical"] else 0
        if a.cmd == "redteam":
            _emit(kit.red_team(tk.ManifestsIn(manifests=text, platform=platform, version=a.pversion)), fmt)
            return 0
        res = kit.fix(tk.FixIn(manifests=text, platform=platform, version=a.pversion, harden=not a.no_harden))
        if len(sources) > 1:
            # One stream out of several files in, and the file boundaries are gone: a caller who redirected
            # this over their directory would have one file where they had five. Said on stderr, where the
            # summary already goes, rather than refused -- the output is still correct YAML (G251).
            print(
                f"note: {len(sources)} files were read and one stream was written, so the file boundaries are "
                f"not preserved ({', '.join(p for p, _ in sources[:3])}"
                f"{' and more' if len(sources) > 3 else ''}). Run `fix` per file to keep them.",
                file=sys.stderr,
            )
        if a.output:
            Path(a.output).write_text(res["manifests"], encoding="utf-8")
        else:
            print(res["manifests"], end="")
        print(
            yaml.safe_dump(
                {"changes": res["changes"], "manualFollowUps": res["manualFollowUps"], "after": res["after"]},
                sort_keys=False,
            ),
            file=sys.stderr,
        )
        return 0

    if a.cmd == "protocol":
        bp = yaml.safe_load(_read(a.blueprint)) if a.blueprint else None
        out = kit.run_protocol(
            tk.ProtocolIn(
                request=a.request,
                manifests=_read(a.file) if a.file else None,
                blueprint=bp,
                platform=getattr(a, "platform", None),
                version=a.pversion,
                apply_fixes=not a.no_fix,
            )
        )
        if a.format == "text" and out.get("status") in {"ready", "blocked"}:
            brief = out["auditValidationBrief"]
            print("## Audit & Validation Brief")
            print(yaml.safe_dump(brief, sort_keys=False), end="")
            print("\n## Production Manifest")
            print(out["productionManifest"], end="")
            print("\n## Red Team Findings & Safeguards")
            print(yaml.safe_dump(out["redTeamFindingsAndSafeguards"], sort_keys=False), end="")
            print("\n## Validate in the cluster")
            print("\n".join(out["validationCommands"]))
        else:
            _emit(out, fmt)
        return {"ready": 0, "blocked": 1, "needs-clarification": 3}.get(out["status"], 0)

    if a.cmd in {"generate", "helm-chart"}:
        from kube_noob.generate.blueprint import Blueprint

        bp_model = Blueprint.model_validate(_blueprint_from_args(a))
        if a.cmd == "generate":
            out = kit.generate(tk.BlueprintIn(blueprint=bp_model))
            if out["status"] != "ok":
                _emit(out, fmt)
                return 3
            if a.output:
                Path(a.output).write_text(out["manifests"], encoding="utf-8")
            else:
                print(out["manifests"], end="")
            print(
                yaml.safe_dump({k: out[k] for k in ("assumptions", "prerequisites", "audit")}, sort_keys=False),
                file=sys.stderr,
            )
            return 0
        from kube_noob.generate.helm import generate_chart

        info = generate_chart(bp_model, a.output or ".")
        _emit({k: v for k, v in info.items() if k != "renderedManifests"}, fmt)
        return 0

    if a.cmd == "helm-audit":
        from kube_noob.generate.helm_render import audit_chart

        chart_report, lint = audit_chart(a.chart, a.platform, a.pversion, a.values, a.namespace)
        d = chart_report.as_dict()
        d["chartLint"] = lint
        _print_report(d) if a.format == "text" else _emit(d, fmt)
        for issue in lint:
            print(f"[CHART] {issue}")
        top = chart_report.max_severity()
        return 1 if top is not None and top >= 3 else 0

    if a.cmd == "insight":
        from kube_noob import insight as insight_mod

        if a.text and a.file is not None:
            raise ConfigError("pass the text or -f, not both")
        if a.file not in (None, "-") and Path(a.file).is_file():
            data = Path(a.file).read_bytes()[: insight_mod.MAX_TEXT]
            kinds = insight_mod.recognise_bytes(data)
            if [k.kind for k in kinds] == ["packet-capture"]:
                pcap: dict[str, Any] = {
                    "kinds": [k.as_dict() for k in kinds],
                    "ran": [],
                    "findings": [],
                    "skipped": [{"kind": "packet-capture", "why": insight_mod.PENDING["packet-capture"]}],
                }
                _emit(pcap, fmt) if a.format != "text" else _print_insight(pcap)
                return 0
            text = data.decode("utf-8", errors="replace")
        else:
            text = "\n".join(a.text) if a.text else _read_text_or_file(a.file if a.file is not None else "-", "insight")
        if len(text.strip()) < 3:
            raise ConfigError("nothing to read: pass the text in quotes, a file with -f, or pipe it in")
        found = kit.insight(tk.InsightIn(text=text[-tk.MAX_DIAGNOSE_TEXT :], platform=a.platform, version=a.pversion))
        if a.format == "text":
            _print_insight(found)
        else:
            _emit(found, fmt)
        return 0
    if a.cmd == "diagnose":
        if a.text and a.file is not None:
            raise ConfigError("pass the text or -f, not both")
        text = "\n".join(a.text) if a.text else _read_text_or_file(a.file if a.file is not None else "-")
        if len(text.strip()) < 3:
            raise ConfigError("nothing to diagnose: pass the error text in quotes, a file with -f, or pipe it in")
        if len(text) > tk.MAX_DIAGNOSE_TEXT:  # a long Alertmanager payload keeps every alert's labels and summary
            text = alertmanager.compact(text) or text[-tk.MAX_DIAGNOSE_TEXT :]
        _emit(
            kit.diagnose(
                tk.DiagnoseIn(text=text, platform=getattr(a, "platform", None), version=getattr(a, "pversion", None))
            ),
            fmt,
        )
        return 0

    if a.cmd == "known-issues":
        if a.text and a.file is not None:
            raise ConfigError("pass the text or -f, not both")
        text = "\n".join(a.text) if a.text else _read_text_or_file(a.file if a.file is not None else "-")
        if len(text.strip()) < 3:
            raise ConfigError("nothing to match: pass the error text in quotes, a file with -f, or pipe it in")
        out = kit.known_issues(tk.KnownIssuesIn(text=text, platform=a.platform, version=a.pversion, limit=a.limit))
        if a.format == "text":
            _print_known_issues(out)
        else:
            _emit(out, fmt)
        return 0

    if a.cmd == "ksi":
        # Delegated to the toolkit rather than audited here. Two implementations of one view is what N14 was:
        # this command and the `fedramp_ksi` tool each audited the bundle their own way, so the same files gave
        # two sets of numbers -- and the fix for one would not have been the fix for the other (G246). What the
        # command still owns is its input pipeline: `--skip-unreadable`, and an unreadable file that must exit 5
        # and be named rather than dropped.
        from pydantic import ValidationError

        from kube_noob.audit.exceptions import ExceptionsError

        manifests: str | None = None
        not_read: list[dict[str, str]] = []
        if a.file:
            manifests, not_read = _manifest_input(a)
            if not_read and not a.skip_unreadable:
                _refuse_unreadable(not_read)
                return 5
        try:
            out = kit.fedramp_ksi(
                tk.KsiIn(
                    manifests=manifests,
                    platform=a.platform or s.default_platform,
                    version=a.pversion,
                    cni=a.cni,
                    partial_bundle=_partial_input(a) if a.file else False,
                    indicator=a.indicator,
                    control=a.control,
                    evidenced_only=a.evidenced_only,
                    exceptions=_read(a.exceptions) if a.exceptions else None,
                    min_severity=a.min_severity,
                )
            )
        except ExceptionsError as exc:
            raise ConfigError(f"{a.exceptions}: {exc}") from exc
        except ValidationError as exc:
            # An over-long --indicator or --version used to escape as a raw pydantic error and exit 4, where
            # the same flag with an unknown value exits 2 with a sentence. One front door, one exit code for a
            # bad flag (G249).
            detail = "; ".join(str(e["msg"]).removeprefix("Value error, ") for e in exc.errors())
            raise ConfigError(detail or str(exc)) from exc
        if not_read:
            out["unreadable"] = not_read
        _write_html(a.html, out)
        if a.format == "text":
            _tprint(_ksi_markdown(out, audited=bool(a.file)))
            _print_exceptions(out)
        else:
            _emit(out, fmt)
        # The exception gate decides the exit code here as it does for `audit`: the page already printed
        # "gate: failed" for an expired or refused entry, and saying so while exiting 0 is two answers (G249).
        gate = (out.get("exceptions") or {}).get("gate")
        return 0 if gate is not False else 1

    if a.cmd == "upgrade-risks":
        from pydantic import ValidationError

        try:
            req = tk.UpgradeRisksIn(current=a.from_version, target=a.to_version, arch=a.arch)
        except ValidationError as exc:
            flags = {"current": "--from", "target": "--to", "arch": "--arch"}
            reasons = []
            for e in exc.errors():
                where = ", ".join(flags.get(str(x), str(x)) for x in e["loc"])
                msg = str(e["msg"]).removeprefix("Value error, ")
                reasons.append(f"{where}: {msg}" if where else msg)
            raise ConfigError("; ".join(reasons)) from exc
        out = kit.upgrade_risks(req)
        if a.format == "text":
            _print_upgrade_risks(out)
        else:
            _emit(out, fmt)
        return 0

    if a.cmd == "signals":
        if a.text and a.file is not None:
            raise ConfigError("pass the text or -f, not both")
        text = "\n".join(a.text) if a.text else _read_text_or_file(a.file if a.file is not None else "-")
        if len(text) > tk.MAX_SIGNAL_TEXT:
            text = alertmanager.compact(text) or text[-tk.MAX_SIGNAL_TEXT :]
        out = kit.extract_signals(tk.SignalsIn(text=text))
        if a.format == "text":
            for x in out["signals"]:
                detail = f"  {x['detail']}" if x.get("detail") else ""
                _tprint(f"{x['kind']:15} {x['name']}{detail}")
            for x in out["implied"]:
                _tprint(f"{x['kind']:15} {x['name']}  implied by '{x['detail']}'")
            if out["playbooks"]:
                _tprint(f"playbooks: {', '.join(out['playbooks'])}")
            if not out["signals"] and not out["implied"]:
                print("no signals found")
        else:
            _emit(out, fmt)
        return 0

    if a.cmd == "ticket":
        out = kit.ticket(tk.TicketIn(key=a.key, version=a.pversion))
        if a.format != "text":
            _emit(out, fmt)
        elif not out.get("found"):
            _tprint(out["note"])
        else:
            _tprint(f"{out['id']}  {out['summary']}")
            resolution = out["resolution"] or "Unresolved"
            _tprint(f"  {out['type']} | {out['jiraStatus']} | {resolution} | updated {out['updated'] or 'unknown'}")
            _tprint(f"  {out['status']}")
            _print_ticket_lines(out)
            for link in out.get("related") or []:
                _tprint(f"  {link['relation']} {link['key']}")
            _tprint(f"  {out['url']}  ({out['source']})")
        return 0 if out.get("found") else 1

    if a.cmd == "policy":
        return _policy(a, s, kit, fmt)

    if a.cmd == "posture":
        return _posture(a, s, fmt)
    if a.cmd == "operators":
        return _operators_cmd(a, s, fmt)
    if a.cmd == "exceptions":
        return _exceptions_cmd(a, fmt)
    if a.cmd == "rhacs":
        return _rhacs_cmd(a, s, fmt)
    if a.cmd == "vuln":
        return _vuln_cmd(a, s, fmt)
    if a.cmd == "code":
        return _code_cmd(a, s, fmt)
    if a.cmd == "must-gather":
        from kube_noob.mustgather import analyse, ingest
        from kube_noob.mustgather import report as mg_report

        try:
            bundle = ingest.open_bundle(Path(a.path))
        except ingest.MustGatherError as exc:
            raise ConfigError(str(exc)) from exc
        if a.case_draft and not a.report:
            raise ConfigError("--case-draft needs --report DIR")
        analysis = analyse.analyse(bundle)
        rep = mg_report.build(
            bundle, analysis, data_dir=s.data_dir, memory_dirs=[Path(m) for m in s.memory.paths] or None
        )
        written = []
        if a.report:
            try:
                written = mg_report.write(rep, Path(a.report), draft=a.case_draft)
            except (OSError, ValueError) as exc:
                raise ConfigError(f"--report {a.report}: {exc}") from exc
        from kube_noob import operators
        from kube_noob.mustgather import operators as mg_operators

        inventory = operators.inventory(mg_operators.collect(bundle))
        if a.format == "text":
            text = ingest.render_text(bundle) + "\n" + analyse.render_text(analysis)
            for m in rep["knownIssues"]:
                text += f"\nknown issue {m['id']} ({m.get('status') or ''}): {m.get('summary') or ''}"[:300]
            for m in rep["memory"]:
                text += f"\nteam memory [mem:{m['id']}]: {m.get('symptom', '')}"[:300]
            for path in written:
                text += f"\nwrote {path}"
            _tprint(text + "\n" + operators.render_text(inventory))
        else:
            _emit({**bundle.as_dict(), **rep, "operatorInventory": inventory}, fmt)
        if analyse.failing(analysis, a.fail_on):
            return 1
        # A gate that passes on evidence nobody could read is a false all-clear, and exit 0 cannot say which one it
        # was. 5 rather than 2: 1 is findings at or above --fail-on, and 2, 3 and 4 already mean a config or missing
        # file, a clarification, and a refused input. 5 means the run itself is not trustworthy enough to act on.
        if getattr(a, "require_complete", False) and not analysis.completeness()["complete"]:
            c = analysis.completeness()
            print(
                f"refusing a clean verdict: {c['analysersRead']} of {c['analysersExpected']} analysers had data and "
                f"{c['unreadableFiles']} file(s) could not be read",
                file=sys.stderr,
            )
            return 5
        return 0
    if a.cmd == "admission":
        return _admission_cmd(a, s, fmt)
    if a.cmd == "build":
        return _build_cmd(a, kit, fmt)
    if a.cmd == "gate":
        return _gate_cmd(a, s, fmt)
    if a.cmd == "watch":
        return _watch(a, s, fmt)

    if a.cmd == "incidents":
        return _incidents(a, kit, fmt)

    if a.cmd == "bundle":
        from kube_noob.debug.diagnose import bundle_markdown

        kind, _, name = a.target.partition("/")
        if not name:
            raise ConfigError("target must be kind/name, e.g. deployment/orders-api")
        if not s.cluster.enabled:
            raise ConfigError("a bundle needs read-only cluster access: pass --cluster-enabled or set cluster.enabled")
        result = kit.cluster_debug(
            tk.ClusterDebugIn(
                namespace=a.namespace, kind=kind.lower(), name=name, platform=getattr(a, "platform", None)
            )
        )
        bundle_dir = Path(a.out)
        bundle_dir.mkdir(parents=True, exist_ok=True)
        (bundle_dir / "bundle.json").write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        (bundle_dir / "bundle.md").write_text(bundle_markdown(result), encoding="utf-8")
        _emit(
            {"bundle": str(bundle_dir), "files": ["bundle.md", "bundle.json"], "diagnoses": len(result["diagnoses"])},
            fmt,
        )
        return 0

    if a.cmd == "debug":
        kind, _, name = a.target.partition("/")
        if not name:
            raise ConfigError("target must be kind/name, e.g. deployment/orders-api")
        if not s.cluster.enabled:
            raise ConfigError("live debugging needs cluster access: pass --cluster-enabled or set cluster.enabled")
        _emit(
            kit.cluster_debug(
                tk.ClusterDebugIn(
                    namespace=a.namespace, kind=kind.lower(), name=name, platform=getattr(a, "platform", None)
                )
            ),
            fmt,
        )
        return 0

    if a.cmd == "search":
        _emit(kit.search(tk.SearchIn(query=a.query, limit=a.limit, source=a.source)), fmt)
        return 0
    if a.cmd == "rules":
        _emit(kit.rules(tk.EmptyIn()), fmt)
        return 0
    if a.cmd == "explain":
        _emit(kit.explain(tk.RuleIn(rule_id=a.rule_id)), fmt)
        return 0

    if a.cmd == "learn":
        lc = a.learn_cmd
        if lc == "tracks":
            _emit(kit.tracks(tk.LearnerIn(learner=a.learner)), fmt)
        elif lc == "lesson":
            out = kit.lesson(tk.LessonIn(lesson_id=a.lesson_id, learner=a.learner))
            if a.format == "text":
                print(f"# {out['title']}\n\n{out['content']}\n")
                for c in out["citations"]:
                    print(f"- source: {c.get('title')} {c.get('url') or ''} ({c.get('license')})")
            else:
                _emit(out, fmt)
        elif lc == "exercise":
            _emit(kit.exercise(tk.ExerciseIn(exercise_id=a.exercise_id)), fmt)
        elif lc == "submit":
            res = kit.submit(tk.SubmitIn(exercise_id=a.exercise_id, answer=_read(a.file), learner=a.learner))
            _emit(res, fmt)
            return 0 if res["passed"] else 1
        elif lc == "quiz":
            _emit(kit.quiz(tk.QuizIn(question_id=a.question_id, choice=a.choice, learner=a.learner)), fmt)
        elif lc == "progress":
            _emit(kit.progress(tk.LearnerIn(learner=a.learner)), fmt)
        return 0

    if a.cmd == "learning":
        return _learning(a, kit, fmt)

    if a.cmd == "memory":
        return _memory(a, s, kit, fmt)

    if a.cmd == "ask":
        from kube_noob.agent.loop import Agent

        answer_res = Agent(s).ask(a.question)
        if a.format == "text":
            print(answer_res.answer)
            for n in answer_res.notes:
                print(f"\n[note] {n}", file=sys.stderr)
            if answer_res.invalid_citations:
                print(f"\n[warning] invalid citations: {answer_res.invalid_citations}", file=sys.stderr)
        else:
            _emit(answer_res.as_dict(), fmt)
        return 0

    if a.cmd == "mcp":
        from kube_noob.server.mcp_app import build_server

        build_server(s).run("stdio")
        return 0

    if a.cmd == "serve":
        import uvicorn

        from kube_noob.server.http import http_app

        if a.host:
            s.server.host = a.host
        if a.port:
            s.server.port = a.port
        from kube_noob.sources import db_bundle
        from kube_noob.sources.jira_snapshot import seed_on_start

        try:  # a pod starts with the public kube-noob-db (docs, known issues) when its image is newer
            db_seeded = db_bundle.seed_on_start(s.data_dir)
        except (OSError, ValueError, KubeNoobError) as exc:
            print(f"kube-noob-db seed not imported: {exc}", file=sys.stderr)
        else:
            if db_seeded:
                print(
                    f"kube-noob-db imported from {db_seeded['seed']} (built {db_seeded['bundle']['builtAt']}): "
                    f"{', '.join(db_seeded['imported'])}",
                    file=sys.stderr,
                )
        try:  # a pod starts with the organisation's Jira copy instead of waiting for a first sync
            seeded = seed_on_start(s.data_dir)
        except (OSError, ValueError, KubeNoobError) as exc:
            print(f"jira seed not imported: {exc}", file=sys.stderr)
        else:
            if seeded:
                print(f"jira seed imported from {seeded['seed']}: {', '.join(seeded['imported'])}", file=sys.stderr)
        app = http_app(s, allow_unauthenticated=a.allow_unauthenticated)
        if a.watch or s.watch.enabled:
            from kube_noob.watch import start_background

            start_background(s)
        if s.jira.sync_enabled:
            from kube_noob.sources.jira import start_background as start_jira_sync

            if s.offline:
                raise ConfigError("jira.syncEnabled downloads tickets; the offline lock forbids it (unset one)")
            sync = start_jira_sync(s)
            print(
                f"jira sync: first run in {sync.first_delay:.0f} s, then every {s.jira.interval_hours} h +/- 10%",
                file=sys.stderr,
            )
        else:
            print("jira sync: off (the copy changes only when a newer seed is imported)", file=sys.stderr)
        if s.posture.report_enabled:
            if not s.cluster.enabled:
                raise ConfigError("posture.reportEnabled reads the cluster: set cluster.enabled (read-only)")
            from kube_noob.drift_schedule import start_background as start_report

            rep = start_report(s)
            print(f"posture report: first in {rep.first_delay:.0f} s, then every 24 h +/- 10%", file=sys.stderr)
        uvicorn.run(
            app,
            host=s.server.host,
            port=s.server.port,
            log_level="info",
            proxy_headers=False,
            server_header=False,
            limit_concurrency=64,  # beyond this, new requests get 503 instead of piling up in memory
            timeout_keep_alive=5,
        )
        return 0

    if a.cmd == "corpus":
        return _corpus(a, s, fmt)
    if a.cmd == "train":
        return _train(a, s, fmt)
    if a.cmd == "config":
        _emit(kit.config_status(tk.EmptyIn()), fmt)
        return 0
    if a.cmd == "selftest" and a.cases:
        from kube_noob.evals import problems

        if a.gate is not None and not 0 <= a.gate <= 1:
            raise ConfigError("--gate is a pass rate from 0 to 1, e.g. 0.9")
        try:
            loaded = problems.load(Path(a.cases))
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
        prep = problems.run_cases(s, loaded, a.gate)
        md = problems.markdown(prep)
        if a.out:
            out_dir = Path(a.out)
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "report.md").write_text(md, encoding="utf-8")
            (out_dir / "report.json").write_text(json.dumps(prep, indent=2, ensure_ascii=False) + "\n", "utf-8")
        if a.format == "text":
            _tprint(md.rstrip())
        else:
            _emit(prep, fmt)
        failed = any(r["status"] in {"fail", "error"} for r in prep["results"])
        if prep["gate"] is not None:
            return 0 if prep["gate"]["passed"] else 1
        return 1 if failed else 0
    if a.cmd == "selftest":
        from kube_noob.evals.selftest import run as run_selftest

        rep = run_selftest(s, a.category)
        if a.format == "text":
            print(f"kube-noob self-test: {rep['passed']}/{rep['total']} passed")
            for cat, r in rep["byCategory"].items():
                print(f"  {cat:11} {r['passed']}/{r['total']}")
            for f in rep["failures"]:
                print(f"FAIL {f['id']} ({f['kind']}): {f['detail']}")
        else:
            _emit(rep, fmt)
        return 0 if not rep["failures"] else 1
    if a.cmd == "verify":
        return _verify_cmd(a, s, fmt)
    if a.cmd == "hook":
        return _hook_install(a, fmt)
    if a.cmd == "demo":
        from kube_noob import demo

        if a.list_demos or not a.scenario:
            if a.format == "text":
                for d in demo.listing():
                    print(f"{d['name']:10} {d['title']}  [{d['for']}]")
                print("\nRun: kube-noob demo <name>   or   kube-noob demo all")
            else:
                _emit(demo.listing(), fmt)
            return 0
        names = list(demo.SCENARIOS) if a.scenario == "all" else [a.scenario]
        for n in names:
            if n not in demo.SCENARIOS:
                raise KeyError(f"unknown demo {n!r}; choose from {', '.join(demo.SCENARIOS)} or 'all'")
            demo.run(n, s)
            print()
        return 0
    if a.cmd == "doctor":
        from kube_noob.knowledge_status import line, status
        from kube_noob.posture import posture, render_text

        report = posture(s)
        # Why here and not in posture(): posture.py ships inside the Claude plugin, which must name no credential
        # variable for a reviewer, and this check has to name one. doctor is CLI-only, so the check lives with it.
        report["conflicts"] = (
            list(report["conflicts"]) + _model_conflicts(s.llm, "llm") + _model_conflicts(s.judge, "judge")
        )
        # posture() set this before the model conflicts existed. Leaving it alone printed `posture: OK` on the
        # first line with `CONFLICT:` on the last, and `"status": "ok"` beside a non-empty list in the JSON --
        # the exact defect this check was added to remove, one line further down the page.
        report["status"] = "conflict" if report["conflicts"] else "ok"
        if a.format == "text":
            print(render_text(report))
            print(f"Knowledge: {line(s.data_dir)}")
        else:
            _emit({**report, "knowledge": status(s.data_dir)}, fmt)
        return 1 if report["conflicts"] else 0
    raise ConfigError(f"unknown command {a.cmd}")


def _model_conflicts(llm: Any, what: str) -> list[str]:
    """What stops this provider answering, worked out without calling anything.

    `doctor` is what someone runs to find out whether the thing is set up, and it printed `posture: OK` with a
    provider configured, no SDK installed and no key set -- while its own help promises "exit 1 on conflicts". Both
    reasons `ask` cannot run are knowable locally: the optional dependency is absent, or the variable holding the
    key is unset. `provider: none` is not a conflict; nothing is meant to run.
    """
    if llm.provider == "none":
        return []
    out: list[str] = []
    if llm.provider == "anthropic" and importlib.util.find_spec("anthropic") is None:
        out.append(
            f"{what}.provider is 'anthropic' but the Anthropic SDK is not installed, so `kube-noob ask` cannot run. "
            "Add it with: uv tool install 'kube-noob[ask]' (a Homebrew install has no way to add the extra)."
        )
    from kube_noob.agent.providers import _PROVIDER_KEY_ENV, key_env

    name = key_env(llm)
    if name is None:
        # No key variable at all is only a conflict for a provider that has a default one. `openai-compatible`
        # points at whatever endpoint the user named -- a local vLLM, an in-cluster model -- and providers.py is
        # explicit that with no apiKeyEnv "the request carries no Authorization header at all". That is the
        # documented no-key path, and the only provider the offline lock allows; refusing it broke a working setup.
        if llm.provider in _PROVIDER_KEY_ENV:
            out.append(
                f"{what}.provider is {llm.provider!r} and no {what}.apiKeyEnv is set, so the request would carry "
                "no credential. Set it to the variable holding this endpoint's key."
            )
    elif not os.environ.get(name):
        out.append(f"{what}.provider is {llm.provider!r} but {name} is not set, so `kube-noob ask` cannot run.")
    return out


_TERMINAL_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _tprint(text: str = "") -> None:
    """Print text that may echo a manifest or a log: control characters (terminal escapes) are dropped."""
    print(_TERMINAL_CONTROL.sub("", text))


def _print_denials(out: dict[str, Any]) -> None:
    for d in out["denials"]:
        name = " / ".join(x for x in (d.get("policy"), d.get("rule")) if x)
        head = (
            f"{d['engineName']}" + (f"  {name}" if name else "") + (f"  ({d['resource']})" if d.get("resource") else "")
        )
        _tprint(("WARN " if d["mode"] == "warn" else "DENY ") + head)
        _tprint(f"  {d['meaning']}")
        if d.get("path"):
            _tprint(f"  at {d['path']}")
        if d.get("readOnlyNextSteps"):
            _tprint("  check (read-only):")
            for step in d["readOnlyNextSteps"]:
                _tprint(f"    {step.get('command') or step.get('instruction')}")
        if d.get("proposedChanges"):
            _tprint("  fix (needs approval):")
            for c in d["proposedChanges"]:
                _tprint(f"    - {c['change']}")
        if d.get("patch"):
            _tprint("  patch:")
            for line in d["patch"].rstrip().splitlines():
                _tprint(f"    {line}")
        if d.get("relatedRules"):
            _tprint(f"  caught before deploy by: {', '.join(d['relatedRules'])} (kube-noob audit)")
        _tprint()
    if out.get("signals"):
        _tprint("signals: " + ", ".join(f"{x['kind']} {x['name']}" for x in out["signals"]))
    _tprint(out.get("summary") or out.get("note", ""))


def _print_reach(out: dict[str, Any]) -> None:
    _tprint(f"{out['verdict'].upper()}  {out['source']} -> {out['destination']}  {out['protocol']} {out['port']}")
    for direction in ("egress", "ingress"):
        r = out[direction]
        # Three states, not two: an undetermined direction is not a denial, and printing it as one would be the
        # same false certainty the JSON now refuses.
        word = "UNKNOWN" if r.get("undetermined") else ("allowed" if r["allowed"] else "DENIED ")
        _tprint(f"  {direction:7} {word}  {r['reason']}")
        for pol in [] if r["allowed"] or r.get("undetermined") else r.get("policies", []):
            for rule in pol.get("rules", []):
                if not rule["allows"]:
                    miss = [x for x, ok in (("peer", rule["peerMatches"]), ("port", rule["portMatches"])) if not ok]
                    _tprint(
                        f"          {pol['policy']} rule {rule['rule']}: allows {rule['peer']} on {rule['ports']} "
                        f"(no match: {', '.join(miss)})"
                    )
    if out.get("undeterminedBy"):
        # The verdict says UNDETERMINED and the two direction lines can both read "allowed", so without this the
        # terminal shows a conclusion with no reason while the JSON carries both `undeterminedBy` and `summary`.
        # A caveat belongs in the surface that is read, not only in the one that is parsed.
        _tprint(f"  unknown because: {', '.join(out['undeterminedBy'])} is not evaluated here")
    for entry in out.get("inertPolicies", []):
        # The verdict can read ALLOWED while the operator believes an AdminNetworkPolicy is denying it. That gap
        # is the whole finding, so it goes on the line below the verdict, not into the JSON alone.
        _tprint(f"  NOT ENFORCED  {entry['policy']}: {entry['reason']}")
        _tprint(f"                replace it with an equivalent {entry['replacement']}, or remove it")
    for note in out.get("notes") or []:
        _tprint(f"  note: {note}")
    if out.get("summary") and out["verdict"] == "undetermined":
        _tprint(f"  {out['summary']}")
    if out.get("warning"):
        _tprint(f"  warning: {out['warning']}")
    for c in out.get("proposedChanges", []):
        _tprint(f"\n  fix (needs approval): {c['change']}")
        for line in (c.get("manifest") or "").rstrip().splitlines():
            _tprint(f"    {line}")
        if c.get("caveat"):
            # A fix that something unevaluated could override has to carry that where the fix is read, not only
            # in the JSON: the person pasting the manifest is reading this.
            _tprint(f"    caveat: {c['caveat']}")
    _tprint("\n  check (read-only):")
    for step in out.get("readOnlyNextSteps", []):
        _tprint(f"    {step['command']}")
    _tprint("\n  not evaluated: " + "; ".join(out.get("notEvaluated", [])))


def _policy(a: argparse.Namespace, s: Settings, kit: Any, fmt: str) -> int:
    from kube_noob import toolkit as tk

    if a.policy_cmd == "generate":
        return _policy_generate(a, s, fmt)
    if a.policy_cmd == "migrate-check":
        return _policy_migrate(a, fmt)
    if a.policy_cmd == "explain":
        if a.text and a.file is not None:
            raise ConfigError("pass the text or -f, not both")
        text = "\n".join(a.text) if a.text else _read_text_or_file(a.file if a.file is not None else "-")
        if len(text.strip()) < 3:
            raise ConfigError("nothing to explain: pass the denial in quotes, a file with -f, or pipe it in")
        out = kit.explain_denial(tk.PolicyExplainIn(text=text, platform=getattr(a, "platform", None)))
        _print_denials(out) if a.format == "text" else _emit(out, fmt)
        return 0
    port: int | str = int(a.port) if str(a.port).isdigit() else a.port
    platform = getattr(a, "platform", None)
    if a.live:
        if a.file:
            raise ConfigError("pass -f manifests or --live, not both")
        if not s.cluster.enabled:
            raise ConfigError("--live needs read-only cluster access: pass --cluster-enabled or set cluster.enabled")
        out = kit.cluster_check_traffic(
            tk.TrafficIn(
                source=a.source,
                destination=a.destination,
                port=port,
                protocol=a.protocol,
                platform=platform,
                cni=a.cni,
            )
        )
    else:
        if not a.file:
            raise ConfigError("pass the NetworkPolicies and workloads with -f (repeat for several), or use --live")
        manifests = "\n---\n".join(_read(f) for f in a.file)
        out = kit.check_network_policy(
            tk.NetpolCheckIn(
                manifests=manifests,
                source=a.source,
                destination=a.destination,
                port=port,
                protocol=a.protocol,
                platform=platform,
                default_namespace=a.default_namespace,
                cni=a.cni,
            )
        )
    _print_reach(out) if a.format == "text" else _emit(out, fmt)
    return 0 if out["verdict"] == "allowed" else 1


def _policy_generate(a: argparse.Namespace, s: Settings, fmt: str) -> int:
    from kube_noob.audit import exceptions as exc_mod
    from kube_noob.generate import policies

    platform = a.platform or s.default_platform or "kubernetes"
    engines = tuple(dict.fromkeys(a.engines)) or policies.ENGINES
    try:
        entries = exc_mod.review(_read(a.exceptions)).entries if a.exceptions else []
        g = policies.generate(
            platform=platform,
            platform_version=a.pversion,
            engines=engines,
            mode=a.mode,
            rules=a.rules or None,
            exclude_namespaces=a.exclude_namespaces,
            exceptions=entries,
            # From the configuration file, like the audit's: which registries are approved is an organisational
            # decision, not a flag a caller picks per invocation (G241, G242).
            allowed_registries=tuple(s.audit.allowed_registries),
        )
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    text = g.yaml(
        policies.header(
            g, platform=platform, platform_version=a.pversion, mode=a.mode, engines=engines, exceptions=entries
        )
    )
    if a.output:
        # write_bytes, not write_text: write_text translates newlines on Windows, so the file would be larger
        # than the `bytes` count reported below and a caller's size check would fail on one platform only.
        Path(a.output).write_bytes(text.encode("utf-8"))
    if a.format != "text":
        # A caller that named a file has said where it wants the bytes. Inlining the rendered set as well spent
        # that context twice -- about 96 000 tokens of YAML on the bundled rule set, which made the result with
        # `-o` LARGER than the result without it.
        body: dict[str, Any] = dict(g.summary())
        if a.output:
            body["output"] = a.output
            body["bytes"] = len(text.encode("utf-8"))
        else:
            body["yaml"] = text
        _emit(body, fmt)
        return 0
    if not a.output:
        sys.stdout.write(text)
    rules = sorted({row["ruleId"] for row in g.generated})
    lines = [
        f"{len(g.documents)} policies for {len(rules)} rules ({', '.join(engines)}, mode {a.mode}, {platform})"
        + (f" written to {a.output}" if a.output else ""),
        f"{len(g.skipped)} rules not generated (reasons in the file header): "
        + ", ".join(row["ruleId"] for row in g.skipped),
    ]
    partial = [row["ruleId"] for row in g.generated if row["coverage"] == "partial"]
    if partial:
        lines.append(f"partial coverage (see kube-noob.io/limitation): {', '.join(sorted(set(partial)))}")
    for line in lines:
        print(line, file=sys.stdout if a.output else sys.stderr)
    return 0


def _migrate_finding(f: dict[str, Any], indent: str) -> str:
    return f"{indent}{f['verdict']:8} {f['path']} (line {f['line']}) -> {f['mapsTo']}: {f['reason']} [{f['source']}]"


def _print_migrate(report: dict[str, Any], show_files: bool) -> None:
    for p in report["policies"]:
        verdict = p["verdict"] or "nothing to migrate"
        where = f"{p['file']} line {p['line']}" if p.get("file") else f"line {p['line']}"
        _tprint(f"{p['policy']} ({where}): {verdict} -> {', '.join(p['targets'])}")
        for f in p["findings"]:
            _tprint(_migrate_finding(f, "  "))
        for r in p["rules"]:
            _tprint(f"  rule {r['rule']}: {r['verdict']} -> {r['target']}")
            for f in r["findings"]:
                _tprint(_migrate_finding(f, "    "))
            if show_files and r.get("draft"):
                for line in r["draft"].rstrip().splitlines():
                    _tprint(f"      {line}")
        if show_files and p.get("draft"):
            for line in p["draft"].rstrip().splitlines():
                _tprint(f"    {line}")
        if show_files and p.get("fixture"):
            _tprint(f"  kyverno test fixture ({len(p['fixture']['files'])} files):")
            for path, text in p["fixture"]["files"].items():
                _tprint(f"    --- {path}")
                for line in text.rstrip().splitlines():
                    _tprint(f"      {line}")
        _tprint()
    for s in report["skipped"]:
        where = f"{s['file']} line {s['line']}" if s.get("file") else f"line {s['line']}"
        _tprint(f"skipped {s['ref']} ({where}): {s['reason']}")
    summary = report["summary"]
    counts = ", ".join(f"{n} {v}" for v, n in summary["verdicts"].items())
    _tprint(f"{summary['policies']} policies, {summary['rules']} rules: {counts}. {report['note']}")


def _write_migration(report: dict[str, Any], out_dir: str) -> int:
    from kube_noob import kyverno_migrate

    root = Path(out_dir)
    files = kyverno_migrate.output_files(report)
    resolved_root = root.resolve()
    targets: list[tuple[Path, str]] = []
    for rel, text in files.items():
        parts = Path(rel).parts
        path = (root / rel).resolve()
        if Path(rel).is_absolute() or ".." in parts or not path.is_relative_to(resolved_root):
            raise ConfigError(f"refusing to write {rel!r} outside {out_dir}")
        if path.exists():
            raise ConfigError(f"{path} exists: pick a new --output-dir (nothing was written)")
        targets.append((path, text))
    try:
        for path, text in targets:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("x", encoding="utf-8") as fh:  # "x": never replace a file that appeared meanwhile
                fh.write(text)
    except OSError as exc:
        raise ConfigError(f"cannot write under {out_dir}: {exc}") from exc
    return len(targets)


def _yaml_files(paths: list[str]) -> list[tuple[str, str]]:
    """(name, text) per file: '-' is stdin, a directory gives its *.yaml and *.yml files in order."""
    out: list[tuple[str, str]] = []
    for f in paths:
        p = Path(f)
        if f == "-":
            out.append(("-", sys.stdin.read()))
        elif p.is_dir():
            out += [
                (str(x), x.read_text(encoding="utf-8"))
                for x in sorted(p.rglob("*"))
                if x.suffix in {".yaml", ".yml"} and x.is_file()
            ]
        else:
            out.append((str(p), p.read_text(encoding="utf-8")))
    return out


def _policy_migrate(a: argparse.Namespace, fmt: str) -> int:
    from kube_noob import kyverno_migrate

    report = kyverno_migrate.check_files(_yaml_files(a.file), drafts=not a.no_drafts)
    written = _write_migration(report, a.output_dir) if a.output_dir else None
    if a.format != "text":
        _emit({**report, **({"output": {"directory": a.output_dir, "files": written}} if a.output_dir else {})}, fmt)
    else:
        _print_migrate(report, show_files=written is None)
        if written is not None:
            print(f"wrote {written} files under {a.output_dir}")
    return 1 if kyverno_migrate.failing(report, a.fail_on) else 0


def _snapshot_from_args(a: argparse.Namespace, s: Settings) -> dict[str, Any]:
    from kube_noob import drift
    from kube_noob.audit import exceptions as exc

    rev = exc.review(_read(a.exceptions)) if a.exceptions else None
    platform = a.platform or s.default_platform or "kubernetes"
    if a.live:
        if a.file:
            raise ConfigError("pass -f manifests or --live, not both")
        if not s.cluster.enabled:
            raise ConfigError("--live needs read-only cluster access: pass --cluster-enabled or set cluster.enabled")
        from kube_noob.debug.cluster import get_backend

        objects, not_read = drift.collect_live(get_backend(s), a.namespaces or list(s.posture.namespaces))
        for line in not_read[:5]:
            print(f"not read: {line}", file=sys.stderr)
        return drift.snapshot(
            objects, source="live", platform=platform, version=a.pversion, exceptions=rev, not_read=not_read
        )
    if not a.file:
        raise ConfigError("pass the manifests with -f (repeat for several), or --live with --cluster-enabled")
    if a.namespaces:
        raise ConfigError("-n works with --live; with -f every namespace in the files is recorded")
    from kube_noob.yamlio import load_documents

    docs = load_documents("\n---\n".join(_read(f) for f in a.file))
    return drift.snapshot(
        (d.data for d in docs), source="manifests", platform=platform, version=a.pversion, exceptions=rev
    )


def _print_drift(rep: dict[str, Any]) -> None:
    from kube_noob import drift

    _tprint(drift.markdown(rep))


def _posture_drift(a: argparse.Namespace, s: Settings, fmt: str) -> int:
    from kube_noob import drift
    from kube_noob.audit.exceptions import ExceptionsError

    try:
        if a.posture_cmd == "diff":
            rep = drift.diff(drift.load(Path(a.old)), drift.load(Path(a.new)))
            if a.markdown:
                Path(a.markdown).write_text(drift.markdown(rep), encoding="utf-8")
            _write_html(a.html, rep)
            _print_drift(rep) if a.format == "text" else _emit(rep, fmt)
            return 0
        snap = _snapshot_from_args(a, s)
        if a.posture_cmd == "snapshot":
            out = Path(a.output)
            out.write_text(json.dumps(snap, sort_keys=True), encoding="utf-8")
            out.chmod(0o600)
            summary = {"output": str(out), "objects": len(snap["objects"]), "findings": len(snap["findings"])}
            if a.format == "text":
                n_obj, n_find = summary["objects"], summary["findings"]
                _tprint(f"wrote {out}: {n_obj} objects, {n_find} findings (hashes, no values)")
            else:
                _emit(summary, fmt)
            return 0
        state = Path(a.state_dir) if a.state_dir else s.data_dir / "posture"
        rep, paths = drift.write_report(state, snap, a.keep or s.posture.keep)
        _write_html(a.html, rep)
        if a.format == "text":
            _print_drift(rep)
            _tprint(f"\nwrote {paths['report']} and {paths['markdown']}")
        else:
            _emit({**rep, "files": {k: str(v) for k, v in paths.items()}}, fmt)
        return 0
    except (drift.DriftError, ExceptionsError) as exc:
        raise ConfigError(str(exc)) from exc


def _posture(a: argparse.Namespace, s: Settings, fmt: str) -> int:
    from kube_noob import attack_paths as ap

    if a.posture_cmd in {"snapshot", "diff", "report"}:
        return _posture_drift(a, s, fmt)

    if not 1 <= a.top <= ap.MAX_PATHS:
        raise ConfigError(f"--top must be 1-{ap.MAX_PATHS}")
    if a.live:
        if a.file:
            raise ConfigError("pass -f manifests or --live, not both")
        if not s.cluster.enabled:
            raise ConfigError("--live needs read-only cluster access: pass --cluster-enabled or set cluster.enabled")
        from kube_noob.debug.cluster import get_backend

        out = ap.scan(ap.collect_live(get_backend(s), a.namespaces), top=a.top)
    else:
        if not a.file:
            raise ConfigError("pass the manifests with -f (repeat for several), or --live with --cluster-enabled")
        if a.namespaces:
            raise ConfigError("-n works with --live; with -f every namespace in the files is scanned")
        try:
            out = ap.scan_manifests("\n---\n".join(_read(f) for f in a.file), top=a.top)
        except ap.ScanError as exc:
            raise ConfigError(str(exc)) from exc
    if a.format == "text":
        _tprint(out["summary"])
        for path in out["paths"]:
            br = path["blastRadius"]
            head = f"#{path['rank']}  score {path['score']}  {path['exposure']['kind']}"
            _tprint(f"\n{head} -> {br['capability']} ({br['scope']})")
            for st in path["steps"]:
                _tprint(f"    {st['from']} --{st['edge']}--> {st['to']}")
                _tprint(f"        {st['evidence']}")
            _tprint("    fix: " + "; or ".join(path["fix"]))
        if out["notRead"]:
            _tprint("\nnot read: " + "; ".join(out["notRead"][:10]))
        for note in (out.get("assumptions") or [])[:10]:
            _tprint(f"assumed: {note}")
        if out["secretsIgnored"]:
            _tprint(f"{out['secretsIgnored']} Secret object(s) in the input were ignored, unread.")
        # The input-specific limitations only. The three standing ones are documented; these name objects in THIS
        # scan whose exposure edge could not be traced, and a caveat that lives only in the JSON renderer is the
        # defect G221 was about -- the text reader is the one most likely to act on the number above.
        for line in out["limitations"][len(ap.STANDING_LIMITATIONS) :]:
            _tprint("\nnote: " + line)
    else:
        _emit(out, fmt)
    top_score = out["paths"][0]["score"] if out["paths"] else 0
    return 1 if a.fail_above is not None and top_score > a.fail_above else 0


_OPERATOR_SUFFIXES = (".yaml", ".yml", ".json")


def _operator_files(paths: list[str]) -> tuple[list[tuple[str, list[Any]]], list[dict[str, str]]]:
    """Each file parsed on its own. A file named on the command line that cannot be read is refused (exit 2 or 4);
    a file found in a directory that cannot be read is named in the answer and makes it partial, because dropping it
    and answering from the rest is a shorter list that reads as a complete one (G270). In a directory every
    ``.yaml``, ``.yml`` and ``.json`` file is read, whatever the case of its suffix; links are not followed."""
    from kube_noob.yamlio import load_documents

    sources: list[tuple[str, list[Any]]] = []
    unreadable: list[dict[str, str]] = []
    for given in paths:
        d = Path(given)
        if given == "-" or not d.is_dir():
            sources.append((given, [doc.data for doc in load_documents(_read(given))]))
            continue
        for f in sorted(d.rglob("*")):
            if not f.name.lower().endswith(_OPERATOR_SUFFIXES):
                continue
            rel = str(f.relative_to(d))
            if f.is_symlink() or not f.is_file():
                if f.is_symlink():
                    unreadable.append({"path": rel, "reason": "a link (not followed)"})
                continue
            try:
                docs = [doc.data for doc in load_documents(f.read_text(encoding="utf-8"))]
            except (UnicodeDecodeError, OSError) as exc:
                unreadable.append({"path": rel, "reason": f"not readable as UTF-8 text ({type(exc).__name__})"})
                continue
            except ManifestError as exc:
                unreadable.append({"path": rel, "reason": " ".join(str(exc).split())[:300]})
                continue
            sources.append((rel, docs))
    return sources, unreadable


def _operators_cmd(a: argparse.Namespace, s: Settings, fmt: str) -> int:
    from kube_noob import operators

    if not 1 <= a.top <= operators.MAX_OPERATORS:
        raise ConfigError(f"--top must be 1-{operators.MAX_OPERATORS}")
    given = [
        name for name, on in (("-f", bool(a.file)), ("--must-gather", bool(a.must_gather)), ("--live", a.live)) if on
    ]
    if len(given) != 1:
        raise ConfigError("pass exactly one of -f manifests, --must-gather PATH or --live (with --cluster-enabled)")
    if a.namespaces and not a.live:
        raise ConfigError("-n works with --live; files and must-gathers are read whole")
    if a.live:
        if not s.cluster.enabled:
            raise ConfigError("--live needs read-only cluster access: pass --cluster-enabled or set cluster.enabled")
        from kube_noob.debug.cluster import get_backend

        collected = operators.collect_live(get_backend(s), a.namespaces)
    elif a.must_gather:
        from kube_noob.mustgather import ingest
        from kube_noob.mustgather import operators as mg_operators

        try:
            collected = mg_operators.collect(ingest.open_bundle(Path(a.must_gather)))
        except ingest.MustGatherError as exc:
            raise ConfigError(str(exc)) from exc
    else:
        sources, unreadable = _operator_files(a.file)
        collected = operators.from_sources(sources, unreadable)
    out = operators.inventory(collected, top=a.top)
    if a.format == "text":
        _tprint(operators.render_text(out))
    else:
        _emit(out, fmt)
    if a.require_complete and not out["complete"]:
        print(f"refusing a complete verdict: the inventory is {out['verdict']} ({out['summary']})", file=sys.stderr)
        return 5
    return 0


def _print_poll(result: dict[str, Any]) -> None:
    ch = result["changes"]
    _tprint(
        f"{result['polledAt']}  {', '.join(result['namespaces']) or 'nothing readable'}: "
        f"{len(ch['opened'])} new, {len(ch['reopened'])} back again, {len(ch['resolved'])} resolved, "
        f"{len(result['open'])} open"
    )
    for row in result["open"]:
        _tprint(f"  {row['id']}  {row['headline']}")
    for err in result.get("errors", []):
        _tprint(f"  read failed: {err}")


def _watch(a: argparse.Namespace, s: Settings, fmt: str) -> int:
    import threading

    from kube_noob.debug.cluster import get_backend
    from kube_noob.watch import Watcher, resolve_namespaces

    if not s.cluster.enabled:
        raise ConfigError("watch needs read-only cluster access: pass --cluster-enabled or set cluster.enabled")
    if a.interval is not None:
        if not 15 <= a.interval <= 3600:
            raise ConfigError("--interval must be 15 to 3600 seconds")
        s.watch.interval_seconds = a.interval
    watcher = Watcher(s, get_backend(s), resolve_namespaces(s, a.namespaces), getattr(a, "platform", None))
    if a.once:
        result = watcher.poll()
        _print_poll(result) if a.format == "text" else _emit(result, fmt)
        return 0
    stop = threading.Event()
    try:
        while not stop.is_set():
            result = watcher.poll()
            _print_poll(result) if a.format == "text" else _emit(result, fmt)
            sys.stdout.flush()
            stop.wait(s.watch.interval_seconds)
    except KeyboardInterrupt:
        return 0
    return 0


def _incidents(a: argparse.Namespace, kit: Any, fmt: str) -> int:
    from kube_noob import toolkit as tk

    cmd = a.incidents_cmd or "list"
    if cmd == "show":
        out = kit.incident(tk.IncidentIn(id=a.incident_id))
        _emit(out, fmt)
        return 0
    if cmd == "confirm":
        _emit(
            kit.incident_confirm(
                tk.IncidentConfirmIn(id=a.incident_id, cause=a.cause, fix=a.fix, confirmed_by_user=True)
            ),
            fmt,
        )
        return 0
    out = kit.incidents(
        tk.IncidentsIn(
            status="all" if getattr(a, "all", False) else "open", namespace=getattr(a, "namespace", None), limit=100
        )
    )
    if a.format == "text":
        for row in out["incidents"]:
            _tprint(f"{row['id']}  {row['status']:8} x{row['occurrences']}  {row['headline']}")
        if out.get("note"):
            _tprint(out["note"])
    else:
        _emit(out, fmt)
    return 0


def _memory(a: argparse.Namespace, s: Settings, kit: Any, fmt: str) -> int:
    from datetime import date

    from pydantic import ValidationError

    from kube_noob.memory import match as mmatch
    from kube_noob.memory import repo, verify

    cmd = a.memory_cmd
    if cmd == "init":
        out: dict[str, Any] = {"repository": a.dir, **repo.init_repo(Path(a.dir))}
        if a.format == "text":
            for rel in out["created"]:
                _tprint(f"created {rel}")
            for rel in out["kept"]:
                _tprint(f"kept    {rel} (already there)")
            _tprint(f"next: kube-noob memory add {a.dir} --symptom ... --cause ... --fix ...")
        else:
            _emit(out, fmt)
        return 0
    if cmd == "add":
        from kube_noob.debug.steps import classify_step

        signals = []
        for raw in a.signal:
            kind, sep, name = raw.partition(":")
            if not sep:
                raise ConfigError(f"--signal {raw!r}: use kind:name, e.g. alert:etcdNoLeader")
            signals.append({"kind": kind, "name": name})
        fields: dict[str, Any] = {
            "kind": a.kind,
            "signals": signals,
            "symptom": a.symptom,
            "platform": a.platform or s.default_platform or "kubernetes",
            "versions": {k: v for k, v in (("introduced", a.introduced), ("fixedIn", a.fixed_in)) if v},
            "cause": a.cause,
            "fix": {
                "text": a.fix,
                "commands": [
                    {"command": c, "label": "read-only" if classify_step(c) == "read" else "needs-approval"}
                    for c in a.commands
                ],
            },
            "owners": a.owners or ["unassigned"],
            "sources": a.sources,
        }
        try:
            path, entry = repo.add_entry(Path(a.dir), fields)
        except ValidationError as exc:
            raise ValueError(f"entry not written: {repo._reason(exc)}") from None
        out = {"written": str(path), "id": entry.id, "status": entry.status}
        if a.format == "text":
            _tprint(f"wrote {path} ({entry.id}, proposed): review it, then set status: approved")
        else:
            _emit(out, fmt)
        return 0
    if cmd == "validate":
        rep = verify.validate_repo(Path(a.dir), strict=a.strict)
        if a.format == "text":
            for p in rep["errors"] + rep["warnings"]:
                who = p["entry"] or p["file"]
                _tprint(f"{p['level'].upper():7} {who}  {p['check']}: {p['detail']}")
            _tprint(
                f"{rep['entries']} entries ({rep['approved']} approved, {rep['proposed']} proposed, "
                f"{rep['retired']} retired): {len(rep['errors'])} errors, {len(rep['warnings'])} warnings"
            )
        else:
            _emit(rep, fmt)
        return 0 if rep["ok"] else 1
    if cmd == "match":
        if a.text and a.file is not None:
            raise ConfigError("pass the text or -f, not both")
        text = "\n".join(a.text) if a.text else _read_text_or_file(a.file if a.file is not None else "-")
        if len(text.strip()) < 3:
            raise ConfigError("nothing to match: pass the error text in quotes, a file with -f, or pipe it in")
        dirs = a.dirs or [str(d) for d in s.memory.paths]
        if not dirs:
            raise ConfigError("pass the memory repository with --dir (repeat for several) or set memory.paths")
        operators: dict[str, str] = {}
        for raw in a.operator:
            name, sep, ver = raw.partition("=")
            if not sep or not name or not ver:
                raise ConfigError(f"--operator {raw!r}: use name=version")
            operators[name] = ver
        out = mmatch.match(
            [Path(d) for d in dirs],
            text,
            version=a.pversion,
            platform=a.platform,
            operators=operators,
            include_proposed=a.include_proposed,
            limit=max(1, min(a.limit, 50)),
        )
        if a.format == "text":
            _print_memory_matches(out)
        else:
            _emit(out, fmt)
        return 0
    if cmd == "outcome":
        when = date.fromisoformat(a.when) if a.when else None
        try:
            entry = repo.add_outcome(Path(a.dir), a.entry_id, a.result, a.ticket, a.cluster, when)
        except ValidationError as exc:
            raise ValueError(f"outcome not recorded: {repo._reason(exc)}") from None
        o = entry.outcomes[-1]
        out = {"id": entry.id, "outcome": o.model_dump(mode="json", exclude_none=True), "outcomes": len(entry.outcomes)}
        if a.format == "text":
            _tprint(f"{entry.id}: recorded {o.result} on {o.date} ({len(entry.outcomes)} outcomes)")
        else:
            _emit(out, fmt)
        return 0
    if cmd == "stats":
        out = mmatch.stats(Path(a.dir), a.by)
        if a.format == "text":
            _tprint(
                f"{out['entries']} entries: "
                + ", ".join(f"{v} {k}" for k, v in out["byStatus"].items())
                + " | outcomes: "
                + ", ".join(f"{v} {k}" for k, v in out["outcomes"].items())
            )
            for g in out.get("groups", []):
                _tprint(
                    f"  {g['key']:40} {len(g['entries'])} entries, applied {g['applied']}, resolved {g['resolved']}"
                )
        else:
            _emit(out, fmt)
        return 0
    if cmd == "replay":
        from kube_noob.memory.importers import MAX_EXPORT
        from kube_noob.memory.replay import load_labels, markdown, replay

        for f in (a.tickets, a.labels):
            if f and not Path(f).is_file():
                raise ConfigError(f"no file {f}")
        if Path(a.tickets).stat().st_size > MAX_EXPORT:
            raise ConfigError(f"{a.tickets} is larger than {MAX_EXPORT // 1_000_000} MB")
        labels = load_labels(Path(a.labels).read_text(encoding="utf-8")) if a.labels else None
        out = replay(
            Path(a.memory),
            a.ticket_format,
            Path(a.tickets).read_text(encoding="utf-8"),
            labels,
            a.as_of_ticket_date,
            include_proposed=not a.approved_only,
        )
        md = markdown(out)
        if a.out:
            target = Path(a.out)
            target.mkdir(parents=True, exist_ok=True)
            (target / "report.md").write_text(md, encoding="utf-8")
            (target / "report.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
        if a.format == "text":
            print(md, end="")
        else:
            _emit(out, fmt)
        return 0
    if cmd == "import":
        from kube_noob.memory.importers import MAX_EXPORT, import_tickets

        if a.file != "-" and not Path(a.file).is_file():
            raise ConfigError(f"no export file {a.file}")
        if a.file != "-" and Path(a.file).stat().st_size > MAX_EXPORT:
            raise ConfigError(f"{a.file} is larger than {MAX_EXPORT // 1_000_000} MB; export fewer tickets at a time")
        text = sys.stdin.read(MAX_EXPORT + 1) if a.file == "-" else Path(a.file).read_text(encoding="utf-8")
        out = import_tickets(
            Path(a.dir),
            a.ticket_format,
            text,
            a.platform or s.default_platform or "kubernetes",
            a.owner,
            a.cluster,
            a.dry_run,
        )
        if a.format == "text":
            verb = "would write" if a.dry_run else "wrote"
            for c in out["created"]:
                _tprint(f"{c['ticket']} -> {c['entry']} ({c['outcome']}, proposed)")
            for sk in out["skipped"]:
                _tprint(f"{sk['ticket']} skipped: {sk['reason']}")
            _tprint(f"{verb} {len(out['created'])} proposed entries; skipped {len(out['skipped'])} tickets")
        else:
            _emit(out, fmt)
        return 0
    notes = kit.learning.notes()
    out = repo.migrate_learning(Path(a.dir), notes, a.owner, s.default_platform or "kubernetes")
    if a.format == "text":
        for c in out["created"]:
            _tprint(f"{c['note']} -> {c['entry']} (proposed)")
        for sk in out["skipped"]:
            _tprint(f"{sk['note']} skipped: {sk['reason']}")
        if not out["created"] and not out["skipped"]:
            _tprint("no confirmed learning notes to migrate")
    else:
        _emit(out, fmt)
    return 0


def _print_memory_matches(out: dict[str, Any]) -> None:
    for m in out["matches"]:
        head = {"fix": "fix", "runbook": "runbook", "tried, did not work": "tried, did not work", "retired": "retired"}
        _tprint(f"{m['citation']} {head[m['state']]} ({m['status']}): {m['symptom']}")
        if m.get("note"):
            _tprint(f"  {m['note']}")
        by = m["matchedBy"]
        _tprint("  matched by: " + ", ".join(by["signals"] + [f"word {w}" for w in by["words"][:5]]))
        _tprint(f"  cause: {m['cause']}")
        _tprint(f"  fix: {m['fix']['text']}")
        for c in m["fix"]["commands"]:
            _tprint(f"    {'check' if c['label'] == 'read-only' else 'needs approval'}: {c['command']}")
        _tprint(f"  {m['outcomes']['summary']}")
        _tprint(f"  {m['repository']}/{m['file']}")
    if out.get("note"):
        _tprint(out["note"])
    q = out["query"]
    _tprint(
        f"memory: {sum(r['entries'] for r in out['repositories'])} entries in {len(out['repositories'])} "
        f"repositor{'y' if len(out['repositories']) == 1 else 'ies'}"
        + (f"; version {q['version']} ({q.get('versionFrom')})" if q.get("version") else "")
    )


def _learning(a: argparse.Namespace, kit: Any, fmt: str) -> int:
    from kube_noob import toolkit as tk

    lc = a.learning_cmd
    if lc == "show":
        out = kit.learning_summary(tk.EmptyIn())
    elif lc == "note":
        out = kit.learning_note_add(
            tk.LearningNoteIn(
                symptom=a.symptom, cause=a.cause, fix=a.fix, platform=a.platform, tags=a.tags, confirmed_by_user=True
            )
        )
    elif lc == "forget":
        if not kit.learning.forget(a.note_id):
            raise KeyError(f"no note {a.note_id}; see `kube-noob learning show`")
        out = {"forgotten": a.note_id}
    else:
        versions = {
            k: getattr(a, k) for k in ("kubernetes", "openshift", "helm", "rhacs", "rosa") if getattr(a, k, None)
        }
        out = kit.learning_profile_set(
            tk.LearningProfileIn(platform=a.platform, versions=versions, conventions=a.conventions)
        )
    _emit(out, fmt)
    return 0


def _advisories(a: argparse.Namespace, s: Settings, fmt: str) -> int:
    from kube_noob.sources import advisories
    from kube_noob.vuln import csaf

    if a.from_archive:
        if a.cves or a.since:
            raise ConfigError("--from-archive reads every CVE in the archive; drop --cves and --since")
        archive = Path(a.from_archive)
        if not archive.exists():
            raise ConfigError(f"no such archive: {archive}")
        out = advisories.run(s.data_dir, advisories.from_archive(archive), replace=a.replace)
    else:
        if s.offline:
            raise ConfigError("the offline lock is on; read a downloaded archive instead: --from-archive <file>")
        if not (a.online or s.web_enabled):
            raise ConfigError("advisories are downloaded; pass --online (or set webEnabled: true)")
        if bool(a.cves) == bool(a.since):
            raise ConfigError("pass --cves CVE-...,CVE-... or --since <date> (or --from-archive <file>)")
        if not 1 <= a.max_requests <= 50_000:
            raise ConfigError("--max-requests must be 1-50000")
        with advisories.vex_http(s) as http:
            client = advisories.VexClient(http, max_requests=a.max_requests)
            cves = [c.strip().upper() for c in a.cves.split(",") if c.strip()] if a.cves else []
            if a.since:
                cves = client.changed_since(a.since)[: max(0, a.max_requests - 1)]
            docs: list[Any] = []
            missing: list[str] = []
            failed: list[str] = []
            for cve in cves:
                try:
                    doc = client.document(cve)
                except csaf.AdvisoryError as exc:
                    if "budget" in str(exc):
                        failed.append(f"{cve}: {exc}")
                        break
                    failed.append(f"{cve}: {exc}")
                    continue
                (docs.append(doc) if doc is not None else missing.append(cve))
            if failed and not docs:
                raise csaf.AdvisoryError("no VEX document read: " + "; ".join(failed[:5]))
            out = {**advisories.run(s.data_dir, docs, replace=a.replace), "requests": client.requests}
            if missing:
                out["notPublished"] = missing
            if failed:
                out["failed"] = failed
    if a.format == "text":
        _tprint(
            f"{out['source']} ({out['license']}): {out['documents']} documents read, {out['kept']} about the default "
            f"products, {out['malformed']} malformed; the shard holds {out['cves']} CVEs"
        )
        if out.get("notPublished"):
            _tprint("no VEX published for: " + ", ".join(out["notPublished"]))
        for f in out.get("failed", []):
            _tprint(f"failed: {f}")
    else:
        _emit(out, fmt)
    return 0


def _corpus(a: argparse.Namespace, s: Settings, fmt: str) -> int:
    from kube_noob.sources.corpus import read_manifest, verify, write_shard

    cc = a.corpus_cmd
    if cc == "advisories":
        return _advisories(a, s, fmt)
    if cc in {"build", "jira", "jira-projects", "history", "known-issues"} and s.offline:
        raise ConfigError(
            "the offline lock is on (offline: true / KUBE_NOOB_OFFLINE); corpus downloads are blocked. "
            "Import a prepared corpus instead: kube-noob corpus import <dir-or-tgz>"
        )
    if cc in {"build", "jira", "jira-projects", "history", "known-issues"} and not (a.online or s.web_enabled):
        raise ConfigError("corpus ingestion uses the network; pass --online (or set webEnabled: true)")
    if cc == "known-issues":
        import tempfile

        from kube_noob.sources.release_notes import fetch, snapshot

        minors = [m.strip() for m in a.minors.split(",") if m.strip()]
        with tempfile.TemporaryDirectory(prefix="kube-noob-rn-") as tmp:
            records, commits = fetch(minors, Path(tmp))
        out_dir = s.data_dir / "known_issues"
        out_dir.mkdir(parents=True, exist_ok=True)
        target = out_dir / "openshift-release-notes.json"
        target.write_text(json.dumps(snapshot(records, commits), ensure_ascii=False) + "\n", encoding="utf-8")
        _emit({"file": str(target), "issues": len(records), "commits": commits}, fmt)
        return 0
    if cc == "build":
        from kube_noob.sources.git_ingest import ingest
        from kube_noob.sources.registry import GIT_SOURCES, by_id

        sources = GIT_SOURCES if a.sources == "all" else tuple(by_id(x.strip()) for x in a.sources.split(","))
        summary = {}
        from kube_noob.sources.pacing import pause

        for i, src in enumerate(sources):
            if i:
                pause()  # jittered gap between clones from the same host
            try:
                recs = list(ingest(src, limit=a.limit_per_source))
                summary[src.source_id] = write_shard(s.data_dir, f"git-{src.source_id}", recs)["records"]
            except KubeNoobError as exc:
                summary[src.source_id] = f"error: {exc}"
            print(f"{src.source_id}: {summary[src.source_id]}", file=sys.stderr)
        _emit({"dataDir": str(s.data_dir), "sources": summary}, fmt)
        return 0 if all(isinstance(v, int) for v in summary.values()) else 4
    if cc in {"jira", "jira-projects"}:
        from kube_noob.jira_catalog import DEFAULT_PROJECTS
        from kube_noob.sources.jira import JiraClient, jira_http, run_sync

        email, api_token = os.environ.get("JIRA_EMAIL"), os.environ.get("JIRA_API_TOKEN")
        if bool(email) != bool(api_token):
            raise ConfigError("Set both JIRA_EMAIL and JIRA_API_TOKEN for an authenticated pull, or neither")
        auth = (email, api_token) if email and api_token else None
        if cc == "jira-projects":
            with jira_http(s, s.jira.base_url) as http:
                projects = JiraClient(http, s.jira.base_url, auth=auth, max_requests=20).projects()
            rows = [{**p, "default": p["key"] in DEFAULT_PROJECTS} for p in projects]
            if a.format == "text":
                for r in rows:
                    _tprint(f"{'*' if r['default'] else ' '} {r['key']:12} {r['name']}")
                print(f"{len(rows)} projects; * = in the default set (kube-noob corpus jira --online)")
            else:
                _emit({"projects": rows}, fmt)
            return 0
        if a.max_requests is not None and not 1 <= a.max_requests <= 100_000:
            raise ConfigError("--max-requests must be 1 to 100000")
        out = run_sync(s, a.projects, a.max_requests, auth)
        if a.format == "text":
            for p in out["projects"]:
                state = "complete" if p.get("complete") else "partial, resumes next run"
                extra = f" ({p['error']})" if p.get("error") else ""
                _tprint(f"{p['project']:10} +{p['fetched']:<6} {p['total']:>7} tickets  {state}{extra}")
            if out["skipped"]:
                print(f"not reached this run (budget): {', '.join(out['skipped'])}")
            idx = out.get("index") or {}
            print(
                f"{out['requests']} requests ({out.get('commentRequests', 0)} for comments), {out['retries']} retries; "
                f"index: {idx.get('tickets', 0)} tickets retrieved {idx.get('asOf')}"
            )
            changed = out.get("changes") or {}
            if changed:
                counts = ", ".join(f"{n} {k}" for k, n in changed.items())
                print(f"changes recorded: {counts} (kube-noob corpus jira-changes --since 1d)")
        else:
            _emit(out, fmt)
        errors = [p for p in out["projects"] if p.get("error")]
        return 4 if errors and len(errors) == len(out["projects"]) else 0
    if cc == "history":
        from kube_noob.sources import pacing
        from kube_noob.sources.history import minor_timeline, tags_with_dates, timeline_record
        from kube_noob.sources.registry import HISTORY_REPOS

        recs = []
        for i, (name, repo) in enumerate(HISTORY_REPOS.items()):
            if i:
                pacing.pause(pacing.CLONE_PAUSE)  # clones from the same host spaced by a random pause
            try:
                tl = minor_timeline(tags_with_dates(repo))
                recs.append(timeline_record(name, repo, tl))
                print(f"{name}: {len(tl)} minors", file=sys.stderr)
            except KubeNoobError as exc:
                print(f"{name}: error {exc}", file=sys.stderr)
        _emit(write_shard(s.data_dir, "history", recs), fmt)
        return 0
    if cc == "stats":
        from kube_noob.knowledge.store import get_store

        _emit({"manifest": read_manifest(s.data_dir), "index": get_store(s.data_dir).stats()}, fmt)
        return 0
    if cc == "add-docs":
        from kube_noob.sources.org_docs import ingest_org_docs

        _emit(ingest_org_docs(Path(a.path), s.data_dir, a.source, a.base_url), fmt)
        return 0
    if cc == "jira-audit":
        from kube_noob import jira_audit

        report = jira_audit.audit(s.data_dir, a.project)
        if a.format == "text":
            for line in jira_audit.text_report(report):
                _tprint(line)
        else:
            _emit(report, fmt)
        return 0 if report.get("available") is not False else 1
    if cc == "jira-snapshot":
        from kube_noob.sources.jira_snapshot import export_snapshot

        out = export_snapshot(s.data_dir, Path(a.out))
        if a.format == "text":
            project_list = ", ".join(out["projects"])
            _tprint(
                f"{out['snapshot']}: {out['tickets']} tickets ({project_list}), {out['changes']} changes, "
                f"last sync {out['lastSync']}, {out['bytes'] // 1_000_000} MB"
            )
            _tprint(out["note"])
        else:
            _emit(out, fmt)
        return 0
    if cc == "jira-changes":
        from kube_noob import ticket_changes

        try:
            since = ticket_changes.parse_since(a.since)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
        res = ticket_changes.changes(s.data_dir, since, a.project, a.kind, max(1, min(a.limit, 5000)))
        opened = ticket_changes.open_summary(s.data_dir, a.project)
        if a.format == "text":
            _print_ticket_changes(res, opened)
        else:
            _emit({**res, "openTickets": opened}, fmt)
        return 0
    if cc == "import":
        from kube_noob.sources import db_bundle, seal
        from kube_noob.sources.corpus import import_corpus

        where = Path(a.path)
        if not where.exists():
            raise ConfigError(f"no such file or folder: {where}")
        if where.is_file() and seal.is_sealed(where):
            import tempfile

            secret = seal.read_secret(a.key_file)
            s.data_dir.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(dir=s.data_dir, prefix=".unseal-") as tmp:
                plain = Path(tmp) / "snapshot.tgz"
                seal.unseal(where, plain, secret)
                out = (
                    db_bundle.import_bundle(plain, s.data_dir)
                    if db_bundle.is_bundle(plain)
                    else import_corpus(plain, s.data_dir)
                )
            _emit({**out, "sealed": True}, fmt)
        elif db_bundle.is_bundle(where):
            _emit(db_bundle.import_bundle(where, s.data_dir), fmt)
        else:
            _emit(import_corpus(where, s.data_dir), fmt)
        return 0
    if cc in {"seal", "unseal"}:
        from kube_noob.sources import seal

        where = Path(a.path)
        if not where.is_file():
            raise ConfigError(f"no such file: {where}")
        secret = seal.read_secret(a.key_file)
        done = (seal.seal if cc == "seal" else seal.unseal)(where, Path(a.output), secret)
        if a.format == "text":
            _tprint(f"wrote {a.output} ({done['bytes']} bytes, {done['chunks']} chunks)")
        else:
            _emit({"output": a.output, **done}, fmt)
        return 0
    if cc == "db-bundle":
        from kube_noob.sources import db_bundle

        out = db_bundle.build(s.data_dir, Path(a.output))
        if a.format == "text":
            _tprint(
                f"wrote {out['bundle']} ({out['bytes'] / 1_000_000:.1f} MB, sha256 {out['sha256'][:16]}...): "
                f"{out['records']} records in {len(out['shards'])} shards, {out['knownIssueFiles']} known-issue files"
            )
            _tprint("licenses: " + ", ".join(f"{n} {k}" for k, n in out["licenses"].items()))
            if out["leftOut"]:
                _tprint("left out (not redistributable or Jira): " + ", ".join(out["leftOut"]))
        else:
            _emit(out, fmt)
        return 0
    if cc == "db-check":
        from kube_noob.sources import db_bundle

        where = Path(a.path)
        if not where.exists():
            raise ConfigError(f"no such file or folder: {where}")
        problems = db_bundle.check_archive(where)
        if a.format == "text":
            _tprint(f"{where}: ok" if not problems else f"{where}: {len(problems)} problems")
            for p in problems:
                _tprint(f"  {p}")
        else:
            _emit({"ok": not problems, "problems": problems}, fmt)
        return 1 if problems else 0
    problems = verify(s.data_dir)
    _emit({"ok": not problems, "problems": problems}, fmt)
    return 0 if not problems else 1


def _train(a: argparse.Namespace, s: Settings, fmt: str) -> int:
    tc = a.train_cmd
    if tc == "export":
        from kube_noob.evals.export import export_grpo, export_sft
        from kube_noob.knowledge.store import get_store

        out = Path(a.out)
        res = {
            "sft": export_sft(out / "sft.jsonl", get_store(s.data_dir), a.include_restricted, a.synthetic_limit),
            "grpo": export_grpo(out / "grpo_prompts.jsonl"),
        }
        _emit(res, fmt)
        return 0
    if tc == "grade":
        from kube_noob.evals.reward import grade_by_id
        from kube_noob.knowledge.store import get_store

        _emit(grade_by_id(a.task, _read(a.file), get_store(s.data_dir)).as_dict(), fmt)
        return 0
    if tc == "tasks":
        from kube_noob.evals.reward import benchmark

        _emit([{"id": t["id"], "type": t.get("type"), "prompt": t["prompt"]} for t in benchmark().values()], fmt)
        return 0
    from kube_noob.evals.runner import run_benchmark

    rep = run_benchmark(s, a.tasks.split(",") if a.tasks else None, use_tools=not a.no_tools)
    if a.out:
        Path(a.out).write_text(json.dumps(rep, indent=2, default=str), encoding="utf-8")
    _emit({k: v for k, v in rep.items() if k != "results"} if a.out else rep, fmt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
