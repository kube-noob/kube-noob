"""SARIF 2.1.0 from static analysis tools, as one normalised list of code findings (requirements R4.5).

What each producer writes was read from its source (checked 2026-10-28):

- Bandit (``bandit/formatters/sarif.py``): rule per test id (``B608``) with ``properties.tags`` ``security`` and
  ``external/cwe/cwe-<n>`` and ``precision`` from the confidence; result ``level`` error/warning/note from
  HIGH/MEDIUM/LOW and ``properties.issue_severity`` / ``issue_confidence``; relative paths, or ``file://`` URIs for
  absolute ones.
- Semgrep (``src/osemgrep/reporting/Sarif_output.ml``): ``defaultConfiguration.level`` from the rule severity, tags
  with the rule's ``cwe`` metadata as written (``CWE-89: Improper Neutralization ...``), ``OWASP-...`` and
  ``<x> CONFIDENCE``, ``security-severity`` when the rule has it; ``uriBaseId`` ``%SRCROOT%``; ``fingerprints``;
  ``suppressions`` (``inSource``) for ignored matches.
- SpotBugs (``edu/umd/cs/findbugs/sarif``): ``message.id`` ``default`` with ``arguments`` (the text lives in the
  rule's ``messageStrings``), the CWE as a rule ``relationships`` target in the CWE taxonomy, the bug category in
  ``tags``, ``level`` from the bug rank, paths relative to a source directory named by a hashed ``uriBaseId`` in
  ``originalUriBaseIds``.
- ESLint (``@microsoft/eslint-formatter-sarif``): severity 2 is ``error``, 1 ``warning``; absolute ``file://``
  URIs; ``suppressions`` for disabled messages (``inSource`` for directives).
- CodeQL: query metadata in the rule's ``properties`` bag (``tags`` with ``security`` and ``external/cwe/cwe-089``,
  ``precision``, ``problem.severity`` or ``severity``, ``security-severity``), rules in ``tool.extensions`` (query
  packs) referenced by ``result.rule.toolComponent.index``, ``partialFingerprints.primaryLocationLineHash``.

Severity: a ``security-severity`` score maps as GitHub code scanning maps it ("over 9.0 is critical, from 7.0 to 8.9
is high, from 4.0 to 6.9 is medium and from 0.1 to 3.9 is low"; 9.0 itself counts as critical, as in CVSS); else
Bandit's ``issue_severity``; else the SARIF level (error high, warning medium, note low). Findings with no CWE and no
security tag (lint and quality rules) are kept apart and never ranked. Suppressed results (a suppression whose
``status`` is absent or ``accepted``, the default), results whose ``baselineState`` is ``absent`` and results whose
``kind`` is not ``fail`` are excluded with the reason. The same file, line and CWE reported by several tools is one
finding with every tool as a source. Inputs are bounded (GitHub's own upload limits: 20 runs, 25,000 results and
25,000 rules per run).
"""

from __future__ import annotations

import dataclasses
import hashlib
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote, urlparse

from kube_noob import sanitize

MAX_BYTES = 50_000_000
MAX_RUNS = 20
MAX_RESULTS = 25_000
MAX_RULES = 25_000
MAX_BASE_DEPTH = 8
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
LEVEL_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
BANDIT_SEVERITY = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNDEFINED": "low"}
SECURITY_RULE_PREFIXES = ("security/", "security-node/", "no-unsanitized/", "@microsoft/sdl/", "xss/")
_CWE = re.compile(r"(?i)(?<![a-z0-9])cwe[-/_ ]?0*(\d{1,5})(?!\d)")
_LINK_REF = re.compile(r"\[([^\]\n]{0,300})\]\(\d{1,4}\)")
_ARG = re.compile(r"\{(\d{1,2})\}")


class SarifError(ValueError):
    """Not SARIF 2.1.0, or over its bounds."""


def _s(v: Any, n: int = 300) -> str:
    """A scalar as one bounded line: control and bidi characters become spaces, lone surrogates (valid JSON, not
    valid UTF-8) become "?"."""
    if not isinstance(v, (str, int, float)) or isinstance(v, bool):
        return ""
    text = str(v)[:n].encode("utf-8", "replace").decode("utf-8")
    return sanitize.visible_squeezed(text).strip()


def _raw(v: Any, n: int) -> str:
    """A URI as written (bounded, lone surrogates replaced): control characters are judged after percent-decoding."""
    return v[:n].encode("utf-8", "replace").decode("utf-8") if isinstance(v, str) else ""


def _dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def _int(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) and 0 < v < 10_000_000 else None


def _index(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 10_000_000 else None


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def _score(v: Any) -> float | None:
    if isinstance(v, bool):
        return None
    try:
        f = float(v) if isinstance(v, (int, float, str)) else None
    except ValueError:
        return None
    return f if f is not None and 0.0 <= f <= 10.0 else None


@dataclass(frozen=True)
class Location:
    path: str  # repository-relative when it could be resolved, else the absolute path or URI as written
    line: int | None = None
    column: int | None = None
    end_line: int | None = None
    resolved: bool = True  # False: an absolute path outside the source root, or an unresolvable base

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"path": self.path}
        if self.line:
            out["line"] = self.line
        if self.column:
            out["column"] = self.column
        if self.end_line and self.end_line != self.line:
            out["endLine"] = self.end_line
        if not self.resolved:
            out["resolved"] = False
        return out


@dataclass
class CodeFinding:
    tool: str
    rule_id: str
    title: str
    message: str
    severity: str
    severity_from: str
    security: bool
    cwe: tuple[int, ...]
    location: Location
    fingerprint: str
    precision: str = ""
    score: float | None = None  # the security-severity score, when the tool gives one
    help_uri: str = ""
    tags: tuple[str, ...] = ()
    sources: list[dict[str, str]] = field(default_factory=list)

    @property
    def id(self) -> str:
        cwe = f"CWE-{self.cwe[0]}" if self.cwe else self.rule_id
        return f"{self.location.path}:{self.location.line or 0}/{cwe}"

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "message": self.message,
            "severity": self.severity,
            "severityFrom": self.severity_from,
            "cwe": [f"CWE-{c}" for c in self.cwe],
            "location": self.location.as_dict(),
            "tools": sorted({s["tool"] for s in self.sources}),
            "sources": self.sources,
            "fingerprint": self.fingerprint,
        }
        if self.score is not None:
            out["securitySeverity"] = self.score
        if self.precision:
            out["precision"] = self.precision
        if self.help_uri:
            out["helpUri"] = self.help_uri
        return out


@dataclass
class SarifReport:
    tools: list[str]
    findings: list[CodeFinding]
    excluded: list[dict[str, Any]]
    quality: list[CodeFinding]
    notes: list[str]


# -- reading ---------------------------------------------------------------------------------------------------------


def _rules(run: dict[str, Any], where: str) -> tuple[list[list[dict[str, Any]]], dict[str, dict[str, Any]]]:
    """Rule lists per tool component (0 = the driver, n = extensions[n-1]) and every rule by id."""
    tool = _dict(run.get("tool"))
    components = [_dict(tool.get("driver")), *(_dict(x) for x in _list(tool.get("extensions"))[:200])]
    lists: list[list[dict[str, Any]]] = []
    by_id: dict[str, dict[str, Any]] = {}
    total = 0
    for comp in components:
        rules = [_dict(r) for r in _list(comp.get("rules"))]
        total += len(rules)
        if total > MAX_RULES:
            raise SarifError(f"{where}: more than {MAX_RULES} rules in a run")
        lists.append(rules)
        for r in rules:
            rid = _s(r.get("id"), 200)
            if rid:
                by_id.setdefault(rid, r)
    return lists, by_id


def _rule_for(
    result: dict[str, Any], lists: list[list[dict[str, Any]]], by_id: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """The rule a result names: ``rule.toolComponent.index`` points into ``tool.extensions`` (absent: the driver),
    ``rule.index`` or ``ruleIndex`` into that component's rules; else the rule with the result's ``ruleId``."""
    ref = _dict(result.get("rule"))
    comp_ref = _dict(ref.get("toolComponent"))
    comp_index = _index(comp_ref.get("index"))
    rules = lists[comp_index + 1] if comp_index is not None and comp_index + 1 < len(lists) else lists[0]
    idx = _index(ref.get("index")) if "index" in ref else _index(result.get("ruleIndex"))
    rid = _s(result.get("ruleId") or ref.get("id"), 200)
    if idx is not None and idx < len(rules):
        rule = rules[idx]
        if not rid or _s(rule.get("id"), 200) in {rid, rid.split("/")[0]}:
            return rule
    return by_id.get(rid, {})


def _bases(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(k)[:200]: _dict(v) for k, v in list(_dict(run.get("originalUriBaseIds")).items())[:100]}


def _resolve(uri: str, base_id: str, bases: dict[str, dict[str, Any]]) -> tuple[str, bool]:
    """The location's URI with its base resolved: (path, absolute). A base the run does not define (``%SRCROOT%``
    with no entry) means the repository root, as GitHub code scanning reads it."""
    parts = [uri]
    seen: set[str] = set()
    cur = base_id
    while cur and cur not in seen and len(seen) < MAX_BASE_DEPTH:
        seen.add(cur)
        base = bases.get(cur)
        if not base:
            break
        parts.append(_s(base.get("uri"), 2000))
        cur = _s(base.get("uriBaseId"), 200)
    joined = ""
    for part in reversed(parts[1:]):
        joined = part if not joined or urlparse(part).scheme else posixpath.join(joined, part)
    full = parts[0] if not joined or urlparse(parts[0]).scheme else posixpath.join(joined, parts[0])
    if full.startswith("file:"):
        return unquote(urlparse(full).path), True
    if urlparse(full).scheme:  # http(s) or another scheme: not a file in the repository
        return full, True
    path = unquote(full)
    return path, path.startswith("/")


def _relative(path: str, absolute: bool, roots: list[str]) -> tuple[str, bool]:
    if absolute:
        for root in roots:
            r = root.rstrip("/") + "/"
            if path.startswith(r):
                return _clean(path[len(r) :])
        return path, False
    return _clean(path)


def _clean(path: str) -> tuple[str, bool]:
    norm = posixpath.normpath(path.replace("\\", "/")).lstrip("/")
    if norm.startswith("../") or norm == "..":
        return norm, False
    return ("" if norm == "." else norm), True


def _location(
    result: dict[str, Any], run: dict[str, Any], bases: dict[str, dict[str, Any]], roots: list[str]
) -> Location | None:
    for loc in _list(result.get("locations"))[:10]:
        phys = _dict(_dict(loc).get("physicalLocation"))
        art = _dict(phys.get("artifactLocation"))
        uri = _raw(art.get("uri"), 2000).strip()
        base_id = _s(art.get("uriBaseId"), 200)
        idx = _index(art.get("index"))
        if not uri and idx is not None:
            arts = _list(run.get("artifacts"))
            if idx < len(arts):
                a = _dict(_dict(arts[idx]).get("location"))
                uri, base_id = _raw(a.get("uri"), 2000).strip(), base_id or _s(a.get("uriBaseId"), 200)
        if not uri:
            continue
        path, absolute = _resolve(uri, base_id, bases)
        path = path.encode("utf-8", "replace").decode("utf-8")
        rel, ok = _relative(path, absolute, roots)
        if sanitize.has_invisible(rel):  # %0A, %00, %1B, U+202E decoded: never a repository file or printed as is
            rel, ok = sanitize.visible(rel, replacement="?"), False
        region = _dict(phys.get("region"))
        return Location(
            rel, _int(region.get("startLine")), _int(region.get("startColumn")), _int(region.get("endLine")), ok
        )
    return None


def _message(result: dict[str, Any], rule: dict[str, Any]) -> str:
    msg = _dict(result.get("message"))
    text = _s(msg.get("text"), 2000)
    if not text:
        mid = _s(msg.get("id"), 100)
        text = _s(_dict(_dict(rule.get("messageStrings")).get(mid)).get("text"), 2000) if mid else ""
    args = [_s(a, 300) for a in _list(msg.get("arguments"))[:20]]
    if args:
        text = _ARG.sub(lambda m: args[int(m.group(1))] if int(m.group(1)) < len(args) else m.group(0), text)
    text = _LINK_REF.sub(r"\1", text)
    return text[:1000]


def _cwes(rule: dict[str, Any], result: dict[str, Any], tags: list[str]) -> tuple[int, ...]:
    found: list[int] = []
    for tag in tags:
        found += [int(m) for m in _CWE.findall(tag)]
    for rel in _list(rule.get("relationships"))[:50]:
        target = _dict(_dict(rel).get("target"))
        comp = _s(_dict(target.get("toolComponent")).get("name"), 100).upper()
        tid = _s(target.get("id"), 40)
        if "CWE" in comp and tid.isdigit():
            found.append(int(tid))
        else:
            found += [int(m) for m in _CWE.findall(tid)]
    for taxon in _list(result.get("taxa"))[:50]:
        t = _dict(taxon)
        comp = _s(_dict(t.get("toolComponent")).get("name"), 100).upper()
        tid = _s(t.get("id"), 40)
        if "CWE" in comp and tid.isdigit():
            found.append(int(tid))
    return tuple(sorted({c for c in found if 0 < c < 100_000}))


def _tool_name(run: dict[str, Any]) -> tuple[str, str]:
    driver = _dict(_dict(run.get("tool")).get("driver"))
    name = _s(driver.get("name"), 100) or "unknown tool"
    return name, _s(driver.get("semanticVersion") or driver.get("version"), 60)


def _security(tool: str, rule_id: str, cwe: tuple[int, ...], tags: list[str]) -> bool:
    low = [t.lower() for t in tags]
    if cwe or "security" in low or any(t.startswith("owasp") for t in low):
        return True
    if tool.lower().startswith("bandit"):
        return True
    if tool.lower().startswith("spotbugs") and any(t == "security" for t in low):
        return True
    return rule_id.startswith(SECURITY_RULE_PREFIXES)


def _severity(tool: str, result: dict[str, Any], rule: dict[str, Any], security: bool) -> tuple[str, str, float | None]:
    rprops, props = _dict(rule.get("properties")), _dict(result.get("properties"))
    score = _score(props.get("security-severity"))
    if score is None:
        score = _score(rprops.get("security-severity"))
    level = _s(result.get("level"), 20) or _s(_dict(rule.get("defaultConfiguration")).get("level"), 20) or "warning"
    if not security:
        return "info", f"level {level} (not a security rule)", None
    if score is not None:
        return severity_from_score(score), f"security-severity {score:g}", score
    bandit = _s(props.get("issue_severity"), 20).upper()
    if bandit in BANDIT_SEVERITY:
        return BANDIT_SEVERITY[bandit], f"{tool} issue_severity {bandit}", None
    problem = _s(rprops.get("problem.severity") or rprops.get("severity"), 20).lower()
    if not result.get("level") and problem in {"error", "warning", "recommendation"}:
        return (
            {"error": "high", "warning": "medium", "recommendation": "low"}[problem],
            f"problem.severity {problem}",
            None,
        )
    return LEVEL_SEVERITY.get(level, "medium"), f"level {level}", None


def _suppressed(result: dict[str, Any]) -> dict[str, str] | None:
    for raw in _list(result.get("suppressions"))[:20]:
        s = _dict(raw)
        status = _s(s.get("status"), 20) or "accepted"
        if status == "accepted":
            out = {"kind": _s(s.get("kind"), 20) or "unknown"}
            if s.get("justification"):
                out["justification"] = _s(s.get("justification"), 300)
            return out
    return None


def _fingerprint(result: dict[str, Any], tool: str, rule_id: str, loc: Location, message: str) -> str:
    for key in ("partialFingerprints", "fingerprints"):
        fp = _dict(result.get(key))
        for name in ("primaryLocationLineHash", *sorted(fp)):
            v = _s(fp.get(name), 200)
            if v:
                return f"{name}:{v}"[:240]
    raw = "\x1f".join([tool, rule_id, loc.path, str(loc.line or 0), message])
    return "kube-noob:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def parse(
    data: str | bytes,
    where: str = "SARIF",
    roots: list[str] | None = None,
    max_depth: int = sanitize.MAX_JSON_DEPTH,
) -> SarifReport:
    """Every run's failing results, normalised. ``roots``: absolute source roots the scanners ran in (for example
    ``/home/runner/work/shop/shop``), so absolute paths become repository-relative."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > MAX_BYTES:
        raise SarifError(f"{where}: larger than {MAX_BYTES} bytes")
    try:
        doc = sanitize.loads_bounded(raw, max_depth)
    except sanitize.JsonTooDeep as exc:
        raise SarifError(f"{where}: JSON nested too deeply") from exc
    except (ValueError, RecursionError) as exc:
        raise SarifError(f"{where}: not JSON") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        raise SarifError(f"{where}: not SARIF (no runs)")
    version = _s(doc.get("version"), 20)
    if version and version != "2.1.0":
        raise SarifError(f"{where}: SARIF {version}; kube-noob reads 2.1.0")
    runs = doc["runs"]
    if len(runs) > MAX_RUNS:
        raise SarifError(f"{where}: more than {MAX_RUNS} runs")
    out = SarifReport([], [], [], [], [])
    root_list = [r for r in (roots or []) if r.startswith("/")]
    for raw_run in runs:
        run = _dict(raw_run)
        tool, tool_version = _tool_name(run)
        out.tools.append(f"{tool} {tool_version}".strip())
        lists, by_id = _rules(run, where)
        bases = _bases(run)
        results = _list(run.get("results"))
        if len(results) > MAX_RESULTS:
            raise SarifError(f"{where}: more than {MAX_RESULTS} results in a run of {tool}")
        unplaced = 0
        unresolved = 0
        for raw_result in results:
            result = _dict(raw_result)
            rule = _dict(_rule_for(result, lists, by_id))
            rule_id = _s(result.get("ruleId") or _dict(result.get("rule")).get("id") or rule.get("id"), 200)
            loc = _location(result, run, bases, root_list)
            if loc is None:
                unplaced += 1
                continue
            if not loc.resolved:
                unresolved += 1
            rprops = _dict(rule.get("properties"))
            tags = [_s(t, 200) for t in _list(rprops.get("tags"))[:50] if _s(t, 200)]
            cwe = _cwes(rule, result, tags)
            security = _security(tool, rule_id, cwe, tags)
            sev, sev_from, score = _severity(tool, result, rule, security)
            message = _message(result, rule)
            title = (
                _s(_dict(rule.get("shortDescription")).get("text"), 300)
                or _s(rule.get("name"), 300)
                or rule_id
                or message[:120]
            )
            finding = CodeFinding(
                tool=tool,
                rule_id=rule_id or "unnamed rule",
                title=title,
                message=message,
                severity=sev,
                severity_from=sev_from,
                security=security,
                cwe=cwe,
                location=loc,
                fingerprint=_fingerprint(result, tool, rule_id, loc, message),
                precision=_s(rprops.get("precision") or _dict(result.get("properties")).get("issue_confidence"), 30),
                score=score,
                help_uri=_s(rule.get("helpUri"), 500),
                tags=tuple(tags[:20]),
                sources=[{"tool": tool, "ruleId": rule_id, "severity": sev}],
            )
            kind = _s(result.get("kind"), 30) or "fail"
            suppressed = _suppressed(result)
            baseline = _s(result.get("baselineState"), 20)
            reason = ""
            if kind != "fail":
                reason = f"not a failure: the result's kind is {kind}"
            elif suppressed:
                reason = f"suppressed ({suppressed['kind']})" + (
                    f": {suppressed['justification']}" if suppressed.get("justification") else ""
                )
            elif baseline == "absent":
                reason = "fixed: the baseline had it and this run does not (baselineState absent)"
            if reason:
                out.excluded.append({"finding": finding.as_dict(), "reason": reason})
            elif security:
                out.findings.append(finding)
            else:
                out.quality.append(finding)
        if unplaced:
            out.notes.append(f"{tool}: {unplaced} results without a file location are not read")
        if unresolved:
            out.notes.append(
                f"{tool}: {unresolved} results name files outside the source root; pass --source-root with the "
                "directory the scanner ran in to map them to the repository"
            )
    return out


def merge(findings: list[CodeFinding]) -> list[CodeFinding]:
    """One finding per file, line and weakness: results of several tools at the same place that share a CWE (or are
    the same rule of the same tool) become one, keeping the highest severity and every tool as a source."""
    groups: dict[tuple[str, int], list[CodeFinding]] = {}
    for f in findings:
        groups.setdefault((f.location.path, f.location.line or 0), []).append(f)
    out: list[CodeFinding] = []
    for group in groups.values():
        merged: list[CodeFinding] = []
        by_cwe: dict[int, int] = {}  # CWE -> index in merged; linear, not a scan of merged per finding
        by_rule: dict[tuple[str, str], int] = {}
        # each merged finding's sources, for a constant-time membership test
        keys: list[set[tuple[tuple[str, str], ...]]] = []
        for f in group:
            hits = [by_cwe[c] for c in f.cwe if c in by_cwe]
            if (f.tool, f.rule_id) in by_rule:
                hits.append(by_rule[(f.tool, f.rule_id)])
            if not hits:
                merged.append(dataclasses.replace(f, sources=list(f.sources)))
                keys.append({tuple(sorted(x.items())) for x in f.sources})
                n = len(merged) - 1
                by_rule.setdefault((f.tool, f.rule_id), n)
                for c in f.cwe:
                    by_cwe.setdefault(c, n)
                continue
            n = min(hits)
            target = merged[n]
            key = tuple(sorted(f.sources[0].items()))
            if key not in keys[n]:
                keys[n].add(key)
                target.sources.append(f.sources[0])
            if not set(f.cwe) <= set(target.cwe):
                target.cwe = tuple(sorted(set(target.cwe) | set(f.cwe)))
            by_rule.setdefault((f.tool, f.rule_id), n)
            for c in f.cwe:
                by_cwe.setdefault(c, n)
            higher = SEVERITY_RANK[f.severity] > SEVERITY_RANK[target.severity]
            same = SEVERITY_RANK[f.severity] == SEVERITY_RANK[target.severity]
            if higher or (same and (f.score or 0.0) > (target.score or 0.0)):
                target.severity, target.severity_from, target.score = f.severity, f.severity_from, f.score
                target.title, target.message = f.title, f.message
        out.extend(merged)
    return sorted(out, key=lambda f: (-SEVERITY_RANK[f.severity], f.location.path, f.location.line or 0, f.rule_id))
