"""Your own problems as a test: ``kube-noob selftest --cases problems.yaml``.

Feed kube-noob the problems your teams actually hit (questions from a post, incident snippets, events, logs, alert
payloads, manifests) and get a scorecard. A case with expectations passes or fails; a case without any is run and
reported as ``unlabelled``, so a list of raw questions is a valid first file: read what kube-noob answered, add the
expected answer, and the case becomes a regression test. Nothing is learned automatically and nothing leaves the
machine: kube-noob has no model, so a failure becomes a fix (a playbook, signal, rule or team memory entry) that is
reviewed like any other change.

Accepted files (at most 2,000 cases, 2 MB per input):

- YAML: a list of cases, or ``{cases: [...]}``;
- JSONL: one case object per line;
- CSV with a header row: ``id``, ``input`` and optional ``kind``, ``platform``, ``version``, ``playbook``, ``rules``,
  ``docs``, ``issues``, ``mention``, ``not_mention``, ``source`` (lists separated by ``;``);
- plain text: one question per line, or multi-line inputs separated by a line ``---``.

A case: ``input`` (required), ``id``, ``kind`` (auto, diagnose, search, audit, known-issues), ``platform``,
``version``, ``source`` and ``expect``: ``playbook`` (one id or a list: any of them in the top ``top`` diagnoses,
default 1), ``rules`` (all fire), ``notRules`` (none fires), ``docs`` (any in the top 3 search results), ``issues``
(any among the reported issues), ``mention`` (every phrase appears in the answer, case-insensitive) and
``notMention`` (none appears).
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from kube_noob import sanitize
from kube_noob.config import Settings

MAX_CASES = 2_000
MAX_INPUT = 2_000_000
MAX_FILE = 50_000_000
PlatformT = Literal["kubernetes", "openshift", "rosa-classic", "rosa-hcp"]
_ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$"
_RULE = r"^KN-[A-Z]\d{3}$"


class Expect(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    playbook: list[str] = Field(default_factory=list, max_length=10)
    top: int = Field(1, ge=1, le=5)
    rules: list[str] = Field(default_factory=list, max_length=50)
    not_rules: list[str] = Field(default_factory=list, max_length=50, alias="notRules")
    docs: list[str] = Field(default_factory=list, max_length=10)
    issues: list[str] = Field(default_factory=list, max_length=10)
    mention: list[str] = Field(default_factory=list, max_length=20)
    not_mention: list[str] = Field(default_factory=list, max_length=20, alias="notMention")

    @field_validator("playbook", "rules", "not_rules", "docs", "issues", "mention", "not_mention", mode="before")
    @classmethod
    def _as_list(cls, v: Any) -> Any:
        if v is None or v == "":
            return []
        if isinstance(v, str):
            return [x.strip() for x in v.split(";") if x.strip()]
        return v

    @field_validator("rules", "not_rules")
    @classmethod
    def _rule_ids(cls, v: list[str]) -> list[str]:
        import re

        bad = [x for x in v if not re.fullmatch(_RULE, x)]
        if bad:
            raise ValueError(f"not rule ids: {bad[:3]} (rules look like KN-S001)")
        return v

    @field_validator("mention", "not_mention", "docs", "issues", "playbook")
    @classmethod
    def _short(cls, v: list[str]) -> list[str]:
        if any(len(x) > 200 for x in v):
            raise ValueError("each expected value is at most 200 characters")
        return v

    def labelled(self) -> bool:
        return any((self.playbook, self.rules, self.not_rules, self.docs, self.issues, self.mention, self.not_mention))


class Case(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field("", pattern=r"^$|" + _ID)
    input: str = Field(..., min_length=3, max_length=MAX_INPUT)
    kind: Literal["auto", "diagnose", "search", "audit", "known-issues"] = "auto"
    platform: PlatformT | None = None
    version: str | None = Field(None, max_length=20, pattern=r"^\d+\.\d+(\.\d+)?$")
    source: str = Field("", max_length=300)
    expect: Expect = Field(default_factory=Expect)


def _rows_to_cases(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for raw_row in rows:
        row = {k.strip(): v for k, v in raw_row.items() if k and v not in (None, "")}
        expect = {
            key: row.pop(col)
            for col, key in (
                ("playbook", "playbook"),
                ("rules", "rules"),
                ("not_rules", "notRules"),
                ("docs", "docs"),
                ("issues", "issues"),
                ("mention", "mention"),
                ("not_mention", "notMention"),
                ("top", "top"),
            )
            if col in row
        }
        if expect:
            row["expect"] = expect
        out.append(row)
    return out


def parse(text: str, name: str = "") -> list[Case]:
    """Cases from a YAML, JSONL, CSV or plain-text file's content. Errors name the case."""
    if len(text) > MAX_FILE:
        raise ValueError(f"{name or 'the file'} is larger than {MAX_FILE // 1_000_000} MB")
    suffix = Path(name).suffix.lower()
    raw: list[Any]
    if suffix == ".jsonl":
        raw = []
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            if not sanitize.json_nesting_ok(line):
                raise ValueError(f"{name} line {n}: not JSON (or nested too deeply)")
            try:
                raw.append(json.loads(line))
            except (ValueError, RecursionError) as exc:
                raise ValueError(f"{name} line {n}: not JSON (or nested too deeply)") from exc
    elif suffix == ".csv":
        raw = _rows_to_cases(list(csv.DictReader(io.StringIO(text))))
    elif suffix in {".txt", ".md", ""} and not text.lstrip().startswith(("cases:", "- ", "{", "[")):
        blocks = [b.strip() for b in text.split("\n---\n")] if "\n---\n" in text else text.splitlines()
        raw = [{"input": b} for b in blocks if b.strip() and not b.lstrip().startswith("#")]
    else:
        doc = yaml.safe_load(text)
        raw = doc.get("cases", []) if isinstance(doc, dict) else doc if isinstance(doc, list) else []
    if not isinstance(raw, list) or not raw:
        raise ValueError(f"{name or 'the file'} holds no cases")
    if len(raw) > MAX_CASES:
        raise ValueError(f"{len(raw)} cases: at most {MAX_CASES} per file")
    out: list[Case] = []
    for i, item in enumerate(raw, 1):
        if not isinstance(item, dict):
            raise ValueError(f"case {i}: expected a mapping with an `input`")
        try:
            case = Case.model_validate(item)
        except ValidationError as exc:
            first = exc.errors()[0]
            where = ".".join(str(x) for x in first.get("loc", ()))
            raise ValueError(f"case {item.get('id') or i}: {where}: {first.get('msg')}") from exc
        out.append(case.model_copy(update={"id": case.id or f"P{i:04d}"}))
    ids = [c.id for c in out]
    if len(set(ids)) != len(ids):
        raise ValueError("case ids must be unique")
    return out


def load(path: Path) -> list[Case]:
    if not path.is_file():
        raise ValueError(f"{path}: no such file")
    if path.stat().st_size > MAX_FILE:
        raise ValueError(f"{path} is larger than {MAX_FILE // 1_000_000} MB")
    return parse(path.read_text(encoding="utf-8"), path.name)


def _looks_like_manifests(text: str) -> bool:
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError:
        return False
    return bool(docs) and all(isinstance(d, dict) and "apiVersion" in d and "kind" in d for d in docs)


def answer(kit: Any, case: Case) -> dict[str, Any]:
    """What kube-noob says about one case, as the CLI and MCP tools would."""
    from kube_noob import toolkit as tk

    kinds = {case.kind}
    if case.kind == "auto":
        kinds = {"audit"} if _looks_like_manifests(case.input) else {"diagnose", "search", "known-issues"}
    out: dict[str, Any] = {"kinds": sorted(kinds)}
    if "diagnose" in kinds:
        d = kit.diagnose(tk.DiagnoseIn(text=case.input[:200_000], platform=case.platform, version=case.version))
        out["diagnoses"] = [
            {k: x.get(k) for k in ("id", "title", "confidence", "rootCauses", "readOnlyNextSteps", "proposedChanges")}
            for x in d["diagnoses"][:5]
        ]
        out["context"] = d.get("context", {})
    if "search" in kinds:
        hits = kit.search(tk.SearchIn(query=case.input[:500], limit=8))["results"]
        docs: list[dict[str, Any]] = []
        for h in hits:  # the top 3 documents, not chunks: one document can hold several of the best chunks
            doc = h["chunkId"].split("#", 1)[0].removeprefix("kn:")
            if doc not in {d["doc"] for d in docs}:
                docs.append({"doc": doc, "title": h.get("title")})
        out["docs"] = docs[:3]
    if "known-issues" in kinds:
        k = kit.known_issues(
            tk.KnownIssuesIn(text=case.input[:100_000], platform=case.platform, version=case.version, limit=5)
        )
        out["issues"] = [{"id": m.get("id"), "title": m.get("title")} for m in k.get("matches", [])]
    if "audit" in kinds:
        where = {k: v for k, v in (("platform", case.platform), ("version", case.version)) if v}
        rep = kit.audit(tk.AuditIn(manifests=case.input, **where))
        out["rules"] = sorted({f["ruleId"] for f in rep["findings"]})
        out["findings"] = [f"{f['ruleId']} {f['resource']}: {f['message']}" for f in rep["findings"][:50]]
    return out


def judge(case: Case, said: dict[str, Any]) -> list[str]:
    """Why the answer misses the case's expectations (empty: it passes)."""
    e = case.expect
    misses: list[str] = []
    top = [d["id"] for d in said.get("diagnoses", [])[: e.top]]
    if e.playbook and not set(e.playbook) & set(top):
        misses.append(f"expected playbook {' or '.join(e.playbook)} in the top {e.top}, got {', '.join(top) or 'none'}")
    fired = set(said.get("rules", []))
    if e.rules and (missing := [r for r in e.rules if r not in fired]):
        misses.append(f"rules did not fire: {', '.join(missing)}")
    if e.not_rules and (extra := [r for r in e.not_rules if r in fired]):
        misses.append(f"rules fired that should not: {', '.join(extra)}")
    docs = [d["doc"] for d in said.get("docs", [])]
    if e.docs and not set(e.docs) & set(docs):
        misses.append(f"expected doc {' or '.join(e.docs)} in the top 3, got {', '.join(docs) or 'none'}")
    issues = [str(i["id"]) for i in said.get("issues", [])]
    if e.issues and not set(e.issues) & set(issues):
        misses.append(f"expected issue {' or '.join(e.issues)}, got {', '.join(issues) or 'none'}")
    blob = json.dumps(said, ensure_ascii=False).lower()
    if missing_words := [m for m in e.mention if m.lower() not in blob]:
        misses.append(f"answer does not mention: {'; '.join(missing_words)}")
    if present := [m for m in e.not_mention if m.lower() in blob]:
        misses.append(f"answer mentions what it must not: {'; '.join(present)}")
    return misses


def run_cases(settings: Settings, cases: list[Case], gate: float | None = None) -> dict[str, Any]:
    """Run every case offline (web and cluster off) and score the labelled ones."""
    from kube_noob import toolkit as tk

    safe = settings.model_copy(
        update={"web_enabled": False, "cluster": settings.cluster.model_copy(update={"enabled": False})}
    )
    kit = tk.Toolkit(safe)
    rows: list[dict[str, Any]] = []
    for case in cases:
        try:
            said = answer(kit, case)
            misses = judge(case, said) if case.expect.labelled() else []
            status = ("pass" if not misses else "fail") if case.expect.labelled() else "unlabelled"
        except (ValueError, ValidationError) as exc:
            said, misses, status = {}, [f"could not run: {str(exc)[:300]}"], "error"
        rows.append(
            {
                "id": case.id,
                "status": status,
                "kind": case.kind,
                "source": case.source,
                "input": case.input[:300],
                "said": said,
                "misses": misses,
            }
        )
    labelled = [r for r in rows if r["status"] in {"pass", "fail", "error"}]
    passed = sum(r["status"] == "pass" for r in labelled)
    rate = round(passed / len(labelled), 3) if labelled else None
    return {
        "cases": len(rows),
        "labelled": len(labelled),
        "passed": passed,
        "passRate": rate,
        "unlabelled": len(rows) - len(labelled),
        "gate": None if gate is None else {"threshold": gate, "passed": rate is not None and rate >= gate},
        "results": rows,
    }


def markdown(rep: dict[str, Any]) -> str:
    """The scorecard as Markdown: summary, then every failed, error and unlabelled case with what kube-noob said."""
    rate = "n/a" if rep["passRate"] is None else f"{rep['passRate']:.0%}"
    lines = [
        "# kube-noob problem eval",
        "",
        "| Measure | Value |",
        "| --- | --- |",
        f"| Cases | {rep['cases']} |",
        f"| Labelled | {rep['labelled']} |",
        f"| Passed | {rep['passed']} of {rep['labelled']} ({rate}) |",
        f"| Unlabelled (answered, not scored) | {rep['unlabelled']} |",
    ]
    if rep["gate"]:
        verdict = "PASSED" if rep["gate"]["passed"] else "FAILED"
        lines.append(f"| Gate (pass rate >= {rep['gate']['threshold']:.0%}) | **{verdict}** |")
    for status, title in (("fail", "Failed"), ("error", "Could not run"), ("unlabelled", "Unlabelled: add `expect`")):
        group = [r for r in rep["results"] if r["status"] == status]
        if not group:
            continue
        lines += ["", f"## {title} ({len(group)})", ""]
        for r in group:
            said = r["said"]
            top = ", ".join(f"{d['id']} ({d['confidence']})" for d in said.get("diagnoses", [])[:3]) or "-"
            first = (said.get("diagnoses") or [{}])[0].get("rootCauses") or [""]
            lines.append(f"### {r['id']}" + (f" ({r['source']})" if r["source"] else ""))
            lines.append("")
            lines.append("> " + " ".join(r["input"].split())[:200])
            lines.append("")
            lines.append(f"- playbooks: {top}")
            if first[0]:
                lines.append(f"- first cause: {first[0][:200]}")
            if said.get("docs"):
                lines.append("- docs: " + ", ".join(d["doc"] for d in said["docs"]))
            if said.get("issues"):
                lines.append("- reported issues: " + ", ".join(str(i["id"]) for i in said["issues"]))
            if said.get("rules"):
                lines.append("- rules fired: " + ", ".join(said["rules"]))
            lines += [f"- miss: {m}" for m in r["misses"]]
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"
