"""Reproducible verdict receipts: one self-describing document a third party can check without trusting the runner.

The product claim is a deterministic three-valued verdict. A deterministic verdict nobody can re-derive is a claim,
not evidence, so ``audit --receipt PATH`` and ``gate --receipt PATH`` write one JSON document that binds, in one
place: the schema it is written to, the kube-noob that wrote it, every input by SHA-256 (file by file, with the path
as given and the path it resolved to), the identity and the **meaning** of every rule in the rule set, the settings
and flags that changed the verdict, the scope actually read and what was not read, and the verdict itself -- counts,
score, or the reason there is no verdict (the command's own: ``summary.verdictReason`` under
``summary.verdict: undetermined`` for an audit, which ``Report.undetermined()`` decided, and
``model.incomplete_reason`` for a gate -- a receipt records the verdict it was given and never re-judges it),
exit code, and every finding by ``Finding.fingerprint()``.

``kube-noob receipt verify PATH`` re-runs those inputs and answers one of three things:

- **identical** -- the verdict is reproduced, exit 0;
- **differs** -- it is not, and the answer names every field that moved, exit 1;
- **cannot be checked** -- an input is missing, an input's digest differs, the receipt was written by another
  kube-noob, the rule set has changed, or the run is not replayable from the files the receipt binds. Exit **5**.

The third answer is the one worth building. A verifier that cannot get an input and says "pass" is worse than no
verifier, and a verifier that calls a changed input a changed verdict invites a reader to treat a fresh audit as a
reproduction. So a changed input digest is never "differs": it is a different question, and the answer names it.

**Integrity, not authenticity.** SHA-256 and nothing else: no signature, no key, no ``cryptography``. The document
proves that the same inputs give the same verdict and proves **nothing** about who produced it -- anyone who can run
kube-noob can write a receipt for any input they hold. It says exactly that in its own text
(``integrity.statement``), and a test in ``tests/test_receipts.py`` holds that sentence. A signer is an adapter
over this document: it would wrap ``payload`` and ``integrity`` and add its own block beside them. The seam is
the payload digest; nothing here is built towards a key.

**Determinism is the product.** ``payload`` must be byte-identical for identical inputs, so every fact that cannot
be deterministic -- the clock, the duration -- lives in ``envelope``, outside the digest. ``envelope`` records no
hostname and no runner identity: an unsigned document cannot attest to who produced it, so a self-asserted host in
it would be a claim the document says it cannot support, and a receipt is made to be forwarded. The fields are
present and null with the reason in their place, because a reader who does not find the key cannot tell a tool that
withheld it from one that never had it.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

from kube_noob import __version__
from kube_noob.errors import ConfigError, KubeNoobError
from kube_noob.yamlio import json_document

SCHEMA = "kube-noob.receipt/1"
SCHEMA_VERSION = 1
ALGORITHM = "sha256"
#: Truncated like ``Finding.fingerprint()``: an identity, not a commitment. 16 hex characters of SHA-256 over a
#: rule's own declaration -- long enough that two rule declarations will not collide, short enough to read.
MEANING_CHARS = 16
#: Input digests and the payload digest are full-length: they are what a third party re-computes with `sha256sum`.
MAX_INPUTS = 2000
#: Scope lists that grow with the input are capped, with what was left out counted beside them: a receipt for a
#: thousand-document bundle is still a document somebody reads, and a cap with no count is class 2.
MAX_SCOPE_LIST = 500

INTEGRITY_STATEMENT = (
    "This receipt proves that the same inputs give the same verdict: every input is bound by its SHA-256 digest, "
    "and the verdict payload by one more. It proves nothing about who produced it. There is no signature and no "
    "key, so anyone who can run kube-noob can write a receipt for any input they hold. Check it with "
    "`kube-noob receipt verify`, and check the inputs with `sha256sum`."
)
ENVELOPE_NOT_INCLUDED = (
    "The host and the user who ran this are not recorded. An unsigned document cannot attest to who produced it, "
    "so a self-asserted hostname here would be a claim this document says it cannot support -- and a receipt is "
    "written to be forwarded."
)
PROVES = "the same inputs give the same verdict; not who produced it"

STATUS_EXIT = {"identical": 0, "differs": 1, "cannot-be-checked": 5}


class ReceiptError(KubeNoobError):
    """The document is not a receipt this build can read, or it is not self-consistent. Refused input: exit 4.

    Deliberately NOT "cannot be checked": exit 5 means kube-noob looked and the evidence was incomplete, and a
    document whose payload does not match the digest it carries is not incomplete evidence -- it is not a receipt.
    """


def _now() -> dt.datetime:
    """Patched in tests. The clock is the one fact a receipt must keep out of its payload."""
    return dt.datetime.now(dt.UTC)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj: Any) -> str:
    """The bytes a digest is taken over: keys sorted, no insignificant space, every non-ASCII character escaped.

    Through ``json_document``, so a payload holding a CI service message cannot put a workflow command in a log
    when the receipt is printed (G279) -- and so the digest is taken over the bytes that are written.
    """
    return json_document(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest_of(obj: Any) -> str:
    return sha256_bytes(canonical(obj).encode("utf-8"))


# --- rule meaning --------------------------------------------------------------------------------------------------


def rule_meaning(rule_id: str) -> str:
    """Which *meaning* of this rule, derived from the rule's own declaration -- never a hand-maintained number.

    A rule id is stable on purpose: a baseline, an exception list and a SARIF alert history all key on it. That is
    exactly why a receipt cannot rest on it. ``Rule.as_dict()`` is the rule's declared meaning -- its title, stage,
    category, default severity, description, remediation, citations, RHACS policy names and NIST controls -- so a
    change to any of them changes the version here while the id stays put, and a receipt can say which KN-S001 it
    used. The check function is not hashed: a refactor that does not change the declaration does not rotate every
    receipt's rule versions, and a behaviour change that is not visible in the declaration is caught by the tool
    version instead, which `receipt verify` checks first.
    """
    from kube_noob.audit.rules import RULES

    rule = RULES.get(rule_id)
    if rule is None:
        raise ReceiptError(f"no rule {rule_id} in this kube-noob ({__version__})")
    declaration = {k: v for k, v in rule.as_dict().items() if k != "ruleId"}
    return sha256_bytes(canonical(declaration).encode("utf-8"))[:MEANING_CHARS]


def rule_set() -> dict[str, Any]:
    """The rule set's identity: how many rules, every rule's meaning version, and one digest over all of them."""
    from kube_noob.audit.rules import RULES

    meanings = {rid: rule_meaning(rid) for rid in sorted(RULES)}
    return {"rules": len(meanings), "digest": digest_of(meanings), "meanings": meanings}


# --- inputs --------------------------------------------------------------------------------------------------------


def _resolved(path: Path) -> str | None:
    try:
        return str(path.resolve())
    except (OSError, RuntimeError, ValueError):
        return None


def file_input(given: str, *, order: int, role: str = "manifest") -> dict[str, Any]:
    """One input bound by the digest of its bytes on disk, which is what ``sha256sum`` prints.

    The bytes, not the text kube-noob decoded: a reader checks a receipt against the file they were handed, and a
    digest of a decoded-and-replaced string is a number nothing else in the world computes.
    """
    p = Path(given)
    entry: dict[str, Any] = {"order": order, "role": role, "path": given, "resolvedPath": _resolved(p)}
    try:
        data = p.read_bytes()
    except OSError as exc:
        entry.update(sha256=None, bytes=None, notRetrievable=f"not readable now: {exc.strerror or exc}")
        return entry
    entry.update(sha256=sha256_bytes(data), bytes=len(data))
    return entry


def text_input(given: str, text: str, *, order: int, role: str, not_retrievable: str) -> dict[str, Any]:
    """An input that was read but is not a file to re-read: standard input, a rendered chart.

    It is bound by hash like any other -- the digest still says what was audited -- and it carries why its bytes
    cannot be fetched again, so ``receipt verify`` answers "cannot be checked" and names it rather than passing.
    """
    return {
        "order": order,
        "role": role,
        "path": given,
        "resolvedPath": None,
        "sha256": sha256_bytes(text.encode("utf-8")),
        "bytes": len(text.encode("utf-8")),
        "notRetrievable": not_retrievable,
    }


# --- the verdict ---------------------------------------------------------------------------------------------------


def findings_of(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every finding by its line-independent identity, in a total order.

    ``Finding.fingerprint()`` is the shipped identity (G190) and this calls it rather than re-deriving one: a second
    definition of a finding's identity is the defect class where a private copy of a shared list drifts from it.
    Duplicates are kept: two findings that share an identity are two findings, and dropping one would make a
    receipt disagree with the counts beside it.
    """
    from kube_noob.audit.model import fingerprint_for

    def identity(f: dict[str, Any]) -> str:
        recorded = f.get("fingerprint")
        if recorded:
            return str(recorded)
        return fingerprint_for(_s(f, "ruleId"), _s(f, "resource"), _locator(f))

    out = [{"fingerprint": identity(f), "ruleId": _s(f, "ruleId"), "severity": _s(f, "severity")} for f in findings]
    return sorted(out, key=lambda x: (x["fingerprint"], x["ruleId"], x["severity"]))


def _s(f: dict[str, Any], key: str) -> str:
    value = f.get(key)
    return "" if value is None else str(value)


def _locator(f: dict[str, Any]) -> str:
    return _s(f, "locator") or _s(f, "path")


def capped(values: list[Any], limit: int = MAX_SCOPE_LIST) -> tuple[list[Any], int]:
    """``limit`` entries and how many were left out. The count is always recorded, even when it is zero: a reader
    who does not find the number cannot tell a complete list from one that was cut."""
    return list(values[:limit]), max(0, len(values) - limit)


def audit_undetermined(report: dict[str, Any]) -> str | None:
    """Why this serialised AUDIT report is not a verdict, or None when it is one. Read, never decided.

    ``Report.undetermined()`` is the one predicate, and ``Report.as_dict`` writes its answer as
    ``summary.verdict: undetermined`` with ``summary.verdictReason`` beside it (G281). This reads those two keys
    and nothing else. It used to read ``summary.scoreWithheld``, the name G272 gave the same string and G281
    retired; after that the key was simply absent, an absent key read as "not withheld", and an undetermined audit
    would have exited 0 under ``--fail-on never`` with a receipt saying so (G359, review classes 4 and 9).

    A report that says ``undetermined`` and gives no reason is still undetermined: the word decides, and the
    reason is the word itself rather than nothing.
    """
    summary = report.get("summary")
    if not isinstance(summary, dict) or summary.get("verdict") != "undetermined":
        return None
    return str(summary.get("verdictReason") or "undetermined")


def gate_undetermined(report: dict[str, Any]) -> str | None:
    """Why this GATE report is incomplete, or None when it is not: ``report["incomplete"]``, which ``gate.run``
    decided, with the reason from ``model.incomplete_reason`` -- the reader every gate renderer uses.

    Three things make a gate incomplete (an undetermined audit, a file the walk declined to read as a manifest,
    a file that could not be read and nobody accepted: G272, G325, G340). A receipt that read ``undetermined``
    alone recorded no reason for the other two.
    """
    from kube_noob.audit.model import incomplete_reason

    if not report.get("incomplete"):
        return None
    return incomplete_reason(report) or "incomplete"


def audit_exit_code(report: dict[str, Any], fail_on: str) -> int:
    """The exit code an ``audit`` report means, in ONE place, by the rule AGENTS.md publishes.

    ``1`` means a verdict was reached and it is not a pass; ``5`` means no verdict was reached at all, and ``5``
    is decided before this is called (an unreadable file without ``--skip-unreadable``), never here. So an
    **undetermined** report is 1, and ``--fail-on`` cannot lower it: an undetermined report is not a clean one at
    any threshold, so "no severity is worth failing on" must not turn it into a 0
    (AGENTS.md, "1 and 5 are not two answers to the same question", G272).

    Whether the report is undetermined is NOT decided here. ``Report.undetermined()`` is the one predicate, and
    it reaches this function already serialised as ``summary.verdict`` (``audit_undetermined`` reads it) -- which
    is also why there is no second undetermined rule in this module: a receipt records the verdict the command
    gave, including the reason there is none, and does not re-judge it. The CLI returns this, the receipt records
    it, and the MCP verifier recomputes it when it replays a run; three copies of the arithmetic would be three
    chances for a receipt to record an exit code the command did not return, and the exit code is a published
    contract.
    """
    from kube_noob.audit.model import Severity

    if report.get("exceptions") and not report["exceptions"]["gate"]:
        return 1
    if audit_undetermined(report):
        return 1
    if fail_on == "never":
        return 0
    limit = Severity.parse(fail_on)
    return 1 if any(Severity.parse(f["severity"]) >= limit for f in report["findings"]) else 0


def gate_exit_code(report: dict[str, Any]) -> int:
    """The exit code a ``gate`` report means, in ONE place: what the CLI returns, the receipt records and
    ``receipt verify`` recomputes on a replay (G359).

    ``5`` when no verdict was reached because of evidence the gate refused to decide from: a file that could not
    be read and that ``--skip-unreadable`` did not accept (``model.open_unread``: the row carries ``acceptedBy``
    when the flag was given, G340), or a file the walk declined to read as a manifest, which no flag waves
    through (``model.blocked_manifests``, G325). Otherwise ``report["passed"]`` decides between 0 and 1, and
    ``gate.run`` has already made that false for an undetermined audit. Nothing here re-derives any of the three:
    they are read off the report.
    """
    from kube_noob.audit.model import blocked_manifests, open_unread

    if open_unread(report) or blocked_manifests(report):
        return 5
    return 0 if report["passed"] else 1


def verdict(
    *,
    counts: dict[str, int],
    score: float | None,
    undetermined: str | None,
    exit_code: int,
    findings: list[dict[str, Any]],
    excepted: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """The verdict as a receipt records it -- the verdict the command gave, never a second judgement of it.

    ``score`` and ``undetermined`` are passed in from the report the command produced, where
    ``Report.undetermined()`` already decided them: the ONE predicate (G272). They are recorded as given. A
    receipt that applied its own rule for withholding a score could withhold one the command printed, or print
    one the command withheld, and then the document would disagree with the run it claims to describe.

    ``excepted`` findings are carried apart rather than mixed in: the counts exclude them, so putting them in
    ``findings`` would make the list disagree with the numbers beside it -- and an exception is a reviewed, owned,
    expiring decision about a control, which is evidence of its own and must not vanish from the record.
    """
    return {
        "counts": dict(sorted(counts.items())),
        "score": score,
        "undetermined": undetermined,
        "exitCode": exit_code,
        "findings": findings_of(findings),
        "excepted": findings_of(excepted or []),
    }


# --- building and writing ------------------------------------------------------------------------------------------


def build(
    *,
    command: str,
    inputs: list[dict[str, Any]],
    settings: dict[str, Any],
    scope: dict[str, Any],
    verdict: dict[str, Any],
    replay: dict[str, Any],
    duration_ms: int | None = None,
) -> dict[str, Any]:
    """One receipt. ``payload`` is deterministic; ``envelope`` holds what cannot be."""
    if len(inputs) > MAX_INPUTS:
        raise ReceiptError(f"more than {MAX_INPUTS} inputs: a receipt binds one run, not a whole repository")
    payload = {
        "schema": SCHEMA,
        "schemaVersion": SCHEMA_VERSION,
        "command": command,
        "tool": {"name": "kube-noob", "version": __version__},
        "ruleSet": rule_set(),
        "inputs": sorted(inputs, key=lambda i: (int(i["order"]), str(i["path"]))),
        "settings": dict(sorted(settings.items())),
        "scope": dict(sorted(scope.items())),
        "verdict": verdict,
        "replay": replay,
    }
    return {
        "schema": SCHEMA,
        "integrity": {
            "algorithm": ALGORITHM,
            "payloadDigest": digest_of(payload),
            "signed": False,
            "proves": PROVES,
            "statement": INTEGRITY_STATEMENT,
            "verifyWith": "kube-noob receipt verify",
        },
        "envelope": {
            "takenAt": _now().replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "durationMs": duration_ms,
            "host": None,
            "runner": None,
            "notIncluded": ENVELOPE_NOT_INCLUDED,
        },
        "payload": payload,
    }


def write(path: Path, doc: dict[str, Any]) -> None:
    """The whole document or nothing, readable by its owner only, through the one output boundary.

    Written to a temporary file in the same directory and moved into place: a reader that opened the path while
    this was being written would otherwise get half a document, and half a receipt reads as a receipt (class 16).
    The temporary name is random and created by ``mkstemp`` (0600, O_EXCL), not ``<path>.partial``: a guessable
    name beside a path the caller chose is a name something else can plant a link at first (class 18).
    """
    import os
    import tempfile

    text = json_document(doc, indent=2, sort_keys=True) + "\n"
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".receipt-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def load(path: Path) -> dict[str, Any]:
    """Read a receipt, bounded, and refuse anything that is not one.

    Through ``sanitize.loads_bounded``, not ``json.loads``: the depth at which a nesting bomb is refused must be
    the same on every machine rather than whatever the interpreter's recursion limit happens to be here.
    """
    from kube_noob import sanitize

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        # Exit 2, not 4: "a file that is not there" is the published meaning of 2, and a receipt somebody has not
        # been given yet is that, not a refused document.
        raise ConfigError(f"{path}: {exc.strerror or exc}") from exc
    try:
        doc = sanitize.loads_bounded(raw, sanitize.MAX_JSON_DEPTH_FILE)
    except sanitize.JsonTooDeep as exc:
        raise ReceiptError(f"{path}: {exc}") from exc
    except ValueError as exc:
        raise ReceiptError(f"{path}: not JSON ({exc})") from exc
    if not isinstance(doc, dict):
        raise ReceiptError(f"{path}: not a kube-noob receipt (the document is not an object)")
    schema = doc.get("schema")
    if schema != SCHEMA:
        raise ReceiptError(
            f"{path}: schema {schema!r} is not {SCHEMA!r}, the only receipt schema this kube-noob ({__version__}) reads"
        )
    payload = doc.get("payload")
    integrity = doc.get("integrity")
    if not isinstance(payload, dict) or not isinstance(integrity, dict):
        raise ReceiptError(f"{path}: not a kube-noob receipt (no payload or no integrity block)")
    if integrity.get("algorithm") != ALGORITHM:
        raise ReceiptError(f"{path}: integrity.algorithm {integrity.get('algorithm')!r} is not {ALGORITHM!r}")
    recorded = integrity.get("payloadDigest")
    computed = digest_of(payload)
    if recorded != computed:
        raise ReceiptError(
            f"{path}: the payload does not match the payloadDigest this document carries "
            f"(recorded {recorded}, computed {computed}). The document has been changed since it was written, so "
            "it is refused rather than checked."
        )
    return doc


# --- verifying -----------------------------------------------------------------------------------------------------

#: Called with the receipt's payload; returns the verdict a fresh run of the same inputs produced, or raises
#: ``ReceiptError``. The replay lives outside this module so that nothing here has to import a command.
Replay = Callable[[dict[str, Any]], dict[str, Any]]


def check_inputs(payload: dict[str, Any], *, base: Path | None = None) -> list[dict[str, Any]]:
    """Every input this receipt binds that cannot be got back, with the reason -- the answer's third value."""
    out: list[dict[str, Any]] = []
    for entry in payload.get("inputs") or []:
        given, recorded = str(entry.get("path")), entry.get("sha256")
        if entry.get("notRetrievable"):
            out.append({"what": "input", "which": given, "why": str(entry["notRetrievable"])})
            continue
        candidates = [Path(given)] if base is None else [base / given, Path(given)]
        if entry.get("resolvedPath"):
            candidates.append(Path(str(entry["resolvedPath"])))
        for path in candidates:
            try:
                data = path.read_bytes()
            except OSError:
                continue
            got = sha256_bytes(data)
            if got != recorded:
                out.append(
                    {
                        "what": "input",
                        "which": given,
                        "why": f"sha256 differs: the receipt records {recorded}, {path} is {got}. A changed input "
                        "is a different question, not a changed verdict.",
                    }
                )
            break
        else:
            where = " or ".join(str(c) for c in dict.fromkeys(candidates))
            out.append({"what": "input", "which": given, "why": f"not found at {where}"})
    return out


def _compare(recorded: dict[str, Any], rerun: dict[str, Any]) -> list[dict[str, Any]]:
    """Every field of the verdict that moved, named. ``score``/``undetermined`` are compared as given."""
    out: list[dict[str, Any]] = []
    for key in sorted(set(recorded.get("counts") or {}) | set(rerun.get("counts") or {})):
        a, b = (recorded.get("counts") or {}).get(key), (rerun.get("counts") or {}).get(key)
        if a != b:
            out.append({"field": f"verdict.counts.{key}", "receipt": a, "rerun": b})
    for key in ("score", "undetermined", "exitCode"):
        if recorded.get(key) != rerun.get(key):
            out.append({"field": f"verdict.{key}", "receipt": recorded.get(key), "rerun": rerun.get(key)})
    for key in ("findings", "excepted"):
        was = {(f["fingerprint"], f["ruleId"], f["severity"]) for f in recorded.get(key) or []}
        now = {(f["fingerprint"], f["ruleId"], f["severity"]) for f in rerun.get(key) or []}
        for fp, rid, sev in sorted(was - now):
            out.append({"field": f"verdict.{key}", "receipt": f"{rid} {sev} {fp}", "rerun": None})
        for fp, rid, sev in sorted(now - was):
            out.append({"field": f"verdict.{key}", "receipt": None, "rerun": f"{rid} {sev} {fp}"})
    return out


def verify(doc: dict[str, Any], *, replay: Replay, base: Path | None = None) -> dict[str, Any]:
    """Is this receipt's verdict reproduced? identical, differs (naming the fields), or cannot be checked.

    The order matters. The tool version and the rule set are checked BEFORE the inputs are re-run, because a
    receipt from another kube-noob cannot be reproduced by this one whatever the files say, and reporting that as
    "differs" would read as a regression in the code rather than a receipt this build cannot check.
    """
    payload = doc["payload"]
    recorded_version = str(((payload.get("tool") or {}).get("version")) or "")
    cannot: list[dict[str, Any]] = []
    if recorded_version != __version__:
        cannot.append(
            {
                "what": "toolVersion",
                "which": recorded_version or "(none)",
                "why": f"the receipt was written by kube-noob {recorded_version or '(unstated)'} and this is "
                f"{__version__}; a verdict from another build is not reproduced here, it is a different run",
            }
        )
    else:
        recorded_rules = payload.get("ruleSet") or {}
        mine = rule_set()
        if recorded_rules.get("digest") != mine["digest"]:
            moved = sorted(
                rid
                for rid in set(recorded_rules.get("meanings") or {}) | set(mine["meanings"])
                if (recorded_rules.get("meanings") or {}).get(rid) != mine["meanings"].get(rid)
            )
            cannot.append(
                {
                    "what": "ruleSet",
                    "which": moved[:20],
                    "why": f"{len(moved)} rule(s) do not mean here what they meant when this receipt was written, "
                    "so the same inputs are not being asked the same question",
                }
            )
    cannot.extend(check_inputs(payload, base=base))
    plan = payload.get("replay") or {}
    if not plan.get("supported"):
        cannot.append(
            {
                # The command, not the reason: ``which`` names the thing that could not be got and ``why`` says
                # why, and putting the reason in both made the text view print the same sentence twice.
                "what": "replay",
                "which": payload.get("command") or "(unstated)",
                "why": str(
                    plan.get("notSupportedBecause") or "this run cannot be replayed from the files this receipt binds"
                ),
            }
        )
    answer: dict[str, Any] = {
        "status": "cannot-be-checked",
        "receipt": {
            "schema": payload.get("schema"),
            "command": payload.get("command"),
            "toolVersion": recorded_version,
            "payloadDigest": doc["integrity"].get("payloadDigest"),
            "takenAt": (doc.get("envelope") or {}).get("takenAt"),
        },
        "integrity": {"algorithm": ALGORITHM, "payloadDigest": "matches", "signed": False, "proves": PROVES},
        "verdictReproduced": None,
        "cannotCheck": cannot,
        "differs": [],
        "statement": INTEGRITY_STATEMENT,
    }
    if cannot:
        return answer
    try:
        fresh = replay(payload)
    except CannotCheck as exc:
        answer["cannotCheck"] = [exc.entry]
        return answer
    differs = _compare(payload["verdict"], fresh)
    answer["differs"] = differs
    answer["status"] = "differs" if differs else "identical"
    answer["verdictReproduced"] = not differs
    return answer


def summary_line(answer: dict[str, Any]) -> str:
    """The one sentence the text view leads with. Built from the same fields the document carries, so the word and
    the numbers beside it cannot disagree (class 13)."""
    command = answer["receipt"].get("command") or "a run"
    if answer["status"] == "identical":
        return f"identical: re-running the inputs this receipt binds reproduced the {command} verdict exactly"
    if answer["status"] == "differs":
        return (
            f"DIFFERS: the same inputs no longer give the {command} verdict this receipt records; "
            f"{len(answer['differs'])} field(s) moved"
        )
    return (
        f"CANNOT BE CHECKED: this is not a pass. {len(answer['cannotCheck'])} thing(s) this {command} receipt needs "
        "could not be got"
    )


class CannotCheck(Exception):
    """Raised by a replay that cannot ask the receipt's question again, with the reason the answer must carry.

    The replay, not this module, knows how a command expands its arguments -- so the replay is where "the set of
    files under this directory is not the set the receipt binds" is noticed. Raising it here, rather than returning
    a verdict, keeps that from being reported as a verdict that moved.
    """

    def __init__(self, what: str, which: Any, why: str) -> None:
        super().__init__(why)
        self.entry = {"what": what, "which": which, "why": why}


def input_set_digest(pairs: list[tuple[str, str]]) -> str:
    """One digest over the whole input set: each input's path as the command named it, with its own digest.

    Per-input digests catch a file that changed. They cannot catch a file that was ADDED to a directory since the
    receipt was written: the receipt names the files it read, the replay reads those files, both agree, and a
    `kube-noob audit -f dir/` run today would answer differently. The set digest is what catches it, and it is the
    class-1 defect in its own right -- a skipped input reading as complete.
    """
    return digest_of([[p, d] for p, d in sorted(pairs)])
