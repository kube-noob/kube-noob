"""``kube-noob memory validate``: the poisoning guard for a memory repository.

An entry that reaches ``approved`` is shown to people fixing production, so validation checks more than shape:

- every entry file loads (schema, content rules, file name), with no stray files in ``entries/``;
- no two entries describe the same symptom on the same platform (an error), or carry the same signals (a warning);
- review dates (``reviewBy``) that passed are warnings (errors with ``--strict``); an expired risk acceptance is void;
- no credential anywhere in a file, including fields the model does not treat as prose;
- the verifier on every fix: a ``patch`` runs through kube-noob's own validate, audit and red-team stages, and a HIGH or
  CRITICAL finding fails; grants of the privileged SCC, cluster-admin, hostPath and wildcard RBAC fail, whether they
  arrive in a patch or a command; commands that change state carry ``needs-approval``. A verifier failure becomes a
  warning only when the entry records ``riskAccepted`` (owner and reason) that has not expired.

Sources for the grants: Kubernetes RBAC good practices (https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
and OpenShift's SCC docs (the privileged SCC allows privileged pods and host directories; access is the ``use`` verb on
``securitycontextconstraints``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from kube_noob.memory.model import MemoryEntry
from kube_noob.memory.repo import load_repo

_GRANT_COMMANDS = (
    (re.compile(r"\badd-scc-to-(user|group)\s+privileged\b"), "grants the privileged SCC"),
    (re.compile(r"\badd-cluster-role-to-(user|group)\s+cluster-admin\b"), "grants cluster-admin"),
    (re.compile(r"--clusterrole[= ]cluster-admin\b"), "binds cluster-admin"),
    (
        re.compile(r"--resource-name[= ]privileged\b.*--verb[= ]use|--verb[= ]use\b.*--resource-name[= ]privileged\b"),
        "grants use of the privileged SCC",
    ),
    (re.compile(r"--verb[= ]['\"]?\*|--resource[= ]['\"]?\*"), "grants wildcard RBAC"),
    (re.compile(r"[\"']?privileged[\"']?\s*:\s*true", re.IGNORECASE), "runs a privileged container"),
    (re.compile(r"[\"']?allowPrivilegedContainer[\"']?\s*:\s*true"), "allows privileged containers"),
    (re.compile(r"\bhostPath\b"), "mounts a host path"),
    (re.compile(r"[\"']verbs[\"']\s*:\s*\[\s*[\"']\*[\"']"), "grants wildcard RBAC"),
)
_PRIVILEGED_SCC_ROLES = {"system:openshift:scc:privileged"}


@dataclass(frozen=True)
class Problem:
    level: str  # "error" or "warning"
    file: str
    entry: str | None
    check: str
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {"level": self.level, "file": self.file, "entry": self.entry, "check": self.check, "detail": self.detail}


def _walk(value: Any, depth: int = 0) -> list[dict[str, Any]]:
    if depth > 30:
        return []
    out: list[dict[str, Any]] = []
    if isinstance(value, dict):
        out.append(value)
        for v in value.values():
            out.extend(_walk(v, depth + 1))
    elif isinstance(value, list):
        for v in value[:2_000]:
            out.extend(_walk(v, depth + 1))
    return out


def _manifest_grants(docs: list[Any]) -> list[str]:
    found: list[str] = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind, name = str(doc.get("kind", "")), str((doc.get("metadata") or {}).get("name", ""))
        ref = f"{kind}/{name}" if name else kind
        if kind in {"Role", "ClusterRole"}:
            for rule in doc.get("rules") or []:
                if not isinstance(rule, dict):
                    continue
                if any("*" in (rule.get(k) or []) for k in ("verbs", "resources", "apiGroups")):
                    found.append(f"{ref} grants wildcard RBAC")
                resources = set(rule.get("resources") or [])
                names = set(rule.get("resourceNames") or [])
                uses_scc = "use" in (rule.get("verbs") or []) and resources & {"securitycontextconstraints", "*"}
                if uses_scc and (not names or "privileged" in names):
                    found.append(f"{ref} grants use of the privileged SCC")
        if kind in {"RoleBinding", "ClusterRoleBinding"}:
            role = str((doc.get("roleRef") or {}).get("name", ""))
            if role == "cluster-admin":
                found.append(f"{ref} binds cluster-admin")
            if role in _PRIVILEGED_SCC_ROLES:
                found.append(f"{ref} grants the privileged SCC")
        if kind == "SecurityContextConstraints":
            if doc.get("allowPrivilegedContainer") or doc.get("allowHostDirVolumePlugin"):
                found.append(f"{ref} allows privileged containers or host directories")
            if name == "privileged" and (doc.get("users") or doc.get("groups")):
                found.append(f"{ref} adds users or groups to the privileged SCC")
        for node in _walk(doc):
            if isinstance(node.get("hostPath"), dict):
                found.append(f"{ref} mounts a host path")
                break
        for node in _walk(doc):
            ctx = node.get("securityContext")
            if isinstance(ctx, dict) and ctx.get("privileged") is True:
                found.append(f"{ref} runs a privileged container")
                break
    return list(dict.fromkeys(found))


def verify_fix(entry: MemoryEntry) -> list[str]:
    """What the verifier refuses in this entry's fix (empty when the fix is clean)."""
    from kube_noob.audit.engine import analyze
    from kube_noob.debug.steps import classify_step
    from kube_noob.yamlio import load_documents

    issues: list[str] = []
    if entry.fix.patch:
        report = analyze(entry.fix.patch, platform=entry.platform).as_dict()
        for f in report["findings"]:
            if f["severity"] in {"high", "critical"}:
                issues.append(f"patch: audit {f['ruleId']} ({f['severity']}) {f['message']}")
        for s in report.get("redTeam") or []:
            if s.get("severity") in {"high", "critical"}:
                issues.append(f"patch: red team {s['scenarioId']} ({s['severity']}) {s['question']}")
        issues += [f"patch: {g}" for g in _manifest_grants([d.data for d in load_documents(entry.fix.patch)])]
    for cmd in entry.fix.commands:
        if classify_step(cmd.command) == "read":
            continue  # reading a hostPath or a binding grants nothing
        for rx, what in _GRANT_COMMANDS:
            if rx.search(cmd.command):
                issues.append(f"command {cmd.command!r} {what}")
        if cmd.label != "needs-approval":
            issues.append(f"command {cmd.command!r} changes state and must be labelled needs-approval")
    return list(dict.fromkeys(issues))


def _norm(text: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9 ]", " ", text.lower()).split())


def validate_repo(root: Path, today: date | None = None, strict: bool = False) -> dict[str, Any]:
    """Every check above; ``ok`` is False when any error remains."""
    from kube_noob.learn.memory import contains_credential

    day = today or date.today()
    problems: list[Problem] = []
    loaded = load_repo(root)
    entries: list[tuple[str, MemoryEntry]] = []
    for item in loaded:
        rel = str(item.path.relative_to(root))
        if item.entry is None:
            problems.append(Problem("error", rel, None, "schema", item.error or "unreadable"))
            continue
        entries.append((rel, item.entry))
        text = item.path.read_text(encoding="utf-8")
        if contains_credential(text):
            problems.append(
                Problem("error", rel, item.entry.id, "credentials", "the file looks like it holds a credential")
            )
    for extra in sorted(p for p in (root / "entries").iterdir() if p.is_file() and p.suffix not in {".yaml", ".yml"}):
        if extra.name != ".gitkeep":
            problems.append(Problem("warning", str(extra.relative_to(root)), None, "layout", "not an entry file"))
    by_symptom: dict[tuple[str, str], str] = {}
    by_signals: dict[tuple[str, str, frozenset[tuple[str, str]]], str] = {}
    for rel, e in entries:
        key = (_norm(e.symptom), e.platform)
        if key in by_symptom:
            problems.append(Problem("error", rel, e.id, "duplicate", f"same symptom and platform as {by_symptom[key]}"))
        else:
            by_symptom[key] = e.id
        sigs = frozenset((s.kind, s.name) for s in e.signals)
        if sigs:
            skey = (e.platform, e.kind, sigs)
            if skey in by_signals:
                problems.append(Problem("warning", rel, e.id, "duplicate", f"same signals as {by_signals[skey]}"))
            else:
                by_signals[skey] = e.id
        if e.review_by and e.review_by < day:
            problems.append(
                Problem("error" if strict else "warning", rel, e.id, "expired", f"review date {e.review_by} has passed")
            )
        issues = verify_fix(e)
        accepted = e.risk_accepted
        if accepted and accepted.expires and accepted.expires < day:
            problems.append(Problem("error", rel, e.id, "expired", f"risk acceptance by {accepted.owner} expired"))
            accepted = None
        for issue in issues:
            if accepted:
                detail = f"{issue.rstrip('.')} (risk accepted by {accepted.owner}: {accepted.reason})"
                problems.append(Problem("warning", rel, e.id, "verifier", detail))
            else:
                problems.append(
                    Problem("error", rel, e.id, "verifier", f"{issue.rstrip('.')}; record riskAccepted to keep it")
                )
    counts = {s: sum(1 for _, e in entries if e.status == s) for s in ("approved", "proposed", "retired")}
    errors = [p.as_dict() for p in problems if p.level == "error"]
    warnings = [p.as_dict() for p in problems if p.level == "warning"]
    return {
        "repository": str(root),
        "entries": len(loaded),
        **counts,
        "errors": errors,
        "warnings": warnings,
        "ok": not errors,
    }
