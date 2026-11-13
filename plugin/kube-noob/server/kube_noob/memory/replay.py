"""``kube-noob memory replay``: would your team's memory have helped with these tickets?

Tickets are replayed in the order they were opened. Each one is matched with what was known when it was opened: its
title and description, never its resolution notes. A ticket never matches the entry imported from it, and with
``as_of_ticket_date`` only entries created before the ticket was opened count (no hindsight; imported entries are
dated when their ticket was resolved).

The report gives the hit rate, hits per signal kind (or "words" for a text-only match), the misses with the signals
they carried, and, with a labels file (ticket ref -> was the match useful, yes or no), the useful-match rate against
the gate: at least 30% of labelled tickets get a useful match.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from kube_noob.memory.importers import Ticket, parse
from kube_noob.memory.model import MemoryEntry

GATE = 0.30
MAX_LABELS = 50_000


@dataclass(frozen=True)
class Labels:
    useful: dict[str, bool]


def load_labels(text: str) -> Labels:
    """A YAML mapping of ticket ref to true/false (or yes/no, useful/not useful)."""
    if len(text) > 5_000_000:
        raise ValueError("the labels file is larger than 5 MB")
    doc = yaml.safe_load(text) or {}
    if not isinstance(doc, dict) or len(doc) > MAX_LABELS:
        raise ValueError("labels are a YAML mapping of ticket ref to true or false (at most 50,000)")
    out: dict[str, bool] = {}
    for k, v in doc.items():
        if isinstance(v, bool):
            out[str(k)] = v
        elif isinstance(v, str) and v.strip().lower() in {"yes", "no", "useful", "not useful", "true", "false"}:
            out[str(k)] = v.strip().lower() in {"yes", "useful", "true"}
        else:
            raise ValueError(f"label for {k!r} must be true or false, got {v!r}")
    return Labels(out)


def _query(t: Ticket) -> str:
    return f"{t.title}\n{t.body}"


def replay(
    memory: Path,
    fmt: str,
    text: str,
    labels: Labels | None = None,
    as_of_ticket_date: bool = False,
    include_proposed: bool = True,
) -> dict[str, Any]:
    from kube_noob.memory.match import match
    from kube_noob.signals import for_text

    tickets = _ordered(parse(fmt, text))
    hits: list[dict[str, Any]] = []
    misses: list[dict[str, Any]] = []
    by_kind: Counter[str] = Counter()
    for t in tickets:
        when = t.opened or t.resolved

        def keep(e: MemoryEntry, t: Ticket = t, when: Any = when) -> bool:
            if any(o.ticket == t.ref for o in e.outcomes):
                return False  # the entry this ticket became
            return not (as_of_ticket_date and when is not None and e.created >= when)

        found = match([memory], _query(t), include_proposed=include_proposed, limit=3, keep=keep)["matches"]
        useful = [m for m in found if m["state"] in {"fix", "runbook"}]
        row: dict[str, Any] = {"ticket": t.ref, "opened": str(when) if when else None}
        if useful:
            top = useful[0]
            kinds = sorted({s.split(":", 1)[0] for s in top["matchedBy"]["signals"]}) or ["words"]
            by_kind.update(kinds)
            row.update(entry=top["id"], state=top["state"], matchedBy=kinds)
            if labels and t.ref in labels.useful:
                row["useful"] = labels.useful[t.ref]
            hits.append(row)
        else:
            row["signals"] = sorted({f"{s.kind}:{s.name}" for s in for_text(_query(t)) if s.kind != "error_template"})[
                :10
            ]
            if labels and t.ref in labels.useful:
                row["useful"] = False
            misses.append(row)
    total = len(tickets)
    out: dict[str, Any] = {
        "memory": str(memory),
        "format": fmt,
        "asOfTicketDate": as_of_ticket_date,
        "tickets": total,
        "hits": len(hits),
        "hitRate": round(len(hits) / total, 3) if total else 0.0,
        "hitsBySignalKind": dict(sorted(by_kind.items())),
        "matched": hits,
        "misses": misses,
    }
    gate: dict[str, Any] = {"threshold": GATE}
    if labels:
        labelled = [r for r in hits + misses if str(r["ticket"]) in labels.useful]
        good = [r for r in labelled if r.get("useful") is True and r.get("entry")]
        rate = len(good) / len(labelled) if labelled else 0.0
        gate.update(labelled=len(labelled), useful=len(good), usefulRate=round(rate, 3), passed=rate >= GATE)
    else:
        gate.update(
            passed=None, note="pass --labels to measure useful matches; the gate is on useful, not any, matches"
        )
    out["gate"] = gate
    return out


def _ordered(tickets: list[Ticket]) -> list[Ticket]:
    """By the day each ticket was opened (or resolved), undated ones last, then by ref."""
    return sorted(tickets, key=lambda t: ((t.opened or t.resolved) is None, str(t.opened or t.resolved or ""), t.ref))


def markdown(report: dict[str, Any]) -> str:
    g = report["gate"]
    lines = [
        "# Memory replay",
        "",
        f"Memory: `{report['memory']}`. Tickets: {report['tickets']} ({report['format']}), replayed in the order they "
        "were opened, matched on title and description only"
        + ("; only entries created before each ticket count." if report["asOfTicketDate"] else "."),
        "",
        "| Measure | Value |",
        "|---|---|",
        f"| Hits | {report['hits']} of {report['tickets']} ({report['hitRate']:.0%}) |",
    ]
    for kind, n in report["hitsBySignalKind"].items():
        lines.append(f"| Hits by {kind} | {n} |")
    if g.get("passed") is None:
        lines += ["", f"Gate (useful matches >= {GATE:.0%}): not measured. {g['note']}."]
    else:
        verdict = "PASSED" if g["passed"] else "FAILED"
        lines += [
            f"| Useful matches | {g['useful']} of {g['labelled']} labelled ({g['usefulRate']:.0%}) |",
            "",
            f"Gate (useful matches >= {GATE:.0%}): **{verdict}**.",
        ]
    if report["misses"]:
        lines += ["", "## Misses", "", "| Ticket | Signals |", "|---|---|"]
        for m in report["misses"][:200]:
            lines.append(f"| {m['ticket']} | {', '.join(m['signals']) or '(none)'} |")
    if report["matched"]:
        lines += ["", "## Matches", "", "| Ticket | Entry | Matched by | Useful |", "|---|---|---|---|"]
        for m in report["matched"][:200]:
            useful = {True: "yes", False: "no"}.get(m.get("useful"), "")
            lines.append(f"| {m['ticket']} | {m['entry']} | {', '.join(m['matchedBy'])} | {useful} |")
    return "\n".join(lines) + "\n"
