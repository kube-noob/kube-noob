"""Prometheus metrics for the HTTP server: counters and gauges, no customer data.

Why this exists: a platform team will not run a pod it cannot alert on, and until now the server had no `/metrics`,
the chart had no PrometheusRule, and there was no way to be told that the corpus had gone stale or that the tools
had started failing. That is the third of platform requirement R6.5 and roadmap item N11.

Three decisions worth stating, because each one is a defect if taken the other way.

**No new dependency.** The Prometheus text format is four fields per line, so it is rendered here. Adding
`prometheus_client` would mean a new hash-pinned runtime dependency, in a tool whose distribution argument is that
it runs in a disconnected cluster, for a format that fits in this file.

**Bounded label values.** `run_tool` records `outcome=<ExceptionName>` for any `KubeNoobError` or `ValueError`, and
exception types are open-ended: a caller who can provoke a new one would otherwise add a Prometheus label value
every time, which is a cardinality attack on the monitoring system rather than on this process. Every label value
here is mapped into a fixed set first, and `tool` is only accepted when it is a tool this server actually serves.

**Nothing about the caller.** Tool name, surface, outcome and duration. No argument, no resource name, no
namespace, no manifest content, no remote address. A metric is scraped by whoever can reach the port and kept for
months, so it is the last place customer data should appear.

Counters are process-local, and the chart runs one process, so the numbers are that pod's. They are not shared
across replicas and this module does not pretend otherwise.
"""

from __future__ import annotations

import threading
import time
from typing import Any

#: Duration buckets in seconds. Chosen for what these tools actually cost: an audit of a directory is tens of
#: milliseconds, a corpus search is hundreds, and the slowest analysers are seconds. `+Inf` is added on render.
BUCKETS: tuple[float, ...] = (0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)

#: The only outcome labels that can ever be emitted. `run_tool` writes an exception class name for an anticipated
#: failure, so anything outside this set collapses to `error`: a label space a caller can grow is a defect in the
#: monitoring system, not a richer metric.
OUTCOMES: frozenset[str] = frozenset({"ok", "invalid-arguments", "not-found", "crash", "error", "busy"})
#: Likewise for the surface. Two exist; a third would be a bug rather than a new label.
SURFACES: frozenset[str] = frozenset({"mcp", "rest"})
#: Receipt-to-report time of an Alertmanager payload (``POST /v1/alert-reports``). The north-star claim is an alert
#: turned into an evidence pack within a minute, but the longest possible answer is the wait for a slot plus
#: ``alertReports.budgetSeconds`` (at most 300) plus the alert in progress, so the buckets run past it: with a top
#: bucket of 60 s, every slow answer sat in +Inf and the histogram could not say how slow (G274).
REPORT_BUCKETS: tuple[float, ...] = (0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0)
#: Whether the receiver kept the report. Fixed, like every other label here.
REPORT_OUTCOMES: tuple[str, ...] = ("not-stored", "stored")
#: Payloads not reported at all: refused because every report slot stayed busy past the wait (503, or an MCP tool
#: error), or dropped because the sender had gone before the report started or before it was kept.
DROP_REASONS: tuple[str, ...] = ("busy", "client-gone")


class Metrics:
    """One process's counters. Every method is safe to call from several request handlers at once."""

    def __init__(self, tools: frozenset[str] | None = None) -> None:
        self._lock = threading.Lock()
        self._tools = tools or frozenset()
        self._calls: dict[tuple[str, str, str], int] = {}
        self._duration_count: dict[str, int] = {}
        self._duration_sum: dict[str, float] = {}
        self._buckets: dict[tuple[str, int], int] = {}
        self._reports: dict[str, int] = dict.fromkeys(REPORT_OUTCOMES, 0)
        self._report_buckets: list[int] = [0] * len(REPORT_BUCKETS)
        self._report_sum = 0.0
        self._evicted = 0
        self._dropped: dict[str, int] = dict.fromkeys(DROP_REASONS, 0)
        self._started = time.time()

    def known_tools(self, tools: frozenset[str]) -> None:
        """Teach it which tool names are real, so an unexpected one becomes `other` rather than a new label."""
        with self._lock:
            self._tools = tools

    def _tool(self, name: str) -> str:
        return name if name in self._tools else "other"

    def record(self, tool: str, via: str, outcome: str, seconds: float) -> None:
        tool = self._tool(tool)
        via = via if via in SURFACES else "other"
        outcome = outcome if outcome in OUTCOMES else "error"
        with self._lock:
            key = (tool, via, outcome)
            self._calls[key] = self._calls.get(key, 0) + 1
            self._duration_count[tool] = self._duration_count.get(tool, 0) + 1
            self._duration_sum[tool] = self._duration_sum.get(tool, 0.0) + max(seconds, 0.0)
            for i, edge in enumerate(BUCKETS):
                if seconds <= edge:
                    self._buckets[(tool, i)] = self._buckets.get((tool, i), 0) + 1

    def alert_report(self, seconds: float, outcome: str, evicted: int = 0) -> None:
        """One Alertmanager payload turned into a report: how long it took, whether it was kept, and how many older
        reports retention removed to keep it."""
        outcome = outcome if outcome in REPORT_OUTCOMES else "not-stored"
        seconds = max(seconds, 0.0)
        with self._lock:
            self._reports[outcome] += 1
            self._report_sum += seconds
            self._evicted += max(evicted, 0)
            for i, edge in enumerate(REPORT_BUCKETS):
                if seconds <= edge:
                    self._report_buckets[i] += 1

    def alert_report_dropped(self, reason: str) -> None:
        """One Alertmanager payload not reported: ``busy`` or ``client-gone``."""
        reason = reason if reason in DROP_REASONS else "busy"
        with self._lock:
            self._dropped[reason] += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "dropped": dict(self._dropped),
                "reports": dict(self._reports),
                "reportBuckets": list(self._report_buckets),
                "reportSum": self._report_sum,
                "evicted": self._evicted,
                "calls": dict(self._calls),
                "durationCount": dict(self._duration_count),
                "durationSum": dict(self._duration_sum),
                "buckets": dict(self._buckets),
                "started": self._started,
            }


#: One registry per process. The server builds it; the CLI and the stdio plugin never touch it.
REGISTRY = Metrics()


def _escape(value: str) -> str:
    """A label value, escaped as the exposition format requires.

    Every value emitted is from a fixed set, so this cannot be reached by caller data today. It is here because
    the next person to add a label will not necessarily keep that true, and an unescaped quote or newline in a
    label value corrupts the whole scrape rather than one line of it.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _labels(**pairs: str) -> str:
    return "{" + ",".join(f'{k}="{_escape(v)}"' for k, v in pairs.items()) + "}"


def _date_to_epoch(value: str | None) -> float | None:
    """A `YYYY-MM-DD` knowledge date as seconds since the epoch, or None when it is absent or unparseable."""
    if not value:
        return None
    import datetime

    try:
        day = datetime.date.fromisoformat(value[:10])
    except ValueError:
        return None
    return time.mktime(day.timetuple())


def render(settings: Any = None, registry: Metrics | None = None) -> str:
    """The whole exposition document, as Prometheus text format 0.0.4."""
    from kube_noob import __version__
    from kube_noob.knowledge_status import status

    reg = registry or REGISTRY
    snap = reg.snapshot()
    now = time.time()
    lines: list[str] = []

    def metric(name: str, kind: str, help_text: str) -> None:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {kind}")

    platform = str(getattr(getattr(settings, "posture", None), "platform", "") or "unknown")
    metric("kube_noob_build_info", "gauge", "Version and default platform of this process.")
    lines.append(f"kube_noob_build_info{_labels(version=__version__, platform=platform)} 1")

    metric("kube_noob_uptime_seconds", "gauge", "Seconds since this process started serving.")
    lines.append(f"kube_noob_uptime_seconds {now - snap['started']:.3f}")

    metric("kube_noob_tool_calls_total", "counter", "Tool calls by tool, surface and outcome.")
    for (tool, via, outcome), count in sorted(snap["calls"].items()):
        lines.append(f"kube_noob_tool_calls_total{_labels(tool=tool, via=via, outcome=outcome)} {count}")

    metric("kube_noob_tool_duration_seconds", "histogram", "Tool call duration in seconds.")
    for tool in sorted(snap["durationCount"]):
        for i, edge in enumerate(BUCKETS):
            # Already cumulative: `record` increments every bucket whose edge the observation is at or below, so
            # the stored count for an edge IS the number of observations <= it, which is what Prometheus requires.
            lines.append(
                f"kube_noob_tool_duration_seconds_bucket{_labels(tool=tool, le=_num(edge))} "
                f"{snap['buckets'].get((tool, i), 0)}"
            )
        total = snap["durationCount"][tool]
        lines.append(f"kube_noob_tool_duration_seconds_bucket{_labels(tool=tool, le='+Inf')} {total}")
        lines.append(f"kube_noob_tool_duration_seconds_sum{_labels(tool=tool)} {snap['durationSum'][tool]:.6f}")
        lines.append(f"kube_noob_tool_duration_seconds_count{_labels(tool=tool)} {total}")

    # Always rendered, zeros included: a dashboard panel on a metric that appears only after the first alert reads
    # as "No data", which nobody can tell apart from a receiver that is not wired up.
    metric(
        "kube_noob_alert_report_duration_seconds",
        "histogram",
        "Receipt-to-report time of an Alertmanager payload posted to /v1/alert-reports, in seconds.",
    )
    reports = sum(snap["reports"].values())
    for i, edge in enumerate(REPORT_BUCKETS):
        lines.append(
            f"kube_noob_alert_report_duration_seconds_bucket{_labels(le=_num(edge))} {snap['reportBuckets'][i]}"
        )
    lines.append(f"kube_noob_alert_report_duration_seconds_bucket{_labels(le='+Inf')} {reports}")
    lines.append(f"kube_noob_alert_report_duration_seconds_sum {snap['reportSum']:.6f}")
    lines.append(f"kube_noob_alert_report_duration_seconds_count {reports}")
    metric(
        "kube_noob_alert_reports_total", "counter", "Alertmanager payloads reported, by whether the report was kept."
    )
    for outcome in REPORT_OUTCOMES:
        lines.append(f"kube_noob_alert_reports_total{_labels(outcome=outcome)} {snap['reports'][outcome]}")
    metric(
        "kube_noob_alert_reports_evicted_total",
        "counter",
        "Stored alert reports removed by retention (alertReports.maxReports, alertReports.maxAgeDays).",
    )
    lines.append(f"kube_noob_alert_reports_evicted_total {snap['evicted']}")
    metric(
        "kube_noob_alert_reports_dropped_total",
        "counter",
        "Alertmanager payloads not reported: busy (no report slot came free in time; answered 503) or client-gone "
        "(the sender left before the report started or was kept).",
    )
    for reason in DROP_REASONS:
        lines.append(f"kube_noob_alert_reports_dropped_total{_labels(outcome=reason)} {snap['dropped'][reason]}")

    # Knowledge freshness. Two separate facts, and conflating them would be dishonest: `asOf` is when the BUNDLED
    # knowledge was reviewed, which is fixed at build time and tells an operator how old the image's facts are;
    # the corpus date is when an imported corpus was last written, and is absent when no corpus is imported. An
    # alert on the first is about the image; an alert on the second is about the refresh job.
    st = status(getattr(settings, "data_dir", None) if settings is not None else None)
    as_of = _date_to_epoch(st.get("asOf"))
    if as_of is not None:
        metric(
            "kube_noob_knowledge_as_of_timestamp_seconds",
            "gauge",
            "When the knowledge built into this image was reviewed (fixed at build time).",
        )
        lines.append(f"kube_noob_knowledge_as_of_timestamp_seconds {as_of:.0f}")
        metric(
            "kube_noob_knowledge_age_seconds",
            "gauge",
            "Age of the knowledge built into this image, in seconds.",
        )
        lines.append(f"kube_noob_knowledge_age_seconds {max(now - as_of, 0.0):.0f}")
    corpus = _date_to_epoch(st.get("corpusAsOf"))
    if corpus is not None:
        metric(
            "kube_noob_corpus_as_of_timestamp_seconds",
            "gauge",
            "When the imported corpus was last written. Absent when no corpus is imported.",
        )
        lines.append(f"kube_noob_corpus_as_of_timestamp_seconds {corpus:.0f}")
    return "\n".join(lines) + "\n"


def _num(value: float) -> str:
    """A bucket edge as Prometheus writes it: 0.05, 1, 30 -- not 1.0 or 30.0."""
    return f"{value:g}"
