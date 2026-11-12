"""The self-contained HTML report (U1, G222).

The audience for per-control standing and the KSI crosswalk is a compliance reviewer, and until now what they got
was terminal text or JSON. These tests hold the two things that make an HTML report trustworthy rather than
merely prettier: every caveat the text view carries survives into it, and nothing from a manifest is ever
rendered as markup.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import charts, drift, gate, report_html

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests/fixtures/drift"


class _Sinks(HTMLParser):
    """Collect every attribute that makes the browser fetch something, and every script."""

    def __init__(self) -> None:
        super().__init__()
        self.loads: list[tuple[str, str]] = []
        self.scripts = 0
        self.events: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "iframe", "object", "embed"}:
            self.scripts += 1
        for name, value in attrs:
            if name.startswith("on"):
                self.events.append(f"{tag}@{name}")
            if name in {"src", "srcset", "data", "action", "poster", "background"} and value:
                self.loads.append((tag, value))
            if name == "href" and value and tag == "link":
                self.loads.append((tag, value))


def _parsed(html: str) -> _Sinks:
    p = _Sinks()
    p.feed(html)
    return p


def _gate_report(**kw: Any) -> dict[str, Any]:
    src = gate.Source("deploy/web.yaml", (ROOT / "examples/insecure-deployment.yaml").read_text())
    return gate.run([src], fail_on="high", **kw)


def _posture_report() -> dict[str, Any]:
    docs = [d for d in yaml.safe_load_all((FIX / "day2.yaml").read_text()) if d]
    snap = drift.snapshot(docs, source="manifests", taken_at=dt.datetime(2026, 10, 28, tzinfo=dt.UTC))
    return drift.first_report(snap)


def test_the_page_fetches_nothing_and_runs_nothing() -> None:
    """A report a reviewer opens from an email attachment, on a laptop with no network, in an air-gapped review
    room. One file: no stylesheet, no script, no font, no image, no inline handler."""
    for report in (_gate_report(), _posture_report()):
        page = report_html.render(report)
        sinks = _parsed(page)
        assert sinks.scripts == 0, "no script, iframe, object or embed"
        assert sinks.events == [], sinks.events
        assert sinks.loads == [], sinks.loads
        assert "<style" in page, "styling is inline or there is none"


def test_a_resource_name_is_never_rendered_as_markup() -> None:
    """Resource names, messages and paths come from someone else's manifests. This is the one place in the
    product where that text becomes a document another person opens."""
    hostile = (
        "apiVersion: apps/v1\nkind: Deployment\n"
        'metadata:\n  name: "<script>alert(1)</script>"\n  namespace: "x<img src=x onerror=alert(2)>"\n'
        "spec:\n  replicas: 1\n  selector: {matchLabels: {app: a}}\n"
        "  template:\n    metadata: {labels: {app: a}}\n"
        "    spec:\n      containers:\n      - name: c\n        image: nginx:latest\n"
        "        securityContext: {privileged: true}\n"
    )
    report = gate.run([gate.Source("evil.yaml", hostile)], fail_on="high")
    page = report_html.render(report)
    sinks = _parsed(page)
    assert sinks.scripts == 0
    assert sinks.events == []
    assert sinks.loads == []
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page, "the name is shown, escaped, not dropped"


def test_every_caveat_the_text_view_carries_survives() -> None:
    """An HTML report that drops the caveats is the G221 defect in a third format. These are the four that
    change what a count means."""
    report = _gate_report()
    report["notCheckedBeyond"] = {"target": "1.40", "removalData": "1.37", "why": "read at 1.37, not 1.40"}
    report["assumptions"] = ["No Kubernetes version given; assumed 1.35."]
    report["unreadable"] = [{"path": "zz-bad.yaml", "why": "not readable as UTF-8 text"}]
    page = report_html.render(report)
    assert "read at 1.37, not 1.40" in page
    assert "assumed 1.35" in page
    assert "zz-bad.yaml" in page
    assert "not a complete" in page.lower(), "an incomplete read has to say the result is not clean"


def test_the_caveats_come_before_the_findings() -> None:
    """Position is the whole point: a reader who meets an empty findings table first has already concluded."""
    report = _gate_report()
    report["assumptions"] = ["No Kubernetes version given; assumed 1.35."]
    first = report["findings"][0]["ruleId"]
    page = report_html.render(report)
    assert page.index("assumed 1.35") < page.index(first)


def test_per_control_standing_keeps_its_five_buckets() -> None:
    report = _posture_report()
    page = report_html.render(report)
    assert "Control standing" in page
    for header in ("Findings", "Excepted", "Withheld", "Clean", "Not evaluated"):
        assert header in page, header


def test_a_withheld_standing_says_why_instead_of_showing_a_table() -> None:
    docs = [d for d in yaml.safe_load_all((FIX / "day2.yaml").read_text()) if d]
    docs = [d for d in docs if d["kind"] not in ("Role", "RoleBinding")]
    snap = drift.snapshot(
        docs,
        source="live",
        taken_at=dt.datetime(2026, 10, 28, tzinfo=dt.UTC),
        not_read=["roles in shop: forbidden"],
    )
    page = report_html.render(drift.first_report(snap))
    assert "forbidden" in page
    assert re.search(r"no standing|withheld entirely|cannot be trusted", page, re.I)
    # And no chart of it either: a bucket that cannot be trusted as a number cannot be trusted as a bar.
    assert "Per-control standing" not in page


def test_the_ksi_view_carries_the_sentence_that_says_what_it_is_not() -> None:
    from kube_noob.audit import fedramp

    page = report_html.render(fedramp.summary([]))
    assert "never a compliance claim" in page
    assert "audited" in page.lower()
    assert fedramp.EVIDENCE["KSI-RPL-ABO"]["doesNotShow"][:40] in page
    assert "shared NIST control" in page, "the off-subject warning"


def test_an_unaudited_ksi_page_shows_no_counts() -> None:
    from kube_noob.audit import fedramp

    page = report_html.render(fedramp.summary([]))
    assert re.search(r"nothing (was )?audited|no audit", page, re.I)


def test_the_page_is_written_where_the_command_was_told() -> None:
    import subprocess
    import sys
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "report.html"
        r = subprocess.run(
            [
                sys.executable,
                "-m",
                "kube_noob.cli",
                "gate",
                "-f",
                "examples/insecure-deployment.yaml",
                "--fail-on",
                "never",
                "--html",
                str(out),
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            cwd=ROOT,
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src"), "HOME": d},
            check=False,
        )
        assert r.returncode == 0, r.stdout + r.stderr
        page = out.read_text()
    assert page.startswith("<!doctype html>")
    assert _parsed(page).loads == []


@pytest.mark.parametrize("report", [{}, {"findings": []}, {"indicators": []}])
def test_an_empty_report_still_renders_a_page(report: dict[str, Any]) -> None:
    page = report_html.render(report)
    assert page.startswith("<!doctype html>")
    assert page.rstrip().endswith("</html>")


def test_the_byline_never_borrows_another_version() -> None:
    """The KSI report carries `dataset.version`; using it as a fallback printed "by kube-noob 2026.11.02.01" in
    the first line of a document written for someone whose job is checking claims."""
    from kube_noob.audit import fedramp

    page = report_html.render(fedramp.summary([]))
    assert "by kube-noob 2026.11.02.01" not in page
    assert fedramp.DATASET_VERSION in page, "the dataset version still appears, where it belongs"
    assert "by kube-noob 0." in report_html.render({"version": "0.7.1", "findings": [], "passed": True})


def test_backticks_become_code_spans_and_hostile_text_stays_inert() -> None:
    """The curated prose is written with markdown backticks. Escaping happens first, so the only markup here is
    markup this code wrote; a name full of backticks and angle brackets is a code span of escaped text."""
    page = report_html.render({"assumptions": ["use `partial_bundle=false` for a whole namespace"]})
    assert "<code>partial_bundle=false</code>" in page
    hostile = report_html.render({"assumptions": ["`<script>alert(1)</script>`"]})
    assert "<script>" not in hostile
    assert "&lt;script&gt;" in hostile
    odd = report_html.render({"assumptions": ["one ` unpaired backtick"]})
    assert "<code>" not in odd


def test_a_row_with_no_counts_does_not_sit_under_the_findings_heading() -> None:
    """An indicator kube-noob cannot evidence has a note where the numbers go. Left as one cell, that note
    rendered in the Findings column -- the one column on the page a reader must not misread."""
    from kube_noob.audit import fedramp

    page = report_html.render(fedramp.summary([], evaluated_rule_ids=[]))
    assert 'colspan="4"' in page or 'colspan="5"' in page


def _series(state: Path, incomplete: int = 0, days: int = 4) -> dict[str, Any]:
    """A posture state folder with ``days`` snapshots, the first ``incomplete`` of them a partial read."""
    docs = [d for d in yaml.safe_load_all((FIX / "day2.yaml").read_text()) if d]
    report: dict[str, Any] = {}
    for i in range(days):
        snap = drift.snapshot(
            docs[: len(docs) - (i % 2)],
            source="live",
            taken_at=dt.datetime(2026, 10, 1, tzinfo=dt.UTC) + dt.timedelta(days=i),
            not_read=["roles in shop: forbidden"] if i < incomplete else [],
        )
        report, _ = drift.write_report(state, snap, keep=365)
    return report


def test_the_chart_shows_the_same_counts_as_the_table_beside_it() -> None:
    """The rule the whole module rests on (U3): a chart is a second reading of numbers the reader can check
    row by row, never a new claim. A bar whose value is not in the table is a claim nobody can audit."""
    report = _gate_report()
    page = report_html.render(report)
    drawn = page[page.index("Findings by severity") : page.index("</svg>")]
    labelled = dict(
        zip(
            re.findall(r'text-anchor="end">([a-z]+)</text>', drawn),
            re.findall(r'class="val"[^>]*>(\d+)</text>', drawn),
            strict=True,
        )
    )
    assert labelled == {k: str(v) for k, v in report["counts"].items()}
    for name, count in report["counts"].items():
        assert re.search(rf"<td>{name}</td><td class=\"n\">{count}</td>", page), name


def test_a_trend_is_drawn_only_when_every_snapshot_was_a_complete_read(tmp_path: Path) -> None:
    """A snapshot that was refused a resource reports a floor, not a measurement. A line through that point
    publishes a fall in findings that may only be a fall in what kube-noob was allowed to see."""
    whole = report_html.render(_series(tmp_path / "ok"))
    assert "Open findings over time" in whole
    assert "<polyline" in whole, "four complete reads are a trend"

    partial = report_html.render(_series(tmp_path / "partial", incomplete=1))
    assert "Open findings over time" in partial
    assert "<polyline" not in partial
    assert "No trend is drawn" in partial
    assert "1 of the 4 kept came from a snapshot that could not read every resource" in partial


def test_a_report_that_cannot_say_whether_it_read_everything_withholds_the_line(tmp_path: Path) -> None:
    """Every report kube-noob wrote before 0.8 carries no completeness record, under the same format string.
    Unknown is not yes, and the page says which of the two it is in the table as well as in the caveat."""
    report = _series(tmp_path / "old")
    report["history"]["points"][0]["complete"] = None
    page = report_html.render(report)
    assert "<polyline" not in page
    assert "1 were written before kube-noob recorded whether a snapshot had read everything" in page
    assert page.count(">not recorded</span>") == 1
    assert page.count(">yes</td>") == 3


def test_a_series_that_mixes_two_populations_is_not_one_line(tmp_path: Path) -> None:
    """A folder holding a `-f manifests` run and a `--live` run holds two different populations. Joining them
    draws a comparison nobody made."""
    report = _series(tmp_path / "mixed")
    report["history"]["points"][1]["source"] = "manifests"
    page = report_html.render(report)
    assert "<polyline" not in page
    assert "mixes snapshots of different things (live, manifests)" in page


def test_the_counts_stay_on_the_page_when_the_trend_is_withheld(tmp_path: Path) -> None:
    """Withholding the line is not withholding the numbers: each point is still listed, marked with whether
    its read was complete, so the reader can see the shape and the reason together."""
    page = report_html.render(_series(tmp_path / "partial", incomplete=2))
    assert page.count('<span class="mono">2026-10-0') == 4, "every kept point is still a row"
    assert page.count('<span class="fails">no</span>') == 2, "both partial reads are marked, not just one"


def test_a_point_with_no_timestamp_withholds_the_line_instead_of_vanishing(tmp_path: Path) -> None:
    """Dropping it would join the line across the gap without saying so, which is the whole defect this page
    exists to avoid."""
    report = _series(tmp_path / "ok")
    report["history"]["points"][1]["at"] = None
    page = report_html.render(report)
    assert "<polyline" not in page
    assert "1 do not say when they were taken" in page
    assert page.count("\u2014</span>") >= 1, "the missing date is a dash, never an empty cell"


def test_a_kept_file_behind_no_point_is_named_even_when_there_is_no_trend(tmp_path: Path) -> None:
    """With one readable report and two that are not, the section used to disappear entirely -- so the page
    said nothing at all about the files it could not place."""
    state = tmp_path / "broken"
    _series(state, days=3)
    for path in sorted(state.glob("report-*.json"))[:2]:
        path.write_text("{not json", encoding="utf-8")
    report = drift.latest_report(state)
    assert report is not None
    page = report_html.render(report)
    assert "Open findings over time" in page
    assert "2 could not be read back or were not read" in page
    assert "<polyline" not in page


def test_a_series_longer_than_the_chart_says_what_it_left_out(tmp_path: Path) -> None:
    """The table carries every point and the chart at most sixty. A reader comparing the two must not find a
    different left-hand end with no reason given."""
    report = _series(tmp_path / "long", days=charts.MAX_POINTS + 3)
    page = report_html.render(report)
    assert "<polyline" in page
    assert "3 older point(s) are in the table below, not in the chart" in page
    assert page.count('<span class="mono">2026-1') == charts.MAX_POINTS + 3


def test_one_snapshot_is_not_a_trend(tmp_path: Path) -> None:
    state = tmp_path / "one"
    docs = [d for d in yaml.safe_load_all((FIX / "day2.yaml").read_text()) if d]
    report, _ = drift.write_report(state, drift.snapshot(docs, source="manifests"), keep=14)
    assert len(report["history"]["points"]) == 1
    assert "Open findings over time" not in report_html.render(report)


def test_the_charts_fetch_nothing_either(tmp_path: Path) -> None:
    for page in (report_html.render(_gate_report()), report_html.render(_series(tmp_path / "ok"))):
        assert "<svg" in page, "the page under test has to actually carry a chart"
        sinks = _parsed(page)
        assert (sinks.scripts, sinks.events, sinks.loads) == (0, [], [])


def test_a_posture_page_says_what_the_audit_had_to_assume(tmp_path: Path) -> None:
    """U4, on the page a reviewer actually opens: a cluster of kinds kube-noob has no reader for must not
    render as a clean one. The caveat block already existed; what was missing was the snapshot keeping the
    assumptions long enough to reach it."""
    rollout = {
        "apiVersion": "argoproj.io/v1alpha1",
        "kind": "Rollout",
        "metadata": {"name": "web", "namespace": "shop"},
        "spec": {"template": {"spec": {"containers": [{"name": "web", "image": "nginx:1.27"}]}}},
    }
    report, _ = drift.write_report(
        tmp_path / "rollouts",
        drift.snapshot([rollout], source="live", taken_at=dt.datetime(2026, 10, 1, tzinfo=dt.UTC)),
        keep=14,
    )
    page = report_html.render(report)
    assert "no reader for" in page
    assert "caveat" in page, "it is rendered as a caveat above the findings, not buried"


def test_the_verdict_agrees_with_the_table_it_summarises(tmp_path: Path) -> None:
    """U5's sharpest risk. The first version summed the standing column and printed "5 findings are open" in
    the largest type on the page, two sections above a table reading 3: one finding is evidence about several
    controls, so the per-control sum double-counts it. The headline is the finding count or nothing."""
    report = _series(tmp_path / "ok", days=2)
    page = report_html.render(report)
    verdict = re.search(r'class="verdict">([^<]+)', page)
    assert verdict, "every report with countable findings states a verdict"
    assert verdict.group(1).startswith(f"{report['findings']['open']} finding")
    assert f'<td class="n">{report["findings"]["open"]}</td>' in page, "and the table says the same number"


def test_the_masthead_names_what_reached_no_verdict_beside_what_failed(tmp_path: Path) -> None:
    """The middle tile is the product: a reader who only ever sees the failure count cannot tell a clean
    cluster from an unexamined one."""
    page = report_html.render(_series(tmp_path / "ok", days=2))
    assert 'class="absence"' in page
    assert "Withheld or not evaluated" in page
    assert "reached no verdict" in page or "Every rule that applies was evaluated" in page


def test_a_limit_is_a_numbered_section_and_not_a_strip_to_skim(tmp_path: Path) -> None:
    rollout = {
        "apiVersion": "argoproj.io/v1alpha1",
        "kind": "Rollout",
        "metadata": {"name": "web", "namespace": "shop"},
        "spec": {"template": {"spec": {"containers": [{"name": "web", "image": "nginx:1.27"}]}}},
    }
    report, _ = drift.write_report(
        tmp_path / "r",
        drift.snapshot([rollout], source="live", taken_at=dt.datetime(2026, 10, 1, tzinfo=dt.UTC)),
        keep=14,
    )
    page = report_html.render(report)
    assert '<h2 id="limits"><span class="num">1</span>Limits of this examination' in page
    assert "no reader for" in page
    assert page.index("Limits of this examination") < page.index("What changed"), "limits come before findings"


def test_sections_are_numbered_in_the_order_they_are_written(tmp_path: Path) -> None:
    """A reviewer cites "section 3" at a colleague, so the contents and the headings have to agree, and the
    numbers have to come from the sections actually rendered rather than from a fixed list."""
    page = report_html.render(_series(tmp_path / "ok", days=3))
    heads = re.findall(r'<h2 id="([a-z]+)"><span class="num">(\d+)</span>([^<]+)', page)
    assert [int(n) for _a, n, _t in heads] == list(range(1, len(heads) + 1)), heads
    for anchor, n, title in heads:
        assert f'<a href="#{anchor}"><span class="n">{n}</span><span class="t">{title}' in page


def test_every_control_row_and_every_finding_can_be_linked_to(tmp_path: Path) -> None:
    gate_page = report_html.render(_gate_report())
    ids = re.findall(r'<a id="(f-[^"]+)" href="#\1"', gate_page)
    assert len(ids) == len(set(ids)) and len(ids) >= 3, ids
    assert all(re.fullmatch(r"f-[A-Za-z0-9._-]+", i) for i in ids), "an anchor is an id, never a path"
    posture_page = report_html.render(_series(tmp_path / "ok", days=2))
    assert re.search(r'<a id="c-AC-6" href="#c-AC-6"', posture_page)


def test_a_finding_keeps_its_anchor_when_the_list_order_changes() -> None:
    """`#f-3` meaning a different finding tomorrow is worse than no anchor. The id is the rule and the
    resource, which is what a reader has in hand when they want to point at a row."""
    report = _gate_report()
    first = set(re.findall(r'id="(f-[^"]+)"', report_html.render(report)))
    report["findings"] = list(reversed(report["findings"]))
    assert set(re.findall(r'id="(f-[^"]+)"', report_html.render(report))) == first


def test_controls_with_nothing_to_report_fold_away_and_open_again_in_print(tmp_path: Path) -> None:
    """Thirty rows of which eight say anything is the shape that hid `notEvaluated` in the first place. What
    is folded is not hidden evidence: the printed PDF must not be a subset of the page a colleague opened."""
    report = _series(tmp_path / "ok", days=2)
    standing = report["controlStanding"]["controls"]
    quiet = [c["id"] for c in standing if c["clean"] and not (c["findings"] or c["notEvaluated"] or c.get("withheld"))]
    if not quiet:
        # Since G281 every control of this fixture has a rule whose kind the bundle lacks, so none is quiet by
        # itself; the fold is exercised on a control whose rules are all evaluated and clean.
        row = next(c for c in standing if not c["findings"] and not c.get("withheld"))
        row["clean"], row["notEvaluated"] = row["clean"] + row["notEvaluated"], 0
        row.pop("notEvaluatedRules", None)
        quiet = [row["id"]]
    page = report_html.render(report)
    assert '<details class="quiet">' in page
    assert "with nothing to report" in page
    assert "details.quiet > div { display: block !important; }" in page
    folded = page[page.index('<details class="quiet">') :]
    assert all(cid in folded for cid in quiet), "the folded rows are present in the document, not dropped"


def test_the_page_states_the_scope_its_numbers_are_true_of(tmp_path: Path) -> None:
    page = report_html.render(_series(tmp_path / "ok", days=2))
    assert 'class="prov"' in page
    for label in ("scope", "taken", "by", "network"):
        assert f"<dt>{label}</dt>" in page


def test_the_redesign_still_fetches_nothing(tmp_path: Path) -> None:
    for page in (report_html.render(_gate_report()), report_html.render(_series(tmp_path / "ok", days=2))):
        sinks = _parsed(page)
        assert (sinks.scripts, sinks.events, sinks.loads) == (0, [], [])


def test_the_masthead_never_points_at_a_section_the_page_does_not_have() -> None:
    """The absence tile counts the checks nobody ran and the verdict sends the reader to section 1 for them,
    so section 1 has to list them. The first version counted them and never rendered them anywhere."""
    page = report_html.render(_gate_report())
    assert "section 1 says what they would have covered" in page
    assert '<h2 id="limits"><span class="num">1</span>Limits of this examination' in page
    assert "Not run." in page and "scanner-report" in page, "the checks the tile counted are the ones listed"


def test_the_ksi_masthead_counts_indicators_and_claims_no_section_it_lacks() -> None:
    """One wording over all three report shapes printed "21 findings are open, and 15 rules reached no
    verdict" over tiles reading "indicators", and sent the reader to a section 1 the crosswalk does not have.
    That is G257's own rule broken in the page that introduced G257, so each shape counts its own units."""
    report = {
        "indicators": [
            {"id": "KSI-SVC-01", "evidenced": True, "findings": 2},
            {"id": "KSI-SVC-02", "evidenced": True, "findings": 0},
            {"id": "KSI-IAM-01", "evidenced": False, "findings": 0},
            {"id": "KSI-IAM-02", "evidenced": False, "findings": 0},
        ]
    }
    page = report_html.render(report)
    verdict = re.search(r'class="verdict">([^<]+)', page)
    assert verdict, "a crosswalk with indicators states a verdict"
    said = verdict.group(1)
    assert said == "1 indicator has findings against it, and 2 have no kube-noob rule behind them at all.", said
    assert "finding are open" not in said and "rules reached no verdict" not in said
    assert "section 1" not in page, "the crosswalk has no limits section to send the reader to"
    assert "not a zero and not a pass" in page


def test_the_ksi_masthead_survives_a_findings_count_of_any_shape() -> None:
    """A KSI row's `findings` is an int; a posture report's is a bucket dict. Reading one as the other
    crashed `ksi --html` outright, so every shape that arrives here must produce a number or a zero."""
    rows = [
        {"id": "a", "evidenced": True, "findings": 3},
        {"id": "b", "evidenced": True, "findings": {"open": 1}},
        {"id": "c", "evidenced": True, "findings": None},
        {"id": "d", "evidenced": True, "findings": True},
        {"id": "e", "evidenced": True, "findings": "4"},
        {"id": "f", "evidenced": True},
    ]
    page = report_html.render({"indicators": rows})
    verdict = re.search(r'class="verdict">([^<]+)', page)
    assert verdict and verdict.group(1).startswith("2 indicators have findings against them"), page[:400]


def test_the_gate_verdict_is_stated_once() -> None:
    page = report_html.render(_gate_report())
    assert page.count("The gate failed") == 1, "the masthead states it; the body used to repeat it"


@pytest.mark.parametrize(
    "argv",
    [
        ["gate", "-f", "EXAMPLE"],
        ["ksi", "-f", "EXAMPLE"],
        ["posture", "diff", "A", "B"],
        ["posture", "report"],
    ],
    ids=["gate", "ksi", "posture-diff", "posture-report"],
)
def test_every_command_that_writes_html_actually_writes_it(tmp_path: Path, argv: list[str]) -> None:
    """Every `--html` path, rendered end to end through the CLI.

    U5 rebuilt the top of the page from each report's own keys, and a KSI row's `findings` is a COUNT where a
    posture report's is a bucket dict -- so `ksi --html` raised AttributeError and wrote no file at all. The
    unit tests all passed: they build reports by hand, and none of them was the shape that broke. A page that
    three of four commands can produce is not a feature, so this covers all four by running the command.
    """
    from kube_noob import drift
    from kube_noob.cli import main

    args = [str(ROOT / "examples" / "insecure-deployment.yaml") if a == "EXAMPLE" else a for a in argv]
    if argv[:2] == ["posture", "diff"]:
        for name, fixture in (("A", "day1.yaml"), ("B", "day2.yaml")):
            objs = [d for d in yaml.safe_load_all((FIX / fixture).read_text()) if d]
            path = tmp_path / f"{name}.json"
            path.write_text(json.dumps(drift.snapshot(objs, source="manifests")), encoding="utf-8")
            args[args.index(name)] = str(path)
    elif argv[:2] == ["posture", "report"]:
        args = ["posture", "report", "--state-dir", str(tmp_path / "state"), "-f", str(FIX / "day1.yaml")]

    out = tmp_path / "page.html"
    main([*args, "--html", str(out)])
    assert out.exists(), f"{' '.join(argv)} --html produced no file"
    page = out.read_text(encoding="utf-8")
    assert page.startswith("<!doctype html>") and page.rstrip().endswith("</html>")
    sinks = _parsed(page)
    assert (sinks.scripts, sinks.events, sinks.loads) == (0, [], [])
