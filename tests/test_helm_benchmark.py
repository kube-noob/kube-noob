"""The Helm-charts-on-OpenShift benchmark: a chart nobody could read is a row that says so, never a clean one (G438).

`scripts/helm_benchmark.py` renders the pinned charts in `bench/charts.yaml` with helm, audits each for OpenShift
4.22 and writes one report. A benchmark that names other people's projects is only worth publishing if every way
of not having an answer stays visible in it:

- a chart that does not pull, or does not render, is a row with helm's exit code -- never dropped, because a
  table of the charts that happened to work reads as a table of all of them;
- a chart that renders no object is "rendered nothing" -- never a zero-finding row with a score;
- a kind kube-noob has no reader for is named in the row of the chart that ships it;
- no verdict is spelt "clean" or "pass".

There is no helm on the machine that runs the unit tests, so the fixture under `tests/fixtures/helm_benchmark/out`
holds handwritten manifests standing in for `helm template` output, with the audit JSON that the `audit` mode
recorded by running the real CLI on them; `test_the_recording_is_what_the_cli_says_today` re-runs it. The render
mode is driven through a stand-in `helm` that exits and prints the way the tests need.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import stat
import sys
from collections import Counter
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "helm_benchmark.py"
CHARTS = ROOT / "bench" / "charts.yaml"
WORKFLOW = ROOT / ".github" / "workflows" / "helm-benchmark.yml"
FIXTURE = ROOT / "tests" / "fixtures" / "helm_benchmark"
DATE = "2026-11-28"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("helm_benchmark", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["helm_benchmark"] = module
    spec.loader.exec_module(module)
    return module


hb = _load()


def _report(tmp_path: Path, out: Path = FIXTURE / "out", charts: Path = FIXTURE / "charts.yaml") -> tuple[str, Any]:
    md = tmp_path / "report.md"
    data = tmp_path / "report.json"
    code = hb.main(
        ["report", "--charts", str(charts), "--out", str(out), "--report", str(md), "--data", str(data)]
        + ["--date", DATE]
    )
    assert code == 0
    return md.read_text(encoding="utf-8"), json.loads(data.read_text(encoding="utf-8"))


def _row(data: Any, chart_id: str) -> dict[str, Any]:
    rows = [r for r in data["charts"] if r["id"] == chart_id]
    assert len(rows) == 1, f"{chart_id} has {len(rows)} rows"
    return dict(rows[0])


def _table_line(md: str, chart_id: str) -> str:
    section = md.split("## Every chart", 1)[1].split("\n## ", 1)[0]
    lines = [ln for ln in section.splitlines() if ln.startswith(f"| {chart_id} |")]
    assert len(lines) == 1, f"{chart_id} has {len(lines)} lines in the per-chart table"
    return lines[0]


# -- the chart list ------------------------------------------------------------------------------------------------


def test_every_chart_is_pinned_to_one_exact_version_and_says_where_it_was_read() -> None:
    spec = yaml.safe_load(CHARTS.read_text(encoding="utf-8"))
    charts = spec["charts"]
    assert 20 <= len(charts) <= 30, f"{len(charts)} charts; the benchmark is 20 to 30"
    ids = [c["id"] for c in charts]
    assert len(set(ids)) == len(ids), "a chart id is used twice, so one row would overwrite the other"
    for c in charts:
        assert isinstance(c["version"], str), f"{c['id']}: an unquoted version is a float to YAML (1.20 is 1.2)"
        assert re.fullmatch(r"v?\d+\.\d+\.\d+", c["version"]), (
            f"{c['id']}: {c['version']!r} is not one exact version; a range or `latest` audits different bytes "
            "on every run"
        )
        assert re.match(r"(https|oci)://", c["repo"]), f"{c['id']}: {c['repo']!r}"
        assert c["versionSource"].strip(), f"{c['id']}: says nowhere the version was read from"
        assert c["category"].strip() and c["chart"].strip()
        assert c["values"] == "defaults", f"{c['id']}: the first render is always the chart's defaults"
        if "fallback" in c:
            assert c["fallback"]["reason"].strip(), f"{c['id']}: fallback values with no reason recorded"
            assert c["fallback"]["set"] and all(re.fullmatch(r"[\w.\[\]-]+=\S+", s) for s in c["fallback"]["set"])


def test_the_chart_list_is_what_the_script_reads_and_the_script_refuses_an_unpinned_one(tmp_path: Path) -> None:
    assert [c.id for c in hb.load_charts(CHARTS).charts] == [
        c["id"] for c in yaml.safe_load(CHARTS.read_text(encoding="utf-8"))["charts"]
    ]
    spec = yaml.safe_load((FIXTURE / "charts.yaml").read_text(encoding="utf-8"))
    for bad in ("latest", ">=1.0.0", "1.2", "", "1.2.x"):
        spec["charts"][0]["version"] = bad
        path = tmp_path / "charts.yaml"
        path.write_text(yaml.safe_dump(spec), encoding="utf-8")
        with pytest.raises(hb.ChartListError, match="exact version"):
            hb.load_charts(path)
    spec["charts"][0]["version"] = "1.2.3"
    spec["charts"][1]["id"] = spec["charts"][0]["id"]
    path.write_text(yaml.safe_dump(spec), encoding="utf-8")
    with pytest.raises(hb.ChartListError, match="twice"):
        hb.load_charts(path)


def test_a_chart_id_cannot_leave_the_output_directory(tmp_path: Path) -> None:
    spec = yaml.safe_load((FIXTURE / "charts.yaml").read_text(encoding="utf-8"))
    for bad in ("../x", "a/b", ".", "..", "-rf", "A B"):
        spec["charts"][0]["id"] = bad
        path = tmp_path / "charts.yaml"
        path.write_text(yaml.safe_dump(spec), encoding="utf-8")
        with pytest.raises(hb.ChartListError, match="id"):
            hb.load_charts(path)


def test_the_sdist_that_carries_the_script_carries_its_chart_list() -> None:
    """The sdist ships scripts/; a runner without the list it reads is the corpus defect again (G377)."""
    include = (ROOT / "pyproject.toml").read_text(encoding="utf-8").split("[tool.hatch.build.targets.sdist]", 1)
    assert len(include) == 2, "pyproject.toml no longer has an sdist include list; update this test"
    listed = re.findall(r'^\s+"([^"]+)",', include[1].split("]", 1)[0], flags=re.M)
    assert "scripts" in listed and "bench" in listed


# -- the report: complete, deterministic, and honest about what it did not read --------------------------------------


def test_every_chart_in_the_list_has_a_row_and_the_ones_that_failed_keep_theirs(tmp_path: Path) -> None:
    md, data = _report(tmp_path)
    wanted = [c.id for c in hb.load_charts(FIXTURE / "charts.yaml").charts]
    assert sorted(r["id"] for r in data["charts"]) == sorted(wanted)
    for chart_id in wanted:
        _table_line(md, chart_id)
    assert _row(data, "unreachable")["verdict"] == "pull failed"
    assert _row(data, "broken")["verdict"] == "render failed"
    assert _row(data, "never-run")["verdict"] == "not rendered"
    assert data["totals"]["charts"] == len(wanted) == 7
    assert data["totals"]["audited"] == 3
    assert data["totals"]["byVerdict"] == {
        "findings": 1,
        "no findings in what was read": 1,
        "not rendered": 1,
        "pull failed": 1,
        "render failed": 1,
        "rendered nothing": 1,
        "undetermined": 1,
    }


def test_the_report_is_the_same_bytes_whatever_order_the_charts_and_files_come_in(tmp_path: Path) -> None:
    first = _report(tmp_path)
    (tmp_path / "again").mkdir()
    assert _report(tmp_path / "again") == first

    spec = yaml.safe_load((FIXTURE / "charts.yaml").read_text(encoding="utf-8"))
    spec["charts"].reverse()
    shuffled = tmp_path / "charts.yaml"
    shuffled.write_text(yaml.safe_dump(spec), encoding="utf-8")
    out = tmp_path / "out"
    for name in sorted((p.name for p in (FIXTURE / "out").iterdir()), reverse=True):
        shutil.copytree(FIXTURE / "out" / name, out / name)
    (tmp_path / "reordered").mkdir()
    md, data = _report(tmp_path / "reordered", out=out, charts=shuffled)
    assert md == first[0]
    assert data == first[1]


def test_the_report_takes_its_date_from_the_caller_and_never_from_the_clock(tmp_path: Path) -> None:
    md, data = _report(tmp_path)
    assert data["date"] == DATE and f"Run on {DATE}" in md
    undated = tmp_path / "undated.md"
    code = hb.main(
        ["report", "--charts", str(FIXTURE / "charts.yaml"), "--out", str(FIXTURE / "out")]
        + ["--report", str(undated), "--data", str(tmp_path / "undated.json")]
    )
    assert code == 0
    assert "date not recorded" in undated.read_text(encoding="utf-8")


def test_a_chart_that_renders_nothing_is_rendered_nothing_and_has_no_score(tmp_path: Path) -> None:
    md, data = _report(tmp_path)
    row = _row(data, "empty")
    assert row["verdict"] == "rendered nothing"
    assert row["score"] is None and row["findings"] is None, "a chart with no objects has no findings to count"
    assert row["documents"] == 0
    assert row["audit"]["exitCode"] == 2, "the recorded exit code of the audit is kept as evidence"
    line = _table_line(md, "empty")
    assert "rendered nothing" in line
    assert "no findings" not in line and "100" not in line
    assert "empty" not in [c for rule in data["rules"] for c in rule["chartIds"]]


def test_no_verdict_is_spelt_clean_or_pass(tmp_path: Path) -> None:
    md, data = _report(tmp_path)
    verdicts = {r["verdict"] for r in data["charts"]}
    assert verdicts <= set(hb.VERDICTS)
    for word in hb.VERDICTS:
        assert not re.search(r"\b(clean|pass|passed|ok|compliant)\b", word), word
    quiet = _row(data, "quiet")
    assert quiet["verdict"] == "no findings in what was read"
    assert quiet["notRead"]["notEvaluated"] > 0, "a ConfigMap alone leaves most rules with nothing to read"
    assert f"{quiet['notRead']['notEvaluated']} rules not evaluated" in _table_line(md, "quiet")


def test_a_kind_kube_noob_has_no_reader_for_is_named_in_the_row_of_its_chart(tmp_path: Path) -> None:
    md, data = _report(tmp_path)
    row = _row(data, "operator")
    assert row["verdict"] == "undetermined"
    assert row["score"] is None, "kube-noob gives no score to an undetermined audit, and the report invents none"
    assert row["notRead"]["notAudited"] == [
        {
            "kind": "Rollout",
            "apiGroup": "argoproj.io",
            "objects": 1,
            "why": "pods are in a kind kube-noob has no reader for",
        }
    ]
    assert {"apiVersion": "kafka.strimzi.io/v1beta2", "kind": "Kafka", "objects": 1} in row["notRead"]["noSchema"]
    line = _table_line(md, "operator")
    assert "Rollout (argoproj.io)" in line and "Kafka" in line
    kinds = {(k["kind"], k["apiGroup"]): k for k in data["notAuditedKinds"]}
    assert kinds["Rollout", "argoproj.io"]["charts"] == 1 and kinds["Rollout", "argoproj.io"]["chartIds"] == [
        "operator"
    ]


def test_the_counts_are_the_counts_in_the_recorded_audit(tmp_path: Path) -> None:
    md, data = _report(tmp_path)
    recorded = json.loads((FIXTURE / "out" / "web" / "audit.json").read_text(encoding="utf-8"))
    by_severity = Counter(f["severity"] for f in recorded["findings"])
    by_rule = Counter(f["ruleId"] for f in recorded["findings"])
    row = _row(data, "web")
    assert row["verdict"] == "findings"
    assert row["findings"]["total"] == len(recorded["findings"]) > 0
    assert row["findings"]["bySeverity"] == {s: by_severity.get(s, 0) for s in hb.SEVERITIES}
    assert row["score"] == recorded["summary"]["score"]
    assert row["audit"]["exitCode"] == 1
    assert sum(r["count"] for r in row["topRules"]) <= row["findings"]["total"]
    assert all(by_rule[r["ruleId"]] == r["count"] for r in row["topRules"])
    # most severe first, then most frequent, then by id: KN-S001 is the one critical finding
    assert row["topRules"][0]["ruleId"] == "KN-S001"
    assert len(row["topRules"]) == min(hb.TOP_RULES, len(by_rule))

    rules = {r["ruleId"]: r for r in data["rules"]}
    assert set(rules) == set(by_rule), "only `web` has findings in the fixture, so the rule table is its rules"
    for rule_id, n in by_rule.items():
        assert rules[rule_id]["charts"] == 1 and rules[rule_id]["findings"] == n
        assert rules[rule_id]["exampleChart"] == "web"
    order = [(-r["charts"], -r["findings"], r["ruleId"]) for r in data["rules"]]
    assert order == sorted(order)
    assert "| KN-S001 | Privileged container | critical | 1 of 3 | 1 | web |" in md


def test_a_rule_counts_each_chart_once_however_many_findings_it_has_there(tmp_path: Path) -> None:
    out = tmp_path / "out"
    shutil.copytree(FIXTURE / "out", out)
    audit = json.loads((out / "web" / "audit.json").read_text(encoding="utf-8"))
    twin = next(f for f in audit["findings"] if f["ruleId"] == "KN-S001")
    audit["findings"].append({**twin, "resource": "Deployment/bench/second"})
    shutil.copytree(out / "web", out / "quiet", dirs_exist_ok=True)  # `quiet` now has web's findings, once each
    (out / "web" / "audit.json").write_text(json.dumps(audit), encoding="utf-8")
    (tmp_path / "r").mkdir()
    _, data = _report(tmp_path / "r", out=out)
    rule = next(r for r in data["rules"] if r["ruleId"] == "KN-S001")
    assert (rule["charts"], rule["findings"], rule["chartIds"]) == (2, 3, ["quiet", "web"])
    assert rule["exampleChart"] == "web", "the example is the chart with the most findings of the rule"


def test_the_restricted_v2_share_names_its_rules_and_counts_only_charts_that_were_read(tmp_path: Path) -> None:
    md, data = _report(tmp_path)
    scc = data["restrictedV2"]
    assert scc["rules"] == sorted(hb.RESTRICTED_V2_RULES)
    assert scc["chartIds"] == ["web"] and scc["audited"] == 3
    assert scc["notDetermined"] == ["broken", "empty", "never-run", "unreachable"]
    assert scc["byRule"] == {**dict.fromkeys(hb.RESTRICTED_V2_RULES, 0), "KN-S001": 1, "KN-S009": 1}
    assert scc["readInPart"] == ["operator"], "a chart whose pods were not read cannot be counted as admitted"
    section = md.split("## Would the restricted-v2 SCC admit it", 1)[1].split("\n## ", 1)[0]
    assert "1 of the 3 charts" in section
    for rule_id in hb.RESTRICTED_V2_RULES:
        assert rule_id in section
    assert "at least" in section
    # every rule the share is built from is a rule kube-noob has, and one whose text is about this SCC or about
    # a pod shape it refuses
    from kube_noob.audit.rules import RULES

    assert set(hb.RESTRICTED_V2_RULES) <= set(RULES)


def test_a_failed_render_keeps_helm_s_exit_code_and_what_it_said(tmp_path: Path) -> None:
    md, data = _report(tmp_path)
    row = _row(data, "broken")
    attempts = row["render"]["template"]
    assert [a["values"] for a in attempts] == ["defaults", "fallback"]
    assert [a["exitCode"] for a in attempts] == [1, 1]
    assert row["audit"] is None and row["score"] is None and row["findings"] is None
    line = _table_line(md, "broken")
    assert "render failed" in line and "helm exit 1" in line
    assert "execution error at (broken/templates/deployment.yaml" in line
    pull = _row(data, "unreachable")["render"]["pull"]
    assert pull["exitCode"] == 1 and "looks like" in pull["stderr"]


def test_what_helm_printed_cannot_add_a_column_a_row_or_a_workflow_command_to_the_report(tmp_path: Path) -> None:
    out = tmp_path / "out"
    shutil.copytree(FIXTURE / "out", out)
    render = json.loads((out / "broken" / "render.json").read_text(encoding="utf-8"))
    hostile = "Error: a | b `c`\n| x | y |\n::error title=kube-noob::All checks passed\n<script>alert(1)</script>"
    for attempt in render["template"]:
        attempt["stderr"] = hostile
    (out / "broken" / "render.json").write_text(json.dumps(render), encoding="utf-8")
    (tmp_path / "r").mkdir()
    md, _ = _report(tmp_path / "r", out=out)
    line = _table_line(md, "broken")
    assert line.count("|") == _table_line(md, "web").count("|"), "helm's stderr added a column"
    assert "<script>" not in md
    assert not any(ln.startswith("::") for ln in md.splitlines())
    assert not any(ln.startswith("| x") for ln in md.splitlines())


def test_the_report_says_what_was_run_how_to_run_it_again_and_what_it_does_not_show(tmp_path: Path) -> None:
    md, data = _report(tmp_path)
    assert data["kubeNoobVersions"] == ["0.11.1"] or re.fullmatch(r"\d+\.\d+\.\d+", data["kubeNoobVersions"][0])
    assert f"kube-noob {data['kubeNoobVersions'][0]}" in md
    for chart in hb.load_charts(FIXTURE / "charts.yaml").charts:
        assert f"| {chart.id} | `{chart.chart}` | {chart.version} |" in md, f"{chart.id}'s version is not stated"
    repro = md.split("## How to reproduce", 1)[1].split("\n## ", 1)[0]
    for command in ("helm_benchmark.py render", "helm_benchmark.py audit", "helm_benchmark.py report"):
        assert command in repro
    assert "gh workflow run helm-benchmark.yml" in repro
    limits = md.split("## What this does not show", 1)[1]
    for phrase in ("default values", "rendered, not deployed", "not a vulnerability report"):
        assert phrase in limits.lower(), phrase
    assert data["platform"] == "openshift" and data["platformVersion"] == "4.22"
    assert "--platform openshift --version 4.22 --format json" in md


def test_a_run_that_audited_nothing_is_not_a_report_the_job_may_call_done(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    args = ["report", "--charts", str(FIXTURE / "charts.yaml"), "--out", str(out)]
    args += ["--report", str(tmp_path / "r.md"), "--data", str(tmp_path / "r.json"), "--date", DATE]
    assert hb.main(args) == 0, "without a floor the report is still written: seven rows that say not rendered"
    data = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert {r["verdict"] for r in data["charts"]} == {"not rendered"}
    assert data["rules"] == [] and data["restrictedV2"]["chartIds"] == []
    assert "not measured" in (tmp_path / "r.md").read_text(encoding="utf-8")
    assert hb.main([*args, "--min-audited", "1"]) == 1


# -- the audit mode, for real ----------------------------------------------------------------------------------------


def _fresh_out(tmp_path: Path) -> Path:
    """The fixture's rendered manifests and render records, without the recorded audits."""
    out = tmp_path / "out"
    shutil.copytree(FIXTURE / "out", out, ignore=shutil.ignore_patterns("audit.json", "audit-meta.json"))
    return out


def test_the_recording_is_what_the_cli_says_today(tmp_path: Path) -> None:
    """The fields the report reads, from the real CLI. Not the whole document: a new rule changes the list of
    rules that had nothing to read, and that must not fail here."""
    out = _fresh_out(tmp_path)
    assert hb.main(["audit", "--charts", str(FIXTURE / "charts.yaml"), "--out", str(out)]) == 0
    for chart_id in ("web", "operator", "quiet", "empty"):
        was = json.loads((FIXTURE / "out" / chart_id / "audit-meta.json").read_text(encoding="utf-8"))
        now = json.loads((out / chart_id / "audit-meta.json").read_text(encoding="utf-8"))
        assert now["exitCode"] == was["exitCode"], chart_id
        assert now["documents"] == was["documents"], chart_id
        assert now["command"] == was["command"], chart_id
        assert "--platform openshift --version 4.22 --format json" in " ".join(now["command"])
    assert not (out / "empty" / "audit.json").read_text(encoding="utf-8").strip()
    for chart_id in ("web", "operator", "quiet"):
        was_doc = json.loads((FIXTURE / "out" / chart_id / "audit.json").read_text(encoding="utf-8"))
        now_doc = json.loads((out / chart_id / "audit.json").read_text(encoding="utf-8"))
        assert now_doc["summary"].get("verdict") == was_doc["summary"].get("verdict"), chart_id
        assert [(n["kind"], n["apiGroup"], n["why"]) for n in now_doc["notAudited"]] == [
            (n["kind"], n["apiGroup"], n["why"]) for n in was_doc["notAudited"]
        ], chart_id
        assert now_doc["resources"] == was_doc["resources"], chart_id
        for key in ("findings", "notEvaluated", "unreadable", "assumptions"):
            assert type(now_doc[key]) is type(was_doc[key]), f"{chart_id}: {key} changed shape"
    (tmp_path / "r").mkdir()
    _, data = _report(tmp_path / "r", out=out)
    assert {r["id"]: r["verdict"] for r in data["charts"]} == {
        "broken": "render failed",
        "empty": "rendered nothing",
        "never-run": "not rendered",
        "operator": "undetermined",
        "quiet": "no findings in what was read",
        "unreachable": "pull failed",
        "web": "findings",
    }


def test_the_audit_mode_audits_only_what_rendered_and_writes_nothing_for_the_rest(tmp_path: Path) -> None:
    out = _fresh_out(tmp_path)
    assert hb.main(["audit", "--charts", str(FIXTURE / "charts.yaml"), "--out", str(out)]) == 0
    assert not (out / "broken" / "audit-meta.json").exists()
    assert not (out / "never-run").exists()
    assert not (out / "unreachable" / "audit-meta.json").exists()


def test_an_audit_whose_answer_is_not_json_is_not_a_row_with_zero_findings(tmp_path: Path) -> None:
    out = tmp_path / "out"
    shutil.copytree(FIXTURE / "out", out)
    (out / "web" / "audit.json").write_text("Traceback (most recent call last):\n", encoding="utf-8")
    meta = json.loads((out / "quiet" / "audit-meta.json").read_text(encoding="utf-8"))
    meta["exitCode"] = 4
    meta["stderr"] = "error: something kube-noob did not anticipate"
    (out / "quiet" / "audit-meta.json").write_text(json.dumps(meta), encoding="utf-8")
    (out / "operator" / "audit.json").write_text(json.dumps({"summary": {}, "findings": "none"}), encoding="utf-8")
    (tmp_path / "r").mkdir()
    md, data = _report(tmp_path / "r", out=out)
    for chart_id in ("web", "quiet", "operator"):
        row = _row(data, chart_id)
        assert row["verdict"] == "audit did not answer", chart_id
        assert row["score"] is None and row["findings"] is None
    assert "kube-noob exit 4" in _table_line(md, "quiet")
    assert data["totals"]["audited"] == 0 and data["rules"] == []


# -- the render mode, through a stand-in helm ------------------------------------------------------------------------

_FAKE_HELM = r"""#!{python}
import json, os, pathlib, sys
argv = sys.argv[1:]
with open(os.environ["FAKE_HELM_LOG"], "a", encoding="utf-8") as fh:
    fh.write(json.dumps(argv) + "\n")
if argv[:1] == ["version"]:
    print("v4.3.2+gfake")
    sys.exit(0)
if argv[0] == "pull":
    chart = argv[1]
    if chart == "unreachable":
        sys.stderr.write("Error: looks like the address is not a valid chart repository\n")
        sys.exit(1)
    dest = pathlib.Path(argv[argv.index("--destination") + 1])
    (dest / f"{{chart}}-{{argv[argv.index('--version') + 1]}}.tgz").write_bytes(b"not a real archive")
    sys.exit(0)
if argv[0] == "template":
    name = pathlib.Path(argv[2]).name
    sets = [argv[i + 1] for i, a in enumerate(argv) if a == "--set"]
    if name.startswith("broken") or (name.startswith("operator") and not sets):
        sys.stderr.write("Error: execution error at (broken/templates/deployment.yaml:3:4): mode must be set\n")
        sys.exit(1)
    if name.startswith("empty"):
        print("---\n# Source: empty/templates/deployment.yaml")
        sys.exit(0)
    head = "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: " + name.split("-")[0]
    print(head + "\ndata:\n  sets: '" + ",".join(sets) + "'")
    sys.exit(0)
sys.exit(64)
"""


@pytest.fixture
def fake_helm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    helm = tmp_path / "bin" / "helm"
    helm.parent.mkdir()
    helm.write_text(_FAKE_HELM.format(python=sys.executable), encoding="utf-8")
    helm.chmod(helm.stat().st_mode | stat.S_IXUSR)
    log = tmp_path / "helm.log"
    log.write_text("", encoding="utf-8")
    monkeypatch.setenv("FAKE_HELM_LOG", str(log))
    return helm


def _render_charts(tmp_path: Path) -> Path:
    spec = yaml.safe_load((FIXTURE / "charts.yaml").read_text(encoding="utf-8"))
    by_id = {c["id"]: c for c in spec["charts"]}
    by_id["operator"]["fallback"] = {"reason": "the stand-in refuses its defaults", "set": ["mode=deployment"]}
    path = tmp_path / "render-charts.yaml"
    path.write_text(yaml.safe_dump(spec), encoding="utf-8")
    return path


def test_render_keeps_a_row_for_a_chart_that_does_not_pull_or_does_not_render(
    tmp_path: Path, fake_helm: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "out"
    charts = _render_charts(tmp_path)
    assert hb.main(["render", "--charts", str(charts), "--out", str(out), "--helm", str(fake_helm)]) == 0
    printed = capsys.readouterr()
    records = {p.parent.name: json.loads(p.read_text(encoding="utf-8")) for p in out.glob("*/render.json")}
    assert sorted(records) == sorted(c.id for c in hb.load_charts(charts).charts), "a chart was dropped"
    assert records["unreachable"]["pull"]["exitCode"] == 1
    assert records["unreachable"]["template"] == [] and not (out / "unreachable" / "rendered").exists()
    assert [a["exitCode"] for a in records["broken"]["template"]] == [1, 1]
    assert not (out / "broken" / "rendered").exists(), "a failed render must leave nothing for the audit to read"
    assert records["web"]["helmVersion"] == "v4.3.2+gfake"
    assert "Error:" not in printed.out, "helm's own words are recorded in render.json, not printed to the log"
    for chart_id in records:
        assert chart_id in printed.out


def test_render_tries_the_defaults_first_and_records_that_the_fallback_was_what_rendered(
    tmp_path: Path, fake_helm: Path
) -> None:
    out = tmp_path / "out"
    charts = _render_charts(tmp_path)
    assert hb.main(["render", "--charts", str(charts), "--out", str(out), "--helm", str(fake_helm)]) == 0
    record = json.loads((out / "operator" / "render.json").read_text(encoding="utf-8"))
    assert [(a["values"], a["exitCode"], a["set"]) for a in record["template"]] == [
        ("defaults", 1, []),
        ("fallback", 0, ["mode=deployment"]),
    ]
    assert "sets: 'mode=deployment'" in (out / "operator" / "rendered" / "manifests.yaml").read_text(encoding="utf-8")
    web = json.loads((out / "web" / "render.json").read_text(encoding="utf-8"))
    assert [(a["values"], a["exitCode"]) for a in web["template"]] == [("defaults", 0)]

    calls = [json.loads(ln) for ln in Path(os.environ["FAKE_HELM_LOG"]).read_text(encoding="utf-8").splitlines()]
    pulls = [c for c in calls if c[0] == "pull"]
    assert len(pulls) == 7
    for call in pulls:
        assert "--version" in call and "--repo" in call
    assert pulls[0][:6] == ["pull", "web", "--repo", "https://charts.example.com/web", "--version", "1.2.3"]
    templates = [c for c in calls if c[0] == "template"]
    for call in templates:
        assert call[1] == "bench"
        assert call[call.index("--kube-version") + 1] == "1.35.0"
        assert call[call.index("--namespace") + 1] == "bench"
        assert "--no-hooks" not in call and "--skip-tests" not in call, "hooks are part of what a chart installs"

    # and the three modes fit together: what render wrote is what audit and report read
    assert hb.main(["audit", "--charts", str(charts), "--out", str(out)]) == 0
    (tmp_path / "r").mkdir()
    md, data = _report(tmp_path / "r", out=out, charts=charts)
    assert _row(data, "operator")["valuesUsed"] == "fallback: mode=deployment"
    assert "fallback" in _table_line(md, "operator")
    assert _row(data, "empty")["verdict"] == "rendered nothing"
    assert _row(data, "unreachable")["verdict"] == "pull failed"
    assert _row(data, "never-run")["verdict"] == "no findings in what was read"  # the stand-in renders a ConfigMap


def test_render_without_helm_is_an_error_and_not_seven_rows_of_pull_failed(tmp_path: Path) -> None:
    out = tmp_path / "out"
    code = hb.main(
        ["render", "--charts", str(FIXTURE / "charts.yaml"), "--out", str(out), "--helm", str(tmp_path / "no-helm")]
    )
    assert code == 2
    assert not list(out.glob("*/render.json"))


def test_an_oci_chart_is_pulled_by_reference_and_not_with_repo(tmp_path: Path, fake_helm: Path) -> None:
    spec = yaml.safe_load((FIXTURE / "charts.yaml").read_text(encoding="utf-8"))
    spec["charts"] = [{**spec["charts"][0], "repo": "oci://registry.example.com/charts"}]
    charts = tmp_path / "oci.yaml"
    charts.write_text(yaml.safe_dump(spec), encoding="utf-8")
    assert hb.main(["render", "--charts", str(charts), "--out", str(tmp_path / "out"), "--helm", str(fake_helm)]) == 0
    calls = [json.loads(ln) for ln in Path(os.environ["FAKE_HELM_LOG"]).read_text(encoding="utf-8").splitlines()]
    pull = next(c for c in calls if c[0] == "pull")
    assert pull[1] == "oci://registry.example.com/charts/web" and "--repo" not in pull


# -- the workflow's shape --------------------------------------------------------------------------------------------


def _workflow() -> dict[str, Any]:
    spec: dict[str, Any] = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return spec


def test_the_benchmark_runs_only_when_someone_dispatches_it() -> None:
    spec = _workflow()
    triggers = spec.get("on") or spec.get(True)
    assert list(triggers) == ["workflow_dispatch"], (
        "the benchmark pulls 25 charts from other people's servers and names their projects; it runs when the "
        "owner asks, never on a push, a pull request or a clock"
    )
    open_pr = triggers["workflow_dispatch"]["inputs"]["open_pr"]
    assert open_pr["type"] == "boolean" and open_pr["default"] is False
    assert spec["permissions"] == {"contents": "read"}


def test_every_job_has_a_budget_and_every_action_is_pinned_by_commit() -> None:
    spec = _workflow()
    assert set(spec["jobs"]) == {"benchmark", "open-pr"}
    for name, job in spec["jobs"].items():
        assert isinstance(job.get("timeout-minutes"), int) and 0 < job["timeout-minutes"] <= 60, name
        for step in job["steps"]:
            uses = step.get("uses")
            assert not uses or re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", uses), f"{name}: {uses} is not pinned by SHA"
    used = {s["uses"] for job in spec["jobs"].values() for s in job["steps"] if s.get("uses")}
    elsewhere = "\n".join(
        p.read_text(encoding="utf-8") for p in sorted(WORKFLOW.parent.glob("*.yml")) if p.name != WORKFLOW.name
    )
    for uses in sorted(used):
        assert uses in elsewhere, f"{uses} is a pin no other workflow here uses; reuse the repository's pins"


def test_helm_is_the_official_setup_action_at_one_pinned_version() -> None:
    steps = _workflow()["jobs"]["benchmark"]["steps"]
    helm = [s for s in steps if str(s.get("uses", "")).startswith("azure/setup-helm@")]
    assert len(helm) == 1
    version = helm[0]["with"]["version"]
    assert re.fullmatch(r"v\d+\.\d+\.\d+", version), f"{version!r}: `latest` renders differently next month"
    runs = "\n".join(str(s.get("run", "")) for s in steps)
    order = [runs.index(f"helm_benchmark.py {mode}") for mode in ("render", "audit", "report")]
    assert order == sorted(order)
    assert "pip install -e ." in runs, "the kube-noob that audits is the checkout's, not a release from PyPI"
    assert "--min-audited" in runs, "a run that audited no chart must fail, not upload an empty table as a result"
    upload = [s for s in steps if "upload-artifact" in str(s.get("uses", ""))]
    assert len(upload) == 1 and upload[0].get("if") == "always()", "the rows are evidence even when a step fails"
    paths = upload[0]["with"]["path"]
    assert "docs/benchmarks/helm-charts-openshift-4.22.md" in paths
    assert "docs/benchmarks/helm-charts-openshift-4.22.json" in paths


def test_a_pull_request_is_opened_only_when_asked_and_only_that_job_can_write() -> None:
    spec = _workflow()
    bench, pr = spec["jobs"]["benchmark"], spec["jobs"]["open-pr"]
    assert "permissions" not in bench, "the job that runs helm on other people's charts holds no write token"
    assert pr["if"] == "inputs.open_pr"
    assert pr["needs"] == "benchmark"
    assert pr["permissions"] == {"contents": "write", "pull-requests": "write"}
    for step in bench["steps"]:
        if "checkout" in str(step.get("uses", "")):
            assert step["with"]["persist-credentials"] is False
    runs = "\n".join(str(s.get("run", "")) for s in pr["steps"])
    assert "gh pr create" in runs
    assert (
        "git add docs/benchmarks/helm-charts-openshift-4.22.md docs/benchmarks/helm-charts-openshift-4.22.json" in runs
    )
    assert "git add -A" not in runs and "git add ." not in runs, "the pull request carries the report and nothing else"
    assert "git commit -s" in runs, "every commit here is signed off"
    assert "push --force" not in runs and "push -f" not in runs
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "does not start CI" in text, (
        "a pull request opened with GITHUB_TOKEN starts no workflow, so its checks never report; the job has to "
        "say so where the owner will read it"
    )
    assert "exit 1" in runs, "a pull request that could not be opened is a red job with the command to open it"
