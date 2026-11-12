"""R4.3: the CI gate before deploy, its SARIF, summary and code quality output, and the three CI templates."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from kube_noob import __version__, gate
from kube_noob.cli import main

ROOT = Path(__file__).resolve().parents[1]
GOOD = ROOT / "tests" / "fixtures" / "gate" / "good"
BAD = ROOT / "tests" / "fixtures" / "gate" / "bad"
CF = ROOT / "tests" / "fixtures" / "containerfile"


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _run(paths: list[Path], **kw: object) -> dict:  # type: ignore[type-arg]
    return gate.run(gate.collect([str(p) for p in paths], _read), **kw)  # type: ignore[arg-type]


def test_the_good_bundle_passes_and_the_bad_one_fails() -> None:
    good = _run([GOOD], platform="openshift", version="4.20")
    assert good["passed"] and good["failures"] == [] and good["findings"] == []
    bad = _run(
        [BAD],
        platform="openshift",
        version="4.20",
        containerfiles=[("Containerfile", _read(str(CF / "KN-B005.bad.Containerfile")))],
    )
    assert not bad["passed"] and bad["failures"][0].endswith("at high or above")
    assert {"KN-S013", "KN-N002", "KN-B005"} <= {f["ruleId"] for f in bad["findings"]}
    assert bad["notRun"] and "vulnerability" in bad["notRun"][0]
    assert _run([BAD], fail_on="never")["passed"]


def test_findings_point_at_their_file_and_line(tmp_path: Path) -> None:
    a = tmp_path / "a.yaml"
    b = tmp_path / "b.yaml"
    a.write_text("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c, namespace: shop}\ndata: {k: v}\n")
    b.write_text(_read(str(BAD / "route.yaml")))
    rep = _run([a, b], platform="openshift", version="4.20")
    route = next(f for f in rep["findings"] if f["ruleId"] == "KN-N002")
    assert route["uri"] == gate._uri(b) and not route["uri"].startswith("..")
    lines = b.read_text().splitlines()
    assert route["line"] is not None and 1 <= route["line"] <= len(lines)


def test_rendered_chart_findings_point_at_the_template() -> None:
    rendered = "---\n# Source: shop/templates/route.yaml\n" + _read(str(BAD / "route.yaml"))
    src = gate.Source("rendered.yaml", rendered, chart="charts/shop")
    rep = gate.run([src], platform="openshift", version="4.20")
    route = next(f for f in rep["findings"] if f["ruleId"] == "KN-N002")
    assert route["uri"] == "charts/shop/templates/route.yaml" and route["line"] is None
    evil = gate.Source("r.yaml", "# Source: shop/../../etc/passwd\n" + _read(str(BAD / "route.yaml")), chart="c")
    assert all("etc/passwd" not in f["uri"] for f in gate.run([evil], platform="openshift")["findings"])


def test_admission_and_exceptions() -> None:
    rep = _run([BAD], platform="openshift", version="4.20")
    by_rule = {f["ruleId"]: f for f in rep["findings"]}
    assert by_rule["KN-N002"]["admission"] == "refused in enforce mode"
    assert by_rule["KN-S013"]["admission"].startswith("refused in enforce mode (partly: ")
    assert rep["admission"]["refusedInEnforceMode"] >= 2 and "--mode enforce" in rep["admission"]["command"]
    exceptions = yaml.safe_dump(
        {
            "apiVersion": "kube-noob.io/v1",
            "kind": "ExceptionList",
            "exceptions": [
                {
                    "id": "EXC-1",
                    "rule": "KN-N002",
                    "scope": {"namespace": "shop", "kind": "Route", "name": "legacy"},
                    "owner": "web-team",
                    "reason": "TLS ends at the external load balancer in front of the router",
                    "expires": "2027-06-30",
                }
            ],
        }
    )
    accepted = _run([BAD], platform="openshift", version="4.20", exceptions=exceptions)
    assert accepted["excepted"] == 1 and "KN-N002" not in {f["ruleId"] for f in accepted["findings"]}
    expired = exceptions.replace("2027-06-30", "2020-01-01")
    rep = _run([GOOD], platform="openshift", version="4.20", exceptions=expired)
    assert not rep["passed"] and "exception list" in rep["failures"][0]


def test_reported_issues_for_deployed_kinds() -> None:
    cm = gate.Source("cm.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c, namespace: shop}\n")
    rep = gate.run([cm], platform="openshift", version="4.20")
    assert rep["knownIssues"] and all("ConfigMap" in k["kinds"] for k in rep["knownIssues"])
    assert gate.run([cm], platform="kubernetes", version="1.33")["knownIssues"] == []


def test_sarif_codequality_and_markdown() -> None:
    rep = _run(
        [BAD],
        platform="openshift",
        version="4.20",
        containerfiles=[("Containerfile", _read(str(CF / "KN-B005.bad.Containerfile")))],
    )
    doc = gate.sarif(rep)
    assert doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert run["tool"]["driver"]["version"] == __version__
    assert len(run["results"]) == len(rep["findings"])
    for r in run["results"]:
        assert rules[r["ruleIndex"]]["id"] == r["ruleId"] and r["level"] in {"error", "warning", "note"}
        loc = r["locations"][0]["physicalLocation"]
        assert not loc["artifactLocation"]["uri"].startswith("/") and loc.get("region", {}).get("startLine", 1) >= 1
        assert re.fullmatch(r"[0-9a-f]{32}", r["partialFingerprints"]["kubeNoob/v1"])
    assert all(re.fullmatch(r"\d+\.\d", x["properties"]["security-severity"]) for x in rules)
    again = gate.sarif(
        _run(
            [BAD],
            platform="openshift",
            version="4.20",
            containerfiles=[("Containerfile", _read(str(CF / "KN-B005.bad.Containerfile")))],
        )
    )
    assert again == doc, "deterministic: the same input gives the same SARIF"
    cq = gate.codequality(rep)
    assert {c["severity"] for c in cq} <= {"info", "minor", "major", "critical", "blocker"}
    assert all({"description", "check_name", "fingerprint", "severity", "location"} <= set(c) for c in cq)
    md = gate.markdown(rep)
    assert md.startswith("## kube-noob gate failed") and "| high |" in md and "### Why it failed" in md
    assert "### Not run" in md


def test_bounds_and_errors(tmp_path: Path) -> None:
    with pytest.raises(gate.GateError, match="nothing to check"):
        gate.run([])
    with pytest.raises(gate.GateError, match="no such file"):
        gate.collect([str(tmp_path / "missing")], _read)
    for i in range(3):
        (tmp_path / f"{i}.yaml").write_text("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n")
    original = gate.MAX_FILES
    try:
        gate.MAX_FILES = 2
        with pytest.raises(gate.GateError, match="more than"):
            gate.collect([str(tmp_path)], _read)
    finally:
        gate.MAX_FILES = original


def test_cli_writes_every_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = {k: tmp_path / k for k in ("g.sarif", "g.md", "g.json")}
    args = [
        "--platform",
        "openshift",
        "--version",
        "4.20",
        "--sarif",
        str(out["g.sarif"]),
        "--summary",
        str(out["g.md"]),
        "--codequality",
        str(out["g.json"]),
    ]
    assert main(["gate", "-f", str(GOOD), *args]) == 0
    assert main(["gate", "-f", str(BAD), "--containerfile", str(CF / "KN-B005.bad.Containerfile"), *args]) == 1
    assert json.loads(out["g.sarif"].read_text())["runs"][0]["results"]
    assert out["g.md"].read_text().startswith("## kube-noob gate failed")
    assert json.loads(out["g.json"].read_text())
    capsys.readouterr()
    assert main(["gate"]) == 2


# -- the three CI templates -----------------------------------------------------------------------------------------


def test_github_action_passes_inputs_through_the_environment() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    assert action["runs"]["using"] == "composite"
    steps = action["runs"]["steps"]
    for step in steps:
        assert "${{ inputs." not in step.get("run", ""), "inputs reach scripts only through env (no injection)"
        if "uses" in step:
            assert re.search(r"@[0-9a-f]{40}$", step["uses"]), f"{step['uses']} must be pinned to a commit"
    gate_step = next(s for s in steps if s.get("id") == "gate")
    assert {"KN_PATHS", "KN_CHART", "KN_FAIL_ON", "KN_SARIF"} <= set(gate_step["env"])
    install = next(s for s in steps if "requirements.lock" in s.get("run", ""))
    assert "--require-hashes" in install["run"] and "--no-build-isolation" in install["run"]
    assert set(action["inputs"]) >= {"paths", "chart", "values", "containerfiles", "platform", "version", "fail-on"}


def test_tekton_task_and_gitlab_template() -> None:
    task = yaml.safe_load((ROOT / "deploy" / "tekton" / "kube-noob-gate.yaml").read_text())
    assert task["apiVersion"] == "tekton.dev/v1" and task["kind"] == "Task"
    step = task["spec"]["steps"][0]
    assert "$(params." not in step["script"], "params reach the script only through env (no injection)"
    assert step["securityContext"]["runAsNonRoot"] and step["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    assert {r["name"] for r in task["spec"]["results"]} == {"result", "counts"}
    image = next(p for p in task["spec"]["params"] if p["name"] == "image")["default"]
    assert image.endswith(f":{__version__}")
    gl = yaml.safe_load((ROOT / "deploy" / "gitlab" / "kube-noob-gate.gitlab-ci.yml").read_text())
    job = gl[".kube-noob-gate"]
    assert job["image"]["name"].endswith(f":{__version__}") and job["image"]["entrypoint"] == [""]
    assert job["artifacts"]["reports"]["codequality"] == "gl-code-quality-report.json"
    assert "--codequality gl-code-quality-report.json" in job["script"][0]
    assert "args+=" not in job["script"][0] and "${" not in job["script"][0], "POSIX sh: no bash arrays"


def test_directory_walks_skip_what_is_not_a_manifest(tmp_path: Path) -> None:
    chart = tmp_path / "chart"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: shop\nversion: 0.1.0\n")
    (chart / "values.yaml").write_text("replicas: 2\n")
    (chart / "templates" / "deploy.yaml").write_text("apiVersion: apps/v1\nkind: Deployment\n{{- if .Values.x }}\n")
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("on: push\njobs: {}\n")
    (tmp_path / "k8s").mkdir()
    (tmp_path / "k8s" / "route.yaml").write_text(_read(str(BAD / "route.yaml")))
    rep = gate.run(gate.collect([str(tmp_path)], _read), platform="openshift", version="4.20")
    assert rep["files"] == [gate._uri(tmp_path / "k8s" / "route.yaml")]
    whys = {Path(x["file"]).name: x["why"] for x in rep["skipped"]}
    assert whys["deploy.yaml"].startswith("a Helm template") and "not a Kubernetes manifest" in whys["values.yaml"]
    assert "ci.yml" not in whys, "dot directories are not walked"
    named = gate.collect([str(chart / "values.yaml")], _read)
    with pytest.raises(gate.GateError, match="nothing here is a Kubernetes manifest"):
        gate.run(named, platform="openshift", fail_on="never")


def test_helm_render_passes_the_callers_kubernetes_version(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from kube_noob.generate.helm_render import kube_version_arg, render_chart

    assert kube_version_arg("kubernetes", None) is None
    assert kube_version_arg("openshift", None) is None
    assert kube_version_arg("kubernetes", "1.33") == "1.33.0"
    assert kube_version_arg("openshift", "4.20") == "1.33.0"
    chart = tmp_path / "chart"
    chart.mkdir()
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: shop\nversion: 0.1.0\n")
    seen: dict[str, list[str]] = {}

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen["args"] = args
        return subprocess.CompletedProcess(args, 0, stdout="apiVersion: v1\nkind: ConfigMap\n", stderr="")

    monkeypatch.setattr("kube_noob.generate.helm_render.helm_binary", lambda *_: "helm")
    monkeypatch.setattr("kube_noob.generate.helm_render.subprocess.run", fake_run)
    render_chart(chart, kube_version=None)
    assert "--kube-version" not in seen["args"]
    render_chart(chart, kube_version="1.33.0")
    assert seen["args"][seen["args"].index("--kube-version") + 1] == "1.33.0"
