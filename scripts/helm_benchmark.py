#!/usr/bin/env python3
"""The Helm-charts-on-OpenShift benchmark: render pinned public charts, audit each, and write one report.

    python scripts/helm_benchmark.py render --out out/helm-benchmark
    python scripts/helm_benchmark.py audit  --out out/helm-benchmark
    python scripts/helm_benchmark.py report --out out/helm-benchmark --date 2026-11-28

`bench/charts.yaml` pins every chart to one exact version. The three modes share one directory:

    <out>/<id>/render.json              what helm did: the pull, and every `helm template` attempt, each with its
                                        exit code and what helm printed on stderr
    <out>/<id>/rendered/manifests.yaml  the rendered chart, only when a render exited 0
    <out>/<id>/audit.json               stdout of `kube-noob audit -f <rendered> --platform openshift --version
                                        4.22 --format json`, byte for byte
    <out>/<id>/audit-meta.json          that command, its exit code, its stderr, the kube-noob version, and how
                                        many Kubernetes objects the rendered file holds

`render` needs helm and the network. `audit` and `report` need neither, so they run on a directory somebody else
rendered -- which is how the unit tests drive them.

Every chart in the list gets a row in the report, whatever happened to it. The verdicts, and none of them is
spelt "clean" or "pass":

    pull failed                    helm could not fetch the pinned version
    render failed                  `helm template` exited non-zero with the defaults, and with the fallback
                                   values if the list gives any
    not rendered                   there is no record that a render was tried
    rendered nothing               helm exited 0 and the output holds no Kubernetes object
    audit did not answer           the audit left no report this script can read: an exit code other than 0 or
                                   1, output that is not the JSON document, or no record of an audit
    undetermined                   kube-noob's own verdict: something in the chart was not read
    findings                       at least one finding
    no findings in what was read   no finding, and kube-noob did not call the audit undetermined. The row still
                                   lists how many rules had nothing to evaluate

Exit codes: 0 the mode did its work (a chart that failed is a row, not an error); 1 `report --min-audited N` and
fewer than N charts were audited; 2 a usage error, a chart list this refuses, or `render` with no helm to run.

What helm and kube-noob print is recorded in the files above and never echoed to this script's own output: the
charts are other people's, and a line of their stderr in a workflow log is a line GitHub may read as a command.

Standard library and PyYAML only.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CHARTS = ROOT / "bench" / "charts.yaml"
DEFAULT_OUT = ROOT / "out" / "helm-benchmark"
DEFAULT_REPORT = ROOT / "docs" / "benchmarks" / "helm-charts-openshift-4.22.md"
DEFAULT_DATA = ROOT / "docs" / "benchmarks" / "helm-charts-openshift-4.22.json"

SEVERITIES = ("critical", "high", "medium", "low", "info")
TOP_RULES = 5
STDERR_KEPT = 4000
HELM_TIMEOUT = 600
AUDIT_TIMEOUT = 900

VERDICTS = (
    "pull failed",
    "render failed",
    "not rendered",
    "rendered nothing",
    "audit did not answer",
    "undetermined",
    "findings",
    "no findings in what was read",
)

# The rules whose every finding is a pod shape the restricted-v2 SecurityContextConstraints does not admit:
# restricted-v2 sets allowPrivilegedContainer, allowHostNetwork, allowHostPID, allowHostIPC, allowHostPorts and
# allowHostDirVolumePlugin to false, allows no added capability but NET_BIND_SERVICE, and takes the UID from the
# namespace's range (MustRunAsRange). A rule that also fires on a field restricted-v2 would default for the pod
# (KN-S002, KN-S006, KN-S008: unset allowPrivilegeEscalation, capabilities not dropped, no seccomp profile) is not
# here, because a finding from it is not a refusal.
RESTRICTED_V2_RULES = {
    "KN-S001": "privileged container",
    "KN-S004": "fixed UID or fsGroup",
    "KN-S005": "dangerous capability added",
    "KN-S009": "host namespace shared",
    "KN-S010": "hostPath volume",
    "KN-S011": "hostPort",
}

_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_VERSION = re.compile(r"v?\d+\.\d+\.\d+\Z")
_SET = re.compile(r"[\w.\[\]-]+=\S+\Z")
_NO_SCHEMA = re.compile(r"No bundled schema for (?P<api>\S+) (?P<kind>\S+) \(")


class ChartListError(ValueError):
    """The chart list is not one this script will run."""


@dataclasses.dataclass(frozen=True)
class Chart:
    id: str
    category: str
    repo: str
    chart: str
    version: str
    app_version: str
    version_source: str
    fallback_set: tuple[str, ...]
    fallback_reason: str


@dataclasses.dataclass(frozen=True)
class ChartList:
    platform: str
    platform_version: str
    kube_version: str
    release: str
    namespace: str
    charts: tuple[Chart, ...]


def load_charts(path: Path) -> ChartList:
    """Read the chart list, refusing anything that would make two runs audit different bytes."""
    try:
        spec = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ChartListError(f"{path}: cannot be read as YAML: {exc}") from exc
    if not isinstance(spec, dict) or not isinstance(spec.get("charts"), list) or not spec["charts"]:
        raise ChartListError(f"{path}: no `charts:` list")
    charts: list[Chart] = []
    seen: set[str] = set()
    for n, raw in enumerate(spec["charts"]):
        if not isinstance(raw, dict):
            raise ChartListError(f"{path}: chart {n} is not a mapping")
        chart_id = raw.get("id")
        if not isinstance(chart_id, str) or not _ID.match(chart_id):
            raise ChartListError(
                f"{path}: chart {n}: id {chart_id!r} must be lower-case letters, digits and dashes; it names a "
                "directory"
            )
        if chart_id in seen:
            raise ChartListError(f"{path}: chart id {chart_id!r} is used twice")
        seen.add(chart_id)
        version = raw.get("version")
        if not isinstance(version, str) or not _VERSION.match(version):
            raise ChartListError(
                f"{path}: {chart_id}: version {version!r} is not one exact version (a quoted X.Y.Z); a range, a "
                "tag like `latest` or an unquoted number audits different bytes on different days"
            )
        for key in ("category", "repo", "chart", "versionSource"):
            if not isinstance(raw.get(key), str) or not raw[key].strip():
                raise ChartListError(f"{path}: {chart_id}: `{key}` is missing")
        if not re.match(r"(https|oci)://[\w./-]+\Z", raw["repo"]):
            raise ChartListError(f"{path}: {chart_id}: repo {raw['repo']!r} is not an https:// or oci:// address")
        if not re.match(r"[\w.-]+\Z", raw["chart"]):
            raise ChartListError(f"{path}: {chart_id}: chart name {raw['chart']!r}")
        if raw.get("values") != "defaults":
            raise ChartListError(f"{path}: {chart_id}: `values` must be `defaults`; other values go in `fallback`")
        fallback = raw.get("fallback") or {}
        sets = fallback.get("set") or []
        if fallback and (not isinstance(sets, list) or not sets or not str(fallback.get("reason", "")).strip()):
            raise ChartListError(f"{path}: {chart_id}: `fallback` needs a `set:` list and a `reason`")
        for item in sets:
            if not isinstance(item, str) or not _SET.match(item):
                raise ChartListError(f"{path}: {chart_id}: fallback value {item!r} is not key=value")
        charts.append(
            Chart(
                id=chart_id,
                category=raw["category"].strip(),
                repo=raw["repo"],
                chart=raw["chart"],
                version=version,
                app_version=str(raw.get("appVersion") or ""),
                version_source=raw["versionSource"].strip(),
                fallback_set=tuple(sets),
                fallback_reason=str(fallback.get("reason", "")).strip(),
            )
        )
    for key in ("platform", "platformVersion", "kubeVersion", "release", "namespace"):
        if not isinstance(spec.get(key), str) or not re.match(r"[\w.-]+\Z", spec[key]):
            raise ChartListError(f"{path}: `{key}` must be a quoted string")
    return ChartList(
        platform=spec["platform"],
        platform_version=spec["platformVersion"],
        kube_version=spec["kubeVersion"],
        release=spec["release"],
        namespace=spec["namespace"],
        charts=tuple(charts),
    )


def _run(argv: list[str], timeout: int) -> tuple[int | None, str, str]:
    """Run one command. The exit code is None when it did not finish in time or could not be started."""
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False, errors="replace")
    except subprocess.TimeoutExpired:
        return None, "", f"did not finish within {timeout} seconds"
    except OSError as exc:
        return None, "", f"could not be started: {exc.strerror or exc}"
    return done.returncode, done.stdout, done.stderr


def _kept(text: str) -> str:
    """What a command printed, trimmed to its end: the last lines of a helm error are the ones that say why."""
    text = text.strip()
    return text if len(text) <= STDERR_KEPT else "[...] " + text[-STDERR_KEPT:]


def _write_json(path: Path, doc: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


# -- render ----------------------------------------------------------------------------------------------------------


def render(charts: ChartList, out: Path, helm: str) -> int:
    code, stdout, stderr = _run([helm, "version", "--short"], 60)
    if code != 0:
        print(f"helm_benchmark: `{helm} version` did not run ({_one_line(stderr) or 'no output'}); nothing rendered")
        return 2
    helm_version = stdout.strip().splitlines()[0] if stdout.strip() else "unknown"
    for chart in charts.charts:
        home = out / chart.id
        if home.exists():
            shutil.rmtree(home)
        pulled = home / "pulled"
        pulled.mkdir(parents=True)
        if chart.repo.startswith("oci://"):
            pull = [helm, "pull", f"{chart.repo.rstrip('/')}/{chart.chart}", "--version", chart.version]
        else:
            pull = [helm, "pull", chart.chart, "--repo", chart.repo, "--version", chart.version]
        pull += ["--destination", str(pulled)]
        code, _, stderr = _run(pull, HELM_TIMEOUT)
        archives = sorted(pulled.glob("*.tgz"))
        record: dict[str, Any] = {
            "id": chart.id,
            "helmVersion": helm_version,
            "pull": {"command": _relative(pull, out), "exitCode": code, "stderr": _kept(stderr)},
            "template": [],
        }
        if code == 0 and len(archives) != 1:
            record["pull"]["exitCode"] = None
            record["pull"]["stderr"] = f"helm exited 0 and left {len(archives)} chart archives, not one"
            code = None
        status = "pull failed"
        if code == 0:
            attempts = [("defaults", ())] + ([("fallback", chart.fallback_set)] if chart.fallback_set else [])
            for label, sets in attempts:
                template = [helm, "template", charts.release, str(archives[0]), "--namespace", charts.namespace]
                template += ["--kube-version", charts.kube_version]
                for item in sets:
                    template += ["--set", item]
                code, stdout, stderr = _run(template, HELM_TIMEOUT)
                record["template"].append(
                    {
                        "values": label,
                        "set": list(sets),
                        "command": _relative(template, out),
                        "exitCode": code,
                        "stderr": _kept(stderr),
                    }
                )
                status = "render failed"
                if code == 0:
                    rendered = home / "rendered"
                    rendered.mkdir()
                    (rendered / "manifests.yaml").write_text(stdout, encoding="utf-8")
                    status = f"rendered ({label})"
                    break
        shutil.rmtree(pulled, ignore_errors=True)
        _write_json(home / "render.json", record)
        print(f"helm_benchmark: {chart.id} {chart.version}: {status}")
    return 0


def _relative(argv: list[str], out: Path) -> list[str]:
    """The command as recorded: paths under the output directory are written relative to it, so the record is
    the same on every machine."""
    prefix = str(out) + "/"
    return [a[len(prefix) :] if a.startswith(prefix) else a for a in argv]


# -- audit -----------------------------------------------------------------------------------------------------------


def count_objects(path: Path) -> int | None:
    """How many documents in the rendered file are Kubernetes objects; None when it is not YAML at all."""
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    try:
        with path.open(encoding="utf-8") as fh:
            docs = list(yaml.load_all(fh, Loader=loader))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return None
    return sum(1 for d in docs if isinstance(d, dict) and d.get("apiVersion") and d.get("kind"))


def audit(charts: ChartList, out: Path, kube_noob: list[str]) -> int:
    code, stdout, stderr = _run([*kube_noob, "--version"], 120)
    if code != 0:
        print(f"helm_benchmark: `{' '.join(kube_noob)} --version` did not run ({_one_line(stderr) or 'no output'})")
        return 2
    version = stdout.strip().removeprefix("kube-noob").strip() or "unknown"
    for chart in charts.charts:
        home = out / chart.id
        rendered = home / "rendered"
        manifests = rendered / "manifests.yaml"
        if not manifests.is_file():
            print(f"helm_benchmark: {chart.id}: nothing rendered to audit")
            continue
        tail = ["audit", "-f", str(rendered), "--platform", charts.platform, "--version", charts.platform_version]
        tail += ["--format", "json"]
        code, stdout, stderr = _run([*kube_noob, *tail], AUDIT_TIMEOUT)
        (home / "audit.json").write_text(stdout, encoding="utf-8")
        _write_json(
            home / "audit-meta.json",
            {
                "id": chart.id,
                "command": ["kube-noob", *_relative(tail, out)],
                "exitCode": code,
                "stderr": _kept(stderr),
                "kubeNoobVersion": version,
                "documents": count_objects(manifests),
            },
        )
        print(f"helm_benchmark: {chart.id}: kube-noob exit {code}")
    return 0


# -- report ----------------------------------------------------------------------------------------------------------


def _one_line(text: object, limit: int = 160) -> str:
    """One line of somebody else's output, safe inside a Markdown table cell and a workflow log.

    The last line that says something is kept (helm puts the cause there), control characters and anything that
    is Markdown or HTML structure are replaced, and it is cut to `limit`.
    """
    lines = [ln.strip() for ln in str(text or "").splitlines() if ln.strip()]
    if not lines:
        return ""
    line = next((ln for ln in lines if ln.lower().startswith("error")), lines[-1])
    line = re.sub(r"[^\x20-\x7e]", " ", line)
    line = re.sub(r"[|`<>\[\]*_~\\]", " ", line).replace("::", ": :")
    line = re.sub(r"\s+", " ", line).strip()
    return line if len(line) <= limit else line[: limit - 3].rstrip() + "..."


def _shape_ok(doc: Any) -> bool:
    """Is this the audit document, in the shape every field below is read from?"""
    if not isinstance(doc, dict):
        return False
    summary = doc.get("summary")
    if not isinstance(summary, dict) or not isinstance(summary.get("counts"), dict):
        return False
    for key, kind in (("findings", list), ("notAudited", list), ("notEvaluated", dict), ("unreadable", list)):
        if not isinstance(doc.get(key), kind):
            return False
    if not isinstance(doc.get("assumptions", []), list):
        return False
    for finding in doc["findings"]:
        if not isinstance(finding, dict) or not isinstance(finding.get("ruleId"), str):
            return False
        if finding.get("severity") not in SEVERITIES:
            return False
    return all(isinstance(n, dict) for n in doc["notAudited"])


def _values_used(chart: Chart, render_record: Any) -> str:
    attempts = render_record.get("template") if isinstance(render_record, dict) else None
    if not isinstance(attempts, list) or not attempts:
        return "none: no render" if isinstance(render_record, dict) else "not recorded"
    last = attempts[-1]
    if last.get("exitCode") != 0:
        return "none: no render exited 0"
    if last.get("values") == "fallback":
        return "fallback: " + " ".join(str(s) for s in last.get("set") or [])
    return "defaults"


def _chart_row(chart: Chart, out: Path) -> dict[str, Any]:
    home = out / chart.id
    render_record = _read_json(home / "render.json")
    meta = _read_json(home / "audit-meta.json")
    manifests = home / "rendered" / "manifests.yaml"
    row: dict[str, Any] = {
        "id": chart.id,
        "chart": chart.chart,
        "repo": chart.repo,
        "version": chart.version,
        "appVersion": chart.app_version,
        "category": chart.category,
        "versionSource": chart.version_source,
        "valuesUsed": _values_used(chart, render_record),
        "fallbackReason": chart.fallback_reason,
        "render": render_record if isinstance(render_record, dict) else None,
        "audit": None,
        "documents": None,
        "verdict": "",
        "detail": "",
        "score": None,
        "findings": None,
        "topRules": [],
        "ruleCounts": {},
        "notRead": None,
        "kubeNoobVersion": None,
    }
    if isinstance(render_record, dict):
        pull = render_record.get("pull") if isinstance(render_record.get("pull"), dict) else {}
        attempts = [a for a in render_record.get("template") or [] if isinstance(a, dict)]
        if pull.get("exitCode") != 0:
            row["verdict"] = "pull failed"
            row["detail"] = f"helm exit {_code(pull.get('exitCode'))}: {_one_line(pull.get('stderr'))}"
            return row
        if not attempts or attempts[-1].get("exitCode") != 0:
            row["verdict"] = "render failed"
            last = attempts[-1] if attempts else {}
            tried = " and with the fallback values" if len(attempts) > 1 else ""
            row["detail"] = (
                f"helm exit {_code(last.get('exitCode'))} with the defaults{tried}: {_one_line(last.get('stderr'))}"
            )
            return row
    if not manifests.is_file():
        row["verdict"] = "not rendered"
        row["detail"] = "no record of a render and no rendered file"
        return row
    if not isinstance(meta, dict):
        row["verdict"] = "audit did not answer"
        row["detail"] = "rendered, and there is no record of an audit"
        return row
    row["audit"] = {"command": meta.get("command"), "exitCode": meta.get("exitCode"), "stderr": meta.get("stderr")}
    row["documents"] = meta.get("documents")
    row["kubeNoobVersion"] = meta.get("kubeNoobVersion")
    if meta.get("documents") == 0:
        row["verdict"] = "rendered nothing"
        row["detail"] = (
            f"helm exited 0 and the output holds no Kubernetes object (kube-noob exit {_code(meta.get('exitCode'))})"
        )
        return row
    doc = _read_json(home / "audit.json")
    if meta.get("exitCode") not in (0, 1) or not _shape_ok(doc):
        row["verdict"] = "audit did not answer"
        said = _one_line(meta.get("stderr")) or "its output is not the audit document"
        row["detail"] = f"kube-noob exit {_code(meta.get('exitCode'))}: {said}"
        return row

    by_severity = Counter(f["severity"] for f in doc["findings"])
    by_rule = Counter(f["ruleId"] for f in doc["findings"])
    info: dict[str, dict[str, str]] = {}
    for f in doc["findings"]:
        info.setdefault(f["ruleId"], {"title": str(f.get("title") or ""), "severity": f["severity"]})
    rank = {s: n for n, s in enumerate(SEVERITIES)}
    ordered = sorted(by_rule, key=lambda r: (rank[info[r]["severity"]], -by_rule[r], r))
    row["findings"] = {"total": len(doc["findings"]), "bySeverity": {s: by_severity.get(s, 0) for s in SEVERITIES}}
    row["topRules"] = [{"ruleId": r, "count": by_rule[r], **info[r]} for r in ordered[:TOP_RULES]]
    row["ruleCounts"] = {r: {"count": by_rule[r], **info[r]} for r in sorted(by_rule)}
    score = doc["summary"].get("score")
    row["score"] = score if isinstance(score, (int, float)) and not isinstance(score, bool) else None

    not_audited = Counter(
        (str(n.get("kind") or "?"), str(n.get("apiGroup") or ""), str(n.get("why") or "")) for n in doc["notAudited"]
    )
    no_schema: Counter[tuple[str, str]] = Counter()
    other = 0
    for text in doc.get("assumptions", []):
        m = _NO_SCHEMA.match(str(text))
        if m:
            no_schema[m["api"], m["kind"]] += 1
        else:
            other += 1
    row["notRead"] = {
        "notAudited": [
            {"kind": kind, "apiGroup": group, "objects": n, "why": why}
            for (kind, group, why), n in sorted(not_audited.items())
        ],
        "noSchema": [{"apiVersion": api, "kind": kind, "objects": n} for (api, kind), n in sorted(no_schema.items())],
        "notEvaluated": len(doc["notEvaluated"]),
        "notEvaluatedRules": sorted(str(r) for r in doc["notEvaluated"]),
        "unreadable": len(doc["unreadable"]),
        "otherAssumptions": other,
    }
    if doc["summary"].get("verdict") == "undetermined":
        row["verdict"] = "undetermined"
        row["detail"] = _one_line(doc["summary"].get("verdictReason"), 200)
    elif doc["findings"]:
        row["verdict"] = "findings"
    else:
        row["verdict"] = "no findings in what was read"
    return row


def _code(code: object) -> str:
    return "none (it did not finish)" if code is None else str(code)


def build(charts: ChartList, out: Path, date: str | None) -> dict[str, Any]:
    rows = sorted((_chart_row(c, out) for c in charts.charts), key=lambda r: str(r["id"]))
    audited = [r for r in rows if r["findings"] is not None]

    rules: dict[str, dict[str, Any]] = {}
    for row in audited:
        for rule_id, entry in row["ruleCounts"].items():
            rule = rules.setdefault(
                rule_id,
                {"ruleId": rule_id, "title": entry["title"], "severity": entry["severity"], "perChart": {}},
            )
            rule["perChart"][row["id"]] = entry["count"]
    rule_rows = []
    for rule in rules.values():
        per = rule.pop("perChart")
        rule_rows.append(
            {
                **rule,
                "charts": len(per),
                "findings": sum(per.values()),
                "chartIds": sorted(per),
                "exampleChart": min(per, key=lambda c: (-per[c], c)),
            }
        )
    rule_rows.sort(key=lambda r: (-r["charts"], -r["findings"], r["ruleId"]))

    kinds: dict[tuple[str, str], dict[str, Any]] = {}
    for row in audited:
        for item in row["notRead"]["notAudited"]:
            kind = kinds.setdefault(
                (item["kind"], item["apiGroup"]),
                {"kind": item["kind"], "apiGroup": item["apiGroup"], "objects": 0, "chartIds": set()},
            )
            kind["objects"] += item["objects"]
            kind["chartIds"].add(row["id"])
    kind_rows = [
        {**k, "chartIds": sorted(k["chartIds"]), "charts": len(k["chartIds"])}
        for _, k in sorted(kinds.items(), key=lambda kv: (-len(kv[1]["chartIds"]), kv[0]))
    ]

    refused = {
        row["id"]: sorted(r for r in row["ruleCounts"] if r in RESTRICTED_V2_RULES)
        for row in audited
        if any(r in RESTRICTED_V2_RULES for r in row["ruleCounts"])
    }
    in_part = [
        row["id"]
        for row in audited
        if row["id"] not in refused and (row["notRead"]["notAudited"] or row["notRead"]["unreadable"])
    ]
    for row in rows:
        del row["ruleCounts"]
    return {
        "benchmark": "helm-charts-openshift",
        "date": date,
        "platform": charts.platform,
        "platformVersion": charts.platform_version,
        "kubeVersion": charts.kube_version,
        "kubeNoobVersions": sorted({str(r["kubeNoobVersion"]) for r in rows if r["kubeNoobVersion"]}),
        "helmVersions": sorted(
            {str(r["render"]["helmVersion"]) for r in rows if r["render"] and r["render"].get("helmVersion")}
        ),
        "totals": {
            "charts": len(rows),
            "audited": len(audited),
            "byVerdict": dict(sorted(Counter(str(r["verdict"]) for r in rows).items())),
        },
        "charts": rows,
        "rules": rule_rows,
        "notAuditedKinds": kind_rows,
        "restrictedV2": {
            "rules": sorted(RESTRICTED_V2_RULES),
            "audited": len(audited),
            "chartIds": sorted(refused),
            "byChart": dict(sorted(refused.items())),
            "byRule": {r: sum(1 for hit in refused.values() if r in hit) for r in sorted(RESTRICTED_V2_RULES)},
            "readInPart": sorted(in_part),
            "notDetermined": sorted(r["id"] for r in rows if r["findings"] is None),
        },
    }


def _not_read_cell(row: dict[str, Any]) -> str:
    not_read = row["notRead"]
    if not_read is None:
        return "everything: " + (row["detail"] or row["verdict"])
    parts = []
    for item in not_read["notAudited"]:
        group = f" ({item['apiGroup']})" if item["apiGroup"] else ""
        parts.append(f"{item['objects']} {_one_line(item['kind'] + group)} not audited")
    if not_read["noSchema"]:
        names = ", ".join(f"{_one_line(k['kind'])} x{k['objects']}" for k in not_read["noSchema"][:6])
        more = len(not_read["noSchema"]) - 6
        parts.append("no schema for " + names + (f" and {more} more kinds" if more > 0 else ""))
    if not_read["unreadable"]:
        parts.append(f"{not_read['unreadable']} files unreadable")
    parts.append(f"{not_read['notEvaluated']} rules not evaluated")
    return "; ".join(parts)


def _severity_cell(row: dict[str, Any]) -> str:
    if row["findings"] is None:
        return "not counted"
    by = row["findings"]["bySeverity"]
    return " / ".join(str(by[s]) for s in SEVERITIES)


def markdown(data: dict[str, Any]) -> str:
    rows: list[dict[str, Any]] = data["charts"]
    totals = data["totals"]
    audited = totals["audited"]
    versions = ", ".join(f"kube-noob {v}" for v in data["kubeNoobVersions"]) or "kube-noob version not recorded"
    helm = ", ".join(data["helmVersions"]) or "not recorded"
    when = f"Run on {data['date']}" if data["date"] else "Run on a date not recorded"
    audit_command = (
        f"kube-noob audit -f <rendered chart> --platform {data['platform']} "
        f"--version {data['platformVersion']} --format json"
    )
    out: list[str] = []
    add = out.append
    add(f"# {totals['charts']} public Helm charts, audited for OpenShift {data['platformVersion']}")
    add("")
    add(
        "<!-- Generated by scripts/helm_benchmark.py from bench/charts.yaml. Do not edit: run it again. The numbers "
        "are in the JSON file beside this one. -->"
    )
    add("")
    add(
        f"{when} with {versions} and helm {helm}. Each chart was rendered at the pinned version below with its "
        f"default values (`helm template --kube-version {data['kubeVersion']}`) and the output was audited with "
        f"`{audit_command}`."
    )
    add("")
    add(
        f"**{audited} of {totals['charts']} charts were audited.** A chart that could not be pulled, did not "
        "render, or rendered no object is a row below that says so; it is not counted in any share on this page, "
        "and it is not a chart with no findings."
    )
    add("")
    add("| Outcome | Charts |")
    add("|---|---|")
    for verdict in VERDICTS:
        if totals["byVerdict"].get(verdict):
            add(f"| {verdict} | {totals['byVerdict'][verdict]} |")
    add("")

    add("## What fails most")
    add("")
    if not data["rules"]:
        add("not measured: no audited chart has a finding" if audited else "not measured: no chart was audited.")
    else:
        add(
            f"Every rule with a finding in at least one chart, by the number of charts it found something in, out "
            f"of the {audited} audited. The example is the chart with the most findings of that rule."
        )
        add("")
        add("| Rule | What it is | Severity | Charts | Findings | Example chart |")
        add("|---|---|---|---|---|---|")
        for rule in data["rules"]:
            add(
                f"| {rule['ruleId']} | {_one_line(rule['title'])} | {rule['severity']} | "
                f"{rule['charts']} of {audited} | {rule['findings']} | {rule['exampleChart']} |"
            )
    add("")

    scc = data["restrictedV2"]
    add("## Would the restricted-v2 SCC admit it")
    add("")
    listed = ", ".join(f"{r} ({RESTRICTED_V2_RULES[r]})" for r in scc["rules"])
    if not audited:
        add("not measured: no chart was audited.")
    else:
        add(
            f"**At least {len(scc['chartIds'])} of the {audited} charts audited** "
            f"({round(100 * len(scc['chartIds']) / audited)}%) render a pod that OpenShift's default "
            "`restricted-v2` SecurityContextConstraints does not admit as written. That is read from these "
            f"rules, each of which reports a pod shape restricted-v2 refuses: {listed}."
        )
        add("")
        add(
            "It is at least that many, and it is a reading of manifests, not an admission result. A chart may "
            "ship or document a grant of a broader SCC to its ServiceAccount, in which case the pod is admitted "
            "under that SCC; KN-S004 reports a fixed UID or fsGroup, which is refused unless the namespace's "
            "range contains it, and OpenShift allocates those ranges from 1000000000 upwards by default. Rules "
            "that fire on a field restricted-v2 fills in for the pod (KN-S002, KN-S006, KN-S008) are not counted."
        )
        add("")
        if scc["chartIds"]:
            add("| Rule | What it reports | Charts |")
            add("|---|---|---|")
            for rule_id in scc["rules"]:
                add(f"| {rule_id} | {RESTRICTED_V2_RULES[rule_id]} | {scc['byRule'][rule_id]} of {audited} |")
            add("")
            add("| Chart | Rules |")
            add("|---|---|")
            for chart_id in scc["chartIds"]:
                add(f"| {chart_id} | {', '.join(scc['byChart'][chart_id])} |")
            add("")
        if scc["readInPart"]:
            add(
                "Not counted as refused, and not known to be admitted, because pods in them were not read: "
                + ", ".join(scc["readInPart"])
                + "."
            )
            add("")
    if scc["notDetermined"]:
        add("Not determined, because there is no audit to read: " + ", ".join(scc["notDetermined"]) + ".")
        add("")

    add("## Every chart")
    add("")
    add(
        "Exit is `kube-noob audit`'s exit code (1: a finding at high or above, or an undetermined verdict). Score "
        "is kube-noob's own, out of 100, and it gives none to an audit it calls undetermined. Findings are "
        f"{' / '.join(SEVERITIES)}."
    )
    add("")
    add("| Chart | Verdict | Exit | Score | Findings | Top rules | What was not read |")
    add("|---|---|---|---|---|---|---|")
    for row in rows:
        exit_code = _code(row["audit"]["exitCode"]) if row["audit"] else "not run"
        if row["audit"] and row["audit"]["exitCode"] is None:
            exit_code = "none"
        score = "none" if row["score"] is None else f"{row['score']:g}"
        top = ", ".join(f"{r['ruleId']} x{r['count']}" for r in row["topRules"]) or "none"
        verdict = row["verdict"]
        if row["notRead"] is not None and row["detail"]:
            verdict += f": {row['detail']}"
        if row["valuesUsed"].startswith("fallback"):
            verdict += " (rendered with fallback values)"
        add(
            f"| {row['id']} | {verdict} | {exit_code} | {score} | {_severity_cell(row)} | {top} | "
            f"{_not_read_cell(row)} |"
        )
    add("")

    if data["notAuditedKinds"]:
        add("## Kinds that were not audited")
        add("")
        add(
            "A kind kube-noob has no reader for is named, and the chart that ships it is undetermined, never "
            "counted as having nothing wrong."
        )
        add("")
        add("| Kind | API group | Objects | Charts |")
        add("|---|---|---|---|")
        for kind in data["notAuditedKinds"]:
            add(
                f"| {_one_line(kind['kind'])} | {_one_line(kind['apiGroup']) or 'core'} | {kind['objects']} | "
                f"{', '.join(kind['chartIds'])} |"
            )
        add("")

    add("## The charts and their versions")
    add("")
    add("| Chart | Name in the repository | Version | App version | Category | Repository | Values |")
    add("|---|---|---|---|---|---|---|")
    for row in rows:
        add(
            f"| {row['id']} | `{row['chart']}` | {row['version']} | {row['appVersion'] or 'not stated'} | "
            f"{row['category']} | {row['repo']} | {_one_line(row['valuesUsed'])} |"
        )
    add("")
    fallbacks = [r for r in rows if r["valuesUsed"].startswith("fallback")]
    if fallbacks:
        add("Charts that did not render with their defaults, and why the values above were used instead:")
        add("")
        for row in fallbacks:
            add(f"- {row['id']}: {_one_line(row['fallbackReason'], 300)}")
        add("")

    add("## How to reproduce")
    add("")
    add(
        "In GitHub Actions, from this repository (the run uploads this page and its data as an artifact; with "
        "`open_pr=true` it also opens a pull request with them):"
    )
    add("")
    add("```bash")
    add("gh workflow run helm-benchmark.yml --repo kube-noob/kube-noob")
    add("```")
    add("")
    add(
        "Or on a machine with helm and network access to the chart repositories, from a checkout at the commit "
        f"of {versions}:"
    )
    add("")
    add("```bash")
    add("pip install -e .")
    add("python scripts/helm_benchmark.py render")
    add("python scripts/helm_benchmark.py audit")
    add('python scripts/helm_benchmark.py report --date "$(date -u +%F)"')
    add("```")
    add("")
    add(
        "`out/helm-benchmark/<chart>/` then holds what helm printed (`render.json`), the rendered manifests, and "
        "the audit JSON each row above was read from."
    )
    add("")

    add("## What this does not show")
    add("")
    add(
        "- **Default values only.** Each chart was rendered with its default values, or with the few values "
        "named above where it does not render without them. Most charts have values that harden them, and many "
        "document OpenShift-specific ones. This page measures what a first `helm install` asks the cluster for, "
        "not what the chart can be configured to."
    )
    add(
        "- **Rendered, not deployed.** Nothing was installed. `helm template` ran with no cluster, so a chart "
        "that changes shape when it detects OpenShift's APIs was rendered in its generic shape, objects from a "
        "chart's `crds/` directory are not in the output, and what an operator creates after it starts was never "
        "seen. Whether a pod is admitted is decided by the cluster, with the SCCs and namespace it actually has."
    )
    add(
        "- **A finding is not a vulnerability report about the project.** A finding says that a rendered manifest "
        "has a property a rule looks for. Some are deliberate: a node agent mounts host paths, an ingress "
        "controller binds host ports. None of this was reported to, or reviewed by, the projects named, and "
        "none of it says a chart is unsafe to run."
    )
    add(
        "- **What was not read is not known.** The last column of the per-chart table lists the kinds kube-noob "
        "has no reader or schema for and the number of rules that had nothing to evaluate. A chart with few "
        "findings and much unread is not a better chart than one read in full."
    )
    add(
        "- **One version, one day.** The versions are pinned in `bench/charts.yaml`. A later release of a chart, "
        "or of kube-noob, gives different numbers."
    )
    add("")
    return "\n".join(out)


def report(charts: ChartList, out: Path, md_path: Path, data_path: Path, date: str | None) -> dict[str, Any]:
    data = build(charts, out, date)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(markdown(data), encoding="utf-8")
    _write_json(data_path, data)
    return data


# -- entry point -----------------------------------------------------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    sub = parser.add_subparsers(dest="mode", required=True)
    for mode, text in (
        ("render", "helm pull and helm template every chart (needs helm and the network)"),
        ("audit", "kube-noob audit every chart that rendered"),
        ("report", "write the Markdown report and its JSON data"),
    ):
        p = sub.add_parser(mode, help=text)
        p.add_argument(
            "--charts", type=Path, default=DEFAULT_CHARTS, help="the chart list (default: bench/charts.yaml)"
        )
        p.add_argument("--out", type=Path, default=DEFAULT_OUT, help="the working directory the three modes share")
        if mode == "render":
            p.add_argument("--helm", default="helm", help="the helm binary")
        if mode == "audit":
            p.add_argument(
                "--kube-noob",
                default=None,
                help="the kube-noob command (default: this Python's `-m kube_noob`, so the checkout's own code)",
            )
        if mode == "report":
            p.add_argument("--report", type=Path, default=DEFAULT_REPORT)
            p.add_argument("--data", type=Path, default=DEFAULT_DATA)
            p.add_argument("--date", default=None, help="the date of the run, YYYY-MM-DD; never read from the clock")
            p.add_argument("--min-audited", type=int, default=0, help="exit 1 when fewer charts than this were audited")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        charts = load_charts(args.charts)
    except ChartListError as exc:
        print(f"helm_benchmark: {exc}", file=sys.stderr)
        return 2
    out = args.out.resolve()
    if args.mode == "render":
        return render(charts, out, args.helm)
    if args.mode == "audit":
        command = args.kube_noob.split() if args.kube_noob else [sys.executable, "-m", "kube_noob"]
        return audit(charts, out, command)
    if args.date is not None and not re.match(r"\d{4}-\d{2}-\d{2}\Z", args.date):
        print(f"helm_benchmark: --date {args.date!r} is not YYYY-MM-DD", file=sys.stderr)
        return 2
    data = report(charts, out, args.report, args.data, args.date)
    totals = data["totals"]
    print(f"helm_benchmark: {totals['audited']} of {totals['charts']} charts audited; report at {args.report}")
    if totals["audited"] < args.min_audited:
        print(
            f"helm_benchmark: fewer than {args.min_audited} charts were audited, so this is not a benchmark result",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
