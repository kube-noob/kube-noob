"""Helm chart generation and Helm chart linting/auditing.

``generate_chart`` turns a Blueprint into a Helm v3-compatible chart (apiVersion: v2): the generator's audited
manifests become templates whose tunables (image, replicas, resources, host) come from values.yaml, with a
values.schema.json so `helm install` rejects bad values before rendering.

``lint_chart_metadata`` checks a chart's files against the Helm advisories and best practices. Rendering a chart with
the `helm` binary and auditing the output lives in ``kube_noob.generate.helm_render`` (the CLI's helm-audit and the
gate; the Claude plugin never starts another program).
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import yaml

from kube_noob.errors import KubeNoobError
from kube_noob.generate.blueprint import Blueprint
from kube_noob.generate.manifests import generate
from kube_noob.yamlio import TerminalSafeDumper, dump_documents

_SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?\Z")
_SCALAR = "__KN_S__"
_INT = "__KN_I__"
_BLOCK = "__KN_B__"


def _split_image(image: str) -> tuple[str, str]:
    if "@" in image:
        repo, digest = image.split("@", 1)
        return repo, "@" + digest
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        repo, tag = image.rsplit(":", 1)
        return repo, tag
    return image, ""


def _templatize(obj: dict[str, Any], name: str) -> dict[str, Any]:
    o = copy.deepcopy(obj)
    o.get("metadata", {}).pop("namespace", None)
    kind = o["kind"]
    if kind in {"Deployment", "StatefulSet"}:
        o["spec"]["replicas"] = f"{_INT}replicaCount"
        c = o["spec"]["template"]["spec"]["containers"][0]
        c["image"] = f"{_SCALAR}image"
        c["imagePullPolicy"] = f"{_SCALAR}pullPolicy"
        c["resources"] = f"{_BLOCK}resources"
        o["spec"]["template"].setdefault("metadata", {}).setdefault("annotations", {})
    if kind == "Route" and "host" in o["spec"]:
        o["spec"]["host"] = f"{_SCALAR}host"
    if kind == "Ingress":
        o["spec"]["rules"][0]["host"] = f"{_SCALAR}host"
        o["spec"]["tls"][0]["hosts"] = [f"{_SCALAR}host"]
    if kind == "PodDisruptionBudget":
        return {"__kn_if__": "podDisruptionBudget.enabled", "obj": o}
    if kind == "HorizontalPodAutoscaler":
        o["spec"]["maxReplicas"] = f"{_INT}autoscaling.maxReplicas"
        return {"__kn_if__": "autoscaling.enabled", "obj": o}
    if kind == "NetworkPolicy":
        return {"__kn_if__": "networkPolicy.enabled", "obj": o}
    return o


_REPLACEMENTS = {
    f"{_SCALAR}image": '"{{ .Values.image.repository }}{{ if hasPrefix "@" .Values.image.tag }}{{ .Values.image.tag }}'
    '{{ else }}:{{ .Values.image.tag | default .Chart.AppVersion }}{{ end }}"',
    f"{_SCALAR}pullPolicy": "{{ .Values.image.pullPolicy }}",
    f"{_SCALAR}host": "{{ .Values.host | quote }}",
    f"{_INT}replicaCount": "{{ .Values.replicaCount }}",
    f"{_INT}autoscaling.maxReplicas": "{{ .Values.autoscaling.maxReplicas }}",
}


def _render_template(entry: dict[str, Any]) -> str:
    cond = None
    obj = entry
    if "__kn_if__" in entry:
        cond, obj = entry["__kn_if__"], entry["obj"]
    # TerminalSafeDumper: a value from the blueprint (an env value) reaches the chart files a CI step may print;
    # a string that would carry a workflow command or a character that does not print is escaped (G279).
    text = str(yaml.dump(obj, Dumper=TerminalSafeDumper, sort_keys=False, default_flow_style=False, width=1000))
    for k, v in _REPLACEMENTS.items():
        text = text.replace(f"'{k}'", v).replace(k, v)
    out_lines = []
    for line in text.splitlines():
        m = re.match(rf"^(\s*)(\w+): {_BLOCK}(\w+)$", line)
        reps = re.match(r"^(\s*)replicas: \{\{ \.Values\.replicaCount \}\}$", line)
        if m:
            indent, key, val = m.groups()
            out_lines.append(f"{indent}{key}:")
            out_lines.append(f"{indent}  {{{{- toYaml .Values.{val} | nindent {len(indent) + 2} }}}}")
        elif reps:
            # the HPA owns the replica count when autoscaling is on (KN-C014; the `helm create` scaffold does the same)
            indent = reps.group(1)
            out_lines += [f"{indent}{{{{- if not .Values.autoscaling.enabled }}}}", line, f"{indent}{{{{- end }}}}"]
        else:
            out_lines.append(line)
    body = "\n".join(out_lines) + "\n"
    if cond:
        body = f"{{{{- if .Values.{cond} }}}}\n{body}{{{{- end }}}}\n"
    return body


def generate_chart(bp: Blueprint, out_dir: str | Path, chart_version: str = "0.1.0") -> dict[str, Any]:
    if not _SEMVER.match(chart_version):
        raise KubeNoobError(f"chart version {chart_version!r} must be SemVer 2 (e.g. 0.1.0)")
    gen = generate(bp)
    repo, tag = _split_image(bp.image)
    if not tag:
        tag = "latest"  # an untagged reference means :latest; keep that explicit (and audited) instead of 0.0.0
    app_version = tag.lstrip(":") if not tag.startswith("@") else "0.0.0"
    out = Path(out_dir) / bp.name
    if out.exists() and any(out.iterdir()):
        raise KubeNoobError(f"{out} already exists and is not empty; choose another output directory")
    (out / "templates").mkdir(parents=True, exist_ok=True)

    chart = {
        "apiVersion": "v2",
        "name": bp.name,
        "description": f"{bp.name} - generated and audited by kube-noob for {bp.platform}",
        "type": "application",
        "version": chart_version,
        "appVersion": str(app_version),
        "kubeVersion": ">=1.25.0-0",
        "annotations": {"kube-noob.io/platform": bp.platform},
    }
    values = {
        "image": {
            "repository": repo,
            "tag": tag if tag.startswith("@") else tag.lstrip(":"),
            "pullPolicy": "IfNotPresent",
        },
        "replicaCount": bp.replicas,
        "resources": next(o for o in gen.objects if o["kind"] in {"Deployment", "StatefulSet"})["spec"]["template"][
            "spec"
        ]["containers"][0]["resources"],
        "host": bp.exposure.host or "",
        "podDisruptionBudget": {"enabled": bp.replicas >= 2},
        "autoscaling": {"enabled": bool(bp.hpa_max_replicas), "maxReplicas": bp.hpa_max_replicas or bp.replicas},
        "networkPolicy": {"enabled": True},
    }
    schema = {
        "$schema": "https://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["image", "replicaCount", "resources"],
        "properties": {
            "image": {
                "type": "object",
                "required": ["repository"],
                "additionalProperties": False,
                "properties": {
                    "repository": {"type": "string", "minLength": 1},
                    "tag": {"type": "string"},
                    "pullPolicy": {"enum": ["IfNotPresent", "Always", "Never"]},
                },
            },
            "replicaCount": {"type": "integer", "minimum": 1},
            "resources": {"type": "object"},
            "host": {"type": "string"},
            "podDisruptionBudget": {"type": "object", "properties": {"enabled": {"type": "boolean"}}},
            "autoscaling": {
                "type": "object",
                "properties": {"enabled": {"type": "boolean"}, "maxReplicas": {"type": "integer", "minimum": 1}},
            },
            "networkPolicy": {"type": "object", "properties": {"enabled": {"type": "boolean"}}},
        },
        "additionalProperties": False,
    }
    files: dict[str, str] = {
        "Chart.yaml": str(yaml.dump(chart, Dumper=TerminalSafeDumper, sort_keys=False)),
        "values.yaml": "# Values for "
        + bp.name
        + " (generated by kube-noob; audited before export)\n"
        + str(yaml.dump(values, Dumper=TerminalSafeDumper, sort_keys=False)),
        "values.schema.json": json.dumps(schema, indent=2) + "\n",
        ".helmignore": ".git/\n*.swp\n*.bak\n*.tmp\n.DS_Store\n",
        "templates/NOTES.txt": (
            f"{bp.name} deployed to {{{{ .Release.Namespace }}}}.\n"
            "Verify: kubectl rollout status deploy/" + bp.name + " -n {{ .Release.Namespace }}\n"
        ),
    }
    counts: dict[str, int] = {}
    for o in gen.objects:
        if o["kind"] == "Namespace":
            continue
        kind = o["kind"].lower()
        counts[kind] = counts.get(kind, 0) + 1
        suffix = "" if counts[kind] == 1 else f"-{counts[kind]}"
        files[f"templates/{kind}{suffix}.yaml"] = _render_template(_templatize(o, bp.name))
    for rel, content in files.items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return {
        "chartDir": str(out),
        "files": sorted(files),
        "assumptions": gen.assumptions,
        "prerequisites": gen.prerequisites,
        "renderedManifests": dump_documents([o for o in gen.objects if o["kind"] != "Namespace"]),
    }


_LOCK_FILES = ("Chart.lock", "requirements.lock")
# A chart name that is a path: a separator, or '.'/'..' (CVE-2024-25620, CVE-2026-35206).
_PATH_NAME = re.compile(r"[/\\]|^\.{1,2}\Z")
MAX_SCHEMA_BYTES = 10 * 1024 * 1024  # the size CVE-2025-32387's advisory gives for the crafted schemas
MAX_TEMPLATE_BYTES = 2 * 1024 * 1024
_TEMPLATE_SUFFIXES = (".yaml", ".yml", ".tpl", ".txt", ".json")
_GET_HOST = re.compile(r"\bgetHostByName\b")
_LOOKUP = re.compile(r"\{\{-?[^}]*\blookup\b")
_CRD = re.compile(r"(?m)^kind:\s*[\"']?CustomResourceDefinition[\"']?\s*$")
_KEEP = re.compile(r"helm\.sh/resource-policy[\"']?\s*:\s*[\"']?keep")


def _src(source_id: str) -> str:
    from kube_noob.catalog import SOURCES

    return SOURCES[source_id].url


def _chart_names(chart: Path, meta: dict[str, Any]) -> list[tuple[str, str]]:
    """(where, name) for the chart, its declared dependencies (name and alias) and the subcharts in charts/."""
    out = [("Chart.yaml name", str(meta.get("name") or ""))]
    for dep in meta.get("dependencies") or []:
        if isinstance(dep, dict):
            out += [(f"Chart.yaml dependency {key}", str(dep[key])) for key in ("name", "alias") if dep.get(key)]
    charts = chart / "charts"
    for sub in sorted(charts.glob("*/Chart.yaml")) if charts.is_dir() else []:
        try:
            sub_meta = yaml.safe_load(sub.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            continue
        if isinstance(sub_meta, dict):
            out.append((f"{sub.relative_to(chart)} name", str(sub_meta.get("name") or "")))
    return out


def _template_issues(chart: Path) -> list[str]:
    issues: list[str] = []
    templates = chart / "templates"
    files = sorted(p for p in templates.rglob("*") if p.is_file()) if templates.is_dir() else []
    for p in files:
        if p.suffix not in _TEMPLATE_SUFFIXES or p.stat().st_size > MAX_TEMPLATE_BYTES:
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        rel = p.relative_to(chart)
        if _GET_HOST.search(text):
            issues.append(
                f"{rel} calls getHostByName, which sends the name to DNS servers while the chart renders "
                "(CVE-2023-25165, Helm before 3.11.1; later releases resolve only with --enable-dns). Pass the "
                f"address in values instead. Source: {_src('ghsa-cve-2023-25165')}"
            )
        if _LOOKUP.search(text):
            issues.append(
                f"{rel} calls lookup, which always returns an empty result under helm template: helm-audit audited "
                "a render without the cluster objects lookup reads at install, so review the branches that depend "
                f"on them. Source: {_src('helm-function-list')}"
            )
        if _CRD.search(text) and not _KEEP.search(text):
            issues.append(
                f"{rel} defines a CustomResourceDefinition in templates/: it is deleted with the release, and every "
                "custom resource of that kind with it. Put CRDs in crds/ (Helm installs them first and never "
                f"upgrades or deletes them) or in a separate chart. Source: {_src('helm-crds')}"
            )
    return issues


def lint_chart_metadata(chart_dir: str | Path) -> list[str]:
    """Static checks that need no helm binary."""
    issues: list[str] = []
    chart = Path(chart_dir)
    cy = chart / "Chart.yaml"
    if not cy.is_file():
        return [f"{chart}: missing Chart.yaml"]
    meta = yaml.safe_load(cy.read_text(encoding="utf-8")) or {}
    if not isinstance(meta, dict):
        return ["Chart.yaml is not a mapping."]
    for lock in _LOCK_FILES:
        if (chart / lock).is_symlink():
            issues.append(
                f"{lock} is a symlink: CVE-2025-53547 (Helm before 3.17.4 and 3.18.4) writes the lock file through "
                "the link on `helm dependency update`, so Chart.yaml content lands in the linked file (a shell rc "
                "file or a script: local code execution). Make it a regular file. Source: "
                + _src("ghsa-cve-2025-53547")
            )
    for where, name in _chart_names(chart, meta):
        if _PATH_NAME.search(name):
            issues.append(
                f"{where} {name!r} is a path ('/', '\\', '.' or '..'): CVE-2024-25620 (Helm before 3.14.1) saved such "
                "a chart outside its directory, and CVE-2026-35206 (Helm before 3.20.2 and 4.1.4) made helm pull "
                f"--untar write into the output directory itself. Use a plain chart name. Source: "
                f"{_src('ghsa-cve-2024-25620')} {_src('ghsa-cve-2026-35206')}"
            )
    for dep in meta.get("dependencies") or []:
        repo = str(dep.get("repository") or "") if isinstance(dep, dict) else ""
        if repo.lower().startswith("http://"):
            issues.append(
                f"Chart.yaml dependency {dep.get('name')!r} comes from {repo}: over plain HTTP anyone on the path can "
                f"swap the chart; use an https:// repository. Source: {_src('helm-dependencies')}"
            )
    schema = chart / "values.schema.json"
    if schema.is_file() and schema.stat().st_size > MAX_SCHEMA_BYTES:
        issues.append(
            f"values.schema.json is {schema.stat().st_size // (1024 * 1024)} MiB: CVE-2025-32387 (Helm before 3.17.3) "
            "overflowed its stack on schemas with a deeply nested chain of references, which the advisory says are "
            f"larger than 10 MiB. Keep the schema small. Source: {_src('ghsa-cve-2025-32387')}"
        )
    issues += _template_issues(chart)
    if meta.get("apiVersion") != "v2":
        issues.append("Chart.yaml apiVersion should be v2 (Helm 3+).")
    if not meta.get("name"):
        issues.append("Chart.yaml is missing name.")
    if not _SEMVER.match(str(meta.get("version", ""))):
        issues.append(f"Chart.yaml version {meta.get('version')!r} is not SemVer 2.")
    if "appVersion" in meta and not isinstance(meta["appVersion"], str):
        issues.append('Chart.yaml appVersion should be a quoted string (e.g. "1.10" not 1.1).')
    values = chart / "values.yaml"
    if values.is_file():
        v = yaml.safe_load(values.read_text(encoding="utf-8")) or {}
        tag = (v.get("image") or {}).get("tag") if isinstance(v, dict) else None
        if tag in ("latest",):
            issues.append("values.yaml image.tag is 'latest'; pin a version or digest.")
    if not (chart / "values.schema.json").is_file():
        issues.append("No values.schema.json; add one so invalid values fail at install time.")
    return issues
