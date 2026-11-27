"""Offline JSON-schema validation against vendored, strict Kubernetes + CRD schemas.

Kubernetes core schemas are the upstream OpenAPI definitions (via yannh/kubernetes-json-schema) made strict, so
misspelled fields fail validation the way ``kubectl apply --validate=strict`` would. CRD schemas (OpenShift, OVN-K,
StackRox, Gateway API) live in ``data/crds``. See ``data/PROVENANCE.json``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Any

from jsonschema import Draft7Validator
from jsonschema.exceptions import ValidationError

from kube_noob import sanitize
from kube_noob.audit.model import Finding, Severity, Stage
from kube_noob.audit.podspec import pod_templates
from kube_noob.yamlio import Document, PathT, fmt_path

SCHEMA_K8S_VERSION = "v1.35.0"
MAX_ERRORS_PER_DOC = 20


@dataclass(frozen=True)
class SchemaIndex:
    definitions: dict[str, Any]
    by_gvk: dict[tuple[str, str, str], str]
    crds: dict[tuple[str, str, str], dict[str, Any]]


def _data_dir() -> Any:
    return resources.files("kube_noob.schemas").joinpath("data")


@cache
def schema_index() -> SchemaIndex:
    data = _data_dir()
    prefix = f"kubernetes-{SCHEMA_K8S_VERSION}-definitions-"
    parts = sorted(
        (f for f in data.iterdir() if f.name.startswith(prefix) and f.name.endswith(".json")), key=lambda f: f.name
    )
    if not parts:
        raise FileNotFoundError(f"no {prefix}*.json schema files in kube_noob.schemas data")
    defs: dict[str, Any] = {}
    for part in parts:
        defs.update(json.loads(part.read_text(encoding="utf-8"))["definitions"])
    by_gvk: dict[tuple[str, str, str], str] = {}
    for name, d in defs.items():
        for gvk in d.get("x-kubernetes-group-version-kind") or []:
            by_gvk[(gvk.get("group", ""), gvk["version"], gvk["kind"])] = name
    crds: dict[tuple[str, str, str], dict[str, Any]] = {}
    crd_dir = data.joinpath("crds")
    if crd_dir.is_dir():
        for f in crd_dir.iterdir():
            if f.name.endswith(".json"):
                group, version, kind = f.name[: -len(".json")].split("_", 2)
                crds[(group, version, kind)] = json.loads(f.read_text(encoding="utf-8"))
    return SchemaIndex(defs, by_gvk, crds)


@cache
def _validator_for(group: str, version: str, kind: str) -> Draft7Validator | None:
    idx = schema_index()
    if (group, version, kind) in idx.crds:
        return Draft7Validator(idx.crds[(group, version, kind)])
    name = idx.by_gvk.get((group, version, kind))
    if name is None:
        return None
    schema = {"definitions": idx.definitions, "$ref": f"#/definitions/{name}"}
    return Draft7Validator(schema)


def _drop_nulls(node: Any) -> Any:
    """kubectl drops explicit nulls before sending; mirror it so 'annotations:' (null) is not a false positive."""
    if isinstance(node, dict):
        return {k: _drop_nulls(v) for k, v in node.items() if v is not None}
    if isinstance(node, list):
        return [_drop_nulls(v) for v in node]
    return node


def _message(err: ValidationError) -> str:
    if err.validator == "additionalProperties":
        return f"unknown field: {err.message.split('(')[-1].rstrip(')')}" if "(" in err.message else err.message
    if err.validator == "oneOf":
        return f"value {err.instance!r} has the wrong type"
    return str(err.message)


def _no_regular_container(d: Document, key_reported: set[PathT]) -> list[Finding]:
    """KN-V007 for each pod spec of ``d`` that has zero regular containers (G431).

    The API server refuses a pod without one (`spec.containers: Required value`), and init and ephemeral
    containers do not count toward it. The upstream OpenAPI schema states only that the KEY is required, so
    `containers: []` validated, every container rule then iterated nothing, and the object was recorded read and
    clean -- with or without init containers beside it, and the mechanism walks held "the containers declare a
    readiness probe" over none. It is reported here, where the missing key already is, because it is the same
    refusal: a validation finding of category `schema`, which is what stops a walk from holding a hop on the
    object (G406), and not a rule a caller can leave out with `--stages`.

    Every pod spec `pod_templates` reads that is a PodSpec proper (its path ends in `spec`): the ten core kinds
    and KubeRay's templates. A KServe component is a different schema whose `containers` list is optional (a
    predictor is written as `model:`), so it is not judged. A kind with no bundled schema that requires the key
    (DeploymentConfig, RayCluster) gets the finding for an absent key too; where the schema already reported the
    key (``key_reported``) nothing is added, so one fact is one finding. A value that is neither absent nor a
    list is the schema's, or `object_unreadable`'s, to report.
    """
    # Imported here: `rules` is a 260 KiB module the schema index does not otherwise need, and the engine has
    # always loaded it by the time a document is validated.
    from kube_noob.audit.rules import refusal

    if refusal(d) is not None:
        return []  # not this reader's object; KN-V002 and `notAudited` already answer for it
    out: list[Finding] = []
    for pt in pod_templates(d):
        if pt.path[-1] != "spec":
            continue
        value = pt.spec.get("containers")
        if value is None:
            if pt.path in key_reported:
                continue
            state, path = "is not set", pt.path
        elif isinstance(value, list) and not value:
            state, path = "is empty", (*pt.path, "containers")
        else:
            continue
        out.append(
            Finding(
                rule_id="KN-V007",
                title="Schema validation error",
                severity=Severity.HIGH,
                stage=Stage.VALIDATE,
                category="schema",
                resource=d.ref(),
                message=f"no regular container: `containers` {state}, and the API server refuses a pod without "
                "one (spec.containers: Required value). Init and ephemeral containers do not count toward it.",
                remediation="Add at least one container under `containers`; an init or ephemeral container "
                "cannot stand in for it.",
                path=fmt_path(path),
                line=d.line_for(path),
                doc_index=d.index,
            )
        )
    return out


def validate_documents(docs: list[Document]) -> tuple[list[Finding], list[str]]:
    """Return schema findings and notes about kinds that could not be schema-checked."""
    findings: list[Finding] = []
    notes: list[str] = []
    for d in docs:
        if not isinstance(d.data, dict) or not d.kind or not d.api_version:
            continue
        group, _, version = d.api_version.rpartition("/")
        validator = _validator_for(group, version, d.kind)
        if validator is None:
            findings.extend(_no_regular_container(d, set()))
            # Input text on one line: a newline in a name forged a second note row in the text view (review 5).
            what = sanitize.one_line(f"{d.api_version} {d.kind} ({d.ref()})")[:200]
            notes.append(f"No bundled schema for {what}; structural checks skipped.")
            continue
        errors = sorted(validator.iter_errors(_drop_nulls(d.data)), key=lambda e: list(e.absolute_path))
        # Only what is SHOWN counts as reported: an error past the cap is in no finding.
        key_reported = {
            tuple(e.absolute_path)
            for e in errors[:MAX_ERRORS_PER_DOC]
            if e.validator == "required" and "'containers'" in e.message
        }
        for err in errors[:MAX_ERRORS_PER_DOC]:
            path = tuple(err.absolute_path)
            if err.validator == "additionalProperties" and isinstance(err.instance, dict):
                allowed = set((err.schema.get("properties") or {}).keys())
                extra = [k for k in err.instance if k not in allowed]
                if extra:
                    path = (*path, extra[0])
            findings.append(
                Finding(
                    rule_id="KN-V007",
                    title="Schema validation error",
                    severity=Severity.HIGH,
                    stage=Stage.VALIDATE,
                    category="schema",
                    resource=d.ref(),
                    message=f"{_message(err)} (schema: Kubernetes {SCHEMA_K8S_VERSION} strict)",
                    remediation="Fix the field name/type; `kubectl explain <kind>.<field>` shows the expected schema.",
                    path=fmt_path(path),
                    line=d.line_for(path),
                    doc_index=d.index,
                    citations=["k8s-deprecation-guide"] if err.validator == "additionalProperties" else [],
                )
            )
        findings.extend(_no_regular_container(d, key_reported))
        if len(errors) > MAX_ERRORS_PER_DOC:
            notes.append(f"{d.ref()}: {len(errors) - MAX_ERRORS_PER_DOC} more schema errors not shown.")
    return findings, notes
