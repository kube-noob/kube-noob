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

from kube_noob.audit.model import Finding, Severity, Stage
from kube_noob.yamlio import Document, fmt_path

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


def _finding(err: ValidationError, source: Document, *, resource: str, doc_index: int, line_from: Document) -> Finding:
    path = tuple(err.absolute_path)
    if err.validator == "additionalProperties" and isinstance(err.instance, dict):
        allowed = set((err.schema.get("properties") or {}).keys())
        extra = [k for k in err.instance if k not in allowed]
        if extra:
            path = (*path, extra[0])
    return Finding(
        rule_id="KN-V007",
        title="Schema validation error",
        severity=Severity.HIGH,
        stage=Stage.VALIDATE,
        category="schema",
        resource=resource,
        message=f"{_message(err)} (schema: Kubernetes {SCHEMA_K8S_VERSION} strict)",
        remediation="Fix the field name/type; `kubectl explain <kind>.<field>` shows the expected schema.",
        path=fmt_path(path),
        line=line_from.line_for(path),
        doc_index=doc_index,
        citations=["k8s-deprecation-guide"] if err.validator == "additionalProperties" else [],
    )


def _wrapper_errors(wrapper: Document, validator: Draft7Validator) -> list[ValidationError]:
    """The wrapper's OWN schema errors: everything that is not an item which was opened into its own document.

    An item that is a mapping was opened and is validated as a document of its own, so keeping the wrapper's
    error about it would report the same defect twice. An item that is NOT a mapping was never validated by
    anything -- no kind, so no schema -- and the wrapper's schema is the only check that sees it (`7 is not of
    type 'object'`, KN-V007). Everything outside `items` is the container's own metadata, which nothing checked
    at all (class 23, G314).
    """
    items = wrapper.data.get("items") if isinstance(wrapper.data, dict) else None
    kept: list[ValidationError] = []
    for err in validator.iter_errors(_drop_nulls(wrapper.data)):
        path = list(err.absolute_path)
        if len(path) >= 2 and path[0] == "items" and isinstance(path[1], int) and isinstance(items, list):
            index = path[1]
            if 0 <= index < len(items) and isinstance(items[index], dict):
                continue  # that item is a document of its own and was validated as one
        kept.append(err)
    return sorted(kept, key=lambda e: list(map(str, e.absolute_path)))


def validate_documents(docs: list[Document]) -> tuple[list[Finding], list[str]]:
    """Return schema findings and notes about kinds that could not be schema-checked.

    Every list WRAPPER a document was opened out of is checked here too (``Document.wrappers``). Without that,
    opening a list hid the container from this function entirely: nothing applied the bundled `PodList` schema,
    so `items: [7, ...]` lost its KN-V007, and one more `List` around a bundle deleted a finding and raised the
    score (G314). A wrapper kind with no bundled schema -- `v1 List` has none upstream, it is a client-side
    envelope -- says so in a note instead, so a skipped check is stated rather than silent.
    """
    findings: list[Finding] = []
    notes: list[str] = []
    for d in docs:
        for wrapper in d.wrappers:
            if not isinstance(wrapper.data, dict) or not wrapper.kind or not wrapper.api_version:
                continue
            group, _, version = wrapper.api_version.rpartition("/")
            validator = _validator_for(group, version, wrapper.kind)
            ref = f"{wrapper.kind_label()}/<wrapper>"
            if validator is None:
                notes.append(
                    f"No bundled schema for {wrapper.api_version} {wrapper.kind} ({ref}); structural checks skipped."
                )
                continue
            errors = _wrapper_errors(wrapper, validator)
            findings += [
                _finding(err, wrapper, resource=ref, doc_index=d.index, line_from=wrapper)
                for err in errors[:MAX_ERRORS_PER_DOC]
            ]
            if len(errors) > MAX_ERRORS_PER_DOC:
                notes.append(f"{ref}: {len(errors) - MAX_ERRORS_PER_DOC} more schema errors not shown.")
        if not isinstance(d.data, dict) or not d.kind or not d.api_version:
            continue
        group, _, version = d.api_version.rpartition("/")
        validator = _validator_for(group, version, d.kind)
        if validator is None:
            notes.append(f"No bundled schema for {d.api_version} {d.kind} ({d.ref()}); structural checks skipped.")
            continue
        errors = sorted(validator.iter_errors(_drop_nulls(d.data)), key=lambda e: list(e.absolute_path))
        findings += [
            _finding(err, d, resource=d.ref(), doc_index=d.index, line_from=d) for err in errors[:MAX_ERRORS_PER_DOC]
        ]
        if len(errors) > MAX_ERRORS_PER_DOC:
            notes.append(f"{d.ref()}: {len(errors) - MAX_ERRORS_PER_DOC} more schema errors not shown.")
    # A `List` inside a `List` produces the same sentence twice, which says nothing the first one did not; first
    # occurrence order is kept, so the same input still writes the same bytes.
    return findings, list(dict.fromkeys(notes))
