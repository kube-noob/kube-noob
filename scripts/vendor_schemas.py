#!/usr/bin/env python3
"""Vendor JSON schemas into src/kube_noob/schemas/data.

* Kubernetes core: yannh/kubernetes-json-schema ``<version>/_definitions.json`` (generated from the upstream OpenAPI).
  We make it *strict* (additionalProperties: false on every object that declares properties, unless it preserves
  unknown fields) so typos like ``imagePullPolice`` are caught, and strip descriptions to keep the wheel small. Written
  as plain JSON in parts under PART_LIMIT bytes, one definition per line, so every file stays readable text (the Claude
  plugin directory reads files up to 256 KiB and holds compressed or larger ones for review).
* CRDs (OpenShift, OVN-K, StackRox, Gateway API): JSON schemas listed in CRD_SOURCES.
* SARIF 2.1.0 (``--sarif``): the OASIS schema, into tests/fixtures/sarif/, so kube-noob's own SARIF output can be
  validated against the format it claims rather than against the URI it prints. Written on its own: ``--sarif``
  fetches nothing else, and the wheel does not carry it.

Every vendored file is recorded in PROVENANCE.json with source URL, upstream sha256 and license.

Usage: python scripts/vendor_schemas.py [--k8s v1.33.0]
Requires network access to raw.githubusercontent.com; run by maintainers / CI, never at query time.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "src" / "kube_noob" / "schemas" / "data"
YANNH = "https://raw.githubusercontent.com/yannh/kubernetes-json-schema/master"
DATREE = "https://raw.githubusercontent.com/datreeio/CRDs-catalog/main"
# SARIF 2.1.0 from the OASIS technical committee that owns the format. json.schemastore.org serves the same
# schema and is the URI kube-noob writes as `$schema`, but it is not reachable from a locked-down build and it is a
# redistribution, not the source. The schema is a TEST fixture, not wheel data: nothing at runtime reads it.
SARIF = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
SARIF_OUT = ROOT / "tests" / "fixtures" / "sarif"

PART_LIMIT = 200_000

DATREE_SHA = "3eb90d47aba8d61919d4419dd38301536e32a94b"
CNO_SHA = "a1b26444418f0f14c7d35a1242c2bbd705932bdb"
STACKROX_SHA = "3373dee426f5cdeecc0b3a631346dd2442463f1e"

# (group, version, kind, url, format, license) - format "json" = JSON schema, "crd" = CRD YAML (multi-doc ok)
CRD_SOURCES: list[tuple[str, str, str, str, str, str]] = [
    (
        "route.openshift.io",
        "v1",
        "Route",
        f"https://raw.githubusercontent.com/datreeio/CRDs-catalog/{DATREE_SHA}/openshift/v4.15-strict/"
        "route_route.openshift.io_v1.json",
        "json",
        "MIT (datreeio/CRDs-catalog), from openshift/api Apache-2.0",
    ),
    (
        "security.openshift.io",
        "v1",
        "SecurityContextConstraints",
        f"https://raw.githubusercontent.com/datreeio/CRDs-catalog/{DATREE_SHA}/openshift/v4.15-strict/"
        "securitycontextconstraints_security.openshift.io_v1.json",
        "json",
        "MIT (datreeio/CRDs-catalog), from openshift/api Apache-2.0",
    ),
    (
        "gateway.networking.k8s.io",
        "v1",
        "HTTPRoute",
        f"https://raw.githubusercontent.com/datreeio/CRDs-catalog/{DATREE_SHA}/gateway.networking.k8s.io/"
        "httproute_v1.json",
        "json",
        "MIT (datreeio/CRDs-catalog), from kubernetes-sigs/gateway-api Apache-2.0",
    ),
    (
        "gateway.networking.k8s.io",
        "v1",
        "Gateway",
        f"https://raw.githubusercontent.com/datreeio/CRDs-catalog/{DATREE_SHA}/gateway.networking.k8s.io/"
        "gateway_v1.json",
        "json",
        "MIT (datreeio/CRDs-catalog), from kubernetes-sigs/gateway-api Apache-2.0",
    ),
    (
        "k8s.ovn.org",
        "v1",
        "EgressFirewall",
        f"https://raw.githubusercontent.com/openshift/cluster-network-operator/{CNO_SHA}/bindata/network/"
        "ovn-kubernetes/common/001-crd.yaml",
        "crd",
        "Apache-2.0 (openshift/cluster-network-operator)",
    ),
    (
        "platform.stackrox.io",
        "v1alpha1",
        "Central",
        f"https://raw.githubusercontent.com/stackrox/stackrox/{STACKROX_SHA}/operator/config/crd/bases/"
        "platform.stackrox.io_centrals.yaml",
        "crd",
        "Apache-2.0 (stackrox/stackrox)",
    ),
    (
        "platform.stackrox.io",
        "v1alpha1",
        "SecuredCluster",
        f"https://raw.githubusercontent.com/stackrox/stackrox/{STACKROX_SHA}/operator/config/crd/bases/"
        "platform.stackrox.io_securedclusters.yaml",
        "crd",
        "Apache-2.0 (stackrox/stackrox)",
    ),
]


def crd_to_schema(raw: bytes, group: str, version: str, kind: str) -> dict[str, Any]:
    """Extract the openAPIV3Schema of one kind/version from a (multi-document) CRD YAML, made strict."""
    import yaml

    for doc in yaml.safe_load_all(raw):
        if not isinstance(doc, dict) or doc.get("kind") != "CustomResourceDefinition":
            continue
        spec = doc.get("spec") or {}
        if spec.get("group") != group or (spec.get("names") or {}).get("kind") != kind:
            continue
        for v in spec.get("versions") or []:
            if v.get("name") == version:
                schema = ((v.get("schema") or {}).get("openAPIV3Schema")) or {}
                schema = strictify(schema)
                props = schema.setdefault("properties", {})
                props["apiVersion"] = {"type": "string", "enum": [f"{group}/{version}"]}
                props["kind"] = {"type": "string", "enum": [kind]}
                props["metadata"] = {"type": "object"}
                schema["additionalProperties"] = False
                return schema
    raise RuntimeError(f"{kind}.{group}/{version} not found in CRD source")


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "kube-noob-vendor/1"})  # noqa: S310 - fixed https URLs
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
        if resp.status != 200:
            raise RuntimeError(f"{url}: HTTP {resp.status}")
        return bytes(resp.read())


def strictify(node: Any) -> Any:
    if isinstance(node, dict):
        out = {k: strictify(v) for k, v in node.items() if k not in {"description"}}
        if (
            "properties" in out
            and "additionalProperties" not in out
            and not out.get("x-kubernetes-preserve-unknown-fields")
        ):
            out["additionalProperties"] = False
        return out
    if isinstance(node, list):
        return [strictify(x) for x in node]
    return node


def strip_descriptions(node: Any) -> Any:
    if isinstance(node, dict):
        return {k: strip_descriptions(v) for k, v in node.items() if k != "description"}
    if isinstance(node, list):
        return [strip_descriptions(x) for x in node]
    return node


def write_definition_parts(definitions: dict[str, Any], k8s: str, out: Path = OUT) -> list[Path]:
    """Write ``{"definitions": {...}}`` as numbered parts under PART_LIMIT bytes, one definition per line."""
    for old in [*out.glob("kubernetes-*-definitions.json.gz"), *out.glob("kubernetes-*-definitions-*.json")]:
        old.unlink()
    parts: list[list[str]] = [[]]
    size = 0
    for name in sorted(definitions):
        line = json.dumps(name) + ":" + json.dumps(definitions[name], separators=(",", ":"), sort_keys=True)
        if parts[-1] and size + len(line) + 2 > PART_LIMIT - 64:
            parts.append([])
            size = 0
        parts[-1].append(line)
        size += len(line) + 2
    written = []
    for i, lines in enumerate(parts, start=1):
        target = out / f"kubernetes-{k8s}-definitions-{i}.json"
        target.write_text('{"definitions":{\n' + ",\n".join(lines) + "\n}}\n", encoding="utf-8")
        written.append(target)
    return written


def vendor_sarif(out: Path = SARIF_OUT) -> int:
    """The OASIS SARIF 2.1.0 schema, with its provenance beside it.

    It is pretty-printed rather than minified: it is read by people checking what the validator enforces, and the
    plugin directory's 256 KiB per-file limit does not apply to tests.
    """
    out.mkdir(parents=True, exist_ok=True)
    raw = fetch(SARIF)
    schema = json.loads(raw)
    version = schema.get("$id") or schema.get("id") or ""
    target = out / "sarif-schema-2.1.0.json"
    target.write_text(json.dumps(schema, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    (out / "PROVENANCE.json").write_text(
        json.dumps(
            {
                "files": [
                    {
                        "file": target.name,
                        "source": SARIF,
                        "sha256Upstream": hashlib.sha256(raw).hexdigest(),
                        "schemaId": version,
                        "license": "the SARIF 2.1.0 specification is published by OASIS; the schema is part of it",
                        "transform": "re-serialised with sorted keys and one-space indent; no value changed",
                    }
                ]
            },
            indent=1,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {target} ({target.stat().st_size} bytes)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--k8s", default="v1.35.0")
    ap.add_argument(
        "--sarif",
        action="store_true",
        help="vendor only the OASIS SARIF 2.1.0 schema into tests/fixtures/sarif and exit",
    )
    args = ap.parse_args()
    if args.sarif:
        return vendor_sarif()
    OUT.mkdir(parents=True, exist_ok=True)
    provenance: dict[str, Any] = {"files": []}

    url = f"{YANNH}/{args.k8s}/_definitions.json"
    raw = fetch(url)
    defs = json.loads(raw)
    strict = strictify(defs)
    for target in write_definition_parts(strict["definitions"], args.k8s):
        provenance["files"].append(
            {
                "file": target.name,
                "source": url,
                "sha256Upstream": hashlib.sha256(raw).hexdigest(),
                "license": "Apache-2.0 (yannh/kubernetes-json-schema); generated from kubernetes/kubernetes OpenAPI",
                "transform": "strict additionalProperties=false; descriptions removed; split into parts",
            }
        )
        print(f"wrote {target} ({target.stat().st_size} bytes)")

    crd_dir = OUT / "crds"
    crd_dir.mkdir(exist_ok=True)
    for old in crd_dir.glob("*.json"):
        old.unlink()
    for group, version, kind, src, fmt, lic in CRD_SOURCES:
        raw = fetch(src)
        if fmt == "crd":
            schema = crd_to_schema(raw, group, version, kind)
        else:
            schema = strip_descriptions(json.loads(raw))
            props = schema.get("properties") or {}
            if isinstance(props.get("metadata"), dict):
                props["metadata"] = {"type": "object"}
        name = f"{group}_{version}_{kind}.json"
        (crd_dir / name).write_text(json.dumps(schema, separators=(",", ":"), sort_keys=True))
        provenance["files"].append(
            {
                "file": f"crds/{name}",
                "source": src,
                "sha256Upstream": hashlib.sha256(raw).hexdigest(),
                "license": lic,
                "group": group,
                "version": version,
                "kind": kind,
            }
        )
        print(f"wrote crds/{name}")

    (OUT / "PROVENANCE.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
