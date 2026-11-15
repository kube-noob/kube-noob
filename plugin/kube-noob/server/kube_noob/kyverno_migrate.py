"""Legacy Kyverno policies, rule by rule: what maps to the CEL policy types and what does not (policy migrate-check).

Kyverno 1.19 deprecates the ``kyverno.io`` ClusterPolicy, Policy, CleanupPolicy, ClusterCleanupPolicy and the legacy
PolicyException, and 1.20 removes them (migration guide, "Deprecation Notice"; kyverno/website@b0131526
src/content/blog/announcing-kyverno-release-1.19/index.md, 2026-08-20: removal in v1.20, Nov 2026 estimated). The
replacements are the ``policies.kyverno.io/v1`` types: ValidatingPolicy, MutatingPolicy, GeneratingPolicy,
ImageValidatingPolicy, DeletingPolicy (each with a ``Namespaced`` variant for a namespaced Policy or CleanupPolicy)
and the new PolicyException.

This module is a lint. For every field of every rule it reports one verdict:

- ``direct``: a documented one-to-one mapping (``validationFailureAction: Enforce`` -> ``validationActions: [Deny]``,
  ``match.any[].resources.kinds`` -> ``matchConstraints.resourceRules``, a pattern that requires a value);
- ``inverted``: it maps, but the logic flips: a ``deny`` (or a negated pattern value) describes what fails, while a CEL
  validation must be true for the request to pass;
- ``manual``: the guide names where it goes, but it needs hand work (JMESPath, API calls, anchors, strategic merge
  patches, Pod Security levels...);
- ``blocked``: no CEL equivalent is documented (the guide says "not supported" or links an open issue, or the
  JMESPath-to-CEL guide lists a function as not yet supported).

Each finding names the rule, the field path and line, the target kind, the reason and the documentation section it
comes from (``SOURCES``: repository, file and commit). Where every field of a rule maps directly (or inverted and
simple), a draft CEL policy is written as text with a ``# DRAFT, prove with kyverno test`` header, plus a ``kyverno
test`` fixture skeleton per policy: the same good and bad resources (taken from the rule's own pattern where possible)
run against the legacy rule and against the draft, in two separate tests, so equivalence is proven by the Kyverno CLI
rather than asserted. Nothing is applied, converted in place or fetched: the input is parsed with ``kube_noob.yamlio``
(size, document, node and depth caps) and Secret documents are skipped unread.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from kube_noob import sanitize
from kube_noob.errors import ManifestError
from kube_noob.yamlio import MAX_DOCUMENTS, MAX_INPUT_BYTES, Document, PathT, dump_documents, fmt_path, load_documents

Verdict = Literal["direct", "inverted", "manual", "blocked"]
VERDICTS: tuple[Verdict, ...] = ("direct", "inverted", "manual", "blocked")
FAIL_ON: tuple[str, ...] = ("never", "manual", "blocked")
_RANK: dict[str, int] = {v: i for i, v in enumerate(VERDICTS)}
_MAX_PATTERN_DEPTH = 30
_MAX_NAME = 63
_DNS_SUBDOMAIN = 253

NOTE = (
    "Lint only: nothing was applied or rewritten. A draft is a starting point, not a finished policy: prove it with "
    "kyverno test (the fixture runs the legacy rule and the draft on the same resources) before you apply it."
)


# --- sources -----------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Source:
    repo: str
    commit: str
    date: str
    file: str
    page: str

    @property
    def url(self) -> str:
        return f"https://github.com/{self.repo}/blob/{self.commit}/{self.file}"

    def as_dict(self) -> dict[str, str]:
        return {
            "repo": self.repo,
            "commit": self.commit,
            "date": self.date,
            "file": self.file,
            "url": self.url,
            "page": self.page,
        }


# Pinned on 2026-10-29. kyverno/website main carries the current (CEL) docs; its release-1-18-0 branch carries the
# legacy ClusterPolicy semantics (anchors, autogen, preconditions, the legacy kyverno test format).
_WEB = ("kyverno/website", "b0131526d7d8d6e4fa80856adb75aa4d7b2f4c89", "2026-10-27")
_WEB118 = ("kyverno/website", "712382f830a614b4eca6fc04f1b07b65955ef31c", "2026-07-29")
_KYV = ("kyverno/kyverno", "e63308f1e16c05cd009ac4864be6ec25c66b49be", "2026-10-21")  # tag v1.19.2
_POL = ("kyverno/policies", "e107540edad393b2ac88a425bff63c66eda7cc9e", "2026-10-27")
_D = "src/content/docs/docs/"
_P = "https://kyverno.io/docs/"
_P118 = "https://release-1-18-0.kyverno.io/docs/"

SOURCES: dict[str, Source] = {
    "migration-to-cel": Source(*_WEB, _D + "guides/migration-to-cel.md", _P + "guides/migration-to-cel/"),
    "jmespath-to-cel": Source(*_WEB, _D + "guides/jmespath-to-cel.md", _P + "guides/jmespath-to-cel/"),
    "policy-types": Source(*_WEB, _D + "policy-types/overview.md", _P + "policy-types/overview/"),
    "validating-policy": Source(
        *_WEB, _D + "policy-types/validating-policy.mdx", _P + "policy-types/validating-policy/"
    ),
    "mutating-policy": Source(*_WEB, _D + "policy-types/mutating-policy.mdx", _P + "policy-types/mutating-policy/"),
    "generating-policy": Source(
        *_WEB, _D + "policy-types/generating-policy.mdx", _P + "policy-types/generating-policy/"
    ),
    "deleting-policy": Source(*_WEB, _D + "policy-types/deleting-policy.mdx", _P + "policy-types/deleting-policy/"),
    "image-validating-policy": Source(
        *_WEB, _D + "policy-types/image-validating-policy.mdx", _P + "policy-types/image-validating-policy/"
    ),
    "cel-libraries": Source(*_WEB, _D + "policy-types/cel-libraries.mdx", _P + "policy-types/cel-libraries/"),
    "kyverno-cli": Source(*_WEB, _D + "subprojects/kyverno-cli.mdx", _P + "subprojects/kyverno-cli/"),
    "legacy-validate": Source(
        *_WEB118, _D + "policy-types/cluster-policy/validate.md", _P118 + "policy-types/cluster-policy/validate/"
    ),
    "legacy-autogen": Source(
        *_WEB118, _D + "policy-types/cluster-policy/autogen.md", _P118 + "policy-types/cluster-policy/autogen/"
    ),
    "legacy-preconditions": Source(
        *_WEB118,
        _D + "policy-types/cluster-policy/preconditions.md",
        _P118 + "policy-types/cluster-policy/preconditions/",
    ),
    "legacy-kyverno-cli": Source(*_WEB118, _D + "subprojects/kyverno-cli.mdx", _P118 + "subprojects/kyverno-cli/"),
    "kyverno-autogen": Source(
        *_KYV, "pkg/cel/policies/vpol/autogen/autogen.go", "https://github.com/kyverno/kyverno/tree/v1.19.2"
    ),
    "kyverno-pattern": Source(
        *_KYV, "pkg/engine/pattern/pattern.go", "https://github.com/kyverno/kyverno/tree/v1.19.2"
    ),
    "kyverno-test-results": Source(
        *_KYV, "cmd/cli/kubectl-kyverno/apis/v1alpha1/test_result.go", "https://github.com/kyverno/kyverno/tree/v1.19.2"
    ),
    "kyverno-test-output": Source(
        *_KYV, "cmd/cli/kubectl-kyverno/commands/test/output.go", "https://github.com/kyverno/kyverno/tree/v1.19.2"
    ),
    "kyverno-policies-tests": Source(
        *_POL, "psa-mpol/add-psa-labels/.kyverno-test/kyverno-test.yaml", "https://github.com/kyverno/policies"
    ),
}
_MIG = "migration-to-cel"


@dataclass(frozen=True)
class Mapping:
    """One row of a mapping table: the verdict, where the field goes, why, and the documentation it comes from."""

    verdict: Verdict
    maps_to: str
    reason: str
    source: str  # a SOURCES key
    section: str


# kyverno/website@b0131526 src/content/docs/docs/guides/migration-to-cel.md, "Policy Settings" -> "Common Fields"; the
# deprecated spec-level spellings follow the rule-level rows they default (validate.md@712382f8, "Failure Action").
POLICY_FIELDS: dict[str, Mapping] = {
    "admission": Mapping("direct", "spec.evaluation.admission.enabled", "same setting", _MIG, "Common Fields"),
    "background": Mapping("direct", "spec.evaluation.background.enabled", "same setting", _MIG, "Common Fields"),
    "emitWarning": Mapping(
        "direct",
        "spec.validationActions: Warn",
        "audit results shown as warnings become the Warn action",
        _MIG,
        "Common Fields",
    ),
    "useServerSideApply": Mapping(
        "blocked",
        "no field listed",
        "the guide links kyverno/kyverno#14853 instead of a CEL field",
        _MIG,
        "Common Fields",
    ),
    "failurePolicy": Mapping(
        "direct",
        "spec.failurePolicy",
        "deprecated spelling of spec.webhookConfiguration.failurePolicy, which maps to spec.failurePolicy",
        _MIG,
        "Common Fields",
    ),
    "webhookTimeoutSeconds": Mapping(
        "direct",
        "spec.webhookConfiguration.timeoutSeconds",
        "deprecated spelling of spec.webhookConfiguration.timeoutSeconds, the same field in CEL policies",
        _MIG,
        "Common Fields",
    ),
    "validationFailureAction": Mapping(
        "direct",
        "spec.validationActions",
        "Enforce becomes [Deny], Audit becomes [Audit] (the spec-level field is "
        "the deprecated default of validate.failureAction)",
        _MIG,
        "Validate Rule",
    ),
    "validationFailureActionOverrides": Mapping(
        "manual",
        "PolicyException (policies.kyverno.io/v1)",
        "per-namespace failure actions are not supported; use policy exceptions instead",
        _MIG,
        "Validate Rule",
    ),
    "mutateExistingOnPolicyUpdate": Mapping(
        "direct",
        "spec.evaluation.mutateExisting.enabled",
        "mutating existing resources is an evaluation setting",
        _MIG,
        "Mutate Rule",
    ),
    "generateExisting": Mapping(
        "direct",
        "spec.evaluation.generateExisting.enabled",
        "generating for existing triggers is an evaluation setting",
        _MIG,
        "Generate Rule",
    ),
    "generateExistingOnPolicyUpdate": Mapping(
        "direct",
        "spec.evaluation.generateExisting.enabled",
        "generating for existing triggers is an evaluation setting",
        _MIG,
        "Generate Rule",
    ),
}
# Same file, "Common Fields": spec.webhookConfiguration.*.
WEBHOOK_FIELDS: dict[str, Mapping] = {
    "failurePolicy": Mapping("direct", "spec.failurePolicy", "same setting", _MIG, "Common Fields"),
    "matchConditions": Mapping("direct", "spec.matchConditions", "same CEL match conditions", _MIG, "Common Fields"),
    "timeoutSeconds": Mapping(
        "direct", "spec.webhookConfiguration.timeoutSeconds", "same field", _MIG, "Common Fields"
    ),
}
_APPLY_ONE = Mapping(
    "manual",
    "one policy per rule, with spec.matchConditions",
    "applyRules is not applicable: convert each rule to a policy and use matchConditions so only one applies",
    _MIG,
    "Common Fields",
)
# Same file, "Rule Fields".
RULE_FIELDS: dict[str, Mapping] = {
    "celPreconditions": Mapping(
        "direct", "spec.matchConditions", "already CEL: copy the conditions", _MIG, "Rule Fields"
    ),
    "skipBackgroundRequests": Mapping(
        "blocked",
        "no field listed",
        "the guide links kyverno/kyverno#14852 instead of a CEL field",
        _MIG,
        "Rule Fields",
    ),
    "reportProperties": Mapping(
        "direct", "spec.auditAnnotations", "report properties become audit annotations", _MIG, "Rule Fields"
    ),
    "imageExtractors": Mapping(
        "manual",
        "spec.images (ImageValidatingPolicy) or spec.variables",
        "image extractors become CEL expressions that list the images",
        _MIG,
        "Rule Fields",
    ),
}
_MATCH = Mapping("direct", "spec.matchConstraints", "match becomes match constraints", _MIG, "Rule Fields")
_EXCLUDE = Mapping(
    "direct",
    "spec.matchConstraints.excludeResourceRules",
    "exclude becomes exclude resource rules",
    _MIG,
    "Rule Fields",
)
_CONTEXT = Mapping("manual", "spec.variables", "context entries become CEL variables", _MIG, "Rule Fields")
_PRECONDITIONS = Mapping(
    "direct", "spec.matchConditions", "preconditions become CEL match conditions", _MIG, "Rule Fields"
)
# Same file, "Validate Rule".
VALIDATE_FIELDS: dict[str, Mapping] = {
    "allowExistingViolations": Mapping(
        "manual",
        "PolicyException (policies.kyverno.io/v1)",
        "not supported; use policy exceptions instead",
        _MIG,
        "Validate Rule",
    ),
    "failureAction": Mapping(
        "direct", "spec.validationActions", "Enforce becomes [Deny], Audit becomes [Audit]", _MIG, "Validate Rule"
    ),
    "failureActionOverrides": Mapping(
        "manual",
        "PolicyException (policies.kyverno.io/v1)",
        "not supported; use policy exceptions instead",
        _MIG,
        "Validate Rule",
    ),
    "manifests": Mapping(
        "blocked", "no CEL equivalent", "the guide lists manifest validation as not supported", _MIG, "Validate Rule"
    ),
    "podSecurity": Mapping(
        "manual",
        "spec.validations, one per Pod Security control",
        "not supported as a field; write a validation for each Pod Security control",
        _MIG,
        "Validate Rule",
    ),
    "message": Mapping("direct", "spec.validations[].message", "same message", _MIG, "Validate Rule"),
    "pattern": Mapping(
        "direct", "spec.validations[].expression", "each pattern field becomes a CEL check", _MIG, "Validate Rule"
    ),
    "anyPattern": Mapping(
        "direct", "spec.validations[].expression", "the patterns become checks joined with ||", _MIG, "Validate Rule"
    ),
    "deny": Mapping(
        "inverted",
        "spec.validations[].expression",
        "deny conditions say what fails, a CEL validation must be true to pass: invert the logic",
        _MIG,
        "Validate Rule",
    ),
    "foreach": Mapping(
        "direct",
        "spec.validations with all() / exists()",
        "the loop becomes a CEL comprehension over the list",
        _MIG,
        "Validate Rule",
    ),
    "cel": Mapping("direct", "spec.validations", "already CEL: copy the expressions", _MIG, "Validate Rule"),
}
_MESSAGE_VARS = Mapping(
    "manual",
    "spec.validations[].messageExpression",
    "the message uses JMESPath variables: write it as a CEL messageExpression",
    _MIG,
    "Validate Rule",
)
# Same file, "Mutate Rule".
MUTATE_FIELDS: dict[str, Mapping] = {
    "foreach": Mapping(
        "manual",
        "CEL comprehensions in spec.mutations",
        "rewrite the loop with all(), exists() or map()",
        _MIG,
        "Mutate Rule",
    ),
    "mutateExistingOnPolicyUpdate": Mapping(
        "direct",
        "spec.evaluation.mutateExisting.enabled",
        "mutating existing resources is an evaluation setting",
        _MIG,
        "Mutate Rule",
    ),
    "patchStrategicMerge": Mapping(
        "manual",
        "spec.mutations (patchType: ApplyConfiguration or JSONPatch)",
        "strategic merge patches are not supported: convert to an ApplyConfiguration or JSONPatch mutation",
        _MIG,
        "Mutate Rule",
    ),
    "patchesJson6902": Mapping(
        "direct",
        "spec.mutations (patchType: JSONPatch)",
        "each RFC 6902 operation becomes a JSONPatch{} entry",
        _MIG,
        "Mutate Rule",
    ),
    "targets": Mapping(
        "manual",
        "spec.matchConstraints or spec.targetMatchConstraints",
        "mutate-existing targets are selected with match constraints and CEL",
        _MIG,
        "Mutate Rule",
    ),
}
# Same file, "Generate Rule"; field shapes from policy-types/generating-policy.mdx, "Synchronization".
GENERATE_FIELDS: dict[str, Mapping] = {
    "synchronize": Mapping("direct", "spec.evaluation.synchronize.enabled", "same setting", _MIG, "Generate Rule"),
    "generateExisting": Mapping(
        "direct", "spec.evaluation.generateExisting.enabled", "same setting", _MIG, "Generate Rule"
    ),
    "orphanDownstreamOnPolicyDelete": Mapping(
        "direct", "spec.evaluation.orphanDownstreamOnPolicyDelete.enabled", "same setting", _MIG, "Generate Rule"
    ),
}
_GENERATE_EXPRESSIONS = ("apiVersion", "kind", "name", "namespace", "data", "clone", "cloneList", "foreach")
_GENERATE = Mapping(
    "manual",
    "spec.generate[].expression (generator.Apply)",
    "the generated resource (apiVersion, kind, name, namespace, data or clone) becomes a CEL expression",
    _MIG,
    "Generate Rule",
)
# Same file, "Verify Images Rule"; credentials limits from policy-types/image-validating-policy.mdx, "credentials".
VERIFY_FIELDS: dict[str, Mapping] = {
    "imageReferences": Mapping(
        "direct", "spec.matchImageReferences", "each reference becomes a glob entry", _MIG, "Verify Images Rule"
    ),
    "skipImageReferences": Mapping(
        "manual",
        "spec.matchImageReferences with CEL expressions",
        "skipped references become a CEL match expression",
        _MIG,
        "Verify Images Rule",
    ),
    "type": Mapping(
        "direct",
        "spec.attestors[].cosign or spec.attestors[].notary",
        "the signature type picks the attestor kind",
        _MIG,
        "Verify Images Rule",
    ),
    "attestors": Mapping(
        "manual",
        "spec.attestors",
        "attestor entries (keys, certificates, keyless) take the ImageValidatingPolicy attestor shape: move them by "
        "hand",
        _MIG,
        "Verify Images Rule",
    ),
    "attestations": Mapping(
        "manual",
        "spec.attestations and spec.validations",
        "attestation conditions become CEL validations",
        _MIG,
        "Verify Images Rule",
    ),
    "imageRegistryCredentials": Mapping(
        "manual",
        "spec.credentials",
        "secrets must be in the Kyverno namespace and Pod imagePullSecrets are not picked up (known limitations)",
        "image-validating-policy",
        "credentials",
    ),
    "mutateDigest": Mapping(
        "direct", "spec.validationConfigurations.mutateDigest", "same setting", _MIG, "Verify Images Rule"
    ),
    "verifyDigest": Mapping(
        "direct", "spec.validationConfigurations.verifyDigest", "same setting", _MIG, "Verify Images Rule"
    ),
    "required": Mapping("direct", "spec.validationConfigurations.required", "same setting", _MIG, "Verify Images Rule"),
}
# Same file, "CleanupPolicy". The DeletingPolicy page's examples keep CEL conditions in spec.conditions.
CLEANUP_FIELDS: dict[str, Mapping] = {
    "deletionPropagationPolicy": Mapping(
        "direct", "spec.deletionPropagationPolicy", "same field", _MIG, "CleanupPolicy"
    ),
    "schedule": Mapping("direct", "spec.schedule", "same cron schedule", _MIG, "CleanupPolicy"),
    "conditions": Mapping(
        "direct",
        "spec.conditions",
        "conditions become CEL (the guide's row says matchConditions; the DeletingPolicy examples use spec.conditions)",
        _MIG,
        "CleanupPolicy",
    ),
}
# Same file, "PolicyException".
EXCEPTION_FIELDS: dict[str, Mapping] = {
    "policyName": Mapping(
        "direct", "spec.policyRefs[].name", "same policy name, with the kind it migrated to", _MIG, "PolicyException"
    ),
    "ruleNames": Mapping(
        "manual",
        "not applicable",
        "CEL policies have no named rules: if the policy was split per "
        "rule, reference the policy that now carries this rule",
        _MIG,
        "PolicyException",
    ),
    "match": Mapping("direct", "spec.matchConditions", "match becomes CEL match conditions", _MIG, "PolicyException"),
    "conditions": Mapping(
        "direct", "spec.matchConditions", "conditions become CEL match conditions", _MIG, "PolicyException"
    ),
    "podSecurity": Mapping(
        "manual",
        "spec.matchConditions with CEL expressions",
        "Pod Security exemptions become CEL match conditions",
        _MIG,
        "PolicyException",
    ),
}

# kyverno/website@b0131526 src/content/docs/docs/guides/jmespath-to-cel.md, "Quick Reference" and the note on
# unsupported filters (compare() "is not carried forward").
JMESPATH_TO_CEL: dict[str, str] = {
    "add": "quantity(q).add(quantity(q2)) or quantity(q).add(int)",
    "base64_decode": "base64.decode(str)",
    "base64_encode": "base64.encode(str)",
    "compare": "not carried forward to CEL",
    "divide": "not yet supported",
    "equal_fold": "a.lowerAscii() == b.lowerAscii()",
    "image_normalize": "image(str).registry(), .tag(), .repository()",
    "items": 'myMap.map(k, {"key": k, "value": myMap[k]})',
    "label_match": "map1 == map2",
    "lookup": 'map["key"] or array[index]',
    "md5": "md5(str)",
    "modulo": "a % b",
    "multiply": "not yet supported",
    "object_from_lists": "listObjToMap(...)",
    "parse_json": "json.unmarshal(str)",
    "parse_yaml": "yaml.parse(str)",
    "path_canonicalize": "'/' + str.split('/').filter(s, s != '').join('/')",
    "pattern_match": "str.matches(regex)",
    "random": "random(pattern)",
    "regex_match": "str.matches(pattern)",
    "regex_replace_all": "not yet supported",
    "regex_replace_all_literal": "not yet supported",
    "replace": "str.replace(old, new, n)",
    "replace_all": "str.replace(old, new, -1)",
    "round": "math.round(num, places)",
    "semver_compare": "semver(str).isGreaterThan(semver(str2)) or .isLessThan()",
    "sha1": "sha1(str)",
    "sha256": "sha256(str)",
    "split": "str.split(delimiter)",
    "subtract": "quantity(q).sub(quantity(q2)) or quantity(q).sub(int)",
    "sum": "not supported (no array-reduce equivalent)",
    "time_add": "timestamp(str) + duration(dur)",
    "time_after": "timestamp(t1) > timestamp(t2)",
    "time_before": "timestamp(t1) < timestamp(t2)",
    "time_between": "timestamp(t) > timestamp(start) && timestamp(t) < timestamp(end)",
    "time_diff": "timestamp(end) - timestamp(start)",
    "time_now": "time.now()",
    "time_now_utc": "time.now()",
    "time_parse": "timestamp(str)",
    "time_since": "time.now() - timestamp(start)",
    "time_to_cron": "time.toCron(timestamp(str))",
    "time_truncate": "time.truncate(timestamp(str), duration(dur))",
    "time_utc": "string(timestamp(str))",
    "to_boolean": 'str.lowerAscii() == "true"',
    "to_lower": "str.lowerAscii()",
    "to_upper": "str.upperAscii()",
    "trim": "str.trim() or str.replace(chars, '')",
    "trim_prefix": "str.replace(prefix, '', 1)",
    "truncate": "str.substring(0, n)",
    "x509_decode": "x509.decode(str)",
}
JMESPATH_BLOCKED = frozenset({"multiply", "divide", "sum", "compare", "regex_replace_all", "regex_replace_all_literal"})

# Lookups in context entries (migration-to-cel.md "Rule Fields": context -> spec.variables; the functions are the
# cel-libraries.mdx Resource, HTTP, GlobalContext and ImageData libraries).
_CONTEXT_KINDS: dict[str, tuple[str, str]] = {
    "configMap": ('spec.variables with resource.Get("v1", "configmaps", <namespace>, <name>)', "Resource library"),
    "globalReference": ("spec.variables with globalContext.Get()", "GlobalContext library"),
    "imageRegistry": ("spec.variables with image.GetMetadata()", "ImageData library"),
}


def mapping_rows() -> list[tuple[str, str, Mapping]]:
    """Every row of every mapping table, for tests and docs: (table, field, row)."""
    tables: dict[str, dict[str, Mapping]] = {
        "policy": POLICY_FIELDS,
        "webhookConfiguration": WEBHOOK_FIELDS,
        "rule": RULE_FIELDS,
        "validate": VALIDATE_FIELDS,
        "mutate": MUTATE_FIELDS,
        "generate": GENERATE_FIELDS,
        "verifyImages": VERIFY_FIELDS,
        "cleanup": CLEANUP_FIELDS,
        "exception": EXCEPTION_FIELDS,
    }
    rows = [(t, f, m) for t, table in tables.items() for f, m in table.items()]
    extra = {
        "applyRules": _APPLY_ONE,
        "match": _MATCH,
        "exclude": _EXCLUDE,
        "context": _CONTEXT,
        "preconditions": _PRECONDITIONS,
        "messageVariables": _MESSAGE_VARS,
        "generateExpressions": _GENERATE,
    }
    return rows + [("other", f, m) for f, m in extra.items()]


# --- kinds -------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Gvr:
    group: str
    version: str
    plural: str
    namespaced: bool = True

    @property
    def api_version(self) -> str:
        return f"{self.group}/{self.version}" if self.group else self.version


# Built-in kinds (Kubernetes API reference, https://kubernetes.io/docs/reference/kubernetes-api/, and the OpenShift API
# groups kube-noob already audits). A kind outside this table needs its group, version and plural by hand.
KINDS: dict[str, Gvr] = {
    "Pod": Gvr("", "v1", "pods"),
    "Service": Gvr("", "v1", "services"),
    "ConfigMap": Gvr("", "v1", "configmaps"),
    "Secret": Gvr("", "v1", "secrets"),
    "ServiceAccount": Gvr("", "v1", "serviceaccounts"),
    "PersistentVolumeClaim": Gvr("", "v1", "persistentvolumeclaims"),
    "PersistentVolume": Gvr("", "v1", "persistentvolumes", False),
    "Namespace": Gvr("", "v1", "namespaces", False),
    "Node": Gvr("", "v1", "nodes", False),
    "Endpoints": Gvr("", "v1", "endpoints"),
    "LimitRange": Gvr("", "v1", "limitranges"),
    "ResourceQuota": Gvr("", "v1", "resourcequotas"),
    "ReplicationController": Gvr("", "v1", "replicationcontrollers"),
    "Deployment": Gvr("apps", "v1", "deployments"),
    "StatefulSet": Gvr("apps", "v1", "statefulsets"),
    "DaemonSet": Gvr("apps", "v1", "daemonsets"),
    "ReplicaSet": Gvr("apps", "v1", "replicasets"),
    "Job": Gvr("batch", "v1", "jobs"),
    "CronJob": Gvr("batch", "v1", "cronjobs"),
    "Ingress": Gvr("networking.k8s.io", "v1", "ingresses"),
    "IngressClass": Gvr("networking.k8s.io", "v1", "ingressclasses", False),
    "NetworkPolicy": Gvr("networking.k8s.io", "v1", "networkpolicies"),
    "PodDisruptionBudget": Gvr("policy", "v1", "poddisruptionbudgets"),
    "HorizontalPodAutoscaler": Gvr("autoscaling", "v2", "horizontalpodautoscalers"),
    "Role": Gvr("rbac.authorization.k8s.io", "v1", "roles"),
    "RoleBinding": Gvr("rbac.authorization.k8s.io", "v1", "rolebindings"),
    "ClusterRole": Gvr("rbac.authorization.k8s.io", "v1", "clusterroles", False),
    "ClusterRoleBinding": Gvr("rbac.authorization.k8s.io", "v1", "clusterrolebindings", False),
    "StorageClass": Gvr("storage.k8s.io", "v1", "storageclasses", False),
    "PriorityClass": Gvr("scheduling.k8s.io", "v1", "priorityclasses", False),
    "EndpointSlice": Gvr("discovery.k8s.io", "v1", "endpointslices"),
    "Lease": Gvr("coordination.k8s.io", "v1", "leases"),
    "CustomResourceDefinition": Gvr("apiextensions.k8s.io", "v1", "customresourcedefinitions", False),
    "ValidatingWebhookConfiguration": Gvr(
        "admissionregistration.k8s.io", "v1", "validatingwebhookconfigurations", False
    ),
    "MutatingWebhookConfiguration": Gvr("admissionregistration.k8s.io", "v1", "mutatingwebhookconfigurations", False),
    "Route": Gvr("route.openshift.io", "v1", "routes"),
    "DeploymentConfig": Gvr("apps.openshift.io", "v1", "deploymentconfigs"),
    "SecurityContextConstraints": Gvr("security.openshift.io", "v1", "securitycontextconstraints", False),
}
_VERSION = re.compile(r"^v\d+(?:(?:alpha|beta)\d+)?\Z")
# Legacy autogen covers these (legacy autogen.md); a CEL policy matching only pods covers the six in
# kyverno pkg/cel/autogen/data.go (ConfigsMap) when spec.autogen is unset (pkg/cel/policies/vpol/autogen/autogen.go).
_LEGACY_AUTOGEN = ("DaemonSet", "Deployment", "Job", "StatefulSet", "ReplicaSet", "ReplicationController", "CronJob")
_CEL_AUTOGEN = ("daemonsets", "deployments", "replicasets", "statefulsets", "jobs", "cronjobs")
_AUTOGEN_KEY = "pod-policies.kyverno.io/autogen-controllers"


def _resolve_kind(raw: str) -> tuple[str, Gvr, str] | str:
    """(Kind, group/version/plural, subresource) for Kyverno's kind spellings, or the reason it cannot be resolved."""
    if "*" in raw or "?" in raw:
        return f"wildcard kind {raw!r}: list the kinds, or match all resources with a matchCondition"
    parts = raw.split("/")
    idx = next((i for i, p in enumerate(parts) if p[:1].isupper()), None)
    if idx is None or idx > 2 or len(parts) - idx > 2:
        return f"kind {raw!r} is not in a form kube-noob reads (Kind, version/Kind or group/version/Kind)"
    kind, before = parts[idx], parts[:idx]
    sub = parts[idx + 1] if len(parts) > idx + 1 else ""
    group: str | None = None
    version: str | None = None
    if len(before) == 2:
        group, version = before
    elif len(before) == 1:
        if not _VERSION.match(before[0]):
            return f"kind {raw!r}: give the version as group/version/Kind"
        group, version = "", before[0]
    known = KINDS.get(kind)
    if known is None or (group is not None and group != known.group):
        return (
            f"kind {raw!r} is not in kube-noob's table: give its API group, version and plural (kubectl api-resources)"
        )
    gvr = known if version is None else Gvr(known.group, version, known.plural, known.namespaced)
    return kind, gvr, sub


# --- CEL text helpers --------------------------------------------------------------------------------------------

# Validators end with \Z, never $ (which also matches before a final newline): a key that passes _IDENT is printed
# into CEL as .key (guidance G100).
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\Z")
_INT = re.compile(r"^-?\d{1,15}\Z")


def cel_literal(value: Any) -> str:
    """A CEL literal for a YAML scalar, list or map (strings JSON-quoted, which CEL accepts)."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(cel_literal(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{json.dumps(str(k))}: {cel_literal(v)}" for k, v in value.items()) + "}"
    return json.dumps(str(value))


@dataclass(frozen=True)
class _Chain:
    """A path from a CEL variable (``object``, a comprehension variable) to a field."""

    base: str
    segs: tuple[str, ...] = ()

    def child(self, key: str) -> _Chain:
        return _Chain(self.base, (*self.segs, key))

    @property
    def opt(self) -> str:
        """Optional chain: never errors on a missing field (``object.metadata.?labels[?"app"]``)."""
        out = self.base
        for i, s in enumerate(self.segs):
            if i == 0 and self.base == "object" and s == "metadata":
                out += ".metadata"
            elif _IDENT.match(s):
                out += f".?{s}"
            else:
                out += f"[?{json.dumps(s)}]"
        return out

    @property
    def plain(self) -> str:
        return self.base + "".join(f".{s}" if _IDENT.match(s) else f"[{json.dumps(s)}]" for s in self.segs)


def _glob_regex(glob: str) -> str:
    out = "".join(".*" if c == "*" else "." if c == "?" else ("\\" + c if c in ".^$+()[]{}|\\" else c) for c in glob)
    return f"^{out}$"


def _glob_match(glob: str, value: str) -> bool:
    return re.fullmatch(_glob_regex(glob)[1:-1], value, flags=re.DOTALL) is not None


def _str_test(expr: str, glob: str) -> str:
    """CEL that is true when the string ``expr`` matches the Kyverno wildcard ``glob``."""
    if "*" not in glob and "?" not in glob:
        return f"{expr} == {json.dumps(glob)}"
    inner = glob.strip("*")
    if "?" not in glob and "*" not in inner:
        if glob.startswith("*") and glob.endswith("*") and len(glob) > 1:
            return f"{expr}.contains({json.dumps(inner)})"
        if glob.endswith("*"):
            return f"{expr}.startsWith({json.dumps(inner)})"
        if glob.startswith("*"):
            return f"{expr}.endsWith({json.dumps(inner)})"
    return f"{expr}.matches({json.dumps(_glob_regex(glob))})"


_SAMPLES = {
    "image": "registry.example.com/app:1.0",
    "name": "app",
    "memory": "128Mi",
    "cpu": "100m",
    "namespace": "team-a",
}


def _sample(key: str) -> str:
    return _SAMPLES.get(key, "value")


def _instance(glob: str, key: str) -> str:
    sample = _sample(key)
    return sample if _glob_match(glob, sample) else glob.replace("*", "x").replace("?", "x")


def _not_matching(globs: list[str], key: str) -> str | None:
    for cand in (_sample(key), "other", "value-2", "x-1"):
        if not any(_glob_match(g, cand) for g in globs):
            return cand
    return None


# --- patterns ----------------------------------------------------------------------------------------------------

_ANCHOR = re.compile(r"^(?P<tag>\(|=\(|\^\(|X\(|<\(|\+\()(?P<key>[^()]+)\)\Z")
_ANCHOR_NAMES = {"(": "conditional", "=(": "equality", "^(": "existence", "<(": "global", "+(": "add-if-not-present"}
_OP = re.compile(r"^(?P<op>>=|<=|>|<)\s*(?P<num>\S+)\Z")
# Values Kyverno compares as a Kubernetes quantity or a Go duration rather than as text (pattern.go, compareQuantity
# and compareDuration); plain integers are handled on their own.
_QUANTITY = re.compile(r"^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+|Ki|Mi|Gi|Ti|Pi|Ei|[numkMGTPE])?\Z")
_DURATION = re.compile(r"^[+-]?(?:\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h))+\Z")
_RANGE = re.compile(r"^-?\d+(?:\.\d+)?[A-Za-z]*\s*!?-\s*-?\d")
_DELETE = object()  # a break that removes the field


@dataclass
class _Cel:
    """A translated piece: CEL conjuncts, the worst verdict, and sample values for the fixture resources."""

    conds: list[str] = field(default_factory=list)
    verdict: Verdict = "direct"
    notes: list[str] = field(default_factory=list)
    ok: bool = True  # False: no draft, the piece needs hand work
    good: dict[str, Any] = field(default_factory=dict)
    breaks: list[tuple[tuple[str | int, ...], Any]] = field(default_factory=list)

    def bump(self, verdict: Verdict, note: str, ok: bool = True) -> None:
        if _RANK[verdict] > _RANK[self.verdict]:
            self.verdict = verdict
        if note not in self.notes:
            self.notes.append(note)
        if not ok:
            self.ok = False

    def absorb(self, other: _Cel) -> None:
        if _RANK[other.verdict] > _RANK[self.verdict]:
            self.verdict = other.verdict
        self.notes += [n for n in other.notes if n not in self.notes]
        self.ok = self.ok and other.ok


def _put(obj: Any, path: tuple[str | int, ...], value: Any) -> None:
    """Set ``value`` at ``path``, creating maps and one-element lists on the way."""
    cur = obj
    for i, p in enumerate(path):
        last = i == len(path) - 1
        nxt: Any = [] if (not last and isinstance(path[i + 1], int)) else {}
        if isinstance(p, int):
            while len(cur) <= p:
                cur.append({} if last else nxt)
            if last:
                cur[p] = value
            else:
                if not isinstance(cur[p], dict | list):
                    cur[p] = nxt
                cur = cur[p]
        elif last:
            cur[p] = value
        else:
            if not isinstance(cur.get(p), dict | list):
                cur[p] = nxt
            cur = cur[p]


def _apply_break(obj: Any, path: tuple[str | int, ...], value: Any) -> None:
    if value is _DELETE:
        cur = obj
        for p in path[:-1]:
            if isinstance(p, int):
                if not isinstance(cur, list) or len(cur) <= p:
                    return
            elif not isinstance(cur, dict) or p not in cur:
                return
            cur = cur[p]
        if isinstance(cur, dict):
            cur.pop(path[-1], None)
        return
    _put(obj, path, value)


def _walk_pattern(node: Any, chain: _Chain, opath: tuple[str | int, ...], out: _Cel, depth: int) -> None:
    if depth > _MAX_PATTERN_DEPTH:
        out.bump("manual", f"pattern nested deeper than {_MAX_PATTERN_DEPTH} levels", ok=False)
        return
    if not isinstance(node, dict) or not node:
        out.bump("manual", "a pattern that is not a non-empty mapping needs hand work", ok=False)
        return
    for raw_key, value in node.items():
        key = str(raw_key)
        m = _ANCHOR.match(key)
        if m:
            tag, name = m["tag"], m["key"]
            if tag == "X(":
                out.bump("inverted", f"negation anchor {key}: the field must be absent, so the CEL check negates it")
                out.conds.append(f"!{chain.child(name).opt}.hasValue()")
                out.breaks.append(((*opath, name), "value"))
            else:
                out.bump(
                    "manual",
                    f"{_ANCHOR_NAMES[tag]} anchor {key}: rewrite its if-then logic as a CEL implication by hand",
                    ok=False,
                )
            continue
        if not key or "{{" in key:
            out.bump("manual", f"pattern key {key!r} needs hand work", ok=False)
            continue
        child = chain.child(key)
        if isinstance(value, dict):
            _walk_pattern(value, child, (*opath, key), out, depth + 1)
        elif isinstance(value, list):
            if len(value) == 1 and isinstance(value[0], dict) and value[0]:
                var = f"e{depth}"
                inner = _Cel()
                _walk_pattern(value[0], _Chain(var), (), inner, depth + 1)
                out.absorb(inner)
                if inner.conds:
                    out.conds.append(f"{child.opt}.hasValue() && {child.plain}.all({var}, {' && '.join(inner.conds)})")
                _put(out.good, (*opath, key), [inner.good])
                out.breaks += [((*opath, key, 0, *p), v) for p, v in inner.breaks]
            else:
                out.bump(
                    "manual", f"{key}: a list pattern other than one mapping (every element) needs hand work", ok=False
                )
        else:
            _leaf(value, child, (*opath, key), key, out)


def _leaf(value: Any, chain: _Chain, opath: tuple[str | int, ...], key: str, out: _Cel) -> None:
    # A missing field fails a pattern (legacy validate.md, "Patterns" rule 1; pattern.go compareString is false for a
    # nil value), except a number, which reads a missing field as 0. ``x.?a.?b.hasValue() && x.a.b ...`` reads the
    # field only once it is known to exist (the guarded form kyverno/policies uses; it never calls .value()).
    opt, plain = chain.opt, chain.plain
    if value is None or value == "":
        out.bump("inverted", f"{key}: an empty pattern value means the field must be absent or empty")
        out.conds.append(f'{opt}.orValue("") == ""')
        out.breaks.append((opath, "value"))
        return
    if isinstance(value, bool):
        out.conds.append(f"{opt}.orValue({cel_literal(not value)}) == {cel_literal(value)}")
        _put(out.good, opath, value)
        out.breaks.append((opath, not value))
        return
    if isinstance(value, int):
        out.conds.append(f"{opt}.hasValue() && {plain} == {value}")
        _put(out.good, opath, value)
        out.breaks.append((opath, value + 1))
        return
    if not isinstance(value, str):
        out.bump("manual", f"{key}: a {type(value).__name__} pattern value needs hand work", ok=False)
        return
    text = value.strip()
    if "{{" in text:
        out.bump(
            "manual",
            f"{key}: the pattern uses JMESPath variables; translate them with the JMESPath-to-CEL guide",
            ok=False,
        )
        return
    if "&" in text or _RANGE.match(text):
        out.bump("manual", f"{key}: {text!r} combines operators or a range; write the CEL comparison by hand", ok=False)
        return
    m = _OP.match(text)
    if m:
        op, num = m["op"], m["num"].strip()
        if not _INT.match(num):
            out.bump(
                "manual",
                f"{key}: {text!r} compares a quantity, duration or version; use quantity(), duration() "
                "or semver() in CEL",
                ok=False,
            )
            return
        n = int(num)
        # Kyverno compares a number pattern as a quantity and reads a missing field as 0 (pattern.go).
        out.conds.append(f"{opt}.orValue(0) {op} {n}")
        good, bad = {">": (n + 1, n), ">=": (n, n - 1), "<": (n - 1, n), "<=": (n, n + 1)}[op]
        _put(out.good, opath, good)
        out.breaks.append((opath, bad))
        return
    negate = text.startswith("!")
    body = text[1:].strip() if negate else text
    if body in ("?*", "*"):
        if negate:
            out.bump("manual", f"{key}: {text!r} needs hand work", ok=False)
            return
        out.conds.append(f'{opt}.orValue("") != ""' if body == "?*" else f"{opt}.hasValue()")
        _put(out.good, opath, _sample(key))
        out.breaks.append((opath, _DELETE))
        return
    alts = [a.strip() for a in body.split("|")]  # pattern.go trims each alternative
    if any(not a for a in alts) or (negate and len(alts) > 1):
        out.bump("manual", f"{key}: {text!r} needs hand work", ok=False)
        return
    if any(_INT.match(a) for a in alts):
        if len(alts) > 1:
            out.bump("manual", f"{key}: {text!r} mixes numbers into alternatives; write the CEL by hand", ok=False)
            return
        # A number compares as a quantity, whatever the field's type, and a missing field reads as 0 (pattern.go).
        n = int(alts[0])
        out.conds.append(f'string({opt}.orValue(0)) {"!=" if negate else "=="} "{n}"')
        if negate:
            out.bump("inverted", f"{key}: {text!r} negates a value, so the CEL check states the allowed case")
        _put(out.good, opath, n + 1 if negate else n)
        out.breaks.append((opath, n if negate else n + 1))
        return
    if any(_QUANTITY.match(a) or _DURATION.match(a) for a in alts):
        out.bump(
            "manual",
            f"{key}: {text!r} compares as a Kubernetes quantity or a duration; use quantity() or duration() in CEL",
            ok=False,
        )
        return
    wild = any("*" in a or "?" in a for a in alts)
    if negate:
        out.bump("inverted", f"{key}: {text!r} negates a value, so the CEL check states the allowed case")
    typed = any(a in ("true", "false") for a in alts)  # matches a boolean field too (pattern.go compareString)
    if not wild and not typed and len(alts) == 1:
        lit = json.dumps(alts[0])
        out.conds.append(f"{opt}.hasValue() && {plain} != {lit}" if negate else f'{opt}.orValue("") == {lit}')
    elif not wild and not typed and not negate:
        out.conds.append(f'{opt}.orValue("") in {cel_literal(alts)}')
    else:
        tests = [_str_test(f"string({plain})", a) for a in alts]
        joined = tests[0] if len(tests) == 1 else "(" + " || ".join(tests) + ")"
        out.conds.append(f"{opt}.hasValue() && " + (f"!{joined}" if len(tests) == 1 and negate else joined))
    matching = _instance(alts[0], key)
    other = _not_matching(alts, key)
    sample_good, sample_bad = (other, matching) if negate else (matching, other)
    if sample_good is None:
        out.bump("direct", f"{key}: no sample value avoids {text!r}; write the fixture value by hand")
        return
    _put(out.good, opath, sample_good)
    if sample_bad is not None:
        out.breaks.append((opath, sample_bad))


# --- JMESPath conditions (deny, preconditions, cleanup conditions, exception conditions) ---------------------------

_TEMPLATE = re.compile(r"^\{\{\s*(?P<expr>[^{}]*?)\s*\}\}\Z")
_SEG = r'(?:\.(?:[A-Za-z_][A-Za-z0-9_]*|"[^"\\]+"))'
_REF = re.compile(
    rf"^(?P<root>request\.object|request\.oldObject|element)(?P<rest>{_SEG}*)"
    r"(?:\s*\|\|\s*(?P<default>'[^']*'|`[^`]*`))?\Z"
)
_SEG_RE = re.compile(r'\.(?:(?P<id>[A-Za-z_][A-Za-z0-9_]*)|"(?P<q>[^"\\]+)")')
_ROOTS = {"request.object": "object", "request.oldObject": "oldObject"}
_PLAIN_REFS = {
    "request.operation": "request.operation",
    "request.userInfo.username": "request.userInfo.username",
    "request.namespace": "object.metadata.namespace",  # migration-to-cel.md, "Context Variables"
}
_SET_OPS = {"In": False, "AnyIn": False, "AllIn": False, "NotIn": True, "AnyNotIn": True, "AllNotIn": True}
_NUM_OPS = {
    "GreaterThan": (">", "<="),
    "GreaterThanOrEquals": (">=", "<"),
    "LessThan": ("<", ">="),
    "LessThanOrEquals": ("<=", ">"),
}


@dataclass(frozen=True)
class _Cond:
    pos: str  # CEL true when the legacy condition is true
    neg: str  # CEL true when it is false
    path: tuple[str, ...] | None = None  # field of request.object it reads, for fixtures
    true_value: Any = None
    false_value: Any = None


def _other(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    return f"{value}-other" if value else "other"


def _ref(key: Any, element: str | None) -> tuple[str, tuple[str, ...] | None] | None:
    """CEL for a ``{{ request.object.x }}`` style key, and the request.object path it reads."""
    if not isinstance(key, str):
        return None
    m = _TEMPLATE.match(key.strip())
    if not m:
        return None
    expr = m["expr"].strip()
    if expr in _PLAIN_REFS:
        return _PLAIN_REFS[expr], None
    r = _REF.match(expr)
    if not r:
        return None
    root = r["root"]
    if root == "element":
        if element is None:
            return None
        base = element
    else:
        base = _ROOTS[root]
    segs = tuple(s["id"] or s["q"] for s in _SEG_RE.finditer(r["rest"]))
    chain = _Chain(base, segs)
    path = segs if root == "request.object" else None
    if r["default"] is None:
        return chain.plain, path
    raw = r["default"]
    if raw.startswith("'"):
        default: Any = raw[1:-1]
    else:
        try:
            default = json.loads(raw[1:-1])
        except ValueError:
            return None
        if isinstance(default, dict | list):
            return None
    return f"{chain.opt}.orValue({cel_literal(default)})", path


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _scalar(value: Any) -> bool:
    return isinstance(value, str | int | bool) and not (isinstance(value, str) and "{{" in value)


def _condition(cond: Any, element: str | None) -> _Cond | None:
    if not isinstance(cond, dict) or set(cond) - {"key", "operator", "value", "message"}:
        return None
    ref = _ref(cond.get("key"), element)
    if ref is None:
        return None
    k, path = ref
    op, value = cond.get("operator"), cond.get("value")
    tv: Any
    fv: Any
    if op in ("Equals", "NotEquals"):
        if not _scalar(value):
            return None
        if isinstance(value, str) and ("*" in value or "?" in value):
            test = _str_test(f"string({k})", value)
            pos, neg, tv, fv = test, f"!{test}", _instance(value, path[-1] if path else ""), _not_matching([value], "")
        else:
            lit = cel_literal(value)
            pos, neg, tv, fv = f"{k} == {lit}", f"{k} != {lit}", value, _other(value)
        if op == "NotEquals":
            pos, neg, tv, fv = neg, pos, fv, tv
        return _Cond(pos, neg, path, tv, fv)
    if op in _SET_OPS:
        values = value if isinstance(value, list) else [value]
        if not values or not all(_scalar(v) for v in values):
            return None
        if any(isinstance(v, str) and ("*" in v or "?" in v) for v in values):
            return None
        test = f"{k} in {cel_literal(values)}"
        pos, neg, tv, fv = test, f"!({test})", values[0], _other(values[0])
        if _SET_OPS[op]:
            pos, neg, tv, fv = neg, pos, fv, tv
        return _Cond(pos, neg, path, tv, fv)
    if op in _NUM_OPS:
        if isinstance(value, bool) or not (isinstance(value, int) or (isinstance(value, str) and _INT.match(value))):
            return None
        n = int(value)
        p_op, n_op = _NUM_OPS[op]
        tv, fv = {">": (n + 1, n), ">=": (n, n - 1), "<": (n - 1, n), "<=": (n, n + 1)}[p_op]
        return _Cond(f"{k} {p_op} {n}", f"{k} {n_op} {n}", path, tv, fv)
    return None


@dataclass(frozen=True)
class _Conds:
    pos: str
    neg: str
    single: _Cond | None


def _conditions(conds: Any, element: str | None = None) -> _Conds | None:
    """A legacy condition block (a list, or any/all) as CEL, or None when it needs hand work."""
    if isinstance(conds, list):
        blocks: list[tuple[str, Any]] = [("all", conds)]
    elif isinstance(conds, dict) and conds and not set(conds) - {"any", "all"}:
        blocks = [(k, conds[k]) for k in ("any", "all") if k in conds]
    else:
        return None
    parts: list[str] = []
    every: list[_Cond] = []
    for kind, items in blocks:
        if not isinstance(items, list) or not items:
            return None
        tr = [_condition(c, element) for c in items]
        if any(t is None for t in tr):
            return None
        done = [t for t in tr if t is not None]
        every += done
        # Each condition is one comparison, which binds tighter than && and || in CEL.
        if len(done) == 1:
            parts.append(done[0].pos)
        elif kind == "any":
            parts.append("(" + " || ".join(t.pos for t in done) + ")")
        else:
            parts.append(" && ".join(t.pos for t in done))
    if len(every) == 1:
        return _Conds(every[0].pos, every[0].neg, every[0])
    pos = " && ".join(parts)
    grouped = len(parts) == 1 and blocks[0][0] == "any"
    return _Conds(pos, f"!{pos}" if grouped else f"!({pos})", None)


# --- JMESPath scan -----------------------------------------------------------------------------------------------

_TEMPLATES = re.compile(r"\{\{(.*?)\}\}", re.DOTALL)
_FUNC = re.compile(r"\b([a-z_][a-z0-9_]*)\s*\(")
_JMES_KEYS = frozenset({"jmesPath", "list"})


def _functions(text: str, raw: bool) -> list[str]:
    blobs = [text] if raw else _TEMPLATES.findall(text)
    return list(dict.fromkeys(f for b in blobs for f in _FUNC.findall(b)))


def _walk_strings(node: Any, path: PathT) -> list[tuple[PathT, str, bool]]:
    """Every string under a node with its path; True when the field holds raw JMESPath (no braces)."""
    out: list[tuple[PathT, str, bool]] = []
    stack: list[tuple[Any, PathT]] = [(node, path)]
    while stack:
        cur, p = stack.pop()
        if isinstance(cur, dict):
            stack.extend((v, (*p, str(k))) for k, v in reversed(list(cur.items())))
        elif isinstance(cur, list):
            stack.extend((v, (*p, i)) for i, v in reversed(list(enumerate(cur))))
        elif isinstance(cur, str):
            out.append((p, cur, bool(p) and p[-1] in _JMES_KEYS))
    return out


# --- findings ----------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    rule: str | None
    path: str
    line: int
    verdict: Verdict
    target: str
    maps_to: str
    reason: str
    source: str  # "<SOURCES key>: <section>", several joined with "; "

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "path": self.path,
            "line": self.line,
            "verdict": self.verdict,
            "target": self.target,
            "mapsTo": self.maps_to,
            "reason": self.reason,
            "source": self.source,
        }


def _worst(verdicts: Iterable[str]) -> Verdict | None:
    out: Verdict | None = None
    for v in verdicts:
        if v in _RANK and (out is None or _RANK[v] > _RANK[out]):
            out = VERDICTS[_RANK[v]]
    return out


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """One finding per path: the most severe wins (a blocked JMESPath function over the manual lookup it sits in)."""
    best: dict[str, Finding] = {}
    order: list[str] = []
    for f in findings:
        cur = best.get(f.path)
        if cur is None:
            order.append(f.path)
            best[f.path] = f
        elif _RANK[f.verdict] > _RANK[cur.verdict]:
            best[f.path] = f
    return [best[p] for p in order]


class _Out:
    """Collects findings for one policy document."""

    def __init__(self, doc: Document, target: str) -> None:
        self.doc = doc
        self.target = target
        self.findings: list[Finding] = []

    def add(
        self,
        path: PathT,
        verdict: Verdict,
        maps_to: str,
        reason: str,
        source: str,
        rule: str | None = None,
        target: str | None = None,
    ) -> None:
        self.findings.append(
            Finding(
                rule=rule,
                path=fmt_path(path),
                line=self.doc.line_for(path),
                verdict=verdict,
                target=target or self.target,
                maps_to=maps_to,
                reason=reason,
                source=source,
            )
        )

    def row(
        self,
        path: PathT,
        m: Mapping,
        rule: str | None = None,
        target: str | None = None,
        extra: str = "",
        maps_to: str | None = None,
    ) -> None:
        self.add(path, m.verdict, maps_to or m.maps_to, m.reason + extra, f"{m.source}: {m.section}", rule, target)

    def unknown(self, path: PathT, rule: str | None = None, target: str | None = None) -> None:
        self.add(
            path,
            "manual",
            "decide by hand",
            "not in the migration guide's tables: check whether the CEL policy needs it",
            f"{_MIG}: Policy Settings",
            rule,
            target,
        )

    def scan_jmespath(self, node: Any, path: PathT, rule: str | None, target: str) -> None:
        for p, text, raw in _walk_strings(node, path):
            if p and p[-1] == "name":
                continue
            fns = _functions(text, raw)
            blocked = [f for f in fns if f in JMESPATH_BLOCKED]
            if blocked:
                names = ", ".join(f"{f}()" for f in blocked)
                self.add(
                    p,
                    "blocked",
                    "no CEL equivalent documented",
                    f"uses {names}: the JMESPath-to-CEL guide lists it as not supported in CEL",
                    "jmespath-to-cel: Unsupported or partially supported filters",
                    rule,
                    target,
                )


# --- match and exclude -------------------------------------------------------------------------------------------

_OPERATIONS = frozenset({"CREATE", "UPDATE", "DELETE", "CONNECT"})
_FILTER_KEYS = frozenset({"resources", "subjects", "roles", "clusterRoles"})


@dataclass
class _Match:
    rules: list[dict[str, Any]] = field(default_factory=list)
    namespace_selector: dict[str, Any] | None = None
    object_selector: dict[str, Any] | None = None
    ok: bool = True
    kinds: list[tuple[str, Gvr]] = field(default_factory=list)
    pod_only: bool = False


def _group_rules(
    entries: list[tuple[Gvr, str]], operations: list[str] | None, names: list[str] | None
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[str]] = {}
    for gvr, sub in entries:
        res = gvr.plural + (f"/{sub.lower()}" if sub else "")
        bucket = grouped.setdefault((gvr.group, gvr.version), [])
        if res not in bucket:
            bucket.append(res)
    out: list[dict[str, Any]] = []
    for (g, v), resources in grouped.items():
        rule: dict[str, Any] = {"apiGroups": [g], "apiVersions": [v]}
        if operations is not None:
            rule["operations"] = list(operations)
        rule["resources"] = resources
        if names:
            rule["resourceNames"] = list(names)
        out.append(rule)
    return out


def _filters(block: Any, base: PathT, out: _Out, rule: str | None) -> list[tuple[PathT, dict[str, Any]]] | None:
    if not isinstance(block, dict):
        out.add(
            base,
            "manual",
            "spec.matchConstraints",
            "not a mapping: write the match by hand",
            f"{_MIG}: Rule Fields",
            rule,
        )
        return None
    found: list[tuple[PathT, dict[str, Any]]] = []
    modes = [m for m in ("any", "all") if m in block]
    if len(modes) == 2:
        out.add(
            base,
            "manual",
            "spec.matchConstraints and spec.matchConditions",
            "any and all together: combine them in matchConditions by hand",
            f"{_MIG}: Rule Fields",
            rule,
        )
        return None
    for mode in modes:
        items = block[mode]
        if not isinstance(items, list) or not items:
            out.add(
                (*base, mode),
                "manual",
                "spec.matchConstraints",
                f"{mode} is not a non-empty list",
                f"{_MIG}: Rule Fields",
                rule,
            )
            return None
        for j, item in enumerate(items):
            if not isinstance(item, dict):
                out.add(
                    (*base, mode, j), "manual", "spec.matchConstraints", "not a mapping", f"{_MIG}: Rule Fields", rule
                )
                return None
            found.append(((*base, mode, j), item))
        if mode == "all" and len(items) > 1:
            out.add(
                (*base, mode),
                "manual",
                "spec.matchConditions",
                "all with several filters must hold together: express them in matchConditions by hand",
                f"{_MIG}: Rule Fields",
                rule,
            )
            return None
    if _FILTER_KEYS & set(block):
        found.append((base, block))
    if not found:
        out.add(
            base, "manual", "spec.matchConstraints", "matches nothing kube-noob can read", f"{_MIG}: Rule Fields", rule
        )
        return None
    return found


def _resource_filter(
    res: Any, fpath: PathT, out: _Out, rule: str | None, exclude: bool, operations: list[str] | None, m: _Match
) -> list[tuple[Gvr, str]] | None:
    """Findings for one ``resources`` filter; the kinds it selects, or None when it needs hand work."""
    rpath = (*fpath, "resources")
    if not isinstance(res, dict):
        out.add(rpath, "manual", "spec.matchConstraints", "not a mapping", f"{_MIG}: Rule Fields", rule)
        return None
    row = _EXCLUDE if exclude else _MATCH
    src = f"{row.source}: {row.section}"
    entries: list[tuple[Gvr, str]] = []
    good = True
    kinds = res.get("kinds")
    if exclude and kinds is None:
        # An exclude without kinds narrows the matched kinds (by namespace, name, selector...): its other fields say
        # what it needs; only names and operations need resource rules of their own.
        if {"names", "name", "operations"} & set(res):
            out.add(
                (*rpath, "kinds"),
                "manual",
                row.maps_to,
                "an exclude with names or operations but no kinds: list the kinds it applies to",
                src,
                rule,
            )
            good = False
    elif not isinstance(kinds, list) or not kinds:
        out.add(
            (*rpath, "kinds"),
            "manual",
            row.maps_to,
            "no kinds: list them, or select resources with a matchCondition",
            src,
            rule,
        )
        good = False
    else:
        resolved: list[str] = []
        for raw in kinds:
            r = _resolve_kind(str(raw))
            if isinstance(r, str):
                out.add((*rpath, "kinds"), "manual", row.maps_to, r, src, rule)
                good = False
                break
            kind, gvr, sub = r
            entries.append((gvr, sub))
            m.kinds.append((kind, gvr))
            resolved.append(f"{raw} -> {gvr.plural}{'/' + sub.lower() if sub else ''}")
        if good:
            where = "spec.matchConstraints.excludeResourceRules" if exclude else "spec.matchConstraints.resourceRules"
            out.add((*rpath, "kinds"), "direct", where, "; ".join(resolved), src, rule)
    for key in res:
        kp = (*rpath, key)
        val = res[key]
        if key == "kinds":
            continue
        if key == "operations":
            if isinstance(val, list) and val and all(isinstance(o, str) and o in _OPERATIONS for o in val):
                out.add(
                    kp,
                    "direct",
                    f"{'excludeResourceRules' if exclude else 'resourceRules'}[].operations",
                    "same operations",
                    src,
                    rule,
                )
            else:
                out.add(kp, "manual", "resourceRules[].operations", "operations kube-noob cannot read", src, rule)
                good = False
        elif key in ("names", "name"):
            names = val if isinstance(val, list) else [val]
            if all(isinstance(n, str) and n and not any(c in n for c in "*?{") for n in names):
                out.add(kp, "direct", "resourceRules[].resourceNames", "exact names", src, rule)
            else:
                out.add(
                    kp,
                    "manual",
                    "spec.matchConditions on object.metadata.name",
                    "wildcard names: compare object.metadata.name in a matchCondition",
                    src,
                    rule,
                )
                good = False
        elif key == "namespaces":
            exact = (
                isinstance(val, list)
                and val
                and all(isinstance(n, str) and n and not any(c in n for c in "*?{") for n in val)
            )
            if exclude:
                out.add(
                    kp,
                    "manual",
                    "spec.matchConstraints.namespaceSelector (NotIn) or spec.matchConditions",
                    "the guide maps exclude to excludeResourceRules, which select resources, not namespaces: add "
                    "a namespaceSelector NotIn kubernetes.io/metadata.name or a matchCondition",
                    src,
                    rule,
                )
                good = False
            elif exact and m.namespace_selector is None:
                m.namespace_selector = {
                    "matchExpressions": [
                        {"key": "kubernetes.io/metadata.name", "operator": "In", "values": [str(n) for n in val]}
                    ]
                }
                out.add(
                    kp,
                    "direct",
                    "spec.matchConstraints.namespaceSelector",
                    "kubernetes.io/metadata.name In the listed namespaces",
                    src,
                    rule,
                )
            else:
                out.add(
                    kp,
                    "manual",
                    "spec.matchConditions on object.metadata.namespace",
                    "wildcard namespaces or a second namespace filter: compare in a matchCondition",
                    src,
                    rule,
                )
                good = False
        elif key in ("selector", "namespaceSelector"):
            target = "object_selector" if key == "selector" else "namespace_selector"
            if exclude or not isinstance(val, dict) or getattr(m, target) is not None:
                out.add(
                    kp,
                    "manual",
                    f"spec.matchConstraints.{'objectSelector' if key == 'selector' else key}",
                    "an exclude selector (or a second selector) has to be negated or combined by hand",
                    src,
                    rule,
                )
                good = False
            else:
                setattr(m, target, copy.deepcopy(val))
                out.add(
                    kp,
                    "direct",
                    f"spec.matchConstraints.{'objectSelector' if key == 'selector' else key}",
                    "same label selector",
                    src,
                    rule,
                )
        elif key == "annotations":
            out.add(
                kp,
                "manual",
                "spec.matchConditions on object.metadata.annotations",
                "annotation filters become a CEL matchCondition",
                src,
                rule,
            )
            good = False
        else:
            out.unknown(kp, rule)
            good = False
    return entries if good else None


def _match(
    block: Any,
    base: PathT,
    out: _Out,
    rule: str | None,
    operations: list[str] | None,
    m: _Match,
    exclude: bool = False,
) -> None:
    filters = _filters(block, base, out, rule)
    if filters is None:
        m.ok = False
        return
    union: list[tuple[Gvr, str]] = []
    shapes: set[tuple[str, ...]] = set()
    for fpath, flt in filters:
        for key in ("subjects", "roles", "clusterRoles"):
            if key in flt:
                out.add(
                    (*fpath, key),
                    "manual",
                    "spec.matchConditions on request.userInfo",
                    "who sent the request becomes a CEL matchCondition",
                    f"{_MIG}: Rule Fields",
                    rule,
                )
                m.ok = False
        for key in flt:
            if key not in _FILTER_KEYS:
                out.unknown((*fpath, key), rule)
                m.ok = False
        if "resources" not in flt:
            continue
        res = flt["resources"]
        ops = res.get("operations") if isinstance(res, dict) else None
        own_ops = list(ops) if isinstance(ops, list) else operations
        entries = _resource_filter(res, fpath, out, rule, exclude, own_ops, m)
        if entries is None:
            m.ok = False
            continue
        shapes.add(tuple(sorted(k for k in res if k != "kinds")))
        union += entries
        if own_ops != operations:
            operations = own_ops
    if len(filters) > 1 and (len(shapes) > 1 or any(s for s in shapes)):
        out.add(
            base,
            "manual",
            "spec.matchConditions",
            "several filters with different fields: OR them in a matchCondition by hand",
            f"{_MIG}: Rule Fields",
            rule,
        )
        m.ok = False
    if m.ok and union:
        names: list[str] | None = None
        for _, flt in filters:
            res = flt.get("resources")
            if isinstance(res, dict) and ("names" in res or "name" in res):
                raw = res.get("names", res.get("name"))
                names = [str(n) for n in (raw if isinstance(raw, list) else [raw])]
        m.rules = _group_rules(union, operations, names)
        m.pod_only = (
            not exclude
            and len(union) == 1
            and union[0][0].plural == "pods"
            and not union[0][1]
            and names is None
            and m.object_selector is None
        )


# --- rules -------------------------------------------------------------------------------------------------------


def _target(base: str, namespaced: bool) -> str:
    return ("Namespaced" + base) if namespaced else base


_ACTIONS = {
    "validate": "ValidatingPolicy",
    "mutate": "MutatingPolicy",
    "generate": "GeneratingPolicy",
    "verifyImages": "ImageValidatingPolicy",
}
_TEST_FLAGS = {
    "ValidatingPolicy": "isValidatingPolicy",
    "MutatingPolicy": "isMutatingPolicy",
    "GeneratingPolicy": "isGeneratingPolicy",
    "ImageValidatingPolicy": "isImageValidatingPolicy",
}


@dataclass
class _Rule:
    name: str
    index: int
    line: int
    action: str | None
    target: str
    match: _Match = field(default_factory=_Match)
    exclude: _Match = field(default_factory=_Match)
    spec: dict[str, Any] | None = None  # the draft's action-specific spec, when every field maps
    match_conditions: list[dict[str, str]] = field(default_factory=list)
    variables: list[dict[str, str]] = field(default_factory=list)
    good: dict[str, Any] | None = None
    breaks: list[tuple[tuple[str | int, ...], Any]] = field(default_factory=list)
    draftable: bool = True


def _context(entries: Any, base: PathT, out: _Out, r: _Rule) -> None:
    src = f"{_CONTEXT.source}: {_CONTEXT.section}"
    if not isinstance(entries, list):
        out.add(base, "manual", "spec.variables", "context is not a list", src, r.name)
        r.draftable = False
        return
    for j, entry in enumerate(entries):
        p = (*base, j)
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            out.add(p, "manual", "spec.variables", "a context entry needs a name", src, r.name)
            r.draftable = False
            continue
        name = entry["name"]
        if "variable" in entry:
            var = entry["variable"]
            if (
                isinstance(var, dict)
                and set(var) == {"value"}
                and not any("{{" in s for _, s, _ in _walk_strings(var["value"], ()))
                and _IDENT.match(name)
            ):
                r.variables.append({"name": name, "expression": cel_literal(var["value"])})
                out.add(
                    (*p, "variable", "value"),
                    "direct",
                    "spec.variables",
                    "a static value becomes a CEL literal",
                    src,
                    r.name,
                )
                continue
            hints = ""
            if isinstance(var, dict) and isinstance(var.get("jmesPath"), str):
                known = [f for f in _functions(var["jmesPath"], True) if f in JMESPATH_TO_CEL]
                hints = "".join(f"; {f}() -> {JMESPATH_TO_CEL[f]}" for f in known)
                p2: PathT = (*p, "variable", "jmesPath")
            else:
                p2 = (*p, "variable")
            out.add(
                p2,
                "manual",
                "spec.variables",
                "a JMESPath expression: translate it with the JMESPath-to-CEL guide" + hints,
                f"{src}; jmespath-to-cel: Quick Reference",
                r.name,
            )
        elif "apiCall" in entry:
            call = _mapping(entry["apiCall"])
            service = "service" in call
            post = str(call.get("method", "GET")).upper() == "POST"
            fn = (
                ("http.Post()" if post else "http.Get()")
                if service
                else ("resource.Post()" if post else "resource.Get() or resource.List()")
            )
            out.add(
                (*p, "apiCall"),
                "manual",
                f"spec.variables with {fn}",
                "an API call becomes a CEL lookup; its jmesPath projection becomes CEL too",
                f"{src}; cel-libraries: {'HTTP library' if service else 'Resource library'}",
                r.name,
            )
        else:
            kind = next((k for k in _CONTEXT_KINDS if k in entry), None)
            if kind is None:
                out.unknown(p, r.name)
            else:
                maps_to, lib = _CONTEXT_KINDS[kind]
                out.add(
                    (*p, kind),
                    "manual",
                    maps_to,
                    f"a {kind} lookup becomes a CEL library call",
                    f"{src}; cel-libraries: {lib}",
                    r.name,
                )
        r.draftable = False


def _preconditions(conds: Any, base: PathT, out: _Out, r: _Rule) -> None:
    tr = _conditions(conds)
    src = f"{_PRECONDITIONS.source}: {_PRECONDITIONS.section}"
    if tr is None:
        out.add(
            base,
            "manual",
            "spec.matchConditions",
            "the conditions use JMESPath kube-noob does not translate (functions, projections, context variables "
            "or operators): write the CEL matchCondition by hand",
            f"{src}; legacy-preconditions: Operators",
            r.name,
        )
        r.draftable = False
        return
    r.match_conditions.append({"name": "preconditions", "expression": tr.pos})
    out.add(base, "direct", "spec.matchConditions", "the conditions translate to CEL", src, r.name)


def _actions_text(actions: list[str]) -> str:
    return f"spec.validationActions: [{', '.join(actions)}]"


def _validation_actions(value: Any) -> list[str] | None:
    if not isinstance(value, str):
        return None
    return {"enforce": ["Deny"], "audit": ["Audit"]}.get(value.lower())


def _validate(body: dict[str, Any], base: PathT, out: _Out, r: _Rule) -> None:
    validations: list[dict[str, Any]] = []
    spec: dict[str, Any] = {}
    message = body.get("message")
    for key, value in body.items():
        kp = (*base, key)
        row = VALIDATE_FIELDS.get(key)
        if key == "message":
            if isinstance(value, str) and "{{" in value:
                out.row(kp, _MESSAGE_VARS, r.name)
                r.draftable = False
            else:
                out.row(kp, VALIDATE_FIELDS["message"], r.name)
        elif key == "failureAction":
            actions = _validation_actions(value)
            if actions is None:
                out.add(
                    kp,
                    "manual",
                    "spec.validationActions",
                    f"unknown failure action {value!r}",
                    f"{_MIG}: Validate Rule",
                    r.name,
                )
                r.draftable = False
            else:
                spec["validationActions"] = actions
                out.row(kp, VALIDATE_FIELDS["failureAction"], r.name, maps_to=_actions_text(actions))
        elif key in ("pattern", "anyPattern"):
            patterns = [value] if key == "pattern" else value
            if not isinstance(patterns, list) or not patterns:
                out.add(
                    kp,
                    "manual",
                    "spec.validations",
                    "anyPattern is not a non-empty list",
                    f"{_MIG}: Validate Rule",
                    r.name,
                )
                r.draftable = False
                continue
            pieces = []
            for pat in patterns:
                c = _Cel()
                _walk_pattern(pat, _Chain("object"), (), c, 1)
                pieces.append(c)
            cel = _Cel()
            for c in pieces:
                cel.absorb(c)
            row = VALIDATE_FIELDS[key]
            if not cel.ok:
                out.add(
                    kp,
                    "manual",
                    row.maps_to,
                    "; ".join(cel.notes),
                    f"{row.source}: {row.section}; legacy-validate: Anchors",
                    r.name,
                )
                r.draftable = False
                continue
            if any(not c.conds for c in pieces):
                out.add(
                    kp,
                    "manual",
                    row.maps_to,
                    "a pattern with no checks needs hand work",
                    f"{row.source}: {row.section}",
                    r.name,
                )
                r.draftable = False
                continue
            exprs = [" &&\n".join(c.conds) for c in pieces]
            expr = exprs[0] if len(exprs) == 1 else " ||\n".join(f"({e})" for e in exprs)
            validations.append({"expression": expr})
            notes = "; ".join(cel.notes)
            out.add(
                kp,
                cel.verdict,
                row.maps_to,
                row.reason + (f" ({notes})" if notes else ""),
                f"{row.source}: {row.section}; kyverno-pattern: Validate()",
                r.name,
            )
            r.good = pieces[0].good
            r.breaks = pieces[0].breaks if len(pieces) == 1 else []
        elif key == "deny":
            row = VALIDATE_FIELDS["deny"]
            conds = value.get("conditions") if isinstance(value, dict) else None
            if isinstance(value, dict) and not value:
                validations.append({"expression": "false"})
                out.row(kp, row, r.name, extra="; no conditions: every matched request is denied")
                continue
            tr = _conditions(conds)
            if tr is None:
                out.add(
                    kp,
                    "manual",
                    row.maps_to,
                    row.reason + "; the conditions use JMESPath kube-noob does not "
                    "translate (functions, projections, context variables or operators)",
                    f"{row.source}: {row.section}; legacy-preconditions: Operators",
                    r.name,
                )
                r.draftable = False
                continue
            validations.append({"expression": tr.neg})
            out.row(kp, row, r.name)
            if tr.single is not None and tr.single.path:
                r.good = {}
                _put(r.good, tr.single.path, tr.single.false_value)
                r.breaks = [(tr.single.path, tr.single.true_value)]
        elif key == "foreach":
            _foreach(value, kp, out, r, validations)
        elif key == "cel":
            _validate_cel(value, kp, out, r, validations, spec)
        elif row is not None:
            out.row(kp, row, r.name)
            if row.verdict in ("manual", "blocked"):
                r.draftable = False
        else:
            out.unknown(kp, r.name)
            r.draftable = False
    if message is not None and isinstance(message, str):
        for v in validations:
            v.setdefault("message", message)
    if not validations:
        r.draftable = False
    spec["validations"] = validations
    r.spec = spec


def _foreach(value: Any, kp: PathT, out: _Out, r: _Rule, validations: list[dict[str, Any]]) -> None:
    row = VALIDATE_FIELDS["foreach"]
    src = f"{row.source}: {row.section}"
    if not isinstance(value, list) or not value:
        out.add(kp, "manual", row.maps_to, "foreach is not a non-empty list", src, r.name)
        r.draftable = False
        return
    conds: list[str] = []
    total = _Cel()
    good: dict[str, Any] = {}
    breaks: list[tuple[tuple[str | int, ...], Any]] = []
    problems: list[str] = []
    for j, entry in enumerate(value):
        if not isinstance(entry, dict):
            problems.append(f"entry {j} is not a mapping")
            continue
        extra = sorted(set(entry) - {"list", "pattern", "deny"})
        if extra:
            problems.append(f"entry {j} uses {', '.join(extra)}")
            continue
        lst = entry.get("list")
        ref = _ref("{{ " + lst + " }}", None) if isinstance(lst, str) else None
        if ref is None or ref[1] is None or "orValue" in ref[0]:
            problems.append(f"entry {j} loops over {lst!r}, not a plain request.object field")
            continue
        segs = ref[1]
        chain = _Chain("object", segs)
        if "pattern" in entry and "deny" not in entry:
            c = _Cel()
            _walk_pattern(entry["pattern"], _Chain("el"), (), c, 1)
            total.absorb(c)
            if not c.ok or not c.conds:
                problems.append(f"entry {j}: " + ("; ".join(c.notes) or "no checks"))
                continue
            conds.append(f"{chain.opt}.orValue([]).all(el, {' && '.join(c.conds)})")
            _put(good, segs, [c.good])
            breaks += [((*segs, 0, *p), v) for p, v in c.breaks]
        elif "deny" in entry and "pattern" not in entry:
            deny = entry["deny"]
            tr = _conditions(deny.get("conditions") if isinstance(deny, dict) else None, "el")
            if tr is None:
                problems.append(f"entry {j}: the deny conditions need hand work")
                continue
            total.bump("inverted", "deny conditions are inverted into the allowed case")
            conds.append(f"{chain.opt}.orValue([]).all(el, {tr.neg})")
        else:
            problems.append(f"entry {j} needs exactly one of pattern or deny")
    if problems:
        anchors = any("anchor" in p for p in problems)
        out.add(
            kp,
            "manual",
            row.maps_to,
            "; ".join(problems) + (": nested anchors need hand work" if anchors else ""),
            f"{src}; legacy-validate: foreach",
            r.name,
        )
        r.draftable = False
        return
    validations.append({"expression": " &&\n".join(conds)})
    notes = "; ".join(total.notes)
    out.add(kp, total.verdict, row.maps_to, row.reason + (f" ({notes})" if notes else ""), src, r.name)
    r.good, r.breaks = good, breaks


_VALIDATION_KEYS = ("expression", "message", "messageExpression", "reason")


def _validate_cel(
    value: Any, kp: PathT, out: _Out, r: _Rule, validations: list[dict[str, Any]], spec: dict[str, Any]
) -> None:
    row = VALIDATE_FIELDS["cel"]
    src = f"{row.source}: {row.section}"
    if not isinstance(value, dict):
        out.add(kp, "manual", row.maps_to, "cel is not a mapping", src, r.name)
        r.draftable = False
        return
    for key, val in value.items():
        p = (*kp, key)
        if (
            key == "expressions"
            and isinstance(val, list)
            and val
            and all(isinstance(e, dict) and isinstance(e.get("expression"), str) for e in val)
        ):
            for e in val:
                validations.append({k: e[k] for k in _VALIDATION_KEYS if k in e})
                if set(e) - set(_VALIDATION_KEYS):
                    r.draftable = False
            out.row(p, row, r.name)
        elif key == "variables" and isinstance(val, list):
            r.variables += [dict(v) for v in val if isinstance(v, dict)]
            out.add(p, "direct", "spec.variables", "already CEL: copy the variables", src, r.name)
        elif key == "auditAnnotations" and isinstance(val, list):
            spec["auditAnnotations"] = copy.deepcopy(val)
            out.add(p, "direct", "spec.auditAnnotations", "same audit annotations", src, r.name)
        elif key == "generate":
            if val is True:
                spec["autogen"] = {"validatingAdmissionPolicy": {"enabled": True}}
            out.add(
                p,
                "direct",
                "spec.autogen.validatingAdmissionPolicy.enabled",
                "generating a ValidatingAdmissionPolicy is an autogen setting",
                "validating-policy: autogen",
                r.name,
            )
        elif key in ("paramKind", "paramRef"):
            out.add(
                p,
                "manual",
                "spec.variables (for example resource.Get())",
                "parameter resources are not in the migration guide's tables: read them with a CEL lookup",
                f"{src}; cel-libraries: Resource library",
                r.name,
            )
            r.draftable = False
        else:
            out.unknown(p, r.name)
            r.draftable = False


def _json_patch(text: Any, kp: PathT, out: _Out, r: _Rule) -> str | None:
    row = MUTATE_FIELDS["patchesJson6902"]
    src = f"{row.source}: {row.section}"
    ops: Any = text
    if isinstance(text, str):
        if "{{" in text:
            out.add(
                kp,
                "manual",
                row.maps_to,
                "the patch uses JMESPath variables: write the JSONPatch values in CEL",
                src,
                r.name,
            )
            return None
        try:
            docs = load_documents(text)
        except Exception:  # noqa: BLE001 - any parse failure means hand work, never a crash
            docs = []
        ops = docs[0].data if len(docs) == 1 else None
    if not isinstance(ops, list) or not ops:
        out.add(
            kp, "manual", row.maps_to, "the patch is not a list of RFC 6902 operations kube-noob can read", src, r.name
        )
        return None
    entries: list[str] = []
    for op in ops:
        if (
            not isinstance(op, dict)
            or op.get("op") not in ("add", "remove", "replace", "move", "copy", "test")
            or not isinstance(op.get("path"), str)
            or set(op) - {"op", "path", "value", "from"}
        ):
            out.add(kp, "manual", row.maps_to, "an operation kube-noob cannot read", src, r.name)
            return None
        fields = [f"op: {json.dumps(op['op'])}", f"path: {json.dumps(op['path'])}"]
        if "from" in op:
            fields.append(f"from: {json.dumps(str(op['from']))}")
        if "value" in op:
            fields.append(f"value: {cel_literal(op['value'])}")
        entries.append("JSONPatch{" + ", ".join(fields) + "}")
    out.row(kp, row, r.name)
    return "[\n  " + ",\n  ".join(entries) + "\n]"


def _mutate(body: dict[str, Any], base: PathT, out: _Out, r: _Rule) -> None:
    mutations: list[dict[str, Any]] = []
    spec: dict[str, Any] = {}
    for key, value in body.items():
        kp = (*base, key)
        if key == "patchesJson6902":
            expr = _json_patch(value, kp, out, r)
            if expr is None:
                r.draftable = False
            else:
                mutations.append({"patchType": "JSONPatch", "jsonPatch": {"expression": expr}})
        elif key == "mutateExistingOnPolicyUpdate":
            spec["evaluation"] = {"mutateExisting": {"enabled": bool(value)}}
            out.row(kp, MUTATE_FIELDS[key], r.name)
        elif key in MUTATE_FIELDS:
            row = MUTATE_FIELDS[key]
            extra = ""
            if key == "patchStrategicMerge" and any(
                _ANCHOR.match(str(k)) for p, _, _ in _walk_strings(value, ()) for k in p if isinstance(k, str)
            ):
                extra = "; it uses anchors, which become CEL conditions"
            out.row(kp, row, r.name, extra=extra)
            if row.verdict != "direct":
                r.draftable = False
        else:
            out.unknown(kp, r.name)
            r.draftable = False
    if not mutations:
        r.draftable = False
    spec["mutations"] = mutations
    r.spec = spec


def _generate(body: dict[str, Any], base: PathT, out: _Out, r: _Rule) -> None:
    present = [k for k in _GENERATE_EXPRESSIONS if k in body]
    if present:
        out.row(base, _GENERATE, r.name, extra=f": {', '.join(present)}")
    for key in body:
        if key in _GENERATE_EXPRESSIONS:
            continue
        kp = (*base, key)
        if key in GENERATE_FIELDS:
            out.row(kp, GENERATE_FIELDS[key], r.name)
        else:
            out.unknown(kp, r.name)
    r.draftable = False


def _verify_images(body: Any, base: PathT, out: _Out, r: _Rule) -> None:
    r.draftable = False
    if not isinstance(body, list) or not body:
        out.add(
            base,
            "manual",
            "ImageValidatingPolicy",
            "verifyImages is not a non-empty list",
            f"{_MIG}: Verify Images Rule",
            r.name,
        )
        return
    for j, entry in enumerate(body):
        if not isinstance(entry, dict):
            out.add(
                (*base, j), "manual", "ImageValidatingPolicy", "not a mapping", f"{_MIG}: Verify Images Rule", r.name
            )
            continue
        for key in entry:
            kp = (*base, j, key)
            if key in VERIFY_FIELDS:
                out.row(kp, VERIFY_FIELDS[key], r.name)
            else:
                out.unknown(kp, r.name)


def _rule(doc: Document, out: _Out, i: int, raw: Any, namespaced: bool, settings: dict[str, Any]) -> _Rule:
    base: PathT = ("spec", "rules", i)
    name = str(raw.get("name")) if isinstance(raw, dict) and raw.get("name") else f"rule-{i}"
    action = next((a for a in _ACTIONS if isinstance(raw, dict) and a in raw), None)
    target = _target(_ACTIONS[action], namespaced) if action else _target("ValidatingPolicy", namespaced)
    r = _Rule(name=name, index=i, line=doc.line_for(base), action=action, target=target)
    out.target = target
    if not isinstance(raw, dict):
        out.add(base, "manual", "a CEL policy", "the rule is not a mapping", f"{_MIG}: Rule Fields", name)
        r.draftable = False
        return r
    if action is None or sum(a in raw for a in _ACTIONS) != 1:
        out.add(
            base,
            "manual",
            "a CEL policy",
            "the rule needs exactly one of validate, mutate, generate or verifyImages",
            f"{_MIG}: Rule Fields",
            name,
        )
        r.draftable = False
        return r
    ops = ["CREATE", "UPDATE"]
    if "match" in raw:
        _match(raw["match"], (*base, "match"), out, name, ops, r.match)
    else:
        out.add(
            (*base, "match"), "manual", "spec.matchConstraints", "a rule without match", f"{_MIG}: Rule Fields", name
        )
        r.match.ok = False
    if "exclude" in raw:
        _match(raw["exclude"], (*base, "exclude"), out, name, ops, r.exclude, exclude=True)
    if not (r.match.ok and r.exclude.ok):
        r.draftable = False
    for key, value in raw.items():
        kp = (*base, key)
        if key in ("name", "match", "exclude", *_ACTIONS):
            continue
        if key == "context":
            _context(value, kp, out, r)
        elif key == "preconditions":
            _preconditions(value, kp, out, r)
        elif key == "celPreconditions" and isinstance(value, list):
            r.match_conditions += [dict(c) for c in value if isinstance(c, dict)]
            out.row(kp, RULE_FIELDS[key], name)
        elif key in RULE_FIELDS:
            out.row(kp, RULE_FIELDS[key], name)
            if RULE_FIELDS[key].verdict != "direct":
                r.draftable = False
            if key == "reportProperties":
                r.draftable = False  # a static report property has no expression yet
        else:
            out.unknown(kp, name)
            r.draftable = False
    body = raw[action]
    abase = (*base, action)
    if action == "verifyImages":
        _verify_images(body, abase, out, r)
    elif not isinstance(body, dict):
        out.add(abase, "manual", "a CEL policy", f"{action} is not a mapping", f"{_MIG}: Rule Fields", name)
        r.draftable = False
    elif action == "validate":
        _validate(body, abase, out, r)
        if r.spec is not None and "validationActions" not in r.spec:
            r.spec["validationActions"] = settings["validationActions"]
    elif action == "mutate":
        _mutate(body, abase, out, r)
    else:
        _generate(body, abase, out, r)
    out.scan_jmespath(raw, base, name, target)
    return r


# --- policy documents --------------------------------------------------------------------------------------------

_LEGACY_POLICY_KINDS = frozenset({"ClusterPolicy", "Policy"})
_CLEANUP_KINDS = frozenset({"ClusterCleanupPolicy", "CleanupPolicy"})


def _safe(name: str, limit: int = _MAX_NAME) -> str:
    out = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")
    return out[:limit].strip("-") or "policy"


def _ref_of(kind: str, name: str, ns: str | None) -> str:
    return f"{kind}/{ns}/{name}" if ns else f"{kind}/{name}"


def _header(lines: list[str]) -> str:
    """YAML comment lines. Names from the input reach them, so a newline in a name can never start a YAML line."""
    return "".join("# " + " ".join(sanitize.visible(line).split()) + "\n" for line in lines)


def _draft_text(source: str, obj: dict[str, Any], notes: list[str]) -> str:
    head = [
        "DRAFT, prove with kyverno test: kube-noob policy migrate-check wrote this from " + source + ".",
        "It is not a finished policy. Run the kyverno test fixture (legacy/ and cel/ on the same resources) and keep",
        "it only when both pass.",
        *notes,
    ]
    return _header(head) + dump_documents([obj])


_KEEP_ANNOTATIONS = (
    "policies.kyverno.io/title",
    "policies.kyverno.io/category",
    "policies.kyverno.io/severity",
    "policies.kyverno.io/subject",
    "policies.kyverno.io/description",
)


def _metadata(name: str, ns: str | None, annotations: dict[str, Any]) -> dict[str, Any]:
    meta: dict[str, Any] = {"name": name}
    if ns:
        meta["namespace"] = ns
    kept = {k: str(annotations[k]) for k in _KEEP_ANNOTATIONS if k in annotations}
    if kept:
        meta["annotations"] = kept
    return meta


def _match_constraints(r: _Rule, operations: bool = True) -> dict[str, Any]:
    rules = copy.deepcopy(r.match.rules)
    if not operations:
        for rule in rules:
            rule.pop("operations", None)
    out: dict[str, Any] = {"resourceRules": rules}
    if r.match.namespace_selector is not None:
        out["namespaceSelector"] = r.match.namespace_selector
    if r.match.object_selector is not None:
        out["objectSelector"] = r.match.object_selector
    if r.exclude.rules:
        out["excludeResourceRules"] = copy.deepcopy(r.exclude.rules)
    return out


def _policy_settings(spec: dict[str, Any], annotations: dict[str, Any]) -> dict[str, Any]:
    actions = _validation_actions(spec.get("validationFailureAction")) or ["Audit"]
    if spec.get("emitWarning") is True and "Warn" not in actions and actions != ["Deny"]:
        actions = [*actions, "Warn"]
    settings: dict[str, Any] = {"validationActions": actions, "evaluation": {}}
    for key in ("admission", "background"):
        if isinstance(spec.get(key), bool):
            settings["evaluation"][key] = {"enabled": spec[key]}
    webhook = _mapping(spec.get("webhookConfiguration"))
    failure = webhook.get("failurePolicy", spec.get("failurePolicy"))
    if failure in ("Fail", "Ignore"):
        settings["failurePolicy"] = failure
    timeout = webhook.get("timeoutSeconds", spec.get("webhookTimeoutSeconds"))
    if isinstance(timeout, int) and not isinstance(timeout, bool):
        settings["webhookConfiguration"] = {"timeoutSeconds": timeout}
    if isinstance(webhook.get("matchConditions"), list):
        settings["matchConditions"] = copy.deepcopy(webhook["matchConditions"])
    controllers = annotations.get(_AUTOGEN_KEY)
    if isinstance(controllers, str):
        if controllers.strip().lower() == "none":
            settings["autogen"] = {"podControllers": {"controllers": []}}
        else:
            plurals = [KINDS[c.strip()].plural for c in controllers.split(",") if c.strip() in KINDS]
            settings["autogen"] = {"podControllers": {"controllers": [p for p in plurals if p in _CEL_AUTOGEN]}}
    return settings


def _rule_draft(
    p: _Policy, r: _Rule, settings: dict[str, Any], notes: list[str]
) -> tuple[str, str, dict[str, Any]] | None:
    """(draft name, YAML text, object) for a rule whose every field maps, else None."""
    if not r.draftable or r.spec is None or r.action not in ("validate", "mutate") or not r.match.rules:
        return None
    name = p.name if len(p.rule_names) == 1 else f"{p.name}-{r.name}"
    name = name[:_DNS_SUBDOMAIN]
    spec: dict[str, Any] = {}
    if r.action == "validate":
        spec["validationActions"] = r.spec.get("validationActions", settings["validationActions"])
    evaluation = dict(settings["evaluation"]) if r.action == "validate" else {}
    evaluation.update(r.spec.get("evaluation", {}))
    if evaluation:
        spec["evaluation"] = evaluation
    autogen = copy.deepcopy(r.spec.get("autogen") or {})
    if r.action == "validate" and "autogen" in settings and r.match.pod_only and not r.exclude.rules:
        autogen.update(settings["autogen"])
    if autogen:
        spec["autogen"] = autogen
    for key in ("failurePolicy", "webhookConfiguration"):
        if key in settings:
            spec[key] = copy.deepcopy(settings[key])
    spec["matchConstraints"] = _match_constraints(r)
    conditions = [*settings.get("matchConditions", []), *r.match_conditions]
    if conditions:
        spec["matchConditions"] = conditions
    if r.variables:
        spec["variables"] = r.variables
    if r.action == "validate":
        spec["validations"] = r.spec["validations"]
        if "auditAnnotations" in r.spec:
            spec["auditAnnotations"] = r.spec["auditAnnotations"]
    else:
        spec["mutations"] = r.spec["mutations"]
    obj = {
        "apiVersion": "policies.kyverno.io/v1",
        "kind": r.target,
        "metadata": _metadata(name, p.namespace, p.annotations),
        "spec": spec,
    }
    return name, _draft_text(f"{p.ref} rule {r.name}", obj, notes), obj


@dataclass
class _Policy:
    doc: Document
    kind: str
    name: str
    namespace: str | None
    annotations: dict[str, Any]
    rule_names: list[str] = field(default_factory=list)

    @property
    def ref(self) -> str:
        return _ref_of(self.kind, self.name, self.namespace)


def _policy_level(spec: dict[str, Any], out: _Out, rules: list[_Rule], namespaced: bool) -> None:
    bases = {r.target for r in rules}
    validating = sorted(b for b in bases if b.endswith(("ValidatingPolicy",))) or [
        _target("ValidatingPolicy", namespaced)
    ]
    every = ", ".join(sorted(bases)) or _target("ValidatingPolicy", namespaced)
    for key, value in spec.items():
        kp: PathT = ("spec", key)
        if key == "rules":
            continue
        if key == "webhookConfiguration":
            if not isinstance(value, dict):
                out.unknown(kp, target=every)
                continue
            for sub in value:
                if sub in WEBHOOK_FIELDS:
                    out.row((*kp, sub), WEBHOOK_FIELDS[sub], target=every)
                else:
                    out.unknown((*kp, sub), target=every)
        elif key == "applyRules":
            if value == "One":
                out.row(kp, _APPLY_ONE, target=every)
        elif key == "useServerSideApply":
            if value:
                out.row(kp, POLICY_FIELDS[key], target=every)
        elif key in ("validationFailureAction", "emitWarning", "validationFailureActionOverrides"):
            extra = ""
            if key == "validationFailureAction":
                actions = _validation_actions(value)
                if actions is None:
                    out.add(
                        kp,
                        "manual",
                        "spec.validationActions",
                        f"unknown failure action {value!r}",
                        f"{_MIG}: Validate Rule",
                        target=", ".join(validating),
                    )
                    continue
                if isinstance(value, str) and value in ("enforce", "audit"):
                    extra = " (lowercase spellings are deprecated)"
                out.row(
                    kp, POLICY_FIELDS[key], target=", ".join(validating), extra=extra, maps_to=_actions_text(actions)
                )
                continue
            out.row(kp, POLICY_FIELDS[key], target=", ".join(validating))
        elif key in ("mutateExistingOnPolicyUpdate",):
            out.row(kp, POLICY_FIELDS[key], target=_target("MutatingPolicy", namespaced))
        elif key in ("generateExisting", "generateExistingOnPolicyUpdate"):
            out.row(kp, POLICY_FIELDS[key], target=_target("GeneratingPolicy", namespaced))
        elif key in POLICY_FIELDS:
            out.row(kp, POLICY_FIELDS[key], target=every)
        else:
            out.unknown(kp, target=every)


def _autogen_finding(p: _Policy, out: _Out, rules: list[_Rule]) -> None:
    pods = [r for r in rules if r.action == "validate" and r.match.pod_only and not r.exclude.rules]
    value = p.annotations.get(_AUTOGEN_KEY)
    if not pods and value is None:
        return
    path: PathT = ("metadata", "annotations", _AUTOGEN_KEY)
    shown = f'metadata.annotations["{_AUTOGEN_KEY}"]'
    src = "legacy-autogen: Auto-Gen Rules; kyverno-autogen: Autogen()"
    target = ", ".join(sorted({r.target for r in pods})) or _target("ValidatingPolicy", p.kind == "Policy")
    line = p.doc.line_for(path)
    if value is None:
        reason = (
            "not set: Kyverno generates Pod-controller rules for " + ", ".join(_LEGACY_AUTOGEN) + "; a CEL policy "
            "that matches only pods does the same by default for " + ", ".join(_CEL_AUTOGEN) + " (not "
            "replicationcontrollers), so leave spec.autogen unset unless ReplicationControllers matter"
        )
        verdict: Verdict = "direct"
    elif str(value).strip().lower() == "none":
        reason = "none: set spec.autogen.podControllers.controllers to [] to keep auto-generation off"
        verdict = "direct"
    else:
        names = [c.strip() for c in str(value).split(",") if c.strip()]
        unknown = [c for c in names if c not in KINDS or KINDS[c].plural not in _CEL_AUTOGEN]
        verdict = "manual" if unknown else "direct"
        reason = f"{value}: list the same controllers as plural resources" + (
            f" ({', '.join(unknown)} need the <resource>.<version>.<group> form or are not covered)" if unknown else ""
        )
    out.findings.append(
        Finding(None, shown, line, verdict, target, "spec.autogen.podControllers.controllers", reason, src)
    )


def _sample_object(kind: str, gvr: Gvr, name: str, ns: str | None) -> dict[str, Any]:
    meta: dict[str, Any] = {"name": name}
    if ns:
        meta["namespace"] = ns
    obj: dict[str, Any] = {"apiVersion": gvr.api_version, "kind": kind, "metadata": meta}
    container = {"name": "app", "image": _SAMPLES["image"]}
    if kind == "Pod":
        obj["spec"] = {"containers": [container]}
    elif kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"):
        obj["spec"] = {
            "selector": {"matchLabels": {"app": "app"}},
            "template": {"metadata": {"labels": {"app": "app"}}, "spec": {"containers": [container]}},
        }
    return obj


def _merge(base: Any, extra: Any) -> Any:
    if isinstance(base, dict) and isinstance(extra, dict):
        out = dict(base)
        for k, v in extra.items():
            out[k] = _merge(base[k], v) if k in base else copy.deepcopy(v)
        return out
    if isinstance(base, list) and isinstance(extra, list):
        return [_merge(base[i], v) if i < len(base) else copy.deepcopy(v) for i, v in enumerate(extra)] + base[
            len(extra) :
        ]
    return copy.deepcopy(extra)


def _fixture(
    p: _Policy, dirname: str, rules: list[_Rule], drafts: dict[int, tuple[str, str, dict[str, Any]]]
) -> dict[str, str]:
    """kyverno test skeleton: the legacy rule and its draft on the same good and bad resources, in two tests."""
    ns = p.namespace
    resources: list[str] = []
    legacy_results: list[dict[str, Any]] = []
    cel_results: list[dict[str, Any]] = []
    cel_policies: list[str] = []
    extra_files: dict[str, str] = {}
    skipped: list[str] = []
    pol_ref = f"{ns}/{p.name}" if ns else p.name
    for r in rules:
        if r.action not in ("validate", "mutate", "generate") or not r.match.kinds:
            skipped.append(f"rule {r.name}: no fixture skeleton for {r.action or 'this rule'}; write its test by hand")
            continue
        kind, gvr = r.match.kinds[0]
        draft = drafts.get(r.index)
        draft_name = draft[0] if draft else (p.name if len(p.rule_names) == 1 else f"{p.name}-{r.name}")
        draft_file = _safe(draft_name, _MAX_NAME - 5) + ".yaml"
        if draft_file not in cel_policies:
            cel_policies.append(draft_file)
        cel_ref = f"{ns}/{draft_name}" if ns else draft_name
        flag = _TEST_FLAGS[_ACTIONS[r.action]]

        def res_ref(n: str) -> str:
            return f"{ns}/{n}" if ns else n

        if r.action == "validate":
            good_name, bad_name = _safe(f"good-{r.name}"), _safe(f"bad-{r.name}")
            good = _sample_object(kind, gvr, good_name, ns)
            bad = _sample_object(kind, gvr, bad_name, ns)
            todo_good = todo_bad = f"TODO: make this {kind} {{}} rule {r.name}."
            if r.good is not None:
                good = _merge(good, r.good)
                bad = _merge(bad, r.good)
                bad["metadata"]["name"] = bad_name
                todo_good = ""
                if r.breaks:
                    path, value = r.breaks[0]
                    _apply_break(bad, path, value)
                    todo_bad = ""
            resources.append(_header([todo_good.format("pass")] if todo_good else []) + dump_documents([good]))
            resources.append(_header([todo_bad.format("fail")] if todo_bad else []) + dump_documents([bad]))
            for n, result in ((bad_name, "fail"), (good_name, "pass")):
                legacy_results.append(
                    {"policy": pol_ref, "rule": r.name, "kind": kind, "resources": [res_ref(n)], "result": result}
                )
                cel_results.append(
                    {"policy": cel_ref, flag: True, "kind": kind, "resources": [res_ref(n)], "result": result}
                )
        else:
            trigger = _safe(f"{r.action}-{r.name}")
            obj = _sample_object(kind, gvr, trigger, ns)
            resources.append(_header([f"TODO: a {kind} that triggers rule {r.name}."]) + dump_documents([obj]))
            out_file = _safe(f"{'patched' if r.action == 'mutate' else 'generated'}-{r.name}", _MAX_NAME - 5) + ".yaml"
            what = "the resource as the rule should leave it" if r.action == "mutate" else "the resource it generates"
            extra_files[out_file] = _header([f"TODO: {what} (rule {r.name})."]) + dump_documents([obj])
            key = "patchedResources" if r.action == "mutate" else "generatedResource"
            legacy_results.append(
                {
                    "policy": pol_ref,
                    "rule": r.name,
                    "kind": kind,
                    "resources": [res_ref(trigger)],
                    key: f"../{out_file}",
                    "result": "pass",
                }
            )
            cel_results.append(
                {
                    "policy": cel_ref,
                    flag: True,
                    "kind": kind,
                    "resources": [res_ref(trigger)],
                    key: f"../{out_file}",
                    "result": "pass",
                }
            )
    if not legacy_results:
        return {}
    head = [
        f"kyverno test skeleton for {p.ref} (kube-noob policy migrate-check). Run: kyverno test {dirname}/",
        "legacy/ runs the legacy policy and cel/ the CEL drafts on the same resources: both must pass. They are",
        "separate tests because kyverno test matches results by policy name only (kyverno test output.go).",
        *skipped,
    ]

    def test(name: str, policies: list[str], results: list[dict[str, Any]], note: list[str]) -> str:
        obj = {
            "apiVersion": "cli.kyverno.io/v1alpha1",
            "kind": "Test",
            "metadata": {"name": _safe(name)},
            "policies": policies,
            "resources": ["../resources.yaml"],
            "results": results,
        }
        return _header(head + note) + dump_documents([obj])

    missing = [f for f in cel_policies if f[:-5] not in {_safe(d[0], _MAX_NAME - 5) for d in drafts.values()}]
    files = {
        f"{dirname}/resources.yaml": _header(head) + "".join(resources),
        f"{dirname}/legacy/kyverno-test.yaml": test(f"{p.name}-legacy", ["policy.yaml"], legacy_results, []),
        f"{dirname}/legacy/policy.yaml": _header([f"{p.ref} as given to kube-noob."]) + dump_documents([p.doc.data]),
        f"{dirname}/cel/kyverno-test.yaml": test(
            f"{p.name}-cel",
            cel_policies,
            cel_results,
            [f"TODO: write {', '.join(missing)} (no draft: the rule needs hand work)."] if missing else [],
        ),
    }
    for d_name, text, _ in drafts.values():
        files[f"{dirname}/cel/{_safe(d_name, _MAX_NAME - 5)}.yaml"] = text
    for fname, text in extra_files.items():
        files[f"{dirname}/{fname}"] = text
    return files


def _legacy_policy(doc: Document, drafts_on: bool, dirs: set[str]) -> tuple[dict[str, Any], dict[str, list[str]]]:
    data = doc.data
    annotations = _mapping(_mapping(data.get("metadata")).get("annotations"))
    namespaced = doc.kind == "Policy"
    p = _Policy(doc, doc.kind, doc.name or "<unnamed>", doc.namespace if namespaced else None, annotations)
    out = _Out(doc, _target("ValidatingPolicy", namespaced))
    spec = data.get("spec")
    rules: list[_Rule] = []
    if not isinstance(spec, dict):
        out.add(("spec",), "manual", "a CEL policy", "spec is not a mapping", f"{_MIG}: Policy Settings")
        spec = {}
    raw_rules = spec.get("rules", [])
    if not isinstance(raw_rules, list):
        out.add(("spec", "rules"), "manual", "a CEL policy", "spec.rules is not a list", f"{_MIG}: Policy Settings")
        raw_rules = []
    p.rule_names = [str(r.get("name")) if isinstance(r, dict) else f"rule-{i}" for i, r in enumerate(raw_rules)]
    settings = _policy_settings(spec, annotations)
    for i, raw in enumerate(raw_rules):
        rules.append(_rule(doc, out, i, raw, namespaced, settings))
    _policy_level(spec, out, rules, namespaced)
    _autogen_finding(p, out, rules)
    findings = _dedupe(out.findings)
    policy_findings = [f for f in findings if f.rule is None]
    blocking = [f.path for f in policy_findings if f.verdict in ("manual", "blocked")]
    notes = [f"Policy-level settings that need hand work: {', '.join(blocking)}."] if blocking else []
    rule_rows: list[dict[str, Any]] = []
    drafts: dict[int, tuple[str, str, dict[str, Any]]] = {}
    for r in rules:
        prefix = f"spec.rules[{r.index}]"
        rf = [f for f in findings if f.path == prefix or f.path.startswith((prefix + ".", prefix + "["))]
        verdict = _worst(f.verdict for f in rf) or "manual"
        row: dict[str, Any] = {
            "rule": r.name,
            "index": r.index,
            "line": r.line,
            "verdict": verdict,
            "target": r.target,
            "findings": [f.as_dict() for f in rf],
        }
        if drafts_on and verdict in ("direct", "inverted"):
            draft = _rule_draft(p, r, settings, notes)
            if draft is not None:
                drafts[r.index] = draft
                row["draft"] = draft[1]
        rule_rows.append(row)
    result = _result(p, policy_findings, rule_rows, sorted({r.target for r in rules}))
    if drafts_on and rules:
        dirname = _unique(_safe(p.name), dirs)
        files = _fixture(p, dirname, rules, drafts)
        if files:
            result["fixture"] = {"directory": dirname, "files": files}
    return result, {r.name: [r.target] for r in rules}


def _unique(name: str, used: set[str]) -> str:
    out, n = name, 2
    while out in used:
        out = f"{name[: _MAX_NAME - 4]}-{n}"
        n += 1
    used.add(out)
    return out


def _result(
    p: _Policy, policy_findings: list[Finding], rule_rows: list[dict[str, Any]], targets: list[str]
) -> dict[str, Any]:
    verdicts = [f.verdict for f in policy_findings] + [r["verdict"] for r in rule_rows]
    return {
        "policy": p.ref,
        "kind": p.kind,
        "name": p.name,
        "namespace": p.namespace,
        "line": p.doc.start_line,
        "verdict": _worst(verdicts),
        "targets": targets,
        "findings": [f.as_dict() for f in policy_findings],
        "rules": rule_rows,
    }


def _cleanup_policy(doc: Document, drafts_on: bool) -> dict[str, Any]:
    data = doc.data
    namespaced = doc.kind == "CleanupPolicy"
    target = _target("DeletingPolicy", namespaced)
    annotations = _mapping(_mapping(data.get("metadata")).get("annotations"))
    p = _Policy(doc, doc.kind, doc.name or "<unnamed>", doc.namespace if namespaced else None, annotations)
    out = _Out(doc, target)
    spec = data.get("spec") if isinstance(data.get("spec"), dict) else None
    r = _Rule(name=p.name, index=0, line=doc.start_line, action=None, target=target)
    draft_spec: dict[str, Any] = {}
    if spec is None:
        out.add(("spec",), "manual", "a DeletingPolicy", "spec is not a mapping", f"{_MIG}: CleanupPolicy")
        r.draftable = False
        spec = {}
    for key, value in spec.items():
        kp: PathT = ("spec", key)
        if key == "match":
            _match(value, kp, out, None, None, r.match)
        elif key == "exclude":
            _match(value, kp, out, None, None, r.exclude, exclude=True)
        elif key == "conditions":
            tr = _conditions(value)
            if tr is None:
                row = CLEANUP_FIELDS["conditions"]
                out.add(
                    kp,
                    "manual",
                    row.maps_to,
                    "the conditions use JMESPath kube-noob does not translate "
                    "(functions, projections, target. variables or operators): write the CEL conditions by hand",
                    f"{row.source}: {row.section}; deleting-policy: Example",
                    None,
                )
                r.draftable = False
            else:
                draft_spec["conditions"] = [{"name": "conditions", "expression": tr.pos}]
                out.row(kp, CLEANUP_FIELDS["conditions"])
        elif key == "context":
            _context(value, kp, out, r)
        elif key in CLEANUP_FIELDS:
            out.row(kp, CLEANUP_FIELDS[key])
            draft_spec[key] = copy.deepcopy(value)
        else:
            out.unknown(kp)
            r.draftable = False
    out.scan_jmespath(spec, ("spec",), None, target)
    findings = [dataclasses.replace(f, rule=None) for f in _dedupe(out.findings)]
    result = _result(p, findings, [], [target])
    verdict = result["verdict"]
    if (
        drafts_on
        and verdict in ("direct", "inverted")
        and r.draftable
        and r.match.ok
        and r.exclude.ok
        and r.match.rules
        and "schedule" in draft_spec
    ):
        body: dict[str, Any] = {"schedule": draft_spec["schedule"]}
        if "deletionPropagationPolicy" in draft_spec:
            body["deletionPropagationPolicy"] = draft_spec["deletionPropagationPolicy"]
        body["matchConstraints"] = _match_constraints(r, operations=False)
        if "conditions" in draft_spec:
            body["conditions"] = draft_spec["conditions"]
        obj = {
            "apiVersion": "policies.kyverno.io/v1",
            "kind": target,
            "metadata": _metadata(p.name, p.namespace, annotations),
            "spec": body,
        }
        result["draft"] = _draft_text(p.ref, obj, [])
    return result


def _exception_match(block: Any, base: PathT, out: _Out) -> str | None:
    """CEL for a legacy exception's match block (kinds, names, namespaces), or None with a manual finding."""
    filters = _filters(block, base, out, None)
    if filters is None:
        return None
    mode = "all" if isinstance(block, dict) and "all" in block else "any"
    parts: list[str] = []
    for fpath, flt in filters:
        res = flt.get("resources")
        if set(flt) != {"resources"} or not isinstance(res, dict) or set(res) - {"kinds", "names", "namespaces"}:
            out.add(
                fpath,
                "manual",
                "spec.matchConditions",
                "only kinds, names and namespaces translate; write the rest of this filter in CEL by hand",
                f"{_MIG}: PolicyException",
                None,
            )
            return None
        terms: list[str] = []
        for key, expr in (
            ("kinds", "object.kind"),
            ("names", "object.metadata.name"),
            ("namespaces", "object.metadata.namespace"),
        ):
            vals = res.get(key)
            if vals is None:
                continue
            if not isinstance(vals, list) or not vals or not all(isinstance(v, str) and v for v in vals):
                out.add(
                    (*fpath, "resources", key),
                    "manual",
                    "spec.matchConditions",
                    f"{key} is not a list of names",
                    f"{_MIG}: PolicyException",
                    None,
                )
                return None
            if key == "kinds":
                kinds = [v.split("/")[-1] if v[:1].islower() else v.split("/")[0] for v in vals]
                terms.append(f"{expr} in {cel_literal(kinds)}")
            else:
                tests = [_str_test(expr, v) for v in vals]
                terms.append(tests[0] if len(tests) == 1 else "(" + " || ".join(tests) + ")")
        parts.append(" && ".join(terms) if terms else "true")
    joiner = " && " if mode == "all" else " || "
    return parts[0] if len(parts) == 1 else joiner.join(f"({p})" for p in parts)


def _exception(doc: Document, drafts_on: bool, known: dict[str, dict[str, list[str]]]) -> dict[str, Any]:
    data = doc.data
    annotations = _mapping(_mapping(data.get("metadata")).get("annotations"))
    p = _Policy(doc, doc.kind, doc.name or "<unnamed>", doc.namespace, annotations)
    out = _Out(doc, "PolicyException")
    spec = data.get("spec") if isinstance(data.get("spec"), dict) else None
    refs: list[dict[str, str]] = []
    conditions: list[dict[str, str]] = []
    ok = True
    if spec is None:
        out.add(("spec",), "manual", "a PolicyException", "spec is not a mapping", f"{_MIG}: PolicyException")
        spec = {}
        ok = False
    for key, value in spec.items():
        kp: PathT = ("spec", key)
        if key == "exceptions":
            if not isinstance(value, list) or not value:
                out.add(
                    kp, "manual", "spec.policyRefs", "exceptions is not a non-empty list", f"{_MIG}: PolicyException"
                )
                ok = False
                continue
            for j, entry in enumerate(value):
                ep = (*kp, j)
                if not isinstance(entry, dict) or not isinstance(entry.get("policyName"), str):
                    out.add(ep, "manual", "spec.policyRefs", "an entry needs a policyName", f"{_MIG}: PolicyException")
                    ok = False
                    continue
                name = entry["policyName"].split("/")[-1]
                rules = known.get(name)
                kinds = sorted({t for ts in (rules or {}).values() for t in ts})
                if rules and len(kinds) == 1:
                    kind = kinds[0]
                    extra = f": kind {kind} from the policy in the same input"
                else:
                    kind = "ValidatingPolicy"
                    extra = ": kind assumed ValidatingPolicy; set the kind its policy migrated to"
                refs.append({"name": name, "kind": kind})
                out.row((*ep, "policyName"), EXCEPTION_FIELDS["policyName"], extra=extra)
                if "ruleNames" in entry:
                    names = entry["ruleNames"]
                    if rules is not None and len(rules) == 1 and isinstance(names, list) and set(names) <= set(rules):
                        out.add(
                            (*ep, "ruleNames"),
                            "direct",
                            "not applicable",
                            "the policy has one rule, so its CEL policy carries exactly this rule",
                            f"{_MIG}: PolicyException",
                        )
                    else:
                        out.row((*ep, "ruleNames"), EXCEPTION_FIELDS["ruleNames"])
                        ok = False
                for sub in entry:
                    if sub not in ("policyName", "ruleNames"):
                        out.unknown((*ep, sub))
                        ok = False
        elif key == "match":
            expr = _exception_match(value, kp, out)
            if expr is None:
                ok = False
            else:
                conditions.append({"name": "match", "expression": expr})
                out.row(kp, EXCEPTION_FIELDS["match"])
        elif key == "conditions":
            tr = _conditions(value)
            if tr is None:
                row = EXCEPTION_FIELDS["conditions"]
                out.add(
                    kp,
                    "manual",
                    row.maps_to,
                    "the conditions use JMESPath kube-noob does not translate",
                    f"{row.source}: {row.section}",
                )
                ok = False
            else:
                conditions.append({"name": "conditions", "expression": tr.pos})
                out.row(kp, EXCEPTION_FIELDS["conditions"])
        elif key == "podSecurity":
            out.row(kp, EXCEPTION_FIELDS["podSecurity"])
            ok = False
        else:
            out.unknown(kp)
            ok = False
    out.scan_jmespath(spec, ("spec",), None, "PolicyException")
    findings = _dedupe(out.findings)
    result = _result(p, findings, [], ["PolicyException"])
    if drafts_on and ok and refs and conditions and result["verdict"] in ("direct", "inverted"):
        obj = {
            "apiVersion": "policies.kyverno.io/v1",
            "kind": "PolicyException",
            "metadata": _metadata(p.name, p.namespace, {}),
            "spec": {"policyRefs": refs, "matchConditions": conditions},
        }
        result["draft"] = _draft_text(p.ref, obj, [])
    return result


# --- entry points ------------------------------------------------------------------------------------------------


def _skip_reason(doc: Document) -> str | None:
    """Why a document is not checked; None for a legacy Kyverno policy."""
    group = doc.api_version.split("/")[0] if "/" in doc.api_version else ""
    kind = doc.kind
    if kind == "Secret" and doc.api_version == "v1":
        return "a Secret: not read"
    if not isinstance(doc.data, dict):
        return "not a mapping"
    if group == "policies.kyverno.io":
        return "already a CEL policy type (policies.kyverno.io)"
    if group == "kyverno.io" and kind in (_LEGACY_POLICY_KINDS | _CLEANUP_KINDS | {"PolicyException"}):
        return None
    return "not a legacy Kyverno policy"


def check(text: str, drafts: bool = True) -> dict[str, Any]:
    """Every legacy Kyverno policy in ``text``, rule by rule, against the CEL policy types. Lint only."""
    return _check([(None, d) for d in load_documents(text)], drafts)


def check_files(files: list[tuple[str, str]], drafts: bool = True) -> dict[str, Any]:
    """Like ``check`` for several files: each is parsed on its own (lines stay true to its file) and named in its
    results; a PolicyException still finds the kind of a policy given in another file. The caps of one input apply
    to the files together."""
    if sum(len(text.encode("utf-8", errors="replace")) for _, text in files) > MAX_INPUT_BYTES:
        raise ManifestError(f"The files exceed {MAX_INPUT_BYTES} bytes together; check them in smaller groups.")
    docs = [(name, d) for name, text in files for d in load_documents(text)]
    if len(docs) > MAX_DOCUMENTS:
        raise ManifestError(f"More than {MAX_DOCUMENTS} YAML documents; check them in smaller groups.")
    return _check(docs, drafts)


def _check(docs: Sequence[tuple[str | None, Document]], drafts: bool) -> dict[str, Any]:
    policies: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    known: dict[str, dict[str, list[str]]] = {}
    dirs: set[str] = {"drafts"}  # output_files keeps standalone drafts in drafts/
    pending: list[tuple[int, Document]] = []
    for file, d in docs:
        where = {"file": file} if file is not None else {}
        reason = _skip_reason(d)
        if reason is not None:
            ref = f"{d.kind or '<no kind>'}/{d.name or '<unnamed>'}" if d.kind != "Secret" else f"Secret/{d.name}"
            skipped.append({**where, "document": d.index, "line": d.start_line, "ref": ref, "reason": reason})
            continue
        if d.kind in _LEGACY_POLICY_KINDS:
            result, targets = _legacy_policy(d, drafts, dirs)
            policies.append({**where, **result})
            known.setdefault(d.name, targets)
        else:
            pending.append((len(policies), d))
            policies.append(where)
    for i, d in pending:
        result = _cleanup_policy(d, drafts) if d.kind in _CLEANUP_KINDS else _exception(d, drafts, known)
        policies[i] = {**policies[i], **result}
    units = [r["verdict"] for p in policies for r in p["rules"]] + [
        p["verdict"] for p in policies if p["kind"] not in _LEGACY_POLICY_KINDS and p["verdict"]
    ]
    counts = {v: units.count(v) for v in VERDICTS}
    used = sorted({s.split(":")[0].strip() for p in policies for f in _all_findings(p) for s in f["source"].split(";")})
    return {
        "summary": {
            "documents": len(docs),
            "policies": len(policies),
            "rules": len(units),
            "verdicts": counts,
            "worst": _worst(p["verdict"] for p in policies if p["verdict"]),
            "drafts": sum(1 for p in policies for r in [p, *p["rules"]] if "draft" in r),
        },
        "policies": policies,
        "skipped": skipped,
        "sources": {k: SOURCES[k].as_dict() for k in used if k in SOURCES},
        "note": NOTE,
    }


def output_files(report: dict[str, Any]) -> dict[str, str]:
    """Relative path -> text for every fixture file and draft in a report, for the CLI's ``--output-dir``.

    Paths are built only from sanitised names (``[a-z0-9-]``), so none is absolute or climbs out of the directory.
    """
    files: dict[str, str] = {}
    used: set[str] = set()
    for p in report["policies"]:
        fixture = p.get("fixture")
        if fixture:
            files.update(fixture["files"])
        if "draft" in p:
            stem = _unique(_safe(f"{p['kind']}-{p['name']}", _MAX_NAME - 5), used)
            files[f"drafts/{stem}.yaml"] = p["draft"]
    return files


def _all_findings(p: dict[str, Any]) -> list[dict[str, Any]]:
    return list(p["findings"]) + [f for r in p["rules"] for f in r["findings"]]


def failing(report: dict[str, Any], fail_on: str) -> bool:
    """Whether the report has a verdict at or above ``fail_on`` (never, manual or blocked)."""
    if fail_on == "never":
        return False
    if fail_on not in _RANK:
        raise ValueError(f"fail_on must be one of {list(FAIL_ON)}")
    worst = report["summary"]["worst"]
    return worst is not None and _RANK[worst] >= _RANK[fail_on]


__all__ = [
    "CLEANUP_FIELDS",
    "EXCEPTION_FIELDS",
    "FAIL_ON",
    "GENERATE_FIELDS",
    "JMESPATH_BLOCKED",
    "JMESPATH_TO_CEL",
    "KINDS",
    "MUTATE_FIELDS",
    "NOTE",
    "POLICY_FIELDS",
    "RULE_FIELDS",
    "SOURCES",
    "VALIDATE_FIELDS",
    "VERDICTS",
    "VERIFY_FIELDS",
    "WEBHOOK_FIELDS",
    "Finding",
    "Mapping",
    "Source",
    "Verdict",
    "cel_literal",
    "check",
    "check_files",
    "failing",
    "mapping_rows",
    "output_files",
]
