"""OpenShift's legacy RBAC shape, converted to rbac.authorization.k8s.io the way openshift-apiserver converts it.

One place (class 9): the attack-path scan and the audit rules both read bindings, and a binding in the 3.x shape --
`userNames`/`groupNames`, subject kinds `SystemUser`/`SystemGroup`, a `roleRef` with no kind -- read as binding
nobody in the one that had its own copy of the rules (review 4, R5). The two name lists are the deprecated fields
openshift/api authorization/v1/types.go keeps on RoleBinding and ClusterRoleBinding "when supporting legacy clients
and servers" (`UserNames OptionalNames`, `GroupNames OptionalNames`, branch release-3.11, read 2026-11-13).
"""

from __future__ import annotations

from typing import Any

RBAC_GROUP = "rbac.authorization.k8s.io"
#: OpenShift's legacy RBAC group. It serves Role, RoleBinding, ClusterRole and ClusterRoleBinding as proxies of
#: the rbac.authorization.k8s.io objects (openshift-apiserver pkg/authorization/apiserver/apiserver.go stores all
#: four through the rbac/v1 client, commit 9fc0918d1c6908e8e8ceb8e215e86bde4aeaabec; the kinds are registered in
#: openshift/api authorization/v1/register.go, commit 61403fc4e89fad877aba1b000d72a992f388f549). A legacy binding
#: names its role by `roleRef: {name, namespace}` with no kind -- a namespace means a Role, none a ClusterRole --
#: and its subjects as ObjectReferences whose kinds include SystemUser and SystemGroup, or as `userNames` and
#: `groupNames`, which take precedence when set (rbacconversion/conversion.go at the same commit).
OPENSHIFT_RBAC_GROUP = "authorization.openshift.io"
LEGACY_SUBJECT_KINDS = {"ServiceAccount": "ServiceAccount", "User": "User", "SystemUser": "User", "Group": "Group"}
LEGACY_SUBJECT_KINDS["SystemGroup"] = "Group"


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _ns(obj: dict[str, Any]) -> str:
    meta = obj.get("metadata")
    return str(meta.get("namespace") or "") if isinstance(meta, dict) else ""


def legacy_rbac(obj: dict[str, Any], kind: str) -> tuple[dict[str, Any] | None, str]:
    """An authorization.openshift.io object in the rbac.authorization.k8s.io shape the rest of this module reads,
    converted the way openshift-apiserver converts it; or (None, why) when the server would refuse it."""
    if kind in {"Role", "ClusterRole"}:
        return {**obj, "apiVersion": f"{RBAC_GROUP}/v1"}, ""
    ref = obj.get("roleRef")
    if not isinstance(ref, dict) or not ref.get("name"):
        return None, "roleRef does not name a role"
    ref_ns = str(ref.get("namespace") or "")
    if kind == "ClusterRoleBinding" and ref_ns:
        return None, f"a ClusterRoleBinding cannot reference a role in namespace {ref_ns}"
    if kind == "RoleBinding" and ref_ns and ref_ns != _ns(obj):
        return None, f"a RoleBinding cannot reference a role in namespace {ref_ns}"
    users, groups = obj.get("userNames"), obj.get("groupNames")
    subjects: list[dict[str, Any]] = []
    if isinstance(users, list) or isinstance(groups, list):
        subjects += [{"kind": "User", "name": str(u)} for u in _list(users)]
        subjects += [{"kind": "Group", "name": str(g)} for g in _list(groups)]
    else:
        for s in _list(obj.get("subjects")):
            if not isinstance(s, dict) or s.get("kind") not in LEGACY_SUBJECT_KINDS:
                return (
                    None,
                    f"subject kind {s.get('kind') if isinstance(s, dict) else s!r} is not one OpenShift accepts",
                )
            subject = {"kind": LEGACY_SUBJECT_KINDS[str(s["kind"])], "name": str(s.get("name") or "")}
            if subject["kind"] == "ServiceAccount" and s.get("namespace"):
                subject["namespace"] = str(s["namespace"])
            subjects.append(subject)
    converted = {
        **{k: v for k, v in obj.items() if k not in {"userNames", "groupNames"}},
        "apiVersion": f"{RBAC_GROUP}/v1",
        "subjects": subjects,
        "roleRef": {"apiGroup": RBAC_GROUP, "kind": "Role" if ref_ns else "ClusterRole", "name": str(ref["name"])},
    }
    return converted, ""
