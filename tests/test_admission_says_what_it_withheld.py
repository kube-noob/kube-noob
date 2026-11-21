"""The webhook admits what it cannot evaluate. Admitting is right; doing it silently is not.

`review`'s own docstring says "an input it cannot evaluate is admitted", and that is the correct call: a
fail-closed admission webhook that denies what it cannot read freezes the cluster, including the deploy that
would fix it. Kubernetes gives `failurePolicy` for exactly that trade.

But the response said nothing. `_findings` iterated `report.findings` and nothing else, so an object no rule
reads produced an empty list and the API server admitted it with no warning at all -- at the one point in this
product where a verdict gates a real action. A privileged container in a kind nobody modelled went in clean and
the cluster admin running the webhook saw a blank response.

`warnings` is the channel for this: non-blocking, already used here for cross-object rules that could not be
evaluated, and already read by `kubectl`. So the object is still admitted, out loud.
"""

from __future__ import annotations

from typing import Any

import pytest

from kube_noob import admission

#: A workload kind under a group the audit refuses: something was here and went unread.
REFUSED = {
    "apiVersion": "apps.k8s.io/v1",
    "kind": "Deployment",
    "metadata": {"name": "web", "namespace": "prod"},
    "spec": {
        "template": {
            "spec": {
                "containers": [
                    {"name": "c", "image": "registry.example.com/c:1", "securityContext": {"privileged": True}}
                ]
            }
        }
    },
}

CLEAN = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "ok", "namespace": "prod"},
    "spec": {
        "automountServiceAccountToken": False,
        "containers": [
            {
                "name": "c",
                "image": "registry.example.com/c@sha256:" + "a" * 64,
                "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"memory": "32Mi"}},
                "securityContext": {
                    "privileged": False,
                    "runAsNonRoot": True,
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
            }
        ],
    },
}

PRIVILEGED = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "bad", "namespace": "prod"},
    "spec": {"containers": [{"name": "c", "image": "nginx:1.27", "securityContext": {"privileged": True}}]},
}

WITHHELD = "not fully audited"


def _review(obj: dict[str, Any], **kw: Any) -> dict[str, Any]:
    request = {"uid": "1", "namespace": obj["metadata"].get("namespace", "default"), "object": obj, **kw}
    doc = {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "request": request}
    return dict(admission.review(doc, admission.Config())["response"])


def _withheld(resp: dict[str, Any]) -> list[str]:
    return [w for w in (resp.get("warnings") or []) if WITHHELD in w]


def test_an_object_the_audit_could_not_read_is_admitted_out_loud() -> None:
    """The regression. One warning, and the object still goes in."""
    resp = _review(REFUSED)
    assert resp["allowed"] is True, "the webhook must not deny what it could not read"
    said = _withheld(resp)
    assert len(said) == 1, resp.get("warnings")
    assert "Deployment/prod/web" in said[0], said[0]


def test_a_clean_object_is_admitted_with_nothing_said() -> None:
    """The direction that decides whether this is usable. A warning on every admitted object is a warning every
    cluster admin turns off, and `kubectl` prints them on every apply."""
    resp = _review(CLEAN)
    assert resp["allowed"] is True
    assert _withheld(resp) == []


def test_a_findable_problem_still_reports_as_a_finding_not_as_withheld() -> None:
    """The two are different statements and must not be confused: this object was read, and what was read is
    wrong."""
    resp = _review(PRIVILEGED)
    warnings = resp.get("warnings") or []
    assert any("KN-S001" in w for w in warnings), warnings
    assert _withheld(resp) == []


def test_findings_and_a_withheld_part_are_both_said() -> None:
    """ "This object has problems" and "part of it was never read" are independent. The second does not stop
    being true because the first is, and a reader who sees only the findings concludes the rest was clean."""
    obj = {
        "apiVersion": "apps.k8s.io/v1",
        "kind": "Deployment",
        "metadata": {"name": "web", "namespace": "prod"},
        "spec": {"template": {"spec": {"containers": [{"name": "c", "image": "nginx:latest"}]}}},
    }
    resp = _review(obj)
    assert _withheld(resp), resp.get("warnings")


def test_the_warning_is_within_the_api_servers_length_guidance() -> None:
    """admission/v1: "Limit warnings to 120 characters if possible. Warnings over 256 characters ... may be
    truncated." A truncated caveat is the defect this fixes, one layer out."""
    said = _withheld(_review(REFUSED))
    assert said and all(len(w) <= 256 for w in said), [len(w) for w in said]


@pytest.mark.parametrize("op", ["DELETE", "CONNECT"])
def test_an_operation_the_webhook_skips_is_unchanged(op: str) -> None:
    """The skip paths return before anything is audited, and must not gain a warning that would then appear on
    every delete in the cluster."""
    resp = _review(REFUSED, operation=op)
    assert resp["allowed"] is True
    assert _withheld(resp) == []


def test_the_same_request_gives_the_same_response() -> None:
    first, second = _review(REFUSED), _review(REFUSED)
    assert first == second
