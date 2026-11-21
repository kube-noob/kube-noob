"""An MCP tool's answer is what a model reads, and a model answers the user from it.

Three tools returned an answer in which nothing said the audit had not read the object. `posture_scan` ranked a
privileged `Deployment` under `apps.k8s.io/v1` -- an apiVersion the API server would never serve and the audit
refuses outright -- as a real `apps/v1` Deployment, and reported one workload, no attack paths and an empty
`notRead`. `threat_model`, built on the same inventory, said the same by saying nothing. And `fedramp_ksi` put the
word `undetermined` at byte 54,945 of a 55,269-byte payload, after the whole indicator crosswalk, so a client that
truncates a long result dropped the caveat and kept the page.

This is the product's own rule at the surface where a model speaks for it: an absence, an unknown or an
unrecognised shape must never read as a pass, a zero, or complete.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from kube_noob import toolkit as tk
from kube_noob.toolkit import Toolkit

#: A workload kind the audit knows, under a group it does not know that kind under. `refusal` refuses it, so no
#: rule read the container; the scan's own group checks covered routing and RBAC kinds and never this one.
REFUSED_GROUP = """\
apiVersion: apps.k8s.io/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  replicas: 1
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
      - name: web
        image: registry.example.com/web:1
        securityContext: {privileged: true}
"""

#: The same object under the group the audit does know it under: the control, so a test that finds nothing above
#: is not finding nothing because the fixture is inert.
READ_GROUP = REFUSED_GROUP.replace("apps.k8s.io/v1", "apps/v1")


def test_the_audit_refuses_this_object_so_the_rest_of_this_file_means_something(settings: Any) -> None:
    rep = dict(Toolkit(settings).audit(tk.AuditIn(manifests=REFUSED_GROUP)))
    assert [r["object"] for r in rep["notAudited"]] == ["Deployment/shop/web"]
    assert dict(Toolkit(settings).audit(tk.AuditIn(manifests=READ_GROUP)))["notAudited"] == []


def test_posture_scan_does_not_rank_an_object_the_audit_refused(settings: Any) -> None:
    """The regression. One workload and no attack paths, for a privileged container no rule read."""
    out = dict(Toolkit(settings).posture_scan(tk.PostureScanIn(manifests=REFUSED_GROUP)))
    assert out["workloads"] == 0, "it was ranked as a real Deployment"
    named = [n for n in out["notRead"] if "Deployment/shop/web" in n]
    assert len(named) == 1, out["notRead"]
    assert "group kube-noob does not know Deployment under" in named[0]
    # `refused` is the gated cause (G276): this is a reason a gate fails, not a note beside a pass.
    assert named[0] in out["refused"]


def test_posture_scan_still_ranks_the_same_object_under_the_group_it_knows(settings: Any) -> None:
    """The other direction, and the one that would catch this guard refusing everything."""
    out = dict(Toolkit(settings).posture_scan(tk.PostureScanIn(manifests=READ_GROUP)))
    assert out["workloads"] == 1
    assert [n for n in out["notRead"] if "Deployment/shop/web" in n] == []


def test_an_object_with_no_api_version_is_still_ranked(settings: Any) -> None:
    """`refusal` returns None for an absent apiVersion on purpose: the in-cluster backend's list items carry none,
    and refusing them evaluated three rules against a live cluster. A guard that read absence as refusal would
    empty every live scan."""
    out = dict(
        Toolkit(settings).posture_scan(tk.PostureScanIn(manifests=READ_GROUP.replace("apiVersion: apps/v1\n", "")))
    )
    assert out["workloads"] == 1
    assert [n for n in out["notRead"] if "Deployment/shop/web" in n] == []


def test_threat_model_names_the_object_it_could_not_read(settings: Any) -> None:
    """Same inventory, so one detector answers for both tools rather than each keeping its own idea of refused."""
    out = dict(Toolkit(settings).threat_model(tk.ThreatModelIn(manifests=REFUSED_GROUP)))
    assert any("Deployment/shop/web" in n for n in out.get("notRead") or []), out.get("notRead")


def test_the_ksi_verdict_survives_a_client_that_truncates(settings: Any) -> None:
    """Review class 6: the caveat existed, and only where nobody reads it. A 1 KiB prefix is a modest truncation
    next to a 55 KiB payload, and the verdict has to be inside it."""
    out = dict(Toolkit(settings).fedramp_ksi(tk.KsiIn(manifests=REFUSED_GROUP)))
    assert out["verdict"] == "undetermined"
    assert next(iter(out)) == "verdict", f"the verdict is not first: {list(out)[:4]}"
    body = json.dumps(out)
    assert len(body) > 2000, "the payload is small, so truncation would not have lost anything"
    assert '"verdict"' in body[:1024]


def test_a_determined_ksi_page_carries_no_verdict_word(settings: Any) -> None:
    """The verdict key means undetermined and nothing else; a page that reached one does not gain a field."""
    out = dict(Toolkit(settings).fedramp_ksi(tk.KsiIn(manifests=READ_GROUP)))
    assert "verdict" not in out and "verdictReason" not in out


@pytest.mark.parametrize("tool", ["posture_scan", "threat_model"])
def test_the_same_input_gives_the_same_bytes(settings: Any, tool: str) -> None:
    kit = Toolkit(settings)
    model = {"posture_scan": tk.PostureScanIn, "threat_model": tk.ThreatModelIn}[tool]
    call = getattr(kit, tool)
    first = json.dumps(dict(call(model(manifests=REFUSED_GROUP))), sort_keys=True)
    assert first == json.dumps(dict(call(model(manifests=REFUSED_GROUP))), sort_keys=True)
