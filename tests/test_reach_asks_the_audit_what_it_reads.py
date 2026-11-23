"""`policy reach` and `check_network_policy` ask the audit which objects it reads, instead of matching `kind`.

Found by running the mixed corpus (clean objects beside one object nothing read) through every surface, G365. The
reachability reader took any document whose `kind` was `NetworkPolicy` for a Kubernetes NetworkPolicy. A
`projectcalico.org/v3 NetworkPolicy` is a real, different kind -- `selector` and `types`, where this evaluator
reads `podSelector` and `policyTypes` -- and the reader evaluated its fields as if they were the built-in's:
DENIED, exit 1, "1 NetworkPolicy selects prod/pod/ok", about traffic nothing in the input isolates. `audit` on
the same file refused the object and withheld its verdict, so two commands of one product gave two answers about
one object, and the one that sounded safe was the one that had not read it.

`rules.refusal` is the audit's one detector. `attack_paths` asks it (G330) and the fixer asks it (G344); this was
the third reader and it had its own idea (review classes 3, 9 and 25). The same matrix exemption that hid the
fixer hid this: `mcp.check_network_policy` is in `NOT_A_VERDICT_VIEW` as "not a verdict over the input", which is
true and is not the same as owing nothing.
"""

from __future__ import annotations

import contextlib
import io
from pathlib import Path
from typing import Any

import pytest

from kube_noob import cli
from kube_noob import toolkit as tk
from kube_noob.debug.netpol import Inventory, check_reachability
from kube_noob.toolkit import Toolkit

_POD = """\
apiVersion: v1
kind: Pod
metadata: {name: ok, namespace: prod, labels: {app: ok}}
spec:
  containers:
  - {name: c, image: registry.example.com/c:1}
"""

#: A default-deny that still allows DNS. Under `networking.k8s.io/v1` it isolates `prod/ok` in both directions.
_DENY = """\
apiVersion: {api}
kind: NetworkPolicy
metadata: {{name: default-deny, namespace: prod}}
spec:
  podSelector: {{}}
  policyTypes: [Ingress, Egress]
  egress:
  - ports:
    - {{protocol: UDP, port: 53}}
"""

_REFUSED_DEPLOYMENT = """\
apiVersion: apps.k8s.io/v1
kind: Deployment
metadata: {name: web, namespace: prod}
spec:
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
      - {name: web, image: registry.example.com/web:1}
"""


def _reach(policy_api: str | None, source: str = "prod/ok") -> dict[str, Any]:
    policy = _DENY.format(api=policy_api) if policy_api else _DENY.format(api="x").replace("apiVersion: x\n", "")
    inv = Inventory.from_yaml(f"{_POD}---\n{policy}", "default", None)
    return check_reachability(inv, source, "prod/ok", 8080, "TCP", "kubectl")


# -- the negative controls first: what must keep its answer --------------------------------------------------


@pytest.mark.parametrize("api", ["networking.k8s.io/v1", "extensions/v1beta1"])
def test_a_networkpolicy_the_audit_reads_is_still_evaluated(api: str) -> None:
    """Both groups `SUBJECT_GROUPS` knows the kind under. A fix that refused more than the audit refuses would
    turn every reachability answer undetermined, which is an answer nobody reads twice."""
    out = _reach(api)
    assert out["verdict"] == "denied"
    assert out["ingress"]["evaluated"] is True


def test_a_networkpolicy_with_no_apiversion_is_still_evaluated() -> None:
    """A live list's items carry no `apiVersion`, and `refusal` returns `None` for that on purpose: refusing them
    left three rules evaluated on a real cluster. The reachability reader inherits the decision with the
    predicate."""
    assert _reach(None)["verdict"] == "denied"


# -- the defect ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "api",
    [
        "projectcalico.org/v3",  # a real kind of the same name, with a different schema
        "crd.projectcalico.org/v1",
        "networking.k8s.io.example/v1",  # a group nothing serves
        "rbac.authorization.k8s.io/v1",  # a real group that has no such kind
    ],
)
def test_a_networkpolicy_under_a_group_the_audit_refuses_decides_nothing(api: str) -> None:
    out = _reach(api)
    assert out["verdict"] == "undetermined", (
        f"a {api} NetworkPolicy was evaluated as a Kubernetes NetworkPolicy and answered {out['verdict']!r}"
    )
    # Named, with the audit's own reason, in the sentence a person and a model both read.
    assert "NetworkPolicy/prod/default-deny" in out["summary"]
    assert "does not know NetworkPolicy under" in out["summary"]
    # And it selected nothing: no direction cites a policy that was never read as one.
    for direction in ("egress", "ingress"):
        assert not out[direction].get("policies"), out[direction]


def test_the_mcp_tool_gives_the_same_answer(settings: Any) -> None:
    """At the call site an agent uses, not at the helper: `check_network_policy` builds its own inventory."""
    manifests = f"{_POD}---\n{_DENY.format(api='projectcalico.org/v3')}"
    out = Toolkit(settings).check_network_policy(
        tk.NetpolCheckIn(manifests=manifests, source="prod/ok", destination="prod/ok", port=8080)
    )
    assert out["verdict"] == "undetermined"


def test_the_command_does_not_print_denied_or_exit_zero(tmp_path: Path) -> None:
    """The real command over a real directory. Before G365 this printed `DENIED` and named the Calico policy as
    the NetworkPolicy that blocked the traffic."""
    (tmp_path / "pod.yaml").write_text(_POD, encoding="utf-8")
    (tmp_path / "policy.yaml").write_text(_DENY.format(api="projectcalico.org/v3"), encoding="utf-8")
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(
            ["policy", "reach", "--from", "prod/ok", "--to", "prod/ok", "--port", "8080", "-f", str(tmp_path)]
        )
    text = out.getvalue()
    assert code != 0
    assert text.startswith("UNDETERMINED"), text[:200]
    assert "DENIED" not in text


def test_reach_and_audit_refuse_the_same_objects(settings: Any) -> None:
    """One predicate, asked twice (class 9). Whatever the audit lists as not audited for its apiVersion, the
    reachability reader does not evaluate, for every group in the parametrised list above and the two it reads."""
    for api, refused in (
        ("networking.k8s.io/v1", False),
        ("extensions/v1beta1", False),
        ("projectcalico.org/v3", True),
        ("networking.k8s.io.example/v1", True),
    ):
        manifests = f"{_POD}---\n{_DENY.format(api=api)}"
        audit = dict(Toolkit(settings).audit(tk.AuditIn(manifests=manifests)))
        audit_refuses = "NetworkPolicy/prod/default-deny" in [r["object"] for r in audit["notAudited"]]
        inv = Inventory.from_yaml(manifests, "default", None)
        reach_refuses = any(p.startswith("NetworkPolicy/prod/default-deny") for p in inv.invalid_policies)
        assert audit_refuses == reach_refuses == refused, (api, audit_refuses, reach_refuses)


# -- the neighbour: a refused WORKLOAD named as an endpoint (class 21, class 24) ------------------------------


@pytest.mark.parametrize("spec", ["prod/deployment/web", "prod/web"])
def test_a_refused_workload_is_not_an_endpoint_and_is_not_called_absent(spec: str) -> None:
    """It was read as an endpoint by its `kind`, so reach answered about pods the API server would never create.
    Now it is not an endpoint -- and the refusal says so, because "is not in the manifests" about an object that
    is in them is the absence-for-a-refusal sentence of class 24."""
    inv = Inventory.from_yaml(f"{_POD}---\n{_REFUSED_DEPLOYMENT}", "default", None)
    with pytest.raises(ValueError) as caught:
        inv.resolve(spec)
    message = str(caught.value)
    assert "not in the manifests" not in message
    assert "does not know Deployment under" in message


def test_an_absent_workload_is_still_called_absent() -> None:
    """The control for the test above: the new sentence is for a refusal and for nothing else."""
    inv = Inventory.from_yaml(f"{_POD}---\n{_REFUSED_DEPLOYMENT}", "default", None)
    with pytest.raises(ValueError, match="is not in the manifests"):
        inv.resolve("prod/nope")
