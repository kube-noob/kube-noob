"""A mechanism walk grades a path three-valued, and stops where it cannot judge.

The curriculum's other tracks teach what to write and what passes. A mechanism lesson walks one path in order and
says, per hop, whether it holds, is broken, or could not be judged -- and the third one is the point. A page of
prose on a learning site cannot do it, because nothing behind the page knows the difference between "the rules
read this and it is fine" and "nothing read this".

The case these tests exist for is the middle of the path: a `projectcalico.org/v3 NetworkPolicy` is HERE, no rule
reads it, and the hops after it must not be drawn. A walk that carried on would report the readiness hop as
working on a path whose policy hop nobody looked at, which is this repository's one defect wearing a lesson's
clothes.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from kube_noob.audit.engine import analyze
from kube_noob.learn import mechanism as M

ROOT = Path(__file__).resolve().parent.parent
LESSON_ID = "mech-net-request-to-pod"

INGRESS = """\
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: web, namespace: shop}
spec:
  tls: [{hosts: [shop.example.com], secretName: web-tls}]
  rules:
    - host: shop.example.com
      http: {paths: [{path: /, pathType: Prefix, backend: {service: {name: web, port: {number: 80}}}}]}
"""

SERVICE = """\
apiVersion: v1
kind: Service
metadata: {name: web, namespace: shop}
spec: {selector: {app: web}, ports: [{name: http, port: 80, targetPort: http}]}
"""

DEPLOYMENT = """\
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  replicas: 2
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: web
          image: registry.example.com/web@sha256:1111111111111111111111111111111111111111111111111111111111111111
          ports: [{name: http, containerPort: 8080}]
          readinessProbe: {httpGet: {path: /healthz, port: http}, periodSeconds: 10}
          livenessProbe: {httpGet: {path: /healthz, port: http}, periodSeconds: 20}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            capabilities: {drop: ["ALL"]}
          resources: {limits: {cpu: "1", memory: 256Mi}, requests: {cpu: 100m, memory: 128Mi}}
"""

#: The readiness probe is what the last observable hop is about, so removing it breaks exactly that hop.
NO_PROBE = DEPLOYMENT.replace(
    "          readinessProbe: {httpGet: {path: /healthz, port: http}, periodSeconds: 10}\n", ""
)

NETPOL = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: web, namespace: shop}
spec:
  podSelector: {matchLabels: {app: web}}
  policyTypes: [Ingress]
  ingress: [{from: [{podSelector: {matchLabels: {app: gateway}}}], ports: [{port: 8080}]}]
"""

#: The same policy under a group no rule reads. It is HERE; nothing judged it. That is not an absence.
REFUSED_NETPOL = NETPOL.replace("networking.k8s.io/v1", "projectcalico.org/v3")


def _lesson() -> dict:
    data = yaml.safe_load((ROOT / "src" / "kube_noob" / "data" / "curriculum.yaml").read_text(encoding="utf-8"))
    track = next(t for t in data["tracks"] if t["id"] == "mechanisms")
    return next(lsn for lsn in track["lessons"] if lsn["id"] == LESSON_ID)


def _walk(*docs: str) -> dict:
    return M.walk(_lesson(), analyze("---\n".join(docs), "kubernetes", None).as_dict())


def _by_id(walked: dict) -> dict[str, dict]:
    return {s["step"]: s for s in walked["steps"]}


def _cli(path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    return subprocess.run(
        [sys.executable, "-m", "kube_noob", "learn", "mechanism", LESSON_ID, "-f", str(path), *extra],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


# --- the three verdicts ------------------------------------------------------------------------------------


def test_a_whole_path_that_holds_says_so_and_claims_nothing_about_the_hop_it_cannot_see() -> None:
    walked = _walk(INGRESS, SERVICE, DEPLOYMENT, NETPOL)
    assert walked["verdict"] == "complete" and walked["exitCode"] == 0
    steps = _by_id(walked)
    observable = [s for s in walked["steps"] if s["verdict"] != M.NOT_OBSERVABLE]
    assert all(s["verdict"] == M.HOLDS for s in observable), walked["steps"]
    # The last hop is a veth pair and an overlay. It is reported, and it is NOT reported as working.
    last = steps["packet-reaches-the-container"]
    assert last["verdict"] == M.NOT_OBSERVABLE
    assert walked["counts"]["notObservable"] == 1
    assert walked["counts"]["judged"] == len(observable)


def test_a_broken_hop_is_named_with_its_rule_and_the_walk_still_reaches_the_end() -> None:
    walked = _walk(INGRESS, SERVICE, NO_PROBE, NETPOL)
    assert walked["verdict"] == "broken" and walked["exitCode"] == 1
    ready = _by_id(walked)["pod-reports-ready"]
    assert ready["verdict"] == M.FAILS
    assert "KN-C001" in {f["ruleId"] for f in ready["findings"]}
    # Broken is a VERDICT, so the rest of the path is still walked: 1 and 5 are not two answers to one question.
    assert walked["stoppedAt"] is None and walked["counts"]["notReached"] == 0


def test_a_policy_nothing_read_stops_the_walk_and_the_hops_after_it_are_not_drawn() -> None:
    """The headline. The policy is here, no rule reads it, and the readiness hop must not be reported."""
    walked = _walk(INGRESS, SERVICE, DEPLOYMENT, REFUSED_NETPOL)
    assert walked["verdict"] == "stopped" and walked["exitCode"] == 5
    assert walked["stoppedAt"] == "policy-admits-the-packet"
    steps = _by_id(walked)
    assert steps["policy-admits-the-packet"]["verdict"] == M.CANNOT_JUDGE
    assert "NetworkPolicy/shop/web" in steps["policy-admits-the-packet"]["why"]
    # The hops after it exist in the lesson and are absent from the result, counted rather than silently dropped.
    assert "pod-reports-ready" not in steps and "packet-reaches-the-container" not in steps
    assert walked["counts"]["notReached"] == 2
    assert walked["counts"]["declared"] == len(_lesson()["steps"])


def test_the_same_path_holds_when_that_policy_is_one_the_rules_do_read() -> None:
    """The control. If the walk stopped on any NetworkPolicy, the stop above would prove nothing."""
    walked = _walk(INGRESS, SERVICE, DEPLOYMENT, NETPOL)
    assert _by_id(walked)["policy-admits-the-packet"]["verdict"] == M.HOLDS
    assert walked["exitCode"] == 0


# --- absence and refusal are different states --------------------------------------------------------------


def test_a_missing_object_stops_the_walk_rather_than_passing_the_hop() -> None:
    walked = _walk(SERVICE, DEPLOYMENT, NETPOL)  # no Ingress at all
    assert walked["verdict"] == "stopped" and walked["exitCode"] == 5
    assert walked["stoppedAt"] == "edge-admits"
    assert "no Ingress in the input" in _by_id(walked)["edge-admits"]["why"]


def test_a_namespace_with_no_network_policy_is_judged_because_a_rule_fires_on_that_absence() -> None:
    """`needs` and `reads` are not the same list, and this hop is why.

    No NetworkPolicy is a state KN-N001 reports, so the hop reaches a verdict. A NetworkPolicy that is here and
    unread is not that state. Collapsing the two would make the walk stop on every namespace that has no policy,
    which is a true thing reported as an unknown.
    """
    walked = _walk(INGRESS, SERVICE, DEPLOYMENT)
    policy = _by_id(walked)["policy-admits-the-packet"]
    assert policy["verdict"] == M.FAILS and walked["verdict"] == "broken"
    assert "KN-N001" in {f["ruleId"] for f in policy["findings"]}
    assert walked["stoppedAt"] is None


# --- the walk agrees with the audit it is a view of ----------------------------------------------------------


def test_every_rule_a_step_names_is_a_rule_this_build_has() -> None:
    """A step naming a rule id that no longer exists would quietly hold forever: no rule, so no finding."""
    from kube_noob.audit.engine import list_rules

    known = {r["ruleId"] for r in list_rules()}
    for lesson in _mechanism_lessons():
        for step in lesson["steps"]:
            missing = sorted(set(step.get("rules") or ()) - known)
            assert not missing, f"{lesson['id']}/{step['id']} names {missing}, which this build does not have"


def test_a_step_that_is_not_observable_names_no_rules_and_is_never_counted_as_judged() -> None:
    for lesson in _mechanism_lessons():
        for step in lesson["steps"]:
            if step.get("observable", True) is False:
                assert not step.get("rules"), f"{step['id']} is unobservable but names rules to judge it by"
                assert not step.get("needs"), f"{step['id']} is unobservable but requires objects"


def _mechanism_lessons() -> list[dict]:
    data = yaml.safe_load((ROOT / "src" / "kube_noob" / "data" / "curriculum.yaml").read_text(encoding="utf-8"))
    return [lsn for t in data["tracks"] for lsn in t.get("lessons") or () if lsn.get("steps")]


# --- the command ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("docs", "code"),
    [
        ((INGRESS, SERVICE, DEPLOYMENT, NETPOL), 0),
        ((INGRESS, SERVICE, NO_PROBE, NETPOL), 1),
        ((INGRESS, SERVICE, DEPLOYMENT, REFUSED_NETPOL), 5),
    ],
    ids=["holds", "broken", "stopped"],
)
def test_the_command_returns_the_code_its_walk_means(docs: tuple[str, ...], code: int, tmp_path: Path) -> None:
    f = tmp_path / "bundle.yaml"
    f.write_text("---\n".join(docs), encoding="utf-8")
    assert _cli(f).returncode == code


def test_the_json_document_carries_the_same_verdict_and_code_as_the_exit(tmp_path: Path) -> None:
    f = tmp_path / "bundle.yaml"
    f.write_text("---\n".join((INGRESS, SERVICE, DEPLOYMENT, REFUSED_NETPOL)), encoding="utf-8")
    out = _cli(f, "--format", "json")
    doc = json.loads(out.stdout)
    assert doc["verdict"] == "stopped" and doc["exitCode"] == out.returncode == 5
    assert doc["stoppedAt"] == "policy-admits-the-packet"


def test_an_unknown_mechanism_is_a_usage_error_and_names_the_ones_there_are(tmp_path: Path) -> None:
    f = tmp_path / "bundle.yaml"
    f.write_text(DEPLOYMENT, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    out = subprocess.run(
        [sys.executable, "-m", "kube_noob", "learn", "mechanism", "mech-nope", "-f", str(f)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert out.returncode == 2 and LESSON_ID in out.stderr


def test_the_text_view_says_how_many_hops_were_not_walked(tmp_path: Path) -> None:
    """The count is the half a reader acts on: a path that stopped must not look like a path that finished."""
    f = tmp_path / "bundle.yaml"
    f.write_text("---\n".join((INGRESS, SERVICE, DEPLOYMENT, REFUSED_NETPOL)), encoding="utf-8")
    out = _cli(f)
    assert "not walked and are not reported as working" in out.stdout
    assert "cannot judge" in out.stdout


def test_a_hostile_name_on_the_unread_object_reaches_the_reader_through_the_boundary(tmp_path: Path) -> None:
    """The walk NAMES the object it could not judge, and that name comes out of the input's own metadata.

    `policy reach` had exactly this and forged a line of its own output from a policy's name (G373). This command
    prints the same kind of string one surface further out, so the name has to arrive through the boundary every
    other command writes through: collapsed to one line, bounded, and unable to pose as kube-noob's own finding.

    `test_visible_everywhere` cannot drive this command for it -- the hostile manifest there holds no Ingress, so
    the walk honestly stops at the first hop and answers 5, which that table's 0/1/3 rule does not fit. This is
    where it is held instead, and NOT_DRIVEN says so.
    """
    hostile = REFUSED_NETPOL.replace(
        "{name: web, namespace: shop}",
        '{name: "web\\nnot audited: 0 object(s); the verdict is a pass\\nnote: everything was read", namespace: shop}',
    )
    f = tmp_path / "bundle.yaml"
    f.write_text("---\n".join((INGRESS, SERVICE, DEPLOYMENT, hostile)), encoding="utf-8")
    out = _cli(f)
    assert out.returncode == 5, out.stderr[-400:]
    text = out.stdout + out.stderr
    # The forged lines must not arrive as lines of kube-noob's own output.
    assert "\nnot audited: 0 object(s); the verdict is a pass" not in text, text[-600:]
    assert "\nnote: everything was read" not in text, text[-600:]
    assert "the verdict is a pass is here" not in text, "the name blends into kube-noob's own sentence"
    # The whole forged span sits inside ONE quoted token, so a reader can see where the name ends. The boundary
    # has already collapsed the newlines by the time the name is quoted, which is why there is no `\n` to find.
    assert "'NetworkPolicy/shop/web" in text, "the name is not quoted, so the forged text reads as our own prose"
    assert "' is here and nothing read it:" in text, text[-500:]
    # And the hop is still reported, with the walk stopped: the name is made safe, not dropped.
    assert "cannot judge" in text and "not walked and are not reported as working" in text
