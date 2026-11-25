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


# --- a hop no rule reads (G387) --------------------------------------------------------------------------


def test_an_observable_hop_that_no_rule_reads_cannot_be_judged() -> None:
    """The headline of G387, and the defect this feature shipped with.

    An observable step naming no rules reported `holds` with the words "no rule reads this hop" beside it, and
    the path came out `complete` at exit 0 -- a hop nothing read, reported as a hop that works, inside the
    walk written to show that those are different. It did not bite on the shipped lesson, whose every
    observable step names a rule. It would have bitten on the first control-plane lesson, where for most of
    the path the rules do not exist.
    """
    lesson = {
        "id": "probe",
        "title": "A step nothing reads",
        "layer": "control-plane",
        "steps": [
            {
                "id": "no-rules-at-all",
                "title": "A hop no rule evaluates",
                "needs": ["Deployment"],
                "holds": "the apply reached the API server",
            }
        ],
    }
    walked = M.walk(lesson, analyze(DEPLOYMENT, "kubernetes", None).as_dict())
    assert walked["verdict"] == "stopped" and walked["exitCode"] == 5
    assert walked["stoppedAt"] == "no-rules-at-all"
    step = walked["steps"][0]
    assert step["verdict"] == M.CANNOT_JUDGE
    assert step["why"] == "no rule in this build reads this hop"


def test_an_unobservable_hop_is_still_not_a_stop() -> None:
    """The control for the above: `observable: false` is a DECLARED absence of evidence, not a missing rule.

    It must not stop the walk -- a path whose last hop is a veth pair would never complete if it did.
    """
    lesson = {
        "id": "probe2",
        "title": "A declared unobservable",
        "layer": "network",
        "steps": [
            {"id": "unobservable", "title": "No manifest records this", "observable": False, "holds": "prose"},
            {"id": "after", "title": "Still walked", "needs": ["Deployment"], "holds": "x", "rules": ["KN-C001"]},
        ],
    }
    walked = M.walk(lesson, analyze(DEPLOYMENT, "kubernetes", None).as_dict())
    assert walked["stoppedAt"] is None
    assert walked["steps"][0]["verdict"] == M.NOT_OBSERVABLE
    assert len(walked["steps"]) == 2, "the unobservable hop stopped the walk"


# --- the control-plane lesson ----------------------------------------------------------------------------

NODE_DARK = "mech-cp-a-node-goes-dark"

_WORKLOAD = """\
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  replicas: %(replicas)s
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
%(spread)s      containers:
        - name: web
          image: registry.example.com/web@sha256:3333333333333333333333333333333333333333333333333333333333333333
          readinessProbe: {httpGet: {path: /h, port: 8080}}
          livenessProbe: {httpGet: {path: /h, port: 8080}}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            capabilities: {drop: ["ALL"]}
          resources: {limits: {cpu: "1", memory: 256Mi}, requests: {cpu: 100m, memory: 128Mi}}
"""

_SPREAD = """\
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: DoNotSchedule
          labelSelector: {matchLabels: {app: web}}
"""

_PDB = """\
apiVersion: %(group)s
kind: PodDisruptionBudget
metadata: {name: web, namespace: shop}
spec: {minAvailable: %(min)s, selector: {matchLabels: {app: web}}}
"""


def _node_dark(replicas: int, spread: bool, pdb_min: str, pdb_group: str = "policy/v1") -> dict:
    docs = [
        _WORKLOAD % {"replicas": replicas, "spread": _SPREAD if spread else ""},
        _PDB % {"group": pdb_group, "min": pdb_min},
    ]
    lesson = next(lsn for lsn in _mechanism_lessons() if lsn["id"] == NODE_DARK)
    return M.walk(lesson, analyze("---\n".join(docs), "kubernetes", None).as_dict())


def test_a_workload_that_survives_a_lost_node_walks_the_whole_path() -> None:
    walked = _node_dark(replicas=3, spread=True, pdb_min="1")
    assert walked["verdict"] == "complete" and walked["exitCode"] == 0
    # The scheduler's own decision is declared unobservable, so it is reported and never counted as holding.
    last = walked["steps"][-1]
    assert last["step"] == "the-scheduler-places-the-replacement" and last["verdict"] == M.NOT_OBSERVABLE


def test_one_replica_behind_a_budget_that_blocks_everything_breaks_two_hops() -> None:
    walked = _node_dark(replicas=1, spread=False, pdb_min="100%")
    assert walked["verdict"] == "broken" and walked["exitCode"] == 1
    broken = {s["step"] for s in walked["steps"] if s["verdict"] == M.FAILS}
    assert broken == {"more-than-one-replica", "the-budget-lets-one-go"}, walked["steps"]
    # A verdict is a verdict: the walk reaches the end rather than stopping.
    assert walked["stoppedAt"] is None and walked["counts"]["notReached"] == 0


def test_a_budget_under_a_group_no_rule_reads_stops_the_walk() -> None:
    """Absence and refusal again, in the second lesson: no budget is judged, an unread budget is not."""
    walked = _node_dark(replicas=3, spread=True, pdb_min="1", pdb_group="policy.example.com/v1alpha1")
    assert walked["verdict"] == "stopped" and walked["exitCode"] == 5
    assert walked["stoppedAt"] == "the-budget-lets-one-go"
    assert walked["counts"]["notReached"] == 1


def test_no_budget_at_all_stops_the_walk_because_the_rule_abstains() -> None:
    """Two rules about a missing object, two different answers -- and only measuring tells them apart.

    This test asserted the opposite until G389. The claim was that KN-C009 answers for a namespace with no
    PodDisruptionBudget, the way KN-N001 answers for one with no NetworkPolicy. Measured on the workload
    alone: KN-N001 is in `findings`, and KN-C009 is in `notEvaluated` as "no policy PodDisruptionBudget in
    the input". It abstains, so nothing judges this hop and the walk must stop at it.
    """
    lesson = next(lsn for lsn in _mechanism_lessons() if lsn["id"] == NODE_DARK)
    only_workload = _WORKLOAD % {"replicas": 3, "spread": _SPREAD}
    report = analyze(only_workload, "kubernetes", None).as_dict()
    assert "KN-C009" in (report.get("notEvaluated") or {}), "KN-C009 now judges the absence; this test is stale"
    walked = M.walk(lesson, report)
    assert walked["stoppedAt"] == "the-budget-lets-one-go"
    assert _by_id(walked)["the-budget-lets-one-go"]["verdict"] == M.CANNOT_JUDGE
    assert walked["exitCode"] == 5


def test_the_network_lessons_policy_hop_is_judged_on_the_same_kind_of_absence() -> None:
    """The contrast, held in a test so the two rules cannot be assumed to behave alike again."""
    report = analyze("---\n".join((INGRESS, SERVICE, DEPLOYMENT)), "kubernetes", None).as_dict()
    assert "KN-N001" not in (report.get("notEvaluated") or {})
    assert any(f["ruleId"] == "KN-N001" for f in report.get("findings") or ())
    lesson = next(lsn for lsn in _mechanism_lessons() if lsn["id"] == LESSON_ID)
    walked = M.walk(lesson, report)
    assert walked["stoppedAt"] is None
    assert _by_id(walked)["policy-admits-the-packet"]["verdict"] == M.FAILS


# --- what the ledger says was never read (G389) ------------------------------------------------------------

_NO_TEMPLATE = """\
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  replicas: 2
  selector: {matchLabels: {app: web}}
"""


def test_a_hop_whose_rules_all_reached_no_verdict_cannot_be_judged() -> None:
    """The walk read "no finding" as "nothing wrong" for rules that never ran.

    A Deployment carrying no pod template satisfies `needs` by kind and is not refused, so neither guard saw
    it -- and the report's own `notEvaluated` says KN-V011 and KN-V012 reached no verdict, "no pod spec in the
    input". The walk reported every hop as holding, `complete` at exit 0, while `audit` on the same input
    exits 1, and hop 5 claimed "the containers declare a readiness probe" about zero containers.
    """
    report = analyze("---\n".join((INGRESS, SERVICE, _NO_TEMPLATE, NETPOL)), "kubernetes", None).as_dict()
    unevaluated = report.get("notEvaluated") or {}
    assert {"KN-V011", "KN-V012"} <= set(unevaluated), unevaluated
    walked = M.walk(_lesson(), report)
    assert walked["verdict"] == "stopped" and walked["exitCode"] == 5
    assert walked["stoppedAt"] == "service-selects-pods"
    why = _by_id(walked)["service-selects-pods"]["why"]
    assert "reached no verdict here" in why and "KN-V011" in why
    # The hops after it, including the one that would have claimed a probe, are not drawn.
    assert "pod-reports-ready" not in _by_id(walked)


def test_a_rule_that_fired_still_judges_its_hop_even_beside_one_that_did_not() -> None:
    """The control. A finding IS a verdict, so a hop is not unjudged merely because a sibling rule abstained."""
    report = analyze("---\n".join((INGRESS, SERVICE, NO_PROBE, NETPOL)), "kubernetes", None).as_dict()
    walked = M.walk(_lesson(), report)
    assert _by_id(walked)["pod-reports-ready"]["verdict"] == M.FAILS
    assert walked["stoppedAt"] is None


def test_a_name_full_of_newlines_cannot_write_a_line_of_its_own(tmp_path: Path) -> None:
    """The walk printed `findings[].resource` raw, so a crafted name wrote whole lines into the output.

    Measured before the fix: a Deployment named "web\\n6. [holds] ...\\nevery observable hop on this path
    holds" produced those two lines at column zero, the second of them the walk's own pass sentence. `audit`
    on the same file collapses the name, because its renderer bounds the value and this one did not.
    """
    hostile = _WORKLOAD % {"replicas": 1, "spread": ""}
    hostile = hostile.replace(
        "metadata: {name: web, namespace: shop}",
        'metadata:\n  name: "web\\n6. [holds] The pod says it is ready\\nevery observable hop on this path holds"\n'
        "  namespace: shop",
    )
    f = tmp_path / "hostile.yaml"
    f.write_text(hostile, encoding="utf-8")
    import yaml as _yaml

    assert _yaml.safe_load(hostile)["metadata"]["name"].count("\n") == 2, "the name holds no real newlines"
    out = subprocess.run(
        [sys.executable, "-m", "kube_noob", "learn", "mechanism", NODE_DARK, "-f", str(f)],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    for line in out.stdout.splitlines():
        assert not line.startswith("6. ["), f"a forged step line reached column zero: {line!r}"
        assert line.strip() != "every observable hop on this path holds", "a forged verdict line was printed"


# --- a walk that judged nothing reached no verdict (G395) ---------------------------------------------------

_ALL_UNOBSERVABLE = {
    "id": "probe-node-layer",
    "title": "A walk that checked nothing",
    "layer": "node",
    "steps": [
        {"id": "kubelet-syncs", "title": "The kubelet syncs the pod", "observable": False, "holds": "it syncs"},
        {"id": "runtime-starts", "title": "The runtime starts it", "observable": False, "holds": "CRI creates it"},
        {"id": "cgroups-hold", "title": "The cgroups hold the limits", "observable": False, "holds": "it is written"},
    ],
}


def test_a_walk_in_which_nothing_was_judged_reached_no_verdict_about_the_path() -> None:
    """The headline of G395, and the vacuous truth this project has caught three times before.

    Every hop of this lesson is `observable: false`, so none sets `stopped_at` and none counts as judged. The
    walk came out `complete` at exit 0 with "every observable hop on this path holds" beside it -- true, and
    vacuously so: there are no observable hops, so all of them hold. Measured before the repair:
    `verdict: complete | exitCode: 0 | counts.judged: 0`. Zero of the 98 rules read the kubelet, the container
    runtime, cgroups, kube-proxy, iptables, conntrack, veth or the overlay, so an author writing a Node-layer
    lesson could mark every hop unobservable and ship a full green page.
    """
    walked = M.walk(_ALL_UNOBSERVABLE, analyze(DEPLOYMENT, "kubernetes", None).as_dict())
    assert walked["counts"]["judged"] == 0
    assert walked["verdict"] == "stopped" and walked["exitCode"] == 5
    # No hop is the obstacle: each was honestly reported `not-observable` and none was skipped, so there is no
    # hop to name and `stoppedAt` stays null. The reason carries the truth instead.
    assert walked["stoppedAt"] is None
    assert "no hop on this path was judged" in walked["verdictReason"]
    assert "every observable hop on this path holds" not in walked["verdictReason"]
    assert all(s["verdict"] == M.NOT_OBSERVABLE for s in walked["steps"])
    assert walked["counts"]["notReached"] == 0


def test_one_judged_hop_beside_unobservable_ones_is_still_a_verdict() -> None:
    """The control. `judged == 0` is the bar, not "some hop was unobservable"."""
    lesson = {
        **_ALL_UNOBSERVABLE,
        "steps": [
            *_ALL_UNOBSERVABLE["steps"],
            {"id": "probe", "title": "A hop a rule reads", "needs": ["Deployment"], "holds": "x", "rules": ["KN-C001"]},
        ],
    }
    walked = M.walk(lesson, analyze(DEPLOYMENT, "kubernetes", None).as_dict())
    assert walked["counts"]["judged"] == 1
    assert walked["verdict"] == "complete" and walked["exitCode"] == 0


def test_the_text_view_of_a_walk_that_judged_nothing_does_not_read_as_a_pass() -> None:
    text = M.render(M.walk(_ALL_UNOBSERVABLE, analyze(DEPLOYMENT, "kubernetes", None).as_dict()))
    assert "every observable hop on this path holds" not in text
    assert "no hop on this path was judged" in text


def test_every_mechanism_lesson_declares_an_observable_hop_a_rule_in_this_build_reads() -> None:
    """The curriculum invariant that stops an all-unobservable lesson from being written at all.

    The verdict repair above makes such a lesson answer 5 rather than 0; this makes it impossible to ship. The
    inventory comes from `list_rules()` -- the rules this build really has -- and never from the YAML, because a
    step naming a rule id that no longer exists reads as a rule that found nothing.
    """
    from kube_noob.audit.engine import list_rules

    known = {r["ruleId"] for r in list_rules()}
    for lesson in _mechanism_lessons():
        readable = [
            step
            for step in lesson["steps"]
            if step.get("observable", True) is not False and (set(step.get("rules") or ()) & known)
        ]
        assert readable, (
            f"{lesson['id']} declares no observable hop whose rules name a rule this build has, so every walk of "
            f"it judges nothing and answers 5. Give it at least one hop with `observable: true` and a `rules:` "
            f"list naming a rule from `kube-noob rules list` -- or, if this layer's hops genuinely have no reader "
            f"in this build (nothing reads the kubelet, the container runtime, cgroups, kube-proxy, iptables, "
            f"conntrack, veth or the overlay), write the rule first and the lesson after."
        )


# --- a hop's title asserts only what its rules decide (G395) -------------------------------------------------

#: `podSelector: {}` with `policyTypes: [Ingress]` and no `ingress:` rules. It admits NOTHING, and all three
#: rules the policy hop names are clean on it: KN-N001 fires on an ABSENT policy, KN-N007 on an over-permissive
#: one, KN-N012 on one that selects nothing -- and `podSelector: {}` selects every pod, so KN-N012 skips it.
DENY_ALL = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: web, namespace: shop}
spec:
  podSelector: {}
  policyTypes: ["Ingress"]
"""


def _dir_walk(tmp_path: Path, *docs: str) -> dict:
    """A DIRECTORY, which `cli._partial_input` reads as the whole namespace, so the absence rules are evaluated."""
    d = tmp_path / "bundle"
    d.mkdir()
    (d / "all.yaml").write_text("---\n".join(docs), encoding="utf-8")
    from kube_noob import cli

    return M.walk(_lesson(), analyze(cli._read(str(d)), "kubernetes", None).as_dict())


def test_the_policy_hop_never_says_a_deny_all_policy_lets_the_packet_in(tmp_path: Path) -> None:
    """Measured: hop 4 rendered `[holds] Network policy lets the packet in` over a policy that admits nothing.

    The `holds` SENTENCE was true -- that is exactly what KN-N001, KN-N007 and KN-N012 checked. The TITLE
    claimed admission, which by construction none of them can establish: they fire when a policy is absent,
    too permissive, or inert. A reader saw "the packet gets in" over a policy that denies everything.
    """
    walked = _dir_walk(tmp_path, INGRESS, SERVICE, DEPLOYMENT, DENY_ALL)
    hop = _by_id(walked)["policy-admits-the-packet"]
    assert hop["verdict"] == M.HOLDS, walked
    claim = f"{hop['title']} {hop['why']}".lower()
    assert "lets the packet in" not in claim, hop
    assert "admits the packet" not in claim, hop
    # What the rules DO establish, still said.
    assert "networkpolicy" in claim and ("allow-all" in claim or "selects nothing" in claim), hop


def test_the_edge_hop_never_claims_admission_it_cannot_establish(tmp_path: Path) -> None:
    """KN-N003, KN-N009, KN-N011 and KN-V019 read TLS and ingress-nginx hazards; none reads host or backend.

    Measured: an Ingress whose only backend names a Service that is not in the bundle walked
    `[holds] The edge admits the request`.
    """
    nowhere = INGRESS.replace("{service: {name: web,", "{service: {name: absent-service,")
    assert "absent-service" in nowhere
    walked = _dir_walk(tmp_path, nowhere, SERVICE, DEPLOYMENT, NETPOL)
    hop = _by_id(walked)["edge-admits"]
    assert hop["verdict"] == M.HOLDS, walked
    assert "admits the request" not in f"{hop['title']} {hop['why']}".lower(), hop


def test_the_service_hop_never_claims_a_port_the_containers_do_not_declare(tmp_path: Path) -> None:
    """KN-V012 reads a NAMED targetPort only, so a numeric one no container declares is nobody's finding.

    Measured: `targetPort: 9999` against a container declaring 8080 walked `[holds]` under the words "on a port
    the containers declare".
    """
    svc = SERVICE.replace("targetPort: http", "targetPort: 9999")
    assert "9999" in svc
    walked = _dir_walk(tmp_path, INGRESS, svc, DEPLOYMENT, NETPOL)
    hop = _by_id(walked)["service-selects-pods"]
    assert hop["verdict"] == M.HOLDS, walked
    claim = f"{hop['title']} {hop['why']}".lower()
    assert "on a port the containers declare" not in claim, hop
    assert "selects at least one pod" in claim, hop


def test_the_readiness_hop_claims_a_declared_probe_and_not_a_running_pod(tmp_path: Path) -> None:
    """KN-C001 reads `readinessProbe` in a pod template. Whether a pod IS ready is runtime state no manifest holds."""
    walked = _dir_walk(tmp_path, INGRESS, SERVICE, DEPLOYMENT, NETPOL)
    hop = _by_id(walked)["pod-reports-ready"]
    assert hop["verdict"] == M.HOLDS, walked
    claim = f"{hop['title']} {hop['why']}".lower()
    assert "says it is ready" not in claim and "is ready to receive" not in claim, hop
    assert "readiness probe" in claim, hop


_ONE_REPLICA = _WORKLOAD % {"replicas": 1, "spread": ""}
#: An HPA pinned at 1..1. Until G397 any HPA naming the workload cleared KN-C007 whatever its own
#: `minReplicas`; now a floor of one excuses nothing, and this is the input that proves it.
_HPA_PINNED_AT_ONE = """\
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata: {name: web, namespace: shop}
spec:
  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: web}
  minReplicas: 1
  maxReplicas: 1
  metrics: []
"""
_PDB_ALLOWS_ONE = """\
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: web, namespace: shop}
spec: {maxUnavailable: 1, selector: {matchLabels: {app: web}}}
"""


def test_the_replica_hops_never_describe_one_unspread_replica_as_many_and_spread() -> None:
    """The same gap in the control-plane lesson, and the answer to "can a hop hold on a silent abstention?".

    Measured on one replica, no `topologySpreadConstraints`, no `podAntiAffinity`, an HPA pinned at 1..1 and a
    budget that permits an eviction: the walk came out `complete` at exit 0 with hop 1 saying "the workload runs
    more than a single replica" and hop 2 "the pod template spreads its replicas". Both are false of that input.
    KN-C007 is excused by ANY HorizontalPodAutoscaler naming the workload, and KN-C010 skips a workload below two
    replicas -- neither records anything in `notEvaluated`, so `by_rule` is empty, nothing is unevaluated, and the
    walk's only remaining branch is `holds`. A rule that silently skips its subject is indistinguishable here from
    a rule that read it and was satisfied, which is why these two hops may claim only what the rules test for.
    """
    report = analyze("---\n".join((_ONE_REPLICA, _HPA_PINNED_AT_ONE, _PDB_ALLOWS_ONE)), "kubernetes", None).as_dict()
    unevaluated = report.get("notEvaluated") or {}
    fired = {f["ruleId"] for f in report.get("findings") or ()}
    # G397: KN-C007 reads the autoscaler's floor, so an HPA pinned at one no longer excuses one replica. The hop
    # that held on this input now FAILS, which is the true answer -- one replica does not survive its node.
    assert "KN-C007" in fired, "an HPA with a floor of one excused a single replica again"
    assert "KN-C010" not in unevaluated and "KN-C010" not in fired, "KN-C010 now speaks here; this test is stale"

    lesson = next(lsn for lsn in _mechanism_lessons() if lsn["id"] == NODE_DARK)
    walked = M.walk(lesson, report)
    hops = {s["step"]: s for s in walked["steps"]}
    one = hops["more-than-one-replica"]
    apart = hops["replicas-can-land-apart"]
    assert one["verdict"] == M.FAILS, one
    assert walked["verdict"] == "broken" and walked["exitCode"] == 1, walked
    # KN-C010 is still silent below two replicas, and correctly so -- there is nothing to spread. The hop still
    # holds, so its title may claim only what KN-C010 decides, never that THESE replicas are spread.
    assert apart["verdict"] == M.HOLDS, apart
    assert "runs more than a single replica" not in f"{one['title']} {one['why']}".lower(), one
    assert "there is more than one of it" not in one["title"].lower(), one
    assert "spreads its replicas" not in f"{apart['title']} {apart['why']}".lower(), apart
