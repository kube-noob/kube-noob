"""The RBAC and ServiceAccounts walk, and the measurements its hops were written from (G401).

The two lessons before this one each shipped a hop that claimed more than its rule decided: KN-C009 was assumed to
judge an absent PodDisruptionBudget and abstains (G389), six titles said what no rule read (G395), KN-C007 never
looked at the HPA floor (G397). So this lesson was written the other way round. Each rule was run first on three
inputs -- its object present and fine, present and violating, ABSENT -- and the hops were designed from the answers.

What was measured, and `test_the_measurement_table` pins every cell of it so a rule that changes fails HERE first:

    rule      present, fine   present, violating   its object absent
    KN-S014   silent          fires                no pod spec: abstains. A pod spec and NO ServiceAccount object:
                                                   FIRES, from a directory and from one file alike
    KN-S028   silent          fires                abstains (no RoleBinding or ClusterRoleBinding)
    KN-S016   silent          fires                abstains (no RoleBinding or ClusterRoleBinding)
    KN-S015   silent          fires                abstains (no Role or ClusterRole)
    KN-S017   silent          fires                abstains (no Role or ClusterRole)
    KN-S027   silent          fires                abstains (no Secret)

Three things follow, and each is a test below.

- Five of the six abstain on absence, whole namespace or fragment, so absence stops the walk at that hop.
- KN-S014 is the exception, in the direction G394 found on the network lesson: it reports a pod for mounting the
  token of a ServiceAccount nobody passed, which may be the one that opts out. The hop therefore NEEDS a
  ServiceAccount in the input; without one it is not judged instead of being reported BROKEN.
- No rule joins a pod to its ServiceAccount, a ServiceAccount to its bindings, or a binding to its role. The titles
  say "here" for that reason, and a role a binding names that is not in the input is disclosed, never implied read.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from kube_noob import toolkit as tk
from kube_noob.audit.engine import analyze
from kube_noob.config import load_settings
from kube_noob.learn import mechanism as M

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "mechanism" / "rbac"
LESSON = "mech-sec-rbac-and-serviceaccounts"
HOPS = [
    "no-pod-automounts-a-token",
    "no-binding-grants-to-everyone",
    "no-binding-names-cluster-admin",
    "no-role-uses-a-wildcard",
    "no-role-carries-an-escalation-grant",
    "no-long-lived-token-secret",
    "the-api-server-authorizes-the-request",
]

# --- the inputs the table was measured on ------------------------------------------------------------------------


def _deployment(automount: str = "", sa: str = "orders") -> str:
    return f"""\
apiVersion: apps/v1
kind: Deployment
metadata: {{name: orders-api, namespace: shop}}
spec:
  replicas: 2
  selector: {{matchLabels: {{app: orders-api}}}}
  template:
    metadata: {{labels: {{app: orders-api}}}}
    spec:
      serviceAccountName: {sa}
{automount}      containers:
        - name: api
          image: ghcr.io/acme/orders-api:1.4.2
"""


OFF = "      automountServiceAccountToken: false\n"
ON = "      automountServiceAccountToken: true\n"
SA = "apiVersion: v1\nkind: ServiceAccount\nmetadata: {name: orders, namespace: shop}\n"
SA_OFF = SA + "automountServiceAccountToken: false\n"
OTHER_SA_OFF = SA_OFF.replace("name: orders", "name: somebody-else")


def _role(rule: str) -> str:
    return (
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\n"
        f"metadata: {{name: orders-reader, namespace: shop}}\nrules:{rule}\n"
    )


ROLE_NARROW = _role('\n  - {apiGroups: [""], resources: [configmaps], verbs: [get], resourceNames: [orders-config]}')
ROLE_WILDCARD = _role('\n  - {apiGroups: [""], resources: [secrets], verbs: ["*"]}')
ROLE_EXEC = _role('\n  - {apiGroups: [""], resources: [pods/exec], verbs: [create]}')
ROLE_LISTS_SECRETS = _role('\n  - {apiGroups: [""], resources: [secrets], verbs: [get, list]}')
ROLE_NO_RULES = _role(" []")


def _binding(
    kind: str = "RoleBinding",
    ref: str = "{apiGroup: rbac.authorization.k8s.io, kind: Role, name: orders-reader}",
    subjects: str = "subjects:\n  - {kind: ServiceAccount, name: orders, namespace: shop}\n",
) -> str:
    ns = ", namespace: shop" if kind == "RoleBinding" else ""
    return (
        f"apiVersion: rbac.authorization.k8s.io/v1\nkind: {kind}\n"
        f"metadata: {{name: orders-reader{ns}}}\nroleRef: {ref}\n{subjects}"
    )


_ADMIN = "{apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}"
_EVERYONE = "subjects:\n  - {kind: Group, name: 'system:authenticated', apiGroup: rbac.authorization.k8s.io}\n"
SECRET_OPAQUE = "apiVersion: v1\nkind: Secret\nmetadata: {name: orders-db, namespace: shop}\ntype: Opaque\n"
SECRET_TOKEN = (
    "apiVersion: v1\nkind: Secret\nmetadata:\n  name: orders-token\n  namespace: shop\n"
    "  annotations: {kubernetes.io/service-account.name: orders}\ntype: kubernetes.io/service-account-token\n"
)

SILENT, FIRES, ABSTAINS = "silent", "fires", "abstains"

#: (rule, what the input is, the input, what the rule did). Every row was measured with
#: `python -m kube_noob audit -f <dir> --format json` and again with `-f <dir>/bundle.yaml`; the two agreed on
#: every row, which is itself a measurement and is why each row is asserted under both `partial_bundle` values.
TABLE: list[tuple[str, str, str, str]] = [
    ("KN-S014", "the pod turns the mount off", _deployment(OFF), SILENT),
    ("KN-S014", "unset, and no ServiceAccount object at all", _deployment(), FIRES),
    ("KN-S014", "unset, its ServiceAccount here and silent", _deployment() + "---\n" + SA, FIRES),
    ("KN-S014", "unset, its ServiceAccount here and opting out", _deployment() + "---\n" + SA_OFF, SILENT),
    ("KN-S014", "the pod asks for it over its ServiceAccount", _deployment(ON) + "---\n" + SA_OFF, FIRES),
    ("KN-S014", "unset, and only ANOTHER ServiceAccount opts out", _deployment() + "---\n" + OTHER_SA_OFF, FIRES),
    ("KN-S014", "no pod spec", SA_OFF, ABSTAINS),
    ("KN-S028", "a binding to one ServiceAccount", _binding(), SILENT),
    ("KN-S028", "a binding with no subjects", _binding(subjects=""), SILENT),
    ("KN-S028", "a binding to system:authenticated", _binding(subjects=_EVERYONE), FIRES),
    ("KN-S028", "no binding", _deployment(OFF) + "---\n" + SA + "---\n" + ROLE_NARROW, ABSTAINS),
    ("KN-S016", "a binding to a Role", _binding(), SILENT),
    ("KN-S016", "a RoleBinding to cluster-admin", _binding(ref=_ADMIN), FIRES),
    ("KN-S016", "a ClusterRoleBinding to cluster-admin", _binding("ClusterRoleBinding", _ADMIN), FIRES),
    ("KN-S016", "no binding", _deployment(OFF) + "---\n" + SA + "---\n" + ROLE_NARROW, ABSTAINS),
    ("KN-S015", "get on one named ConfigMap", ROLE_NARROW, SILENT),
    ("KN-S015", "a Role with no rules", ROLE_NO_RULES, SILENT),
    ("KN-S015", "create on pods/exec, no wildcard", ROLE_EXEC, SILENT),
    ("KN-S015", "'*' on secrets", ROLE_WILDCARD, FIRES),
    ("KN-S015", "a binding whose Role is not here", _binding(), ABSTAINS),
    ("KN-S017", "get on one named ConfigMap", ROLE_NARROW, SILENT),
    ("KN-S017", "a Role with no rules", ROLE_NO_RULES, SILENT),
    ("KN-S017", "'*' on secrets", ROLE_WILDCARD, FIRES),
    ("KN-S017", "create on pods/exec", ROLE_EXEC, FIRES),
    ("KN-S017", "get and list on secrets", ROLE_LISTS_SECRETS, FIRES),
    ("KN-S017", "a binding whose Role is not here", _binding(), ABSTAINS),
    ("KN-S027", "an Opaque Secret", SECRET_OPAQUE, SILENT),
    ("KN-S027", "a service-account-token Secret", SECRET_TOKEN, FIRES),
    ("KN-S027", "no Secret", _deployment(OFF) + "---\n" + SA, ABSTAINS),
]


def _did(rule: str, report: dict) -> str:
    """What one rule did on one report, in the three states the walker tells apart."""
    fired = any(f.get("ruleId") == rule for f in report.get("findings") or ())
    abstained = rule in (report.get("notEvaluated") or {})
    assert not (fired and abstained), f"{rule} both fired and is listed as not evaluated"
    return FIRES if fired else ABSTAINS if abstained else SILENT


@pytest.mark.parametrize("partial", [False, True], ids=["whole-namespace", "fragment"])
@pytest.mark.parametrize(("rule", "what", "manifests", "expected"), TABLE, ids=[f"{r}: {w}" for r, w, _, _ in TABLE])
def test_the_measurement_table(rule: str, what: str, manifests: str, expected: str, partial: bool) -> None:
    """The lesson's hops were designed from this table. A cell that changes means a hop has to be re-read.

    In particular: an `abstains` that becomes `silent` turns a stop into a `holds` on an object that is not there,
    and the KN-S014 row "unset, and no ServiceAccount object at all" becoming anything else changes what the
    first hop's `needs: [ServiceAccount]` is protecting.
    """
    report = analyze(manifests, "kubernetes", None, partial_bundle=partial).as_dict()
    assert _did(rule, report) == expected, (
        f"{rule} on {what!r} ({'fragment' if partial else 'whole namespace'}) is no longer {expected}; "
        f"re-read the hop of {LESSON} that names it before changing this row"
    )
    assert not report.get("notAudited"), f"the measurement input itself was refused: {report['notAudited']}"


# --- the walk -----------------------------------------------------------------------------------------------------


def _cli(path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "KUBE_NOOB_OFFLINE": "1"}
    return subprocess.run(
        [sys.executable, "-m", "kube_noob", "learn", "mechanism", LESSON, "-f", str(path), *extra],
        capture_output=True,
        text=True,
        env=env,
        cwd=ROOT,
        check=False,
        timeout=300,
    )


def _kit(tmp_path: Path) -> tk.Toolkit:
    return tk.Toolkit(load_settings(overrides={"offline": True, "dataDir": str(tmp_path / "data")}))


def _tool(tmp_path: Path, manifests: str, partial: bool) -> dict:
    return _kit(tmp_path).mechanism(tk.MechanismIn(mechanism_id=LESSON, manifests=manifests, partial_bundle=partial))


def _docs(bundle: str) -> dict[str, str]:
    """The complete fixture's documents by kind, so an absence case is the fixture minus exactly one object."""
    out: dict[str, str] = {}
    for doc in bundle.split("\n---\n"):
        out[str(yaml.safe_load(doc)["kind"])] = doc.strip("\n") + "\n"
    return out


def _without(*kinds: str) -> str:
    docs = _docs((FIXTURES / "complete" / "bundle.yaml").read_text("utf-8"))
    assert set(kinds) <= set(docs), f"the fixture has no {sorted(set(kinds) - set(docs))} to remove"
    return "---\n".join(d for k, d in docs.items() if k not in kinds)


def _verdicts(walked: dict) -> dict[str, str]:
    return {str(s["step"]): str(s["verdict"]) for s in walked["steps"]}


def test_the_lesson_is_the_path_these_tests_describe() -> None:
    """The ids, in order, and the one hop no manifest can show. A reordering is a design change, not a tidy-up:
    the Secret hop is last on purpose (see its comment in the curriculum)."""
    data = yaml.safe_load((ROOT / "src" / "kube_noob" / "data" / "curriculum.yaml").read_text("utf-8"))
    lesson = next(ls for t in data["tracks"] for ls in t.get("lessons") or () if ls["id"] == LESSON)
    assert lesson["layer"] == "security"
    assert [s["id"] for s in lesson["steps"]] == HOPS
    unobservable = [s["id"] for s in lesson["steps"] if s.get("observable", True) is False]
    assert unobservable == ["the-api-server-authorizes-the-request"], unobservable
    named = [r for s in lesson["steps"] for r in s.get("rules") or ()]
    assert sorted(named) == sorted({r for r, *_ in TABLE}), (
        f"the lesson names {sorted(named)} and the table measures {sorted({r for r, *_ in TABLE})}: "
        "a rule on a hop with no measured row is a rule nobody ran before trusting"
    )


def test_the_complete_bundle_walks_to_the_end_and_claims_nothing_about_the_authorizer() -> None:
    out = _cli(FIXTURES / "complete", "--format", "json")
    doc = json.loads(out.stdout)
    assert out.returncode == doc["exitCode"] == 0, (out.returncode, doc["verdictReason"], out.stderr[-300:])
    assert doc["verdict"] == "complete" and doc["stoppedAt"] is None
    assert [s["step"] for s in doc["steps"]] == HOPS, "a hop was not drawn"
    verdicts = _verdicts(doc)
    assert all(verdicts[h] == M.HOLDS for h in HOPS[:-1]), verdicts
    assert verdicts[HOPS[-1]] == M.NOT_OBSERVABLE, "the authorizer hop was graded; no manifest holds its evidence"
    assert doc["counts"] == {"declared": 7, "judged": 6, "notObservable": 1, "notReached": 0}, doc["counts"]
    text = _cli(FIXTURES / "complete")
    assert text.returncode == 0 and "[not checked] The API server authorizes the request" in text.stdout


def test_a_wildcard_on_secrets_breaks_the_role_hops_and_names_the_rules() -> None:
    """The realistic mistake: the app needed one Secret and its Role was given `*` on all of them."""
    out = _cli(FIXTURES / "broken", "--format", "json")
    doc = json.loads(out.stdout)
    assert out.returncode == doc["exitCode"] == 1, (out.returncode, doc["verdictReason"], out.stderr[-300:])
    assert doc["verdict"] == "broken" and doc["stoppedAt"] is None, "a finding is a verdict; the walk carries on"
    steps = {s["step"]: s for s in doc["steps"]}
    wildcard = steps["no-role-uses-a-wildcard"]
    assert wildcard["verdict"] == M.FAILS
    assert [(f["ruleId"], f["resource"]) for f in wildcard["findings"]] == [
        ("KN-S015", "Role/shop/orders-config-reader")
    ], wildcard["findings"]
    escalation = steps["no-role-carries-an-escalation-grant"]
    assert escalation["verdict"] == M.FAILS
    assert {f["ruleId"] for f in escalation["findings"]} == {"KN-S017"}, escalation["findings"]
    broken = sorted(s for s, v in _verdicts(doc).items() if v == M.FAILS)
    assert broken == ["no-role-carries-an-escalation-grant", "no-role-uses-a-wildcard"], (
        f"the one mistake in this bundle is in the Role; these hops are broken: {broken}"
    )
    assert "no-role-uses-a-wildcard" in doc["verdictReason"]
    text = _cli(FIXTURES / "broken")
    assert text.returncode == 1
    assert "HIGH  KN-S015  Role/shop/orders-config-reader" in text.stdout, text.stdout[-600:]


#: (what is missing, the kinds removed from the complete bundle, the hop that must not hold, words in its reason).
ABSENCES = [
    ("no ServiceAccount", ("ServiceAccount",), "no-pod-automounts-a-token", "no ServiceAccount in the input"),
    ("no pod spec", ("Deployment",), "no-pod-automounts-a-token", "KN-S014 reached no verdict here"),
    ("no binding", ("RoleBinding",), "no-binding-grants-to-everyone", "no RoleBinding or ClusterRoleBinding"),
    ("no Role", ("Role",), "no-role-uses-a-wildcard", "no Role or ClusterRole in the input"),
    ("no Secret", ("Secret",), "no-long-lived-token-secret", "no Secret in the input"),
]


@pytest.mark.parametrize("partial", [False, True], ids=["whole-namespace", "fragment"])
@pytest.mark.parametrize(("what", "kinds", "hop", "says"), ABSENCES, ids=[a[0] for a in ABSENCES])
def test_an_absent_object_stops_the_walk_at_its_hop_and_never_holds(
    what: str, kinds: tuple[str, ...], hop: str, says: str, partial: bool, tmp_path: Path
) -> None:
    """Each object this path reads, removed in turn from a bundle that otherwise walks to the end.

    The hop is `cannot-judge`, not `holds` and not `fails`; the hops before it keep their verdict; the hops after
    it are not drawn; and the path's answer is 5 -- no verdict was reached -- whether the caller said the input is
    a whole namespace or a fragment, because none of these rules decides anything from the absence.
    """
    walked = _tool(tmp_path, _without(*kinds), partial)
    verdicts = _verdicts(walked)
    assert verdicts.get(hop) == M.CANNOT_JUDGE, f"with {what}, {hop} is {verdicts.get(hop)!r}: {walked['steps']}"
    step = next(s for s in walked["steps"] if s["step"] == hop)
    assert says in step["why"], step["why"]
    before = HOPS[: HOPS.index(hop)]
    assert [verdicts[h] for h in before] == [M.HOLDS] * len(before), verdicts
    assert list(verdicts) == [*before, hop], f"hops were drawn past the stop: {list(verdicts)}"
    assert (walked["verdict"], walked["exitCode"], walked["stoppedAt"]) == ("stopped", 5, hop), walked["verdictReason"]
    assert walked["counts"]["notReached"] == len(HOPS) - len(before) - 1


def test_the_bare_role_hop_is_also_stopped_by_the_rule_and_not_only_by_needs(tmp_path: Path) -> None:
    """`needs` and `notEvaluated` both stop the Role hop today, and either alone has to be enough.

    A synthetic copy of the hop with its `needs` removed still stops, on KN-S015's own abstention -- so the stop
    does not rest on a list in the YAML that a later edit could drop. It keeps `reads`: since G408 an observable hop
    must name at least one kind, and `reads` (what the hop looks at) is not `needs` (what must be present).
    """
    report = analyze(_without("Role"), "kubernetes", None, partial_bundle=False).as_dict()
    lesson = {
        "id": "mech-test-no-needs",
        "title": "t",
        "layer": "test",
        "steps": [
            {
                "id": "roles",
                "title": "roles",
                "holds": "h",
                "reads": ["Role", "ClusterRole"],
                "rules": ["KN-S015", "KN-S017"],
            }
        ],
    }
    walked = M.walk(lesson, report)
    assert _verdicts(walked) == {"roles": M.CANNOT_JUDGE}, walked["steps"]
    assert "reached no verdict here" in walked["steps"][0]["why"]


def test_a_single_file_of_the_whole_bundle_walks_exactly_as_its_directory_does() -> None:
    """Unlike the network lesson, where one file is a fragment and the policy hop stops (G394).

    Measured: none of this path's six rules fires because ANOTHER object is absent -- five abstain, and the hop
    over the sixth is not judged without a ServiceAccount -- so a fragment and a whole namespace get the same
    walk, and every hop's claim is about the objects "here", which is true of a fragment too.
    """
    as_dir = _cli(FIXTURES / "complete", "--format", "json")
    as_file = _cli(FIXTURES / "complete" / "bundle.yaml", "--format", "json")
    assert (as_dir.returncode, as_file.returncode) == (0, 0), (as_dir.returncode, as_file.returncode)
    assert json.loads(as_file.stdout) == json.loads(as_dir.stdout)
    broken = _cli(FIXTURES / "broken" / "bundle.yaml", "--format", "json")
    assert broken.returncode == 1 and json.loads(broken.stdout)["verdict"] == "broken"


def test_one_deployment_on_its_own_is_not_told_it_mounts_a_token(tmp_path: Path) -> None:
    """The one place this path could have accused a fragment, and does not.

    `audit` on a lone Deployment that leaves `automountServiceAccountToken` unset reports KN-S014, naming a
    ServiceAccount that was never passed and that may be the one opting the pod out. A hop resting on that rule
    alone would be BROKEN at exit 1 on one pasted file. The hop needs a ServiceAccount, so it is `cannot judge`
    at exit 5 -- from a file and from a directory holding only that file.
    """
    lone = tmp_path / "lone"
    lone.mkdir()
    (lone / "deployment.yaml").write_text(_deployment(), encoding="utf-8")
    audited = analyze(_deployment(), "kubernetes", None, partial_bundle=True).as_dict()
    assert _did("KN-S014", audited) == FIRES, "the audit no longer fires here; this test and the hop are stale"
    for target in (lone / "deployment.yaml", lone):
        out = _cli(target, "--format", "json")
        doc = json.loads(out.stdout)
        assert out.returncode == doc["exitCode"] == 5, (target.name, out.returncode, doc["verdictReason"])
        assert _verdicts(doc) == {"no-pod-automounts-a-token": M.CANNOT_JUDGE}, doc["steps"]
        assert doc["counts"]["notReached"] == 6


def test_the_gap_the_first_hop_still_has_is_the_audits_own_and_is_pinned(tmp_path: Path) -> None:
    """Measured and left, so it is written down where a change to it will be noticed (G401).

    `needs` asks for A ServiceAccount, not for the one the pod names. A fragment holding the Deployment and some
    OTHER ServiceAccount therefore judges the hop, and KN-S014's finding breaks it -- about a ServiceAccount that
    was not passed. That is the audit's own answer on the same input; narrowing it is a change to the rule, which
    this lesson does not make. When the rule learns to withhold there, this fails and the hop can say so.
    """
    walked = _tool(tmp_path, _deployment() + "---\n" + OTHER_SA_OFF, True)
    assert _verdicts(walked)["no-pod-automounts-a-token"] == M.FAILS, walked["steps"]
    assert walked["stoppedAt"] == "no-binding-grants-to-everyone", "and the next hop, with no binding, still stops"
    assert (walked["verdict"], walked["exitCode"]) == ("broken", 1)


def test_a_token_left_mounted_beside_its_serviceaccount_breaks_the_first_hop(tmp_path: Path) -> None:
    """With the ServiceAccount here the hop IS judged, both ways: the violating case of the first hop."""
    docs = _docs((FIXTURES / "complete" / "bundle.yaml").read_text("utf-8"))
    docs["Deployment"] = docs["Deployment"].replace(
        "automountServiceAccountToken: false", "automountServiceAccountToken: true"
    )
    walked = _tool(tmp_path, "---\n".join(docs.values()), False)
    assert _verdicts(walked)["no-pod-automounts-a-token"] == M.FAILS, walked["steps"]
    assert (walked["verdict"], walked["exitCode"]) == ("broken", 1)
    assert len(walked["steps"]) == len(HOPS), "a broken hop is a verdict; the walk still reaches the end"


@pytest.mark.parametrize(
    ("kind", "hop"),
    [("RoleBinding", "no-binding-grants-to-everyone"), ("Role", "no-role-uses-a-wildcard")],
)
def test_an_object_under_a_group_no_rule_reads_stops_the_walk_beside_a_readable_one(
    kind: str, hop: str, tmp_path: Path
) -> None:
    """Absence and refusal are different states, and this is the sharper one: the object is HERE.

    The readable binding and Role are still in the bundle, so each rule has something to be silent about -- and
    the hop still may not hold, because a second object of its kind was read by nothing.
    """
    odd = f"apiVersion: example.com/v1\nkind: {kind}\nmetadata: {{name: odd, namespace: shop}}\n"
    walked = _tool(tmp_path, _without() + "---\n" + odd, False)
    verdicts = _verdicts(walked)
    assert verdicts.get(hop) == M.CANNOT_JUDGE, walked["steps"]
    step = next(s for s in walked["steps"] if s["step"] == hop)
    assert f"{kind}/shop/odd" in step["why"] and "nothing read it" in step["why"], step["why"]
    assert (walked["verdict"], walked["exitCode"], walked["stoppedAt"]) == ("stopped", 5, hop)


def test_a_role_that_is_bound_but_not_here_is_disclosed_and_never_implied_read(tmp_path: Path) -> None:
    """What this lesson cannot do with the rules there are, pinned so it stays said.

    A binding to the built-in `admin` ClusterRole, which no manifest carries, beside an unrelated harmless Role:
    KN-S015 and KN-S017 read the Role that is here and are silent, so the Role hops hold. That is true of what
    their titles claim -- "No Role or ClusterRole here ..." -- and it says nothing about what the ServiceAccount
    can do. No rule joins a binding to its role, so the hop's own sentence has to carry the limit.
    """
    to_admin = _binding(ref="{apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: admin}")
    walked = _tool(tmp_path, _without("RoleBinding") + "---\n" + to_admin, False)
    steps = {s["step"]: s for s in walked["steps"]}
    for hop in ("no-role-uses-a-wildcard", "no-role-carries-an-escalation-grant"):
        assert steps[hop]["verdict"] == M.HOLDS, steps[hop]
        assert "here" in steps[hop]["title"], f"{hop}'s title no longer scopes its claim to the input"
        assert "not in this input was not read" in steps[hop]["why"], steps[hop]["why"]
    for step in walked["steps"]:
        for overclaim in ("bound to", "can do", "least privilege", "is allowed"):
            assert overclaim not in step["title"], f"{step['step']} claims {overclaim!r}, which no rule here decides"


@pytest.mark.parametrize(
    ("fixture", "as_file", "code"),
    [("complete", False, 0), ("broken", False, 1), ("complete", True, 0), ("broken", True, 1)],
)
def test_the_command_and_the_tool_give_the_same_answer(fixture: str, as_file: bool, code: int, tmp_path: Path) -> None:
    """One path, one answer, compared as whole documents (review class 9): the command over a directory against
    the tool told the bundle is a whole namespace, and the command over one file against the tool's default."""
    bundle = FIXTURES / fixture / "bundle.yaml"
    out = _cli(bundle if as_file else bundle.parent, "--format", "json")
    assert out.returncode == code, f"the command exited {out.returncode}: {out.stderr[-300:]}"
    from_tool = _tool(tmp_path, bundle.read_text("utf-8"), as_file)
    assert json.loads(out.stdout) == from_tool, "the command and the tool disagree about the same path"
    assert from_tool["exitCode"] == code


def test_the_stopped_walk_is_the_same_from_the_command_and_the_tool(tmp_path: Path) -> None:
    """Parity on the answer that matters most, the one that is neither a pass nor a failure."""
    d = tmp_path / "ns"
    d.mkdir()
    (d / "bundle.yaml").write_text(_without("Role"), encoding="utf-8")
    out = _cli(d, "--format", "json")
    assert out.returncode == 5, out.stderr[-300:]
    assert json.loads(out.stdout) == _tool(tmp_path, _without("Role"), False)
