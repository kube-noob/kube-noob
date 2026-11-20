"""What answers the question (G235).

`insight` recognises what was pasted. Asked a question in words about a job this product does, it used to run
the generic evidence-gathering steps -- `get pods`, `describe pod`, `get events` -- and return nothing. Those
answer "something is broken, what is it", which is a different question: eight of eighteen realistic questions
came back with no findings and no next step, in a product whose whole adoption story is "paste anything".

These tests hold three properties: the question reaches the command that answers it, the command named exists,
and a pasted error that is not a question gets no advice about any of them.
"""

from __future__ import annotations

import contextlib
import io
import sys

import pytest

from kube_noob.cli import build_parser
from kube_noob.insight import CAPABILITY_ROUTES, MAX_ROUTES, capability_routes
from tests import bounds

#: The loop these two tests time. It was 5 and 20 calls, and they asserted a PER-CALL average of 15 ms against a
#: measured honest cost of 1.2 to 4.2 ms -- under four times, the tightest margin in the suite. Dividing by the
#: loop count divides out the loop, not a stall: fifty milliseconds of descheduling across five calls is ten
#: milliseconds per call, which is most of the margin. 200 calls makes the honest time large enough that
#: `tests/bounds.py` can set a ceiling above a stall and still below the regression.
CALLS_TIMED = 200
#: Measured: 200 calls on the worst of the crafted lines below (nested `from to`, 4.2 ms each).
#: Re-measure with KUBE_NOOB_TEST_BOUNDS_REPORT=1 (tests/bounds.py).
HONEST_200_ROUTE_CALLS = 0.85


def test_every_routed_command_actually_parses() -> None:
    """A suggestion that cannot be run is worse than none: it reads as a product that does not know itself.

    The first version of this test checked that the longest REAL PREFIX of the words was a command, which is a
    one-directional guard of the kind G206 is about: `kube-noob vuln rank` passed because `vuln` exists, and
    eight of the twenty printed invocations could not be run -- a missing `--port`, a required positional, a
    subcommand that does not exist, `-f` that means `--values`. It parses them now, which is the claim.
    """
    for _pattern, command, _why in CAPABILITY_ROUTES:
        for invocation in command.split("&&"):
            words = [("X" if w.startswith("<") else w) for w in invocation.split()]
            assert words and words[0] == "kube-noob", command
            err = io.StringIO()
            try:
                with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                    build_parser().parse_args(words[1:])
            except SystemExit:  # pragma: no cover - only on a regression
                last = (err.getvalue().strip().splitlines() or ["?"])[-1]
                pytest.fail(f"{invocation.strip()!r} does not parse: {last}")


def test_every_route_says_why() -> None:
    for _pattern, command, why in CAPABILITY_ROUTES:
        # Lower case unless it starts with a proper noun, and no full stop: these are printed as a continuation
        # of the command above them, not as sentences of their own.
        assert why and not why.endswith("."), command
        assert why[0].islower() or why.split()[0].strip(",") in {"Kyverno", "Gatekeeper", "FedRAMP", "Red"}, command
        assert len(why) < 200, command


@pytest.mark.parametrize(
    ("question", "expected"),
    [
        ("which of our exposed services could reach a node?", "posture scan"),
        ("can a pod in shop reach a pod in payments?", "policy reach"),
        ("what could break if I upgrade OpenShift from 4.16 to 4.18?", "upgrade-risks"),
        ("we are going from 4.14 to 4.16, what should we watch out for", "upgrade-risks"),
        ("Kyverno 1.20 is dropping old policy types, are our policies affected?", "policy migrate-check"),
        ("which FedRAMP indicators does this speak to?", "ksi"),
        ("how do I suppress KN-S010 for one namespace until next quarter?", "exceptions check"),
        ("what is KN-S010 and why does it matter", "explain"),
        ("what does RHACS check that you do not?", "rhacs compare"),
        ("which of these CVEs actually matter in our cluster?", "vuln report"),
        ("how do I fail a pull request when the audit finds something critical?", "gate"),
        ("what changed in our cluster since yesterday?", "posture diff"),
        ("why did my helm upgrade fail with a rendered manifest error?", "helm-audit"),
        ("my image build failed, what do I do", "build"),
        ("teach me about NetworkPolicy", "learn"),
        ("is this deployment safe to ship?", "audit"),
        ("what could go wrong with this application?", "vuln threat"),
        ("generate a Kyverno policy for this", "policy generate"),
        ("can you fix this manifest for me", "fix"),
        ("open this must-gather", "must-gather analyze"),
        # Added after a red team listed questions with a precise answer and no route at all (G237).
        ("is this a known bug in OpenShift 4.20?", "known-issues"),
        ("why was my pod denied by the SCC?", "policy explain"),
        ("which of these Semgrep findings are in shipped code?", "code report"),
        ("red team these manifests, what would an attacker do?", "redteam"),
        ("scaffold a Helm chart for orders-api", "helm-chart"),
        ("which APIs are removed when we go to Kubernetes 1.32?", "audit"),
        # A third pass (G247): one question was answered with the wrong command and three had no answer at all.
        # "exposed in the public repo" is about Git -- the attack-path scan reads a cluster.
        ("which secrets are exposed in the public repo?", "audit"),
        ("did we commit a secret to git?", "audit"),
        ("we pushed an API key to github by mistake", "audit"),
        # And the plainest form of the question `posture scan` exists for matched nothing, because `internet`
        # and `public` sat in the first lookahead group where the second group could never also hold them.
        ("is anything in my cluster exposed to the internet?", "posture scan"),
        ("is my ingress internet-facing?", "posture scan"),
        ("are any of our services publicly reachable?", "posture scan"),
        ("can anything be reached from outside?", "posture scan"),
        # And a sweep of forty realistic questions found seven more with an exact command answer and no route,
        # plus one answered by the wrong command (G247).
        ("my pod is being denied by pod security admission, what now", "policy explain"),
        ("which rules do you have for storage?", "rules"),
        ("how do I see every rule you check?", "rules"),
        ("is audit logging turned on?", "audit -f apiserver.yaml"),
        ("does this cluster log API requests?", "audit -f apiserver.yaml"),
        ("which images come from registries we have not approved?", "audit"),
        ("can you tell me which images are not pinned by digest?", "audit"),
        ("how do I watch a namespace for incidents?", "watch"),
        ("what happened in the shop namespace last night?", "watch"),
        ("is OCPBUGS-12345 fixed yet?", "ticket"),
        ("does the audit read KServe InferenceService?", "audit"),
        ("my RayCluster has a privileged container, do you see it?", "audit"),
        ("how do I bench the model against the rules?", "train bench"),
        ("what is wrong with my Dockerfile?", "build"),
        ("can you diff two posture snapshots?", "posture"),
        ("how do I audit a whole directory of manifests in CI?", "gate"),
        ("what do you do that RHACS does not?", "rhacs compare"),
    ],
)
def test_a_question_reaches_the_command_that_answers_it(question: str, expected: str) -> None:
    routes = [r["command"] for r in capability_routes(question)]
    assert routes, f"no route for {question!r}"
    assert expected in routes[0], f"{question!r} -> {routes}"


@pytest.mark.parametrize(
    "pasted",
    [
        "0/3 nodes are available: 3 Insufficient cpu.",
        'Error from server (Forbidden): pods is forbidden: User "x" cannot list resource "pods"',
        "Back-off restarting failed container",
        "CrashLoopBackOff",
        "ImagePullBackOff: rpc error: code = Unknown desc = failed to pull and unpack image",
        'MountVolume.SetUp failed for volume "data" : timed out waiting for the condition',
        "The node was low on resource: ephemeral-storage.",
        "readiness probe failed: HTTP probe failed with statuscode: 503",
        'no matches for kind "Route" in version "apps.openshift.io/v1"',
        "kubectl get pods",
        "my cluster is slow",
        "hello",
        "what is a pod",
    ],
)
def test_a_pasted_error_is_not_answered_with_a_command_for_something_else(pasted: str) -> None:
    """An ImagePullBackOff is a runtime pull failure, not a build failure, and the build route matched it on
    "image" plus "failed" until that word came out of the pattern. A wrong suggestion reads as a product that
    does not know what it does."""
    assert capability_routes(pasted) == [], pasted


def test_a_pasted_manifest_or_log_is_never_routed() -> None:
    """Multi-line input is something pasted, not a question, and advice about `upgrade-risks` does not belong
    under somebody's stack trace."""
    manifest = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: upgrade-me\nspec:\n  replicas: 1\n"
    assert capability_routes(manifest) == []
    assert capability_routes("why did the helm upgrade fail\n" + "x" * 50) == []
    assert capability_routes("is this deployment safe to ship? " + "y" * 700) == []


def test_at_most_two_suggestions() -> None:
    """A question that touches several jobs gets the two best, not a menu."""
    busy = (
        "which exposed services reach a node, can pods reach each other, what breaks on upgrade to 4.18, "
        "are our Kyverno policies affected, which FedRAMP indicators, and how do I fail the pull request"
    )
    assert len(capability_routes(busy)) == MAX_ROUTES


def test_the_insight_response_carries_the_routes_and_says_so() -> None:
    from kube_noob.config import load_settings
    from kube_noob.insight import insight
    from kube_noob.toolkit import Toolkit

    kit = Toolkit(load_settings())
    out = insight(kit, "which of our exposed services could reach a node?", platform="openshift")
    assert [r["command"] for r in out["answeredBy"]] == ["kube-noob posture scan -f <dir>"]
    assert "answeredBy" in out["approach"], "the reader has to be told where to look"


def test_the_terminal_prints_them(capsys: pytest.CaptureFixture[str]) -> None:
    from kube_noob import cli

    rc = cli.main(["insight", "which of our exposed services could reach a node?"])
    printed = capsys.readouterr().out
    assert rc == 0
    assert "kube-noob answers this directly:" in printed
    assert "posture scan" in printed


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q", *sys.argv[1:]]))


def test_a_pasted_denial_is_left_to_the_explainer_that_already_ran() -> None:
    """`policy explain` IS the right answer to "why was this denied", so the route is correct in substance -- but
    a pasted denial has already been through the denial explainer by the time the response is assembled, and
    repeating the command under its own output is noise. The kinds gate in `insight` is what distinguishes them,
    which is why that gate lives there and not in `capability_routes` (G237)."""
    from kube_noob.config import load_settings
    from kube_noob.insight import insight
    from kube_noob.toolkit import Toolkit

    denial = 'admission webhook "validation.gatekeeper.sh" denied the request: privileged containers are refused'
    assert capability_routes(denial), "the text alone does match the route"
    out = insight(Toolkit(load_settings()), denial, platform="openshift")
    assert out["answeredBy"] == [], "but the explainer already answered it"


# --- the second pass: what a red team found in the first (G237) --------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        # A route word inside a resource NAME. `\b` treats `-`, `/`, `:` and `.` as boundaries, so these leaked.
        "pod ci-runner-gate-5 is in CrashLoopBackOff",
        "deployment gate in ci is failing readiness",
        "the build deployment keeps restarting, why",
        "my pod called upgrade-checker is OOMKilled, version 1.2",
        "the release pod in namespace migrate is pending",
        "deployment named control in namespace evidence is stuck",
        'Failed to pull image "quay.io/acme/build:latest": unauthorized',
        "OutOfSync: Deployment ci/gate is OutOfSync and Progressing",
        "service ingress-nginx in namespace public crashes on the new node",
        "why can't the app called threats connect to the lesson service",
        # A single word pretending to be two, because it was in both lookahead groups of its route.
        "gate",
        "Gate",
        "takeover",
        "blast radius",
        "threats",
        "evidence",
        "new cluster",
        "ok this",
        "check this",
        "wrong pod",
        "is this cluster ok?",
        # Questions `upgrade-risks` cannot answer: its snapshot holds OpenShift 4.18 and later only.
        "Error: UPGRADE FAILED: release upgrade failed: timed out waiting for the condition",
        "should we move from Calico to Cilium, what breaks?",
        "we are moving the cluster to a new VPC, what breaks?",
        "what version of cert-manager should I upgrade to?",
        "how do I update the node pool to a new instance type with no risk?",
        # Out of scope, or a malfunction rather than a question.
        "what is the blast radius of losing one node?",
        "how do I accept the risk of the node going down temporarily?",
        "I have an exception in my Java stack trace, which rule applies?",
        # G247: the words the exposure route gained must not fire on text that is not asking about exposure.
        "dial tcp: lookup api.example.com: no route to host",
        "the public internet gateway",
        "git commit",
        "publicly",
        # The seven routes added in the same pass, each attacked with text that shares their words (G247).
        "check all pods",
        "which checks failed in CI",
        "liveness check failed on all replicas",
        "the storage team has all the rules",
        "image pull failed from quay",
        "the namespace has a watch annotation",
        "watch the dashboard",
        "the apiserver pod is in the cluster",
        "train the team on namespaces",
        "the model deployment in namespace ml",
        "list all namespaces",
        # G252: the third red team's over-matches, each on a route the second pass added.
        "train the agent on namespaces",
        "deploy a production grade model",
        "the training job pod in namespace ml needs a model volume",
        "image pull errored from quay",
        "why did the pod restart overnight?",
        "what happened to my pods?",
        "events in the cluster are recorded in etcd",
        "the request was recorded by the apiserver",
        "see STOR-1234 for details",
        "every rule",
        "rule ids",
        "do you check",
        'Failed to reach the node node="worker-1": no route to host',
    ],
)
def test_nothing_is_routed_for_text_that_only_shares_words(text: str) -> None:
    """Every string here routed somewhere before the second pass, and each was wrong for one of three reasons:
    a route word sat inside a Kubernetes name, a word was in both lookahead groups of its route so one word
    satisfied both, or the sentence reports a malfunction and the answer is the diagnosis that already ran."""
    assert capability_routes(text) == [], f"{text!r} -> {capability_routes(text)}"


def test_no_word_is_in_two_lookahead_groups_of_a_route() -> None:
    """The structural guard. Every over-matching defect in this table has been this one: `fail` in both halves of
    the CI route, then `gate`, then `takeover` and `blast radius`, then `evidence`. A word in two groups makes a
    route fire on ONE word, which is exactly what requiring two groups was meant to prevent. `_route` refuses it
    at import, so this test is really asserting that the guard is still wired in."""
    from kube_noob import insight

    with pytest.raises(ValueError, match="two lookahead groups"):
        insight._route(r"(?i)(?=.*\bfail\b)(?=.*\b(?:fail|block)\b)")


def test_every_route_is_anchored_so_the_cost_stays_linear() -> None:
    """Unanchored, `search` retried each pattern's lookaheads from every one of up to 600 start positions: 75-92
    ms per call on a 600-character line that matches nothing, paid on every one-line paste, on every surface."""
    for pattern, command, _why in CAPABILITY_ROUTES:
        assert pattern.pattern.startswith("(?i)\\A"), command


@pytest.mark.parametrize(
    "text",
    [
        "zzz " * 150,
        ("reach " + "from to " * 74)[:600],  # three nested `.*` on one line: 32 ms before G252
        ("reach " + "pod " * 140)[:600],
        ("exposed to the " + "to the " * 80)[:600],
        ("ci check " * 66)[:600],
        ("OCPBUGS-" * 70)[:600],
    ],
)
def test_no_crafted_line_costs_more_than_a_few_milliseconds(text: str) -> None:
    """The anchoring made the table linear in the line; a nested unbounded gap made one route quadratic in it
    again, and `test_a_long_non_matching_line_is_cheap` only ever tried one input (G252)."""
    capability_routes(text)  # compile
    with bounds.bounded(
        bounds.SMALL_MULTIPLE,
        honest_seconds=HONEST_200_ROUTE_CALLS,
        guards=f"the route table going quadratic in {text[:40]!r}",
    ):
        for _ in range(CALLS_TIMED):
            capability_routes(text)


def test_a_long_non_matching_line_is_cheap() -> None:
    worst = ("zzz " * 150)[:600]
    capability_routes(worst)  # compile
    with bounds.bounded(
        bounds.SMALL_MULTIPLE,
        honest_seconds=HONEST_200_ROUTE_CALLS,
        guards="the one input this test tried before G252 found that one input was not enough",
    ):
        for _ in range(CALLS_TIMED):
            capability_routes(worst)


@pytest.mark.parametrize(
    ("text", "first"),
    [
        ("why did the build fail in the CI pipeline?", "build diagnose"),
        ("which CVEs matter before we upgrade to 4.18?", "vuln report"),
        ("what is the risk of the Kyverno 1.14 upgrade for our policies?", "policy migrate-check"),
        ("scaffold a Helm chart for orders-api on ROSA HCP", "helm-chart"),
        ("how do I suppress KN-S010 for one namespace until next quarter?", "exceptions check"),
    ],
)
def test_the_better_answer_comes_first(text: str, first: str) -> None:
    """The cap is two and table order decides which of them leads, so the order is part of the answer."""
    routes = [r["command"] for r in capability_routes(text)]
    assert routes and first in routes[0], f"{text!r} -> {routes}"


def test_carriage_returns_count_as_a_line_break() -> None:
    """A manifest with old Mac line endings has no `\n` at all and was read as one long question."""
    assert capability_routes("apiVersion: apps/v1\rkind: Deployment\rmetadata:\r  name: upgrade\r") == []


@pytest.mark.parametrize(
    "pasted",
    [
        '{"apiVersion":"v1","kind":"Event","metadata":{"name":"x"},"message":"pods \\"gate-7d9f\\" is forbidden"}',
        '{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"upgrade","labels":{"version":"1.2"}}}',
        "NAME                 READY   STATUS             RESTARTS   AGE\ngate-7d9f-abc        0/1     "
        "CrashLoopBackOff   5          3m",
    ],
)
def test_a_recognised_artifact_is_not_routed_even_on_one_line(pasted: str) -> None:
    """`capability_routes` sees text, not kinds, so on its own it sent a pasted Event whose pod was called
    `gate-7d9f` to the CI gate and a Deployment named `upgrade` to `upgrade-risks`. `insight` gates on what was
    recognised, which is where that decision belongs (G237)."""
    from kube_noob.config import load_settings
    from kube_noob.insight import insight
    from kube_noob.toolkit import Toolkit

    out = insight(Toolkit(load_settings()), pasted, platform="openshift")
    assert out["answeredBy"] == [], f"{out['kinds']} -> {out['answeredBy']}"


def test_a_question_with_a_direct_answer_is_not_also_given_pod_triage_steps() -> None:
    """The steps G235 condemned were still printed underneath the right answer."""
    from kube_noob.config import load_settings
    from kube_noob.insight import insight
    from kube_noob.toolkit import Toolkit

    out = insight(Toolkit(load_settings()), "which of our exposed services could reach a node?", platform="openshift")
    assert out["answeredBy"]
    assert not out["findings"]
    assert out["readOnlyNextSteps"] == [], out["readOnlyNextSteps"]
    assert "gather" not in out["ran"]


def test_a_question_about_a_repository_is_answered_by_the_audit_first() -> None:
    """S6 from the second red team: "which secrets are exposed in the public repo?" got `posture scan` ONLY.

    G247 fixed that with a negative lookahead for repository words on the exposure route, and G252 took it
    back out: it silenced real questions ("are the github actions runner pods exposed to the internet?") and
    its justification was wrong -- `posture scan -f <dir>` reads a directory, which is usually a repository
    checkout. Table order does the work instead, so the question gets the right answer FIRST and the
    attack-path scan second, which is what two slots are for.
    """
    for question in (
        "which secrets are exposed in the public repo?",
        "are there credentials committed in this repository?",
        "is any token exposed in our gitlab repos?",
    ):
        routes = [r["command"] for r in capability_routes(question)]
        assert routes and "audit" in routes[0], f"{question!r} -> {routes}"


def test_a_repository_word_does_not_silence_a_real_exposure_question() -> None:
    """The negative lookahead G247 added took these away, which is the defect it was fixing, reversed (G252)."""
    for question in (
        "are the github actions runner pods exposed to the internet, and what can they reach?",
        "which exposed services in the gitops repo could reach a node?",
        "we are committed to keeping the ingress internet-facing, what can it reach?",
    ):
        routes = [r["command"] for r in capability_routes(question)]
        assert any("posture scan" in r for r in routes), f"{question!r} -> {routes}"


def test_a_reachability_question_may_name_a_webhook_or_a_quota() -> None:
    """G247's admission guard was the bare nouns, so naming Kyverno or a namespace called quota silenced the
    reachability checker entirely. The guard is the denial PHRASE now (G252)."""
    for question in (
        "can a pod in shop reach the kyverno webhook pod?",
        "can a pod in namespace quota reach a pod in namespace billing?",
        "is traffic from the webhook namespace to the apiserver namespace allowed by network policy?",
    ):
        routes = [r["command"] for r in capability_routes(question)]
        assert any("policy reach" in r for r in routes), f"{question!r} -> {routes}"
    # And the denial it was written for still goes to the explainer.
    denial = capability_routes("my pod is being denied by pod security admission, what now")
    assert denial and "policy explain" in denial[0]["command"]


def test_one_command_is_suggested_once() -> None:
    """Four routes answer with `kube-noob audit -f <dir>`, and a question hitting two of them printed it
    twice with two explanations -- which reads as two suggestions and is one (G252)."""
    for question in (
        "is it ok to deploy an image tagged latest from dockerhub?",
        "is this RayCluster manifest safe to ship? it has a privileged container",
        "does the audit check the KServe InferenceService yaml before we deploy?",
    ):
        commands = [r["command"] for r in capability_routes(question)]
        assert len(commands) == len(set(commands)), f"{question!r} -> {commands}"


def test_the_guard_refuses_a_phrase_that_contains_the_other_groups_word() -> None:
    """The generalisation (G252): `rules?` in one group and the phrase `every rule` in another meant "every
    rule" alone satisfied a route written to need two things, and the old word-level guard could not see it."""
    from kube_noob import insight

    with pytest.raises(ValueError, match="two lookahead groups"):
        insight._route(r"(?i)(?=.*\b(?:rules?|checks?)\b)(?=.*\bevery rule\b)")
    with pytest.raises(ValueError, match="two lookahead groups"):
        insight._route(r"(?i)(?=.*\breach(?:es|ed|able)?\b)(?=.*\breach\b)")
    # And the expansion it rests on: `rules?` is `rule` as well as `rules`.
    assert {"rule", "rules"} <= insight._literal_words(r".*\b(?:rules?)\b")
    assert {"reach", "reached", "reachable"} <= insight._literal_words(r".*\breach(?:es|ed|able)?\b")


def test_a_negative_lookahead_may_lead_a_route_and_is_still_anchored() -> None:
    """The structural guard had to learn one more shape, so the invariant it protects is asserted directly."""
    from kube_noob import insight

    pattern = insight._route(r"(?i)(?!.*\bgit\b)(?=.*\bexposed\b)(?=.*\bnode\b)")
    assert pattern.pattern.startswith("(?i)\\A")
    assert pattern.search("is the node exposed")
    assert not pattern.search("is the node exposed in git")
    with pytest.raises(ValueError, match="must start with"):
        insight._route(r"(?i)\bexposed\b")


def test_a_pull_failure_is_a_diagnosis_and_not_a_registry_policy_question() -> None:
    """The registry route's words are the words a pull failure uses, so it carries a negative guard (G247)."""
    for text in (
        "image pull failed from quay",
        "ErrImagePull: failed to pull and unpack image quay.io/x/y",
        "unauthorized: authentication required pulling from quay.io",
    ):
        assert capability_routes(text) == [], f"{text!r} -> {capability_routes(text)}"
    assert "audit" in capability_routes("which images come from registries we have not approved?")[0]["command"]


def test_a_route_may_not_hide_behind_a_nested_alternation() -> None:
    """A phrase group written `(?:rule|check)` makes the import guard read a bare `check` as its word.

    That refusal is correct -- a word in both groups fires on one word -- so the table writes its phrases out
    flat instead. Asserted because the first attempt at the catalogue route did exactly this and the guard
    caught it, which is the third time a guard has shaped what the table can say (G247).
    """
    from kube_noob import insight

    with pytest.raises(ValueError, match="two lookahead groups"):
        insight._route(r"(?i)(?=.*\b(?:rules?|checks?)\b)(?=.*\bhow many (?:rules|checks)\b)")
