"""Scripted, offline walkthroughs: ``kube-noob demo <scenario>``.

Every scenario runs in-process against the bundled ``examples/`` with web and cluster access forced off and a
throwaway data directory, so a demo never touches the network, a cluster or the user's progress and learning file.
Each step prints the equivalent CLI command, so a viewer can repeat it. The VHS tapes in ``demos/`` record these
scenarios as GIFs for every release.
"""

from __future__ import annotations

import tempfile
import textwrap
import time
from collections.abc import Callable
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from kube_noob.config import Settings

Emit = Callable[[str], None]


def examples_dir() -> Path:
    """Bundled examples (wheel: ``kube_noob/data/examples``; source checkout: ``<repo>/examples``)."""
    packaged = Path(str(resources.files("kube_noob") / "data" / "examples"))
    if packaged.is_dir():
        return packaged
    repo = Path(__file__).resolve().parents[2] / "examples"
    if repo.is_dir():
        return repo
    raise FileNotFoundError("bundled examples are missing from this installation; reinstall kube-noob")


def _example(name: str) -> str:
    return (examples_dir() / name).read_text(encoding="utf-8")


def _wrap(text: str, indent: str = "    ") -> str:
    return textwrap.fill(text, width=100, initial_indent=indent, subsequent_indent=indent + "  ")


@dataclass(frozen=True)
class Scenario:
    name: str
    title: str
    audience: str
    run: Callable[[Any, Emit], None]


def _step(emit: Emit, why: str, command: str) -> None:
    emit(f"\n# {why}")
    emit(f"$ {command}")


def _score(summary: dict[str, Any]) -> str:
    """The headline score, or "not determined" while the audit withholds it (never `None/100`, G272)."""
    return "not determined" if summary.get("score") is None else f"{summary['score']}/100"


def _audit(kit: Any, emit: Emit) -> None:
    from kube_noob import toolkit as tk

    text = _example("insecure-deployment.yaml")
    _step(
        emit,
        "Audit a Deployment that works on a laptop but not on OpenShift",
        "kube-noob audit -f examples/insecure-deployment.yaml --platform openshift --version 4.22",
    )
    rep = kit.audit(tk.AuditIn(manifests=text, platform="openshift", version="4.22"))
    c = rep["summary"]["counts"]
    emit(f"score {_score(rep['summary'])} | high={c['high']} medium={c['medium']} low={c['low']}")
    for f in [f for f in rep["findings"] if f["severity"] in {"critical", "high"}][:3]:
        emit(f"[{f['severity'].upper():8}] {f['ruleId']} line {f['line']}: {f['message']}")
        emit(_wrap(f"fix: {f['remediation']}"))
    _step(
        emit,
        "Apply the safe mechanical fixes and re-audit",
        "kube-noob fix -f examples/insecure-deployment.yaml --platform openshift -o fixed.yaml",
    )
    fixed = kit.fix(tk.FixIn(manifests=text, platform="openshift", version="4.22"))
    emit(f"{len(fixed['changes'])} changes applied; score {_score(rep['summary'])} -> {_score(fixed['after'])}")
    for ch in fixed["changes"][:4]:
        emit(f"  + {ch['path']}: {ch['reason']}")
    emit("Left for a human (needs app knowledge):")
    for m in fixed["manualFollowUps"][:2]:
        emit(_wrap(f"- {m}", "  "))


def _diagnose(kit: Any, emit: Emit) -> None:
    from kube_noob import toolkit as tk

    for name, why in (
        ("events-scc.txt", "Pods are never created: paste the events"),
        ("events-crashloop.txt", "A pod keeps restarting: paste `oc describe pod`"),
    ):
        _step(emit, why, f"kube-noob diagnose -f examples/{name}")
        out = kit.diagnose(tk.DiagnoseIn(text=_example(name), limit=2))
        d = out["diagnoses"][0]
        emit(f"{d['id']}: {d['title']} (confidence {d['confidence']})")
        n = 1
        emit(f"  {n}. read-only first:")
        for s in d["readOnlyNextSteps"][:3]:
            emit(f"     {s.get('command') or s['instruction']}")
            if s.get("why"):
                emit(f"       why: {s['why']}")
        if d["diagnosticCommands"]:
            n += 1
            emit(f"  {n}. runs in a container (asks before running):")
            emit(f"     {d['diagnosticCommands'][0]['command']}")
        if d["proposedChanges"]:
            n += 1
            emit(f"  {n}. change, only after the evidence (asks before running):")
            emit(_wrap(d["proposedChanges"][0]["change"], "     "))


def _protocol(kit: Any, emit: Emit) -> None:
    import yaml

    from kube_noob import toolkit as tk

    _step(
        emit,
        "Describe the app; get audited, platform-correct manifests",
        'kube-noob protocol "Deploy orders-api on ROSA HCP" --blueprint examples/blueprint.yaml',
    )
    out = kit.run_protocol(
        tk.ProtocolIn(request="Deploy orders-api on ROSA HCP", blueprint=yaml.safe_load(_example("blueprint.yaml")))
    )
    brief = out["auditValidationBrief"]
    emit(
        f"status: {out['status']} | {brief['platform']} {brief['platformVersion']} (Kubernetes "
        f"{brief['kubernetesVersion']}) | score {_score(brief['after'])}"
    )
    kinds: dict[str, int] = {}
    for r in brief["resources"]:
        kinds[r.split("/")[0]] = kinds.get(r.split("/")[0], 0) + 1
    emit("generated: " + ", ".join(k + (f" x{n}" if n > 1 else "") for k, n in kinds.items()))
    red = out["redTeamFindingsAndSafeguards"]
    for p in red.get("prerequisites", [])[:2]:
        emit(f"prerequisite: {p}")
    emit("validate before applying:")
    for cmd in out["validationCommands"][:2]:
        emit(f"  {cmd}")


def _learn(kit: Any, emit: Emit) -> None:
    from kube_noob import toolkit as tk

    _step(emit, "Open the first lesson", "kube-noob learn lesson k8s-101-objects")
    lesson = kit.lesson(tk.LessonIn(lesson_id="k8s-101-objects", learner="demo"))
    emit(lesson["title"])
    for kp in lesson["keyPoints"][:3]:
        emit(_wrap(f"- {kp}", "  "))
    _step(
        emit,
        "Submit a first attempt at the exercise; it is graded offline",
        "kube-noob learn submit k8s-ex-hardened-deployment -f examples/exercise-answer.yaml",
    )
    res = kit.submit(
        tk.SubmitIn(exercise_id="k8s-ex-hardened-deployment", answer=_example("exercise-answer.yaml"), learner="demo")
    )
    emit(f"passed: {res['passed']} | score {res['score']} | points {res['pointsEarned']}")
    for fb in res["feedback"][:3]:
        emit(_wrap(f"- {fb['ruleId']}: {fb['message']} fix: {fb['fix']}", "  "))


def _search(kit: Any, emit: Emit) -> None:
    from kube_noob import toolkit as tk

    _step(
        emit,
        "Ask the local knowledge base; every answer carries a citation",
        'kube-noob search "restricted-v2 SCC runAsUser range"',
    )
    out = kit.search(tk.SearchIn(query="restricted-v2 SCC runAsUser range", limit=3))
    for r in out["results"]:
        emit(f"[{r['chunkId']}] {r['title']}")


def _learning(kit: Any, emit: Emit) -> None:
    from kube_noob import toolkit as tk

    note = {
        "symptom": "orders-api pods rejected by SCC: runAsUser 1000 outside the namespace range",
        "cause": "the Helm chart hard-codes runAsUser for vanilla Kubernetes",
        "fix": "drop runAsUser on OpenShift and let restricted-v2 assign the UID",
    }
    _step(
        emit,
        "Remember a fix your team confirmed (summaries only; secrets and logs are rejected)",
        f'kube-noob learning note --symptom "{note["symptom"]}" --cause "{note["cause"]}" --fix "{note["fix"]}"',
    )
    saved = kit.learning_note_add(
        tk.LearningNoteIn(**note, platform="openshift", tags=["scc", "helm"], confirmed_by_user=True)
    )
    emit(f"saved {saved['citation']} to learning.json (local only, survives upgrades)")
    _step(
        emit,
        "Next time, the same search finds your team's note next to the docs",
        'kube-noob search "orders-api SCC runAsUser helm"',
    )
    for r in kit.search(tk.SearchIn(query="orders-api SCC runAsUser helm chart", limit=3))["results"]:
        emit(f"[{r['chunkId']}] {r['title']}")


def _memory(kit: Any, emit: Emit) -> None:
    from kube_noob.memory import dump_entry, repo, verify
    from kube_noob.memory import match as mmatch

    root = Path(kit.settings.data_dir) / "team-memory"
    _step(emit, "Keep your team's fixes as code, in your own repository", "kube-noob memory init team-memory")
    for rel in repo.init_repo(root)["created"]:
        emit(f"created {rel}")

    def seed(fields: dict[str, Any], approve: bool, outcomes: tuple[tuple[str, str], ...] = ()) -> str:
        path, entry = repo.add_entry(root, fields)
        if approve:
            path.write_text(dump_entry(entry.model_copy(update={"status": "approved"})), encoding="utf-8")
        for result, cluster in outcomes:
            repo.add_outcome(root, entry.id, result, cluster=cluster)
        return entry.id

    fix = seed(
        {
            "kind": "fix",
            "signals": [{"kind": "alert", "name": "etcdHighNumberOfLeaderChanges"}],
            "symptom": "etcd leader changes every few minutes after the 4.21.0 update; API requests time out",
            "platform": "openshift",
            "versions": {"introduced": "4.21.0", "fixedIn": "4.21.1"},
            "cause": "Catalog sync wrote to the control-plane disks every few seconds (OCPBUGS-73881).",
            "fix": {
                "text": "Update to 4.21.1; until then lower catalog polling on the busiest catalog sources.",
                "commands": [
                    {"command": "oc get co etcd kube-apiserver", "label": "read-only"},
                    {"command": "oc adm upgrade --to=4.21.1", "label": "needs-approval"},
                ],
            },
            "evidence": [{"kind": "ticket", "ref": "OCPBUGS-73881"}],
            "owners": ["platform-team"],
        },
        True,
        (("resolved", "prod-east"), ("resolved", "prod-west"), ("partial", "dev")),
    )
    seed(
        {
            "kind": "negative",
            "signals": [{"kind": "alert", "name": "etcdHighNumberOfLeaderChanges"}],
            "symptom": "etcd leader elections keep happening; we restarted the etcd pods one by one",
            "platform": "openshift",
            "cause": "Restarting members does not change disk latency, the reason the leader misses heartbeats.",
            "fix": {"text": "Restarting etcd members one at a time: elections came back within ten minutes."},
            "owners": ["platform-team"],
        },
        True,
        (("not-resolved", "prod-east"),),
    )
    poisoned = seed(
        {
            "kind": "fix",
            "symptom": "pods in shop cannot list ConfigMaps after the namespace migration",
            "platform": "openshift",
            "cause": "The default ServiceAccount lost its Role binding.",
            "fix": {
                "text": "Bind the default ServiceAccount to cluster-admin.",
                "patch": "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n"
                "  name: shop-default-admin\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n"
                "  name: cluster-admin\nsubjects:\n- kind: ServiceAccount\n  name: default\n  namespace: shop\n",
            },
            "owners": ["someone"],
        },
        False,
    )
    emit(f"seeded {fix} (approved fix, 3 outcomes), a negative entry, and {poisoned} (proposed)")
    _step(emit, "CI runs the poisoning guard on every pull request", "kube-noob memory validate team-memory")
    rep = verify.validate_repo(root)
    for p in rep["errors"][:2]:
        emit(f"ERROR {p['entry']} {p['check']}: {p['detail'][:140]}")
    verdict = "0" if rep["ok"] else "1"
    emit(f"exit {verdict}: {poisoned} cannot be approved until the fix is safe or the risk is accepted")
    _step(
        emit,
        "An alert fires: what did your team learn last time?",
        "kube-noob memory match -f examples/alertmanager-etcd.json --dir team-memory",
    )
    out = mmatch.match([root], _example("alertmanager-etcd.json"))
    for m in out["matches"]:
        emit(f"{m['citation']} {m['state']}: {m['symptom']}")
        emit(f"  {m['outcomes']['summary']}")
        if m.get("note"):
            emit(f"  {m['note']}")
    emit(f"version {out['query']['version']} from the alert's {out['query'].get('versionFrom', '')}")


def _mustgather(kit: Any, emit: Emit) -> None:
    from kube_noob.mustgather import analyse, ingest, sample
    from kube_noob.mustgather import report as mg_report

    case = Path(kit.settings.data_dir) / "case-01"
    archive = sample.write(case)
    _step(
        emit,
        "A must-gather arrives: open it safely (nothing extracted or run, Secrets never read)",
        "kube-noob must-gather analyze must-gather.tar.gz",
    )
    bundle = ingest.open_bundle(archive)
    skipped = ", ".join(f"{s['count']} {s['reason']}" for s in bundle.as_dict()["skipped"])
    emit(f"{bundle.listed} files read as a stream; skipped: {skipped}")
    analysis = analyse.analyse(bundle)
    text = analyse.render_text(analysis).splitlines()
    emit(text[0])
    emit(text[1])
    for f in analysis.findings[:6]:
        emit(f"  {f.severity.upper():8} {f.title}")
    emit(f"  ... {len(analysis.findings) - 6} more, each with its file, signals and read-only next steps")
    _step(
        emit,
        "Match every finding to known bugs for the version it runs, and draft the support case",
        "kube-noob must-gather analyze must-gather.tar.gz --report report --case-draft",
    )
    rep = mg_report.build(bundle, analysis, data_dir=kit.settings.data_dir)
    for m in rep["knownIssues"]:
        emit(f"{m['id']} (findings {', '.join(str(n) for n in m['findings'])}): {m.get('status') or ''}")
    written = mg_report.write(rep, case / "report", draft=True)
    emit(f"wrote {', '.join(p.name for p in written)}: every [FILL IN] in the case draft is yours to answer")


def _posture(kit: Any, emit: Emit) -> None:
    from kube_noob.posture import posture, render_text

    # As the MCP server and plugin run it: the server itself never calls a model (llm.provider: none).
    settings = kit.settings.model_copy(update={"llm": kit.settings.llm.model_copy(update={"provider": "none"})})
    _step(emit, "Prove what kube-noob can reach (nothing, by default)", "kube-noob doctor")
    emit(render_text(posture(settings)))
    _step(
        emit,
        "Platform teams can lock it: no web, no downloads, local models only",
        "KUBE_NOOB_OFFLINE=1 kube-noob doctor",
    )
    locked = settings.model_copy(update={"offline": True})
    emit(render_text(posture(locked)))


SCENARIOS: dict[str, Scenario] = {
    s.name: s
    for s in (
        Scenario("audit", "Audit and auto-fix a Deployment for OpenShift", "developers, platform engineers", _audit),
        Scenario("diagnose", "Diagnose SCC and CrashLoop/OOM failures, read-only first", "SREs, on-call", _diagnose),
        Scenario(
            "protocol", "Blueprint to audited ROSA HCP manifests (7-step protocol)", "platform engineers", _protocol
        ),
        Scenario("learn", "Lesson plus a graded exercise", "learners, trainers", _learn),
        Scenario("search", "Cited answers from local knowledge", "everyone", _search),
        Scenario("learning", "Remember a confirmed team fix and find it later", "teams", _learning),
        Scenario("memory", "Fixes as code: a team memory repo, its guard and a match", "teams, SREs", _memory),
        Scenario(
            "must-gather",
            "Must-gather pre-flight: what is wrong, the matching bugs, a case draft",
            "support engineers, SREs",
            _mustgather,
        ),
        Scenario("posture", "Show and lock the security posture", "security, platform admins", _posture),
    )
}


def run(name: str, settings: Settings, emit: Emit = print) -> float:
    """Run one scenario offline in a throwaway data dir; returns the elapsed seconds."""
    from kube_noob import toolkit as tk

    scenario = SCENARIOS[name]
    with tempfile.TemporaryDirectory(prefix="kube-noob-demo-") as tmp:
        safe = settings.model_copy(
            update={
                "web_enabled": False,
                "cluster": settings.cluster.model_copy(update={"enabled": False}),
                "data_dir": Path(tmp),
                "learning_enabled": True,
            }
        )
        start = time.monotonic()
        emit(f"== kube-noob demo: {scenario.title} ==")
        scenario.run(tk.Toolkit(safe), emit)
        return time.monotonic() - start


def listing() -> list[dict[str, str]]:
    return [{"name": s.name, "title": s.title, "for": s.audience} for s in SCENARIOS.values()]
