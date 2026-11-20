"""QA1: what the eval over 25,292 community questions (scripts/eval_questions.py, the owner's CSV, not in the repo)
changed, each as a test on text written for this file. Before: an OpenShift release-note bug topped 6,177 answers to
questions about other platforms; OpenShift and ROSA playbooks answered Docker and EKS questions; documents that
shared one incidental word were offered as answers."""

from __future__ import annotations

import csv
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from kube_noob import known_issues as ki
from kube_noob import toolkit as tk
from kube_noob.config import load_settings
from kube_noob.debug.diagnose import diagnose
from kube_noob.insight import recognise
from tests import bounds

#: Measured: three 400 KB inputs through openshift_context.
#: Re-measure with KUBE_NOOB_TEST_BOUNDS_REPORT=1 (tests/bounds.py).
HONEST_CONTEXT_SCAN = 0.22

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def kit(tmp_path_factory: pytest.TempPathFactory) -> tk.Toolkit:
    return tk.Toolkit(
        load_settings(overrides={"dataDir": str(tmp_path_factory.mktemp("qa1")), "learningEnabled": False})
    )


def _ids(text: str, platform: str | None = None) -> list[str]:
    return [d["id"] for d in diagnose(text, platform=platform).as_dict()["diagnoses"]]


def test_release_notes_need_openshift_context_when_no_platform_is_given(kit: tk.Toolkit) -> None:
    post = (
        "Agent pod fails when deployed with the audit plugin\n"
        "Following the docs, the registry mirrors are replaced and the signature check causes the pod to fail."
    )
    out = kit.diagnose(tk.DiagnoseIn(text=post))
    assert out["knownIssues"] == []
    gated = ki.match(post, None, None, 3, require_context=True)
    assert gated["matches"] == [] and "does not say it is about OpenShift" in gated["note"]
    assert ki.openshift_context("oc adm release mirror to a disconnected registry") is True
    assert ki.openshift_context("pods in openshift-etcd restart") is True
    assert ki.openshift_context("my k3s cluster on a Raspberry Pi") is False


def test_everyday_words_are_not_evidence() -> None:
    for word, base in (("deployed", "deploy"), ("following", "follow"), ("causes", "cause"), ("mirrors", "mirror")):
        assert base in ki._forms(word) and base in ki.EVERYDAY_WORDS
    text = "deployed following plugin mirrors causes replaced"
    assert ki.match(text, "openshift", None, 3)["matches"] == []


def test_openshift_playbooks_need_openshift_words(kit: tk.Toolkit) -> None:
    assert "DBG-ARBITRARY-UID" not in _ids("docker compose: /docker-entrypoint.sh: Permission denied")
    assert _ids('[emerg] mkdir() "/var/cache/nginx/client_temp" failed (13: Permission denied)')[0] == (
        "DBG-ARBITRARY-UID"
    )  # the specific nginx line still names it
    assert "DBG-ARBITRARY-UID" in _ids("Permission denied writing /data on OpenShift")
    eks = "Karpenter NodeClaim stuck, nodes NotReady, the VPC endpoint for the node pool is missing"
    assert "DBG-ROSA-HCP-NODES" not in _ids(eks)
    assert "DBG-ROSA-HCP-NODES" in _ids("ROSA HCP machine pool nodes NotReady after the VPC endpoint change")


def test_new_trigger_phrases() -> None:
    assert _ids("PVC creation stuck with the ceph-csi rbd driver on k3s")[0] == "DBG-PVC-PENDING"
    assert _ids("weird DNS issues on k3s: pods time out")[0] == "DBG-DNS"
    row = "etcd 4.17.37 True False True 352d RevisionControllerDegraded: unable to ApplyStatus"
    assert "DBG-CLUSTEROPERATOR" in _ids(f"oc get co during the upgrade\n{row}")
    assert "DBG-CLUSTEROPERATOR" in _ids(row, platform="openshift")


def test_documents_must_share_more_than_an_incidental_word(kit: tk.Toolkit) -> None:
    post = "How to share my web app between two laptops\nI built a small app and want my friend to run it too?"
    out = kit.insight(tk.InsightIn(text=post))
    assert not [f for f in out["findings"] if f["source"] == "doc"]
    typed = kit.insight(tk.InsightIn(text="why does my pod stay Pending?", platform="kubernetes"))
    docs = [f for f in typed["findings"] if f["source"] == "doc"]
    assert docs and all(f["sharedTerms"] for f in docs)
    unknown = kit.insight(tk.InsightIn(text="Talos 1.12 cannot upgrade kubernetes"))
    assert not [f for f in unknown["findings"] if f["source"] == "doc"]


def test_a_forum_post_that_asks_is_a_question() -> None:
    post = (
        "Kubectl command to list only some pods\n"
        "Is there a way to use kubectl to list only the pods of one deployment? Today I grep the whole list."
    )
    assert "question" in [k.kind for k in recognise(post)]


def test_context_detection_is_linear_on_hostile_text() -> None:
    with bounds.bounded(
        bounds.LINEAR, honest_seconds=HONEST_CONTEXT_SCAN, guards="context detection over three 400 KB inputs"
    ):
        for text in ("a-" * 199_000, "a." * 199_000, "x" * 400_000):
            ki.openshift_context(text)


def test_the_eval_script_runs_on_a_small_csv(tmp_path: Path) -> None:
    path = tmp_path / "q.csv"
    cols = ["id", "question", "body_excerpt", "topic_category", "platform_tags", "source", "url", "item_type"]
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerow(
            {
                "id": "1",
                "question": "Pod stuck in CrashLoopBackOff",
                "body_excerpt": "Back-off restarting failed container web",
                "topic_category": "workloads-debugging",
                "platform_tags": "kubernetes",
                "source": "stackexchange:stackoverflow",
                "url": "https://stackoverflow.com/questions/1",
                "item_type": "question",
            }
        )
        w.writerow(
            {
                "id": "2",
                "question": "etcd leader changes on masters",
                "body_excerpt": "etcdserver: leader changed during the upgrade",
                "topic_category": "etcd-control-plane",
                "platform_tags": "openshift",
                "source": "redhat-jira:OCPBUGS",
                "url": "https://redhat.atlassian.net/browse/OCPBUGS-1",
                "item_type": "bug-report",
            }
        )
    spec = importlib.util.spec_from_file_location("eval_questions", ROOT / "scripts" / "eval_questions.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["eval_questions"] = mod
    spec.loader.exec_module(mod)
    out = tmp_path / "out"
    assert mod.main([str(path), "--out", str(out), "--sample-review", "2"]) == 0
    rows = list(csv.DictReader((out / "results.csv").open()))
    assert rows[0]["answer"] == "playbook" and rows[0]["topicAgree"] == "True"
    assert rows[1]["expectedKey"] == "OCPBUGS-1" and rows[1]["keyIndexed"] == "False"
    assert "question" not in rows[0]  # results never carry the question text
    review = list(csv.DictReader((out / "review.csv").open()))
    assert len(review) == 2 and review[0]["verdict"] == ""

    # Grades carry over while the answer is unchanged; a moved answer is listed for re-grading.
    grades = tmp_path / "grades.csv"
    with grades.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(mod.GRADE_COLUMNS))
        w.writeheader()
        w.writerow({"id": "1", "answer": rows[0]["answer"], "top": rows[0]["topId"], "verdict": "correct"})
        w.writerow({"id": "2", "answer": "docs", "top": "kn:somewhere#0", "verdict": "wrong"})
        w.writerow({"id": "9", "answer": "none", "top": "", "verdict": "out-of-scope"})
    out2 = tmp_path / "out2"
    assert mod.main([str(path), "--out", str(out2), "--sample-review", "2", "--grades", str(grades)]) == 0
    graded = json.loads((out2 / "summary.json").read_text())["graded"]
    assert graded["unchanged"] == 1 and graded["notRun"] == 1 and graded["verdicts"]["correct"] == 1
    assert graded["helpfulWhenAnswered"] == 100.0
    assert [c["id"] for c in graded["changed"]] == ["2"] and graded["changed"][0]["was"] == "docs kn:somewhere#0"
    by_id = {r["id"]: r for r in csv.DictReader((out2 / "review.csv").open())}
    assert by_id["1"]["verdict"] == "correct" and by_id["2"]["verdict"] == ""
    assert by_id["2"]["previousVerdict"] == "wrong"
    results = {r["id"]: r for r in csv.DictReader((out2 / "results.csv").open())}
    assert results["1"]["verdict"] == "correct" and results["2"]["previousVerdict"] == "wrong"


def test_several_grades_files_merge_and_an_id_graded_twice_stops_the_eval(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location("eval_questions_m", ROOT / "scripts" / "eval_questions.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["eval_questions_m"] = mod
    spec.loader.exec_module(mod)
    (tmp_path / "q.csv").write_text("id,question,body_excerpt\n1,why is my pod Pending?,\n2,a,b\n")
    one, two, dup = tmp_path / "1.csv", tmp_path / "2.csv", tmp_path / "dup.csv"
    one.write_text("id,answer,top,verdict\n1,none,,missed\n")
    two.write_text("id,answer,top,verdict\n2,none,,out-of-scope\n")
    dup.write_text("id,answer,top,verdict\n1,none,,wrong\n")
    out = tmp_path / "o"
    assert mod.main([str(tmp_path / "q.csv"), "--out", str(out), "--grades", str(one), "--grades", str(two)]) == 0
    assert json.loads((out / "summary.json").read_text())["graded"]["graded"] == 2
    assert mod.main([str(tmp_path / "q.csv"), "--out", str(out), "--grades", str(one), "--grades", str(dup)]) == 2


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("id,answer,top\n1,none,\n", "missing column(s) verdict"),
        ("id,answer,top,verdict\n1,none,,great\n", "is not one of"),
        ("id,answer,top,verdict\n1,none,,wrong\n1,none,,wrong\n", "graded twice"),
        ("id,answer,top,verdict\n,none,,wrong\n", "empty id"),
        ("id,answer,top,verdict,note\n1,none,,wrong," + "x" * 301 + "\n", "note longer"),
    ],
)
def test_a_malformed_grades_file_stops_the_eval(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], body: str, message: str
) -> None:
    spec = importlib.util.spec_from_file_location("eval_questions_g", ROOT / "scripts" / "eval_questions.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["eval_questions_g"] = mod
    spec.loader.exec_module(mod)
    grades = tmp_path / "grades.csv"
    grades.write_text(body)
    (tmp_path / "q.csv").write_text("id,question,body_excerpt\n1,a,b\n")
    assert mod.main([str(tmp_path / "q.csv"), "--out", str(tmp_path / "o"), "--grades", str(grades)]) == 2
    assert message in capsys.readouterr().err
    assert not (tmp_path / "o").exists()  # nothing was scored against a bad file


def test_the_committed_grades_file_is_well_formed() -> None:
    spec = importlib.util.spec_from_file_location("eval_questions_c", ROOT / "scripts" / "eval_questions.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["eval_questions_c"] = mod
    spec.loader.exec_module(mod)
    sizes = {"community-questions-grades.csv": 76, "community-questions-heldout.csv": 40}
    seen: set[str] = set()
    for name, size in sizes.items():
        path = ROOT / "docs" / "evals" / name
        grades = mod.load_grades(path)
        assert len(grades) == size and not seen & set(grades)  # the held-out rows were never tuned on
        seen |= set(grades)
        header = path.read_text(encoding="utf-8").splitlines()[0]
        assert header == ",".join(mod.GRADE_COLUMNS)  # ids and verdicts only: no question text in the repo


def test_test_rows_that_informed_a_change_are_retired_from_the_test_half(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    spec = importlib.util.spec_from_file_location("eval_questions_r", ROOT / "scripts" / "eval_questions.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["eval_questions_r"] = mod
    spec.loader.exec_module(mod)
    test_ids = [str(i) for i in range(1, 60) if mod.split_of(str(i)) == "test"][:3]
    train_id = next(str(i) for i in range(1, 60) if mod.split_of(str(i)) == "train")
    q = tmp_path / "q.csv"
    lines = "".join(f"{i},why is my pod Pending?,\n" for i in [*test_ids, train_id])
    q.write_text("id,question,body_excerpt\n" + lines)
    retired = tmp_path / "retired.csv"
    retired.write_text(f"id,change,date\n{test_ids[0]},helm document,2026-10-28\n{train_id},n/a,2026-10-28\n")
    out = tmp_path / "o"
    assert mod.main([str(q), "--out", str(out), "--split", "test", "--retired", str(retired)]) == 0
    summary = json.loads((out / "summary.json").read_text())
    assert summary["rows"] == 2 and summary["retiredExcluded"] == 1
    assert {r["id"] for r in csv.DictReader((out / "results.csv").open())} == set(test_ids[1:])
    assert mod.main([str(q), "--out", str(out), "--split", "train", "--retired", str(retired)]) == 0
    assert json.loads((out / "summary.json").read_text())["rows"] == 1  # retired rows stay in the train half
    for body, message in (
        ("id,date\n1,2026-10-28\n", "missing column(s) change"),
        ("id,change,date\n1,x,2026-10-28\n1,y,2026-10-28\n", "retired twice"),
        ("id,change,date\n1," + "x" * 201 + ",2026-10-28\n", "change longer"),
    ):
        retired.write_text(body)
        assert mod.main([str(q), "--out", str(tmp_path / "bad"), "--split", "test", "--retired", str(retired)]) == 2
        assert message in capsys.readouterr().err
    committed = mod.load_retired(ROOT / "docs" / "evals" / "community-questions-retired.csv")
    assert committed and all(mod.split_of(i) == "test" for i in committed)


# QA2: the second tuning round, from the graded sample (docs/evals/community-questions-grades.csv). Each test uses
# text written for this file.


def _docs(kit: tk.Toolkit, text: str, platform: str | None = None) -> list[str]:
    out = kit.insight(tk.InsightIn(text=text, platform=platform))
    return [f["id"] for f in out["findings"] if f["source"] == "doc"]


def test_new_knowledge_answers_everyday_how_tos(kit: tk.Toolkit) -> None:
    assert _docs(kit, "how do I list only the pods that belong to my deployment with kubectl?")[0].startswith(
        "kn:k8s-kubectl-selectors#"
    )
    assert _docs(kit, "kubelet service is not starting after I enabled swap")[0].startswith("kn:k8s-node-kubelet#")
    assert _docs(kit, "how do I back up and restore the etcd database")[0].startswith("kn:k8s-etcd-backup#")
    post = (
        "Make an ingress listen on a port other than 80 and 443\n"
        "Not routing to a backend port: I want the ingress itself to listen on another port. Possible?"
    )
    assert _docs(kit, post)[0].startswith("kn:k8s-ingress#")


def test_openshift_only_documents_need_openshift_words(kit: tk.Toolkit) -> None:
    post = (
        "Container cannot write its cache directory\n"
        "Why does mkdir fail with permission denied when the image runs as a non-root user on Kubernetes 1.31?"
    )
    openshift_only = ("kn:ocp-", "kn:rosa-", "kn:openshift#")
    assert not [d for d in _docs(kit, post) if d.startswith(openshift_only)]

    def answers(text: str, platform: str | None = None) -> list[str]:
        out = kit.insight(tk.InsightIn(text=text, platform=platform))
        return [f["id"] for f in out["findings"] if f["source"] in ("doc", "playbook")]

    on_ocp = post.replace("Kubernetes 1.31", "OpenShift 4.20")
    for got in (answers(on_ocp), answers(post, platform="openshift")):
        assert {"DBG-ARBITRARY-UID", "kn:ocp-arbitrary-uid#1"} & set(got), got


def test_narrow_documents_keep_to_their_subject(kit: tk.Toolkit) -> None:
    docker_only = (
        "Share my compose app with a friend\n"
        "I have a docker-compose.yml with a web and a db service and want my friend to run the same images."
    )
    assert not [d for d in _docs(kit, docker_only) if d.startswith("kn:k8s-compose-migration#")]
    to_openshift = (
        "Move a docker-compose app to OpenShift\nWhat is the best way to run my docker-compose services on OpenShift?"
    )
    assert _docs(kit, to_openshift)[0].startswith("kn:k8s-compose-migration#")
    assert not [
        d
        for d in _docs(kit, "can other system components store data in the embedded etcd of k3s?")
        if d.startswith("kn:k8s-etcd-backup#")
    ]


def test_a_question_about_something_unknown_needs_more_shared_words(kit: tk.Toolkit) -> None:
    assert _docs(kit, "consolidateAfterSeconds per node pool") == []  # a name the knowledge never saw
    assert _docs(kit, "trying to understand quotas and CPU limits")  # everyday words are not unknown names


def test_requires_front_matter_is_checked() -> None:
    from kube_noob.knowledge.store import builtin_chunks, requires_groups

    assert requires_groups(None) == []
    assert requires_groups([["Compose", "kompose"], ["pod"]]) == [["compose", "kompose"], ["pod"]]
    for bad in ("compose", [["compose"], []], [[""]], [["ok", 3]], {"a": ["b"]}):
        with pytest.raises(ValueError, match="requires"):
            requires_groups(bad)
    narrow = {c.doc_id for c in builtin_chunks() if c.extra.get("requires")}
    assert {"k8s-compose-migration", "k8s-etcd-backup", "ocp-arbitrary-uid"} <= narrow


def test_low_ports_on_openshift_name_the_arbitrary_uid_playbook() -> None:
    out = diagnose("Error: listen EACCES: permission denied 0.0.0.0:80 on OpenShift").as_dict()
    top = out["diagnoses"][0]
    assert top["id"] == "DBG-ARBITRARY-UID"
    assert any("below 1024" in c for c in top["rootCauses"])


# QA3: the in-scope misses the independent graders named (docs/evals/community-questions-heldout.csv).


def test_a_missing_entrypoint_names_its_own_playbook() -> None:
    # runc looks the command up with Go's exec.LookPath at create time (libcontainer/standard_init_linux.go)
    for text in (
        'runc create failed: unable to start container process: exec: "/opt/app/run": stat /opt/app/run: '
        "no such file or directory",
        'Error: container create failed: exec: "uvicorn": executable file not found in $PATH',
    ):
        assert _ids(text)[0] == "DBG-ENTRYPOINT-NOT-FOUND"
    assert "DBG-ENTRYPOINT-NOT-FOUND" not in _ids("exec /usr/bin/app: exec format error")


def test_a_kubeconfig_exec_plugin_that_is_missing_is_explained(kit: tk.Toolkit) -> None:
    post = (
        "Desktop dashboard cannot connect to my cluster\n"
        "After copying my kubeconfig to another laptop it says getting credentials: exec: executable gcloud not "
        "found. What should I do?"
    )
    assert _docs(kit, post)[0].startswith("kn:k8s-kubeconfig-exec#")


def test_answers_are_scored_without_being_written_out(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location("eval_questions_a", ROOT / "scripts" / "eval_questions.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["eval_questions_a"] = mod
    spec.loader.exec_module(mod)
    hit = mod.answer_overlap(
        "Set securityContext fsGroup so the volume is group-writable; runAsUser picks the uid.",
        "fsGroup makes the volume files group-owned; set runAsUser and fsGroup in the pod securityContext",
    )
    assert hit["answerAgrees"] and hit["answerShared"] >= 3
    assert not mod.answer_overlap("Use securityContext fsGroup for volumes.", "")["answerAgrees"]
    path = tmp_path / "q.csv"
    secret_answer = "ZZTOP-unique-answer-marker fsGroup securityContext runAsUser"
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["id", "question", "body_excerpt", "answer_text", "answer_source_type"])
        w.writeheader()
        w.writerow(
            {
                "id": "1",
                "question": "Why can my non-root container not write to its volume?",
                "body_excerpt": "",
                "answer_text": secret_answer,
                "answer_source_type": "accepted_answer",
            }
        )
    out = tmp_path / "out"
    assert mod.main([str(path), "--out", str(out)]) == 0
    summary = json.loads((out / "summary.json").read_text())
    assert summary["referenceAnswers"]["rows"] == 1
    for name in ("results.csv", "summary.json"):
        assert "ZZTOP" not in (out / name).read_text()
    row = next(csv.DictReader((out / "results.csv").open()))
    assert row["answerSource"] == "accepted_answer" and float(row["answerShare"]) >= 0


def test_a_question_about_another_product_is_not_answered_by_a_doc_that_never_names_it(kit: tk.Toolkit) -> None:
    istio = (
        "Istio sidecar ingress gateway returns 503 for one service\n"
        "With Istio 1.24 the ingress gateway answers 503 for my service while other routes work. How do I debug it?"
    )
    assert _docs(kit, istio) == []
    plain = istio.replace("Istio sidecar ingress gateway", "Ingress").replace(
        "With Istio 1.24 the ingress gateway", "It"
    )
    assert _docs(kit, plain)  # the same question about plain Kubernetes still gets documents
    lens = (
        "Lens cannot connect to my cluster\n"
        "It says getting credentials: exec: executable aws not found after I copied the kubeconfig. What now?"
    )
    assert _docs(kit, lens)[0].startswith("kn:k8s-kubeconfig-exec#")  # "lens" is not on the product list


# QA5: per-technology test half (docs/evals/supported-technologies.md): Helm usage, local images, SCC wording.


def test_helm_usage_questions_get_the_helm_values_document(kit: tk.Toolkit) -> None:
    cases = (
        (
            "helm upgrade dropped my overrides\n"
            "I installed the chart with --set replicaCount=3, then ran helm upgrade with a new chart version and the "
            "replica count went back to 1. How do I keep the values I passed last time?",
            "kn:helm-templates-values#",
        ),
        (
            "Error: unknown flag: --name when running helm install myapp ./chart --name web. Did the flag change?",
            "kn:helm-templates-values#",
        ),
        (
            "nil pointer evaluating interface {}.Release in my chart template inside a range loop over "
            ".Values.services; .Release.Name works outside the loop",
            "kn:helm-templates-values#",
        ),
        (
            "How do I read a values key with a dash, like gitlab-runner, in a helm template? Dot notation fails.",
            "kn:helm-templates-values#",
        ),
    )
    for text, prefix in cases:
        got = _docs(kit, text)
        assert got and got[0].startswith(prefix), (text[:40], got)


def test_the_helm_values_document_keeps_to_helm(kit: tk.Toolkit) -> None:
    for text in (
        "how do I set a default value for an environment variable in my Deployment?",
        "my ConfigMap values are not picked up by the running pod",
    ):
        assert not [d for d in _docs(kit, text) if d.startswith("kn:helm-templates-values#")], text


def test_a_local_image_on_minikube_is_explained_by_the_image_pull_playbook() -> None:
    text = (
        "Built myapp:latest with docker build on my laptop, kubectl apply on minikube and the pod shows "
        "ErrImagePull: pull access denied for myapp, repository does not exist"
    )
    out = diagnose(text).as_dict()
    top = out["diagnoses"][0]
    assert top["id"] == "DBG-IMAGEPULL"
    assert any("in no registry" in c for c in top["rootCauses"])
    assert any("minikube image load" in c["change"] for c in top["proposedChanges"])


def test_the_scc_playbook_reads_a_mangled_denial_line() -> None:
    for text in (
        'pods "web-1" is forbidden: unable to validate against any security context constraint: '
        "[spec.containers[0].securityContext.runAsUser: Invalid value: 0]",
        "Error creating: pods is forbidden: unable to validate against any security-context constraint",
    ):
        assert "DBG-SCC" in _ids(text, platform="openshift")[:2], text
