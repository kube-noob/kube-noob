from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from kube_noob.config import load_settings
from kube_noob.debug.backends import KubectlBackend
from kube_noob.debug.cluster import get_backend, redact_text, resolve_resource
from kube_noob.debug.diagnose import debug_workload, diagnose
from kube_noob.debug.playbooks import PLAYBOOKS
from kube_noob.errors import ClusterAccessError
from kube_noob.knowledge.store import get_store


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('Warning ProvisioningFailed failed to provision volume with StorageClass "gp3-csi"', "DBG-PVC-PENDING"),
        ("forbidden: unable to validate against any security context constraint: provider restricted-v2", "DBG-SCC"),
        ("Error: UPGRADE FAILED: another operation (install/upgrade/rollback) is in progress", "DBG-HELM-LOCK"),
        ('admission webhook "policyeval.stackrox.io" denied the request: Policy: Latest tag', "DBG-STACKROX-ADMISSION"),
        ("Multi-Attach error for volume pvc-123 Volume is already exclusively attached to one node", "DBG-MULTIATTACH"),
        ('no matches for kind "PodDisruptionBudget" in version "policy/v1beta1"', "DBG-NO-MATCHES-KIND"),
        ("container has runAsNonRoot and image will run as root", "DBG-RUNASROOT"),
        ("Cannot evict pod as it would violate the pod's disruption budget", "DBG-PDB-DRAIN"),
        ("standard_init_linux.go:228: exec user process caused: exec format error", "DBG-EXEC-FORMAT"),
    ],
)
def test_diagnose_top_match(text: str, expected: str) -> None:
    res = diagnose(text)
    assert res.diagnoses and res.diagnoses[0].playbook.pid == expected


def test_diagnose_context_and_exit_codes() -> None:
    text = "Name: api-1\nNamespace: orders\n  Last State: Terminated\n    Reason: OOMKilled\n    Exit Code: 137\n"
    res = diagnose(text)
    assert res.context["ns"] == "orders" and res.context["pod"] == "api-1"
    assert 137 in res.exit_codes
    assert any("-n orders" in c for d in res.diagnoses for c in d.checks)


def test_diagnose_no_match_note() -> None:
    assert diagnose("everything is fine").notes


def test_playbook_knowledge_refs_exist() -> None:
    store = get_store()
    for p in PLAYBOOKS:
        for k in p.knowledge:
            assert store.doc(k), f"{p.pid} references missing knowledge doc {k}"


def test_redaction() -> None:
    raw = (
        "Authorization: Bearer abc.def.ghi password=hunter2 AKIAABCDEFGHIJKLMNOP "
        "postgres://user:s3cret@db:5432 eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlMTIz"
    )
    out = redact_text(raw)
    for secret in ("hunter2", "AKIAABCDEFGHIJKLMNOP", "s3cret", "abc.def.ghi", "eyJhbGciOiJIUzI1NiJ9"):
        assert secret not in out


def test_secrets_never_allowed() -> None:
    for r in ("secret", "secrets", "Secrets"):
        with pytest.raises(ClusterAccessError, match="not permitted"):
            resolve_resource(r)
    with pytest.raises(ClusterAccessError, match="allowlist"):
        resolve_resource("pods/exec")
    assert resolve_resource("deploy")[0] == "deployments"


def test_cluster_disabled_by_default() -> None:
    with pytest.raises(ClusterAccessError, match="disabled"):
        get_backend(load_settings())


def _fake_kubectl(tmp_path: Path) -> Path:
    log = tmp_path / "argv.log"
    script = tmp_path / "bin" / "kubectl"
    script.parent.mkdir()
    pods = {
        "kind": "List",
        "items": [
            {
                "metadata": {"name": "api-1", "namespace": "orders"},
                "spec": {
                    "nodeName": "n1",
                    "containers": [{"name": "api", "env": [{"name": "API_TOKEN", "value": "supersecret"}]}],
                },
                "status": {
                    "phase": "Running",
                    "containerStatuses": [
                        {
                            "name": "api",
                            "ready": False,
                            "restartCount": 4,
                            "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                            "lastState": {"terminated": {"reason": "OOMKilled", "exitCode": 137}},
                        }
                    ],
                },
            }
        ],
    }
    deploy = {
        "metadata": {"name": "api"},
        "spec": {"selector": {"matchLabels": {"app": "api"}}},
        "status": {"replicas": 1, "unavailableReplicas": 1},
    }
    events = {
        "kind": "List",
        "items": [
            {
                "type": "Warning",
                "reason": "BackOff",
                "message": "Back-off restarting failed container",
                "metadata": {"name": "ev-1", "namespace": "orders"},
                "involvedObject": {"kind": "Pod", "name": "api-1"},
                "lastTimestamp": "2026-10-27T00:00:00Z",
            }
        ],
    }
    script.write_text(f"""#!/usr/bin/env python3
import json, sys
open({str(log)!r}, "a").write(json.dumps(sys.argv[1:]) + "\\n")
args = sys.argv[1:]
if args[0] == "logs":
    print("starting... password=hunter2\\nkilled")
elif args[0] == "version":
    print(json.dumps({{"serverVersion": {{"gitVersion": "v1.35.1"}}}}))
elif args[1] == "deployments.apps":
    print({json.dumps(deploy)!r})
elif args[1] == "events":
    print({json.dumps(events)!r})
else:
    print({json.dumps(pods)!r})
""")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return log


def test_kubectl_backend_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = _fake_kubectl(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}")
    backend = KubectlBackend("kubectl", context=None, timeout=10)
    out = debug_workload(backend, "orders", "deployment", "api")
    assert out["diagnoses"][0]["id"] in {"DBG-CRASHLOOP", "DBG-OOM"}
    assert "hunter2" not in json.dumps(out)
    argvs = [json.loads(line) for line in log.read_text().splitlines()]
    assert all(a[0] in {"get", "logs", "version"} for a in argvs), "only read-only commands"
    assert out["cluster"]["kubernetes"] == "1.35" and out["cluster"]["newerThanKnowledge"] is False
    assert any(a[:3] == ["get", "clusterversions.config.openshift.io", "version"] for a in argvs)
    assert argvs[0][:7] == ["get", "deployments.apps", "api", "--namespace", "orders", "--output", "json"]
    assert any("--previous" in a for a in argvs if a[0] == "logs")
    pods = backend.get("pods", namespace="orders")
    assert pods["items"][0]["spec"]["containers"][0]["env"][0]["value"] == "***"
    with pytest.raises(ClusterAccessError, match="Invalid name"):
        backend.get("pods", name="x; rm -rf /")
    with pytest.raises(ClusterAccessError, match="Invalid label selector"):
        backend.get("pods", namespace="a", selector="app=$(whoami)")
