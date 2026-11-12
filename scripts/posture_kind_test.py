"""R3.2 acceptance on a real cluster: the attack-path scan ranks the planted path first, reading only the allowlist.

Usage (in CI, against a kind cluster): python scripts/posture_kind_test.py

Applies the Route stand-in CRD and tests/fixtures/posture/seeded.yaml (the planted path internet -> Route -> pod ->
ServiceAccount -> get secrets, decoys, and a Secret), then runs `kube-noob --cluster-enabled posture scan --live`
with a kubectl wrapper first on PATH that records every call. Checks: the planted path is rank 1, the decoys that
must have no path have none, every kubectl call is a read (get or version), no call names Secrets, and the planted
Secret's value appears nowhere in the output. Results are printed as GitHub annotations.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEEDED = ROOT / "tests" / "fixtures" / "posture" / "seeded.yaml"
CRDS = ROOT / "scripts" / "policy_kind_crds.yaml"
PLANTED = (
    "internet -> Route/shop/web -> Service/shop/web -> Deployment/shop/web -> ServiceAccount/shop/web-sa -> "
    "read Secrets (credentials, tokens of other ServiceAccounts) (shop)"
)


def _escape(text: str) -> str:
    return " ".join(text.replace("%", "%25").split())[:1500]


def run(args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=300, check=False, env=env)


def main() -> int:
    kubectl = shutil.which("kubectl")
    if kubectl is None:
        print("::error title=posture kind::kubectl not on PATH")
        return 1
    for step in (
        ["apply", "-f", str(CRDS)],
        ["wait", "--for=condition=Established", "crd", "--all", "--timeout=60s"],
        ["apply", "-f", str(SEEDED)],
    ):
        res = run([kubectl, *step])
        if res.returncode != 0:
            print(f"::error title=posture kind setup::{_escape(res.stderr)}")
            return 1
    problems: list[str] = []
    with tempfile.TemporaryDirectory() as d:
        shim_dir, log = Path(d) / "bin", Path(d) / "calls.jsonl"
        shim_dir.mkdir()
        shim = shim_dir / "kubectl"
        shim.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            f"open({str(log)!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n"
            f"os.execv({kubectl!r}, [{kubectl!r}, *sys.argv[1:]])\n",
            encoding="utf-8",
        )
        shim.chmod(shim.stat().st_mode | stat.S_IEXEC)
        env = {**os.environ, "PATH": f"{shim_dir}{os.pathsep}{os.environ['PATH']}"}
        # As a gate: kind serves no KServe, Ray or OpenShift resources, and those 404s are absences, not refusals,
        # so --fail-above 30 (the maximum score) must exit 0 here, not 5 (G276, third review).
        res = run(
            ["kube-noob", "--cluster-enabled", "--format", "json", "posture", "scan", "--live", "--fail-above", "30"],
            env=env,
        )
        if res.returncode != 0:
            print(f"::error title=posture scan::{_escape(res.stderr or res.stdout)}")
            return 1
        out = json.loads(res.stdout)
        calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    if out["refused"]:
        problems.append(f"reads refused on a healthy cluster: {out['refused'][:3]}")
    summaries = [p["summary"] for p in out["paths"]]
    if not summaries or summaries[0] != PLANTED:
        problems.append(f"rank 1 is not the planted path: {summaries[:3]}")
    for absent in ("Deployment/shop/api", "Deployment/shop/docs", "CronJob/ops/batch"):
        if any(absent in s for s in summaries):
            problems.append(f"{absent} has a path but must not")
    verbs = sorted({c[0] for c in calls if c})
    if set(verbs) - {"get", "version"}:
        problems.append(f"kubectl calls other than reads: {verbs}")
    # Count the calls that named the Secret resource; the log never prints their arguments.
    forbidden = sum(1 for c in calls if any("secret" in str(a).lower() for a in c[:2]))
    if forbidden:
        problems.append(f"{forbidden} kubectl calls asked for Secrets")
    if "hunter2" in res.stdout:
        problems.append("the planted Secret value reached the output")
    for p in problems:
        print(f"::error title=posture kind::{_escape(p)}")
    print(
        f"::notice title=posture kind::{len(calls)} read-only kubectl calls, none for Secrets; rank 1 "
        f"{_escape(summaries[0] if summaries else 'none')} (score {out['paths'][0]['score'] if out['paths'] else 0}); "
        f"{out['total']} paths; exit {res.returncode} at --fail-above 30; "
        f"not read: {_escape('; '.join(out['notRead'][:3]))}"
    )
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
