"""CI guard for the chart's data seeds: reads `helm template` output on stdin and checks one case.

Cases: db (the public kube-noob-db init container next to a Jira seed), db-data (the data volume grows when the
public bundle is enabled), sealed (a sealed Jira seed opened with a key from a Secret). On a failed check it prints a
GitHub annotation with the reason, so the failure is readable without the job log.
Usage: helm template ... | python scripts/chart_seed_guard.py <case>
"""

from __future__ import annotations

import sys
from typing import Any

import yaml

DIGEST = "sha256:" + "a" * 64


class GuardError(Exception):
    pass


def expect(ok: bool, detail: Any) -> None:
    if not ok:
        raise GuardError(detail)


def _pod(docs: list[Any]) -> dict[str, Any]:
    dep = next(d for d in docs if d and d.get("kind") == "Deployment")
    pod: dict[str, Any] = dep["spec"]["template"]["spec"]
    return pod


def check(case: str, docs: list[Any]) -> None:
    pod = _pod(docs)
    main = next(c for c in pod["containers"] if c["name"] == "kube-noob")
    mounts = main.get("volumeMounts", [])
    if case == "db":
        names = [c["name"] for c in pod["initContainers"]]
        expect(names == ["kube-noob-db", "jira-seed"], names)
        init = pod["initContainers"][0]
        expect(init["image"] == "ghcr.io/kube-noob/kube-noob-db@" + DIGEST, init["image"])
        expect(
            init["command"]
            == [
                "cp",
                "--",
                "/kube-noob-db/kube-noob-db.tgz",
                "/kube-noob-db-seed/kube-noob-db.tgz",
            ],
            init["command"],
        )
        expect(init["securityContext"]["readOnlyRootFilesystem"] is True, init["securityContext"])
        expect(init["volumeMounts"] == [{"name": "kube-noob-db", "mountPath": "/kube-noob-db-seed"}], init)
        want = {"name": "kube-noob-db", "mountPath": "/var/lib/kube-noob/seed-db", "readOnly": True}
        expect(want in mounts, mounts)
        expect({"name": "kube-noob-db", "emptyDir": {"sizeLimit": "2Gi"}} in pod["volumes"], pod["volumes"])
    elif case == "db-data":
        expect({"name": "data", "emptyDir": {"sizeLimit": "4Gi"}} in pod["volumes"], pod["volumes"])
    elif case == "sealed":
        init = next(c for c in pod["initContainers"] if c["name"] == "jira-seed")
        expect(init["command"][-1] == "/kube-noob-seed/jira-snapshot.tgz.enc", init["command"])
        env = {e["name"]: e.get("value") for e in main["env"]}
        expect(env.get("KUBE_NOOB_SEED_KEY_FILE") == "/var/run/kube-noob/seed-key/key", env)
        expect({"name": "seed-key", "mountPath": "/var/run/kube-noob/seed-key", "readOnly": True} in mounts, mounts)
        vol = next(v for v in pod["volumes"] if v["name"] == "seed-key")
        expect(
            vol["secret"]
            == {
                "secretName": "kn-seed-key",
                "defaultMode": 288,
                "items": [{"key": "key", "path": "key"}],
            },
            vol,
        )
        expect(pod["securityContext"].get("fsGroup") == 1001, pod["securityContext"])
        for c in pod["initContainers"]:
            expect(not any(m["name"] == "seed-key" for m in c.get("volumeMounts", [])), c["name"])
    else:
        raise SystemExit(f"unknown case {case}")


def main() -> int:
    case = sys.argv[1]
    try:
        check(case, list(yaml.safe_load_all(sys.stdin)))
    except (GuardError, KeyError, StopIteration, TypeError) as exc:
        detail = " ".join(str(exc).split())[:1500] or type(exc).__name__
        print(f"::error title=chart seed guard ({case})::{detail}")
        return 1
    print(f"chart seed guard ({case}): ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
