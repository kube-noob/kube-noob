"""Write a CI history folder from the GitHub Actions API (``ci.githubEnabled``), read-only.

For each workflow run (newest first, up to ``ci.maxRuns`` attempts in all) and each of its attempts: ``GET
/repos/{owner}/{repo}/actions/runs/{id}/attempts/{n}`` and ``.../attempts/{n}/jobs``; the folder holds ``run.json``
with the jobs and their steps, which ``kube_noob.build.analytics`` reads. Test reports and logs are not fetched (GitHub
serves logs and artifacts from another host): download the JUnit artifacts into the run folders with ``gh run download``
to add flaky-test analysis. A random 0.2-0.6 s pause separates requests.

The only module that reads the GitHub token; the Claude plugin ships without it (``scripts/sync_plugin_server.py``).
"""

from __future__ import annotations

import json
import os
import random
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from kube_noob.errors import ConfigError, KubeNoobError, WebDisabledError

DEFAULT_TOKEN_ENV = "GITHUB_TOKEN"  # noqa: S105 - the variable the GitHub CLI and Actions use; a name, not a token
MAX_BYTES = 20_000_000
_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
_WORKFLOW = re.compile(r"^[A-Za-z0-9_.-]{1,100}\Z")
_BRANCH = re.compile(r"^[A-Za-z0-9_./-]{1,200}\Z")


class HistoryFetchError(ValueError):
    """GitHub refused, or the answer was not what the API documents."""


class Reader:
    def __init__(
        self, http: Any, api: str, sleep: Callable[[float], None] = time.sleep, rng: random.Random | None = None
    ) -> None:
        self.http, self.api, self.sleep = http, api.rstrip("/"), sleep
        self.rng = rng or random.Random()  # noqa: S311 - pacing jitter, not crypto
        self.requests = 0

    def get(self, path: str, params: dict[str, str] | None = None) -> Any:
        if self.requests:
            self.sleep(self.rng.uniform(0.2, 0.6))
        self.requests += 1
        try:
            resp = self.http.get(self.api + path, params=params or {})
        except KubeNoobError:
            raise
        except Exception as exc:  # connection, TLS and timeout errors name the path, never the token
            raise HistoryFetchError(f"GET {path}: {type(exc).__name__}: {str(exc)[:200]}") from exc
        if resp.status_code in (401, 403, 404):
            raise HistoryFetchError(
                f"GET {path}: HTTP {resp.status_code}: the token cannot read Actions on this repository (it needs "
                "actions: read), or the repository or workflow does not exist"
            )
        if resp.status_code != 200:
            raise HistoryFetchError(f"GET {path}: HTTP {resp.status_code}")
        if len(resp.content) > MAX_BYTES:
            raise HistoryFetchError(f"GET {path}: answer larger than {MAX_BYTES} bytes")
        try:
            return resp.json()
        except ValueError as exc:
            raise HistoryFetchError(f"GET {path}: not JSON") from exc


def fetch(
    settings: Any,
    repo: str,
    out: Path,
    *,
    workflow: str | None = None,
    branch: str | None = None,
    max_runs: int | None = None,
    transport: Any = None,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    from kube_noob.net import Purpose, http_client

    ci = settings.ci
    if not ci.github_enabled:
        raise WebDisabledError(
            "ci",
            "Reading CI history from GitHub is off (ci.githubEnabled: false). Set ci.githubEnabled: true, or "
            "analyse run folders on disk with kube-noob build analytics --history <dir>.",
        )
    if not _REPO.match(repo) or any(part in {".", ".."} for part in repo.split("/")):
        raise ConfigError(f"--github must be owner/repo, got {repo!r}")
    if workflow is not None and not _WORKFLOW.match(workflow):
        raise ConfigError(f"--workflow must be a workflow file name or id, got {workflow!r}")
    if branch is not None and (not _BRANCH.match(branch) or ".." in branch):
        raise ConfigError(f"--branch is not a branch name: {branch!r}")
    env = ci.github_token_env or DEFAULT_TOKEN_ENV
    token = os.environ.get(env, "").strip()
    if not token:
        raise ConfigError(f"Set {env} to a token that can read Actions (actions: read) on {repo}")
    if len(token) > 4096 or any(c.isspace() or not c.isprintable() for c in token):
        raise ConfigError(f"{env} does not look like a token (whitespace or control characters)")
    limit = min(max_runs or ci.max_runs, ci.max_runs)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    out.mkdir(parents=True, exist_ok=True)
    written = 0
    runs_seen = 0
    with http_client(settings, Purpose.CI, timeout=30, extra_headers=headers, transport=transport) as http:
        reader = Reader(http, ci.github_api_url, sleep=sleep)
        base = f"/repos/{repo}/actions" + (f"/workflows/{workflow}" if workflow else "")
        page = 1
        while written < limit and page <= 50:
            params = {"per_page": "100", "page": str(page)}
            if branch:
                params["branch"] = branch
            listing = reader.get(f"{base}/runs", params)
            runs = listing.get("workflow_runs") if isinstance(listing, dict) else None
            if not isinstance(runs, list):
                raise HistoryFetchError("the runs listing has no workflow_runs")
            if not runs:
                break
            for run in runs:
                if written >= limit:
                    break
                run_id = run.get("id") if isinstance(run, dict) else None
                if not isinstance(run_id, int):
                    continue
                runs_seen += 1
                last = run.get("run_attempt") if isinstance(run.get("run_attempt"), int) else 1
                for attempt in range(1, min(last, 10) + 1):
                    if written >= limit:
                        break
                    meta = reader.get(f"/repos/{repo}/actions/runs/{run_id}/attempts/{attempt}")
                    jobs = reader.get(
                        f"/repos/{repo}/actions/runs/{run_id}/attempts/{attempt}/jobs", {"per_page": "100"}
                    )
                    doc = {
                        "id": run_id,
                        "head_sha": meta.get("head_sha"),
                        "run_attempt": attempt,
                        "conclusion": meta.get("conclusion"),
                        "created_at": meta.get("run_started_at") or meta.get("created_at"),
                        "name": meta.get("name"),
                        "jobs": [
                            {
                                "name": j.get("name"),
                                "conclusion": j.get("conclusion"),
                                "steps": [
                                    {k: s.get(k) for k in ("name", "conclusion", "started_at", "completed_at")}
                                    for s in j.get("steps") or []
                                    if isinstance(s, dict)
                                ],
                            }
                            for j in (jobs.get("jobs") if isinstance(jobs, dict) else None) or []
                            if isinstance(j, dict)
                        ],
                    }
                    folder = out / f"run-{run_id}-{attempt}"
                    folder.mkdir(exist_ok=True)
                    (folder / "run.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
                    written += 1
            page += 1
    return {"repo": repo, "runs": runs_seen, "attempts": written, "requests": reader.requests, "folder": str(out)}
