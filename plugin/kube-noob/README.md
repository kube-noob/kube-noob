# kube-noob plugin

Kubernetes, OpenShift, ROSA HCP, Helm and RHACS/StackRox expertise as tools for Claude. **No AI inside:** Claude does
the thinking; kube-noob supplies the audit rules, read-only-first troubleshooting steps, cited docs and graded
exercises, and runs on your computer. Design and review requests follow a 7-step protocol: Clarify, Validate,
Research, Audit, Calibrate, Generate, Red Team.

## Install

In Claude Code:

```
/plugin marketplace add kube-noob/kube-noob
/plugin install kube-noob@kube-noob
```

In claude.ai or the Claude desktop app: **Customize > Plugins > Add > Add marketplace**, enter
`kube-noob/kube-noob`, then add **kube-noob** from the list. It is saved to your account and also reaches
Claude Code.

The tools run on your computer, so they work in Claude Code and in Cowork sessions on your computer; in a chat
conversation only the skills load. The server needs [uv](https://docs.astral.sh/uv/) (`brew install uv` or
`pipx install uv`).

## How to use it

Ask Claude in your own words; the skills route the work to kube-noob's tools.

- "Review this Deployment for OpenShift 4.22" and paste the YAML: findings with line numbers, fixes and the RHACS
  policy each one would trip.
- "My pod is in CrashLoopBackOff" and paste `oc describe pod` or the events: the likely cause, then read-only checks
  first; anything that changes the cluster comes last and needs your approval.
- "Write manifests for orders-api on ROSA HCP with shared storage": audited YAML through the 7-step protocol.
- "Is this a known bug?" with an OpenShift error: the matching issue from the release notes, its link, the version
  that fixes it and the workaround.
- "Why was this denied?" with a Kyverno, Gatekeeper, Pod Security, SCC, quota or RBAC error, or "can frontend
  reach orders-api on 8080?": the policy and rule that decided it, the field that failed and the fix.
- "Teach me Services" or "give me an exercise": lessons and graded exercises.

Commands in an answer are for you to run: the skills tell Claude to hand them to you rather than run them, and
kube-noob itself never changes your cluster.

## How it runs

Claude Code starts the server with `uv run --frozen --isolated` against the readable Python source in `server/`,
installing the dependencies at the exact versions and SHA-256 hashes in the `uv.lock` beside this file into a
throwaway environment in uv's cache. `-I` keeps your working directory and `PYTHONPATH` off `sys.path`, and `-B`
writes no `.pyc` into the plugin. If no Python 3.11 or later is present, uv downloads its managed CPython once.
Nothing else is downloaded and no LLM SDK is installed.

Running the published package from an index instead would be cleared by the directory's automatic checks, where
this launcher is held for a human reviewer. kube-noob does not do it, and the reason is worth stating plainly: a
launcher that names a package and a version fixes that package, and leaves the rest of the tree to be resolved when
the user first runs it. This one resolves nothing. The source is the readable copy in `server/`, every dependency is
fixed to an exact version and SHA-256 hash in the `uv.lock` beside this file, and `--frozen` refuses to re-resolve
any of it. The trade is a slower listing for an install that is identical on every machine and auditable before it
runs, and that is the right way round for a tool people point at production clusters.

### The pre-action hook

`hooks/hooks.json` registers a PreToolUse hook on Bash and PowerShell that is off until you turn on
`verify_cluster_commands` in `/config`. While it is off, the hook is a POSIX `sh` guard that reads that option from
the environment Claude Code gives it and exits at once: it starts no program, uv included (about 2 ms). Turned on,
it runs the bundled `kube-noob verify` through the same `uv run` launcher as the server, which was measured at
1.5 s per Bash command with uv's cache warm and 2.7 s on the first, cold call; a deny is blocked, a change it cannot decide asks you, and when uv is missing or
its run fails the guard itself blocks the command (exit 2, with a one-line reason), on any Claude Code version. The
check stops itself at 20 seconds, and the guard kills a uv run that has not finished in 45 and blocks, inside Claude
Code's 60-second timeout (which would let the call through). On Windows
the guard needs Git Bash: without it, Claude Code runs the hook in PowerShell, where it does not parse, and the check
does not run at all (nothing is blocked; this is read from Claude Code's documentation and has not been run on
Windows). To have it there, install Git for Windows or use `kube-noob hook install`
from the CLI, which writes a settings entry with `"onFailure": "block"` for you alone.

### What the vendored copy is

The server source in `server/` is the modules of the
[kube-noob repository](https://github.com/kube-noob/kube-noob)'s `src/kube_noob` that the stdio MCP server
imports, copied unchanged. The CLI, the optional model agent, the HTTP service and REST routes, the web client, Helm
rendering and the cluster backends are not included, so nothing in that copy reads a credential, opens a connection or
starts another program. Beside it is a `uv.lock` pinning every dependency to an exact version and SHA-256 hash.

The `uv.lock` beside this file names 32 packages. Eight are what the bundled server imports directly: `mcp`,
`pydantic`, `pydantic-core`, `mcp-types`, `anyio`, `starlette`, `PyYAML` and `jsonschema`. The rest arrive through
`mcp`, which declares its HTTP transports as dependencies whether or not you use them, so the installed tree does
contain HTTP clients and a web server — `httpx2`, `httpcore2`, `h11`, `uvicorn`, `sse-starlette` — along with
`cryptography`, `truststore`, `pyjwt` and their own dependencies. A reviewer reading `uv.lock` will see all of them,
and this file should not say otherwise.

What is true is narrower and checkable: this plugin serves stdio only, the bundled modules under `server/` never
import those packages and never start a server or open a connection, and the CLI, the optional model agent, the HTTP
service and the web client are not part of the copy at all. All 31 dependencies are pinned to an exact version and SHA-256 hash -- the 32nd entry is this plugin itself,
which is a virtual project with no artifact to hash -- and `--frozen` refuses to re-resolve any of it. Vendoring them instead, which would let the plugin run
a plain file with no resolver at all, does not fit the directory's file-count and file-size limits.

## What it accesses

- Network: none of its own. The plugin has no web client and no cluster access, and the server never calls a model;
  uv's one-time install of the pinned dependencies is the only download.
- Files: stores learning progress and `learning.json` (your platform, versions, conventions and the fixes you
  confirmed; never logs, manifests or secrets) in `~/.local/share/kube-noob`, which survives plugin upgrades.
- To read your cluster (read-only, never Secrets) or allowlisted documentation sites, use the kube-noob CLI
  (`pipx install kube-noob`) or the in-cluster service; the plugin stays offline.
- Asks you for nothing and reads nothing out of your environment. The plugin never asks for a token, a key or a
  password: it starts the server with the web, the cluster and the model off, so the settings that would read one
  are unreachable, and the one tool that reads your own files (must-gather analysis) is not in the plugin at all.
- No telemetry and no accounts. Details: [PRIVACY.md](https://github.com/kube-noob/kube-noob/blob/main/PRIVACY.md).

## Skills

kube-master-controller, kubernetes-core, openshift-platform, rosa-hcp, helm-charts, rhacs-stackrox, kube-debugging.

Docs: https://github.com/kube-noob/kube-noob
