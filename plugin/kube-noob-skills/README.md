# kube-noob skills

Seven skills that let Claude run kube-noob, the offline Kubernetes and OpenShift audit CLI, on your machine. No AI
inside: kube-noob is a deterministic rulebook, and Claude explains what it returns.

```
/plugin marketplace add kube-noob/kube-noob
/plugin install kube-noob-skills@kube-noob
```

The skills cover Kubernetes, Red Hat OpenShift, ROSA (Classic and with Hosted Control Planes), Helm and Red Hat
Advanced Cluster Security: auditing manifests, validating them against bundled schemas, diagnosing pasted events and
logs, explaining policy denials, checking whether one pod can reach another, matching an error against reported
OpenShift issues, generating audited manifests and Helm charts, and graded exercises. They also carry the facts a
general model most often gets wrong about these platforms.

## What this plugin contains, runs and fetches

This plugin is Markdown and one image. **There is no MCP server here, no script, no hook and no bundled code.** The
checks are done by the kube-noob command-line tool, which you install yourself (below). The skills tell Claude to run
it through Claude Code's Bash tool, so you see every command and approve it with your normal permission prompt. The
plugin changes no permission setting and pre-approves no command.

- Before any check, a skill looks for the engine in this order: `kube-noob --version`, then `kubectl noob --version`
  (the krew plugin), then, only if you agree, `uvx --from kube-noob==0.9.2 kube-noob --version`. That last one is
  the only thing this plugin can cause to be fetched: uv downloads that pinned kube-noob release and its dependencies
  from PyPI the first time it runs.
- If none of them is there, the skill says that kube-noob is not installed and nothing has been audited, and gives
  you the install command. It does not answer as if a check had run.
- Every check runs as `kube-noob <command> ... --format json` on files Claude writes from what you pasted, under
  `/tmp`. The skills never turn on kube-noob's cluster access, web lookups or model calls, so kube-noob reads only
  those files and sends nothing anywhere.
- A few commands write where you asked them to: `fix`, `generate` and `helm-chart` write YAML to the path given with
  `-o`; `learn submit` and `learn quiz` record your progress in kube-noob's local data folder; `learning profile` and
  `incidents confirm` save what you asked to save there.

In chat on claude.ai there is no shell on your machine, so the skills give you the command to run and read the output
you paste back.

## Getting kube-noob

```
pipx install kube-noob==0.9.2
```

Homebrew, uv, the container image and the krew plugin are in
[the install guide](https://github.com/kube-noob/kube-noob/blob/main/docs/install.md).

The full `kube-noob` plugin, from the project's own marketplace, gives Claude the same engine as MCP tools instead of
shell commands:

```
/plugin marketplace add kube-noob/kube-noob
/plugin install kube-noob@kube-noob
```

## Licence and privacy

Apache-2.0. This plugin collects nothing and sends nothing; kube-noob makes no network call of its own unless you turn
one on. Privacy policy: https://github.com/kube-noob/kube-noob/blob/main/PRIVACY.md
