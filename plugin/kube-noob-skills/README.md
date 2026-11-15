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

## What this plugin contains, runs, reads and writes

This plugin is Markdown and one image. **There is no MCP server here, no script, no hook and no bundled code**, and it
downloads nothing. The checks are done by the kube-noob command-line tool, which you install yourself (below). The
skills tell Claude to run it through Claude Code's Bash tool, under your own permission settings: you are asked before
each command unless you have already allowed such commands without asking. The plugin changes no permission setting and
pre-approves no command.

- **Finding the engine.** A skill runs `kube-noob --version`. If that fails it says that kube-noob is not installed and
  nothing has been audited, gives you the install command, and does not answer as if a check had run. It does not use
  `kubectl noob`, which downloads kube-noob when kube-noob is not installed.
- **A private folder.** Claude makes one folder per session with `umask 077 && mktemp -d`, writes what you pasted into
  it with its file-writing tool, and removes it with `rm -rf` when the work is done.
- **How kube-noob runs.** Every command runs as
  `KUBE_NOOB_FOR_MODEL=1 KUBE_NOOB_LEARNING_ENABLED=false kube-noob <command> ... --format json`, with the output
  written to that folder. The first variable makes kube-noob clean text from your input that is shaped like
  instructions before Claude reads it; the second stops it counting rule ids in its data folder. The skills never turn
  on kube-noob's cluster access, web lookups or model calls.
- **What it reads.** The files in that folder; and, when you point at them, a chart folder (`helm-audit ./mychart`,
  which runs your installed `helm template`), a rendered chart (`helm template` run by Claude, with your approval), a
  Containerfile and its build context (`build audit`), a must-gather folder (`must-gather analyze`), SARIF files and a
  repository (`code report`), and kube-noob's own local stores (`incidents list`, `learning show`, `config`).
- **What it writes.** The private folder; the learning progress kube-noob keeps in its data folder when you read a
  lesson, submit an exercise or answer a quiz; a profile (`learning profile`) or an incident fix (`incidents confirm`)
  only when you ask to save one. A generated chart is written to the private folder and copied into your project only
  if you ask.

In chat on claude.ai there is no shell on your machine, so the skills give you the command to run and read the output
you paste back.

## Getting kube-noob

```
pipx install 'kube-noob>=0.9.3'
```

The skills need kube-noob 0.9.3 or later, and say so when they meet an older one. pipx installs it
from PyPI. Homebrew, uv and the container image are in
[the install guide](https://github.com/kube-noob/kube-noob/blob/main/docs/install.md).

The full `kube-noob` plugin, from the project's own marketplace, gives Claude the same engine as MCP tools instead of
shell commands:

```
/plugin install kube-noob@kube-noob
```

## Licence and privacy

Apache-2.0. This plugin collects nothing and sends nothing; kube-noob makes no network call of its own unless you turn
one on. Privacy policy: https://github.com/kube-noob/kube-noob/blob/main/PRIVACY.md
