# YouTube walkthrough: script, voice-over and metadata

Every release has the rendered cut attached (`.github/workflows/videos.yml`): `kube-noob-walkthrough-4k.mp4` (the
3840x2160 master), `kube-noob-walkthrough-1080p.mp4`, `kube-noob-walkthrough.vtt` (captions),
`youtube-thumbnail.jpg` and `youtube-description.txt` (the description below with its numbers filled and the
chapters at the render's real times). Upload those rather than copying from this page.

There are two cuts:

- The **rendered cut** (about 2 minutes, 3840x2160) is recorded from the installed `kube-noob`'s real output by
  `demos/video/render.sh <out-dir>`, narrated with the voice-over below (Kokoro voice) over the kube-noob brand music.
  Each scene is held until its line is spoken, so chapter times shift by a few seconds.
- The **long cut** (about 5 minutes) is a scene list for a video tool such as Astra. It uses the same commands, so
  every on-screen number is real.

## Metadata

**Title options** (the first is strongest for click-through):

1. Your AI Ran `delete` First. Make It Run `describe`.
2. The Kubernetes Rulebook Your AI Is Missing (OpenShift, ROSA HCP, Helm)
3. Make Claude Debug Kubernetes Like an SRE: Read-Only First, Offline

The tagline "No AI inside. Works with yours." and the second headline (option 2) are never used together: the
headline test in the roadmap decides between them (docs/brand/BRAND.md).

**Thumbnail:** `youtube-thumbnail.png` from the render (`demos/video/thumbnail.html`): "Your AI ran delete first. Make it run describe." with a
struck-through `oc delete` above `oc get events`, `oc describe` and `oc logs --previous`, the tagline, and
kube-noob.com.

**Description:**

```text
kube-noob: no AI inside. Works with yours. Audit rules, read-only-first troubleshooting steps, docs with citations and graded exercises for Kubernetes, OpenShift and ROSA HCP. Claude or OpenShift Lightspeed calls it as tools; the CLI runs it with no AI at all. Free, open source, and it makes no network calls unless you turn them on.

uv tool install kube-noob
kube-noob demo --list

Website: https://kube-noob.com
GitHub: https://github.com/kube-noob/kube-noob
PyPI: https://pypi.org/project/kube-noob/

Chapters
0:00 What kube-noob is
0:05 Audit for the platform you run
0:24 Diagnose before you change anything
0:42 Blueprint to audited ROSA HCP manifests
0:53 Learn Kubernetes objects, graded offline
1:09 Remember what your team fixed
1:27 No AI inside, no network calls
1:44 Check it yourself: {selftest} real questions
1:54 Try it

Kubernetes, Helm, OpenShift, ROSA, RHACS, StackRox, OpenShift Lightspeed, Claude, Anthropic, GitHub and AWS are trademarks of their respective owners; kube-noob is independent and not endorsed by them.
```

**Tags:** kubernetes, openshift, rosa, rosa hcp, helm, rhacs, stackrox, sre, platform engineering, devops, mcp,
claude, openshift lightspeed, kubernetes troubleshooting, crashloopbackoff, scc

## Voice-over for the rendered cut (about 300 words)

`render.sh` speaks these rows in order, one per scene (title, the seven chapters, end card). Timestamps are
approximate. Numbers in braces are filled from the code when the video is rendered (`demos/video/facts.py`); print
this file with them filled in with `python demos/video/facts.py fill demos/youtube-walkthrough.md`.

| Time | Voice-over |
|---|---|
| 0:00 | When a pod breaks at 2 a.m., the fastest command is `delete`. It's also the one that destroys your evidence. kube-noob makes your AI do it the other way round. |
| 0:05 | Here is a Deployment that works on a laptop. On OpenShift 4.22, kube-noob scores it {audit.score} out of 100. The password is hard-coded, the UID is pinned, and privilege escalation is on. Every finding carries its fix, and the RHACS policy it would trip where there is one. One command applies the safe fixes, and it tells you what it left for a human. |
| 0:24 | Now paste the events. Pods are rejected by a security context constraint. kube-noob gives the cause, then read-only steps first: get, describe, logs. Anything that runs in a container or changes the cluster comes last and asks for approval. The crash-looping pod? It's out of memory, exit code 137. |
| 0:42 | Describe an app for ROSA HCP, and the {protocol.steps}-step protocol generates the Deployment, Route, PodDisruptionBudget, autoscaler and NetworkPolicies, then audits them: {protocol.score} out of 100. |
| 0:53 | Learning Kubernetes? Lessons and exercises are graded offline by the same rules. |
| 1:09 | When your team confirms a fix, save it. Next time, search finds your team's note next to the docs, with a citation. Secrets, logs and manifests are rejected. |
| 1:27 | There's no AI inside kube-noob. Claude or Lightspeed does the talking; kube-noob supplies the rules and the citations, or you use the CLI on its own. It makes no network calls and reads no cluster unless you allow it, and `doctor` shows exactly what it can reach. |
| 1:44 | Don't trust me. Run the self-test: {selftest} real questions across Kubernetes, Helm, OpenShift 4.22, ROSA HCP and RHACS. |
| 1:54 | Install it with uv tool install kube-noob, then run kube-noob demo. Get it at kube-noob dot com. |

## Long cut for Astra (about 5 minutes)

Each scene is one shot. "Screen" means a terminal recording of the command shown; generate it with
`kube-noob demo <scenario>` or the rendered cut.

| # | Length | Screen | On-screen text | Voice-over |
|---|---|---|---|---|
| 1 | 0:15 | Thumbnail art, then a terminal typing `oc delete pod api-1` struck through | Your AI ran delete first. | AI assistants jump to the fix. On a shared cluster, the fix is how evidence disappears. |
| 2 | 0:20 | Title card | kube-noob: no AI inside | kube-noob is not another AI. It is a rulebook your AI calls as tools, for Kubernetes, OpenShift, ROSA HCP, Helm and RHACS: free, open source, offline, read-only first. |
| 3 | 0:40 | `kube-noob audit -f examples/insecure-deployment.yaml --platform openshift --version 4.22` | Score {audit.score}/100: {audit.high} HIGH | It audits YAML for the platform you actually run: {rules} rules plus strict schemas, with the RHACS policy that would fire where there is one. |
| 4 | 0:30 | `kube-noob fix ...` | {fix.changes} safe fixes, {fix.manual} left for a human | It fixes what is safe to fix mechanically and tells you what needs a human. |
| 5 | 0:45 | `kube-noob diagnose -f examples/events-scc.txt` | 1. read-only first | Paste events or logs. Read-only steps come first, and anything that changes the cluster asks first. |
| 6 | 0:30 | `kube-noob diagnose -f examples/events-crashloop.txt` | OOMKilled, exit 137 | The specific cause beats the generic symptom: out of memory, not just CrashLoopBackOff. |
| 7 | 0:35 | `kube-noob protocol "Deploy orders-api on ROSA HCP" --blueprint examples/blueprint.yaml` | {protocol.steps} steps, {protocol.score}/100 | Clarify, validate, research, audit, calibrate, generate, red team, for every design request. |
| 8 | 0:30 | `kube-noob learn submit ...` | Graded offline | A flight simulator for Kubernetes objects: write YAML, get graded by production rules. |
| 9 | 0:30 | `kube-noob learning note ...` then `kube-noob search ...` | [kn:local-1#0] | Your team's confirmed fixes become cited answers. Secrets and logs are rejected. |
| 10 | 0:30 | `kube-noob doctor` with and without `KUBE_NOOB_OFFLINE=1` | offline lock ON | Off by default, lockable by admins, provable with doctor. |
| 11 | 0:20 | Lightspeed and Claude screenshots (your own) | Your AI talks. kube-noob checks. | Claude or Lightspeed does the talking and kube-noob does the checking. Or skip the AI and use the CLI. |
| 12 | 0:15 | `kube-noob selftest` | {selftest}/{selftest} | Prove it on your machine: {selftest} real questions. |
| 13 | 0:10 | End card | uv tool install kube-noob · kube-noob.com | Get it at kube-noob dot com. Tell me what it should catch next. |
