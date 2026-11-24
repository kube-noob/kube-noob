# Prompts for a text-to-video model

Three short videos to generate with a text-to-video model (for example Sora, Grok or a similar tool). Paste each
scene's prompt as one generation, then cut the clips together and add the voice-over. To skip the video model, render
all three locally with `demos/video/stage/build.sh` (real terminal text; see [README.md](README.md)). The on-screen
text and voice-over columns are the captions and voice-over of `demos/video/stage/videos.json`, word for word
(tests/test_video_facts.py compares them), so a generated cut says what the rendered one says.

## Before you generate

- **Real terminal text comes from the real recordings.** Video models garble on-screen text, so every scene that
  shows commands asks for a blank, glowing terminal window. Overlay the matching segment of a real recording on it:
  `kube-noob-walkthrough.mp4`, `kube-noob-mcp.mp4` or `kube-noob-sidecar.mp4` (`demos/video/render.sh`).
- **No real logos or people.** Do not ask for the Kubernetes, OpenShift, Red Hat, AWS or Anthropic logos, or for a
  real person's likeness. The prompts use generic shapes instead (pods and clusters are "glowing cubes").
- **Brand look** ([docs/brand/BRAND.md](../docs/brand/BRAND.md)): deep navy background (#050B17 to the brand navy
  #0E2A47), the brand green #43E97B for safe actions, the status red #F87171 only for a destructive command, Inter
  and JetBrains Mono, the rocket mascot from `docs/brand/kube-noob-icon.svg` (upload it as a reference image where
  the tool allows) resting clear of windows and captions, and the end card with kube-noob.com.
- **Format:** 16:9, 3840x2160 master (1920x1080 for the web), 30 fps. Square (1:1) and vertical (9:16) cuts need
  their own layout, not a crop of the 16:9 frame.
- **Numbers:** in braces, filled from the code (`python demos/video/facts.py fill demos/ai-video-prompts.md`); the
  sidecar's come from the transcript recorded on a kind cluster in CI.

## Video 1: launch teaser (30 seconds)

| # | Length | Prompt | On-screen text | Voice-over |
|---|---|---|---|---|
| 1 | 5 s | A dark navy control room at night, one glowing terminal window floating in the center. A red command line appears and the whole room flickers red, like an alarm. Cinematic, shallow depth of field, no readable text. | Your AI ran delete first. | When a pod breaks at two in the morning, the fastest command is delete. |
| 2 | 5 s | The red glow freezes and fades; small glowing cubes (pods) dissolve into dust, suggesting lost evidence. Slow motion, moody. | The evidence is gone. | It's also the one that destroys your evidence. |
| 3 | 7 s | A friendly cartoon rocket with a round window and a smile flies in from the lower left on a green-blue arc of light and stops beside the terminal. Clean 3D illustration style, soft rim light. | kube-noob | Meet kube-noob. There's no AI inside it. |
| 4 | 8 s | Split screen: on the left a chat bubble labelled only with a speech icon, on the right the rocket holding a clipboard with green check marks; a beam connects them. Flat, modern, navy and green palette. | No AI inside. Works with yours. | Your AI does the talking. kube-noob supplies the rules, the read-only steps and the citations. |
| 5 | 5 s | The terminal window turns calm green; three green lines type out (blank text to overlay later). The rocket gives a thumbs up. | uv tool install kube-noob | Free and open source. Get it at kube-noob dot com. |

## Video 2: kube-noob as a sidecar (60 seconds)

| # | Length | Prompt | On-screen text | Voice-over |
|---|---|---|---|---|
| 1 | 8 s | Isometric 3D illustration: a large translucent box (a pod) on a navy grid; inside it two smaller containers side by side, one labelled with a chat icon (the app), one with the rocket mascot. Soft studio lighting. | Your app and kube-noob, one pod | Run kube-noob next to your own app, in the same pod. |
| 2 | 10 s | A short glowing cable loops between the two containers inside the pod only. Outside the pod, other glowing cubes try to reach the rocket and bounce off a transparent shield. | Listens on 127.0.0.1 only | It listens only on localhost, so only the containers in that pod can call it. |
| 3 | 10 s | The pod's outer wall shows a single small door marked with a padlock. One green arrow leaves it for a small DNS sign; red arrows toward the internet and other cluster services fade out before reaching them. | DNS-only egress. No Service, no token. | It makes no outbound calls, so its network policy allows DNS only. kube-noob gets no Service, no Route and no token to manage. |
| 4 | 12 s | Blank glowing terminal window over the isometric scene (overlay the real `kube-noob-sidecar.mp4` segment: audit, rollout, MCP calls, closed port). | Recorded on a cluster that enforces Pod Security restricted | On a test cluster that enforces Pod Security restricted, the app asks it to audit a Deployment and diagnose a crash, over localhost. |
| 5 | 8 s | A small gauge on the rocket's container settles at a low level, green. | {sidecar.peak} MiB peak · {sidecar.limit} MiB limit | In our test cluster it peaked at {sidecar.peak} mebibytes, well under its limit. |
| 6 | 12 s | Pull back to show many pods on the grid, each with a tiny rocket beside its app. | deploy/sidecar/app-with-kube-noob-sidecar.yaml | One example manifest, audited for OpenShift 4.20 and later. Get it at kube-noob dot com. |

## Video 3: kube-noob as tools for Claude (MCP, 60 seconds)

| # | Length | Prompt | On-screen text | Voice-over |
|---|---|---|---|---|
| 1 | 8 s | A laptop on a desk at night, a code editor glowing; a speech bubble rises from the screen. Warm desk lamp, navy room. | Ask in your own words | Ask Claude to review a Deployment for OpenShift 4.22. |
| 2 | 12 s | From the laptop, a thin beam goes to the rocket mascot sitting on the desk next to the laptop (not in the cloud). The rocket flips through a thick rulebook. | Runs on your machine | The kube-noob plugin runs on your machine. Claude calls its tools: audit, fix and diagnose. |
| 3 | 15 s | Blank glowing terminal window (overlay the real `kube-noob-mcp.mp4` segment: tool calls and the score). | {audit.score}/100 · {audit.high} high findings | kube-noob checks the YAML against {rules} rules and returns findings with line numbers and fixes. Same answer every time. |
| 4 | 10 s | A large glowing YAML file fills the frame (overlay the real `kube-noob-mcp.mp4` segment): problem lines light up red one by one, small labels slide in beside them, and a ring gauge counts up to a low score; then the red lines turn green and the gauge climbs. | {audit.score} → {fix.score} after the safe fixes | Each finding lands on its line. The safe fixes take the score from {audit.score} to {fix.score}, and kube-noob lists the {fix.manual} changes that need a person. |
| 5 | 15 s | The speech bubble fills with neat green check marks while the rulebook closes. | Claude explains. kube-noob checks. | Claude explains the result in plain language and cites the rule ids. |
| 6 | 10 s | The laptop's network icon stays dim while the rocket works; a tiny label reads "local". | No AI inside kube-noob | There's no model inside kube-noob, and it makes no network calls of its own. |
| 7 | 6 s | The rocket on the desk waves at the camera; the laptop screen shows two blank command lines (overlay the plugin install commands from the real `kube-noob-mcp.mp4`). | Add it to Claude Code | Add it to Claude Code with two commands. Get it at kube-noob dot com. |

## Video 4: a zero that is not a pass (60 seconds)

| # | Length | Prompt | On-screen text | Voice-over |
|---|---|---|---|---|
| 1 | 6 s | A dark navy control room; one terminal window floats in the centre showing a manifest. A small red padlock icon on one line springs open and the room pulses red once. Cinematic, shallow depth of field, no readable text. | privileged: true, in production. | A privileged container, {scan.replicas} replicas, shipping to production. |
| 2 | 4 s | The pulse settles. The friendly cartoon rocket with a round window flies in from the lower left on a green-blue arc and stops beside the terminal, head tilted as if reading. Clean 3D illustration style, soft rim light. | Now scan it. | So scan it. Here is what kube-noob says. |
| 3 | 8 s | The terminal fills with a calm report; a column of small glowing zeroes runs down its right edge, each one fading to grey as it lands. The rocket does not celebrate. Moody, restrained, navy and green palette. | {scan.findings} findings. Every severity, zero. | {scan.findings} findings. Critical, high, medium, low: every count is zero. |
| 4 | 8 s | The last grey zero lifts out of the column and opens into a thin wireframe box, visibly empty inside, while the boxes around it glow solid green. A green pipeline arrow running left to right stops dead against it and holds. | It names what it did not read. | But the gate does not pass. It names the object nothing read, and exits {scan.exit}. |
| 5 | 9 s | Slow push in on the empty wireframe box; a soft label plate slides under it as if naming it, and the solid green boxes around it dim so only the empty one is lit. | A zero can mean nothing was read. | The container is still privileged. The kind holding it is one kube-noob has no reader for, so its pods were never read. |
| 6 | 8 s | Split screen: on the left a solid green check mark, on the right the same empty wireframe box; a bright line between them refuses to join. The rocket stands on the line, holding a clipboard. | An absence is not a pass. | That is the whole rule. An absence, an unknown, or a shape it does not recognise never reads as a pass, a zero, or complete. |
| 7 | 6 s | The terminal window turns calm green; two green lines type out (blank text to overlay later). The rocket gives a small nod rather than a thumbs up. | Find out what your gate did not read | Find out what your own gate did not read. Get it at kube-noob dot com. |
