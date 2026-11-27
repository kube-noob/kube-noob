# kube-noob brand

One source for how kube-noob looks and sounds, in the docs, the website, the videos and social posts. The values a
program needs are in [tokens.json](tokens.json); the video tools read it through `demos/video/brand.js`, and a test
keeps the two in step.

## Name and line

- **kube-noob**: always lowercase and hyphenated, also at the start of a sentence. Short form for the command: `noob`.
- **Tagline: "No AI inside. Works with yours."** Locked. kube-noob is the rulebook your AI calls as tools; copy never
  calls kube-noob an AI, assistant, chatbot or agent (`tests/test_guidance.py` enforces this in the docs).
- The headline under test, "The ground truth your AI SRE checks against" ([roadmap](../roadmap.md)), is never shown
  next to the tagline: the A/B test decides between them. "The Kubernetes rulebook your AI calls" may describe the
  product under the tagline; say "rulebook", never "AI", for kube-noob itself.
- Call to action: `uv tool install kube-noob` and **kube-noob.com**. Spoken: "Get it at kube-noob dot com." Never "link
  below": the same video plays on the website, YouTube and LinkedIn.

## Colour

From the icon ([kube-noob-icon.svg](kube-noob-icon.svg)). Illustrations in the videos (flames, locks, gauges) keep
their own colours; text, captions, terminals and end cards use only these.

| Token | Hex | Use |
|---|---|---|
| `navy` | `#0E2A47` | Brand navy; backgrounds derive from it |
| `blue` | `#2F6FED` | Links, the blue end of the wordmark gradient, highlights |
| `green` | `#43E97B` | Safe, read-only actions; the green end of the wordmark gradient |
| `teal` | `#22B8CF` | The middle of the wordmark gradient (the icon's ring) |
| `sky` | `#9CCBFF` | Links and highlighted text on dark surfaces (the icon's rocket); `blue` is for fills and large type, where it has 3:1 contrast |
| `navyDeep`, `navyNight`, `panel` | `#081626`, `#050B17`, `#0D2036` | Dark surfaces (video stage, dark mode) |
| `ink`, `inkSoft`, `muted` | `#E8EEF7`, `#C3CFDF`, `#93A3B8` | Text on dark surfaces (contrast on `panel`: 14:1, 10:1, 6.4:1) |
| `greenSoft` | `#BBF7D0` | Commands and code on dark surfaces |
| `danger`, `dangerSoft`, `warning` | `#F87171`, `#FECACA`, `#FBBF24` | **Status only, not brand colours**: a destructive command (the teaser's `delete`), a warning. Never decoration. |

## Type

| Token | Font | Weights | Use |
|---|---|---|---|
| `KN Sans` | Inter 4.1 (variable) | 400 to 800 | Headlines, captions, body |
| `KN Mono` | JetBrains Mono 2.304 | 400, 500, 600 | Commands, terminal output, code |

The files are in [fonts/](fonts/) (SIL Open Font License 1.1; sources and SHA-256 in
[fonts/PROVENANCE.json](fonts/PROVENANCE.json)). Renders load them from these files under the `KN` family names, so a
machine's own fonts can never change the look, and a render stops if they did not load.

## Logo and mascot

- The icon and the rocket mascot come from [kube-noob-icon.svg](kube-noob-icon.svg). Do not recolour or distort them;
  keep at least a quarter of the icon's width clear around it.
- No third-party logos (Kubernetes, OpenShift, Red Hat, AWS, Anthropic) and no real person's likeness in any
  generated image or video. Pods and clusters are drawn as glowing cubes.
- The mascot never sits behind or across a window, caption or the terminal; it stays clear of them.

## Numbers and claims

Every number in copy, captions or voice-over (rules, playbooks, tools, self-test questions, scores) comes from the
code when the asset is built. A test fails when a script's number does not match. Claims stay checkable: say
"deterministic" or "the same input gives the same result", not "every answer is cited".

Trademark line, on every page and every video description:

> Kubernetes, Helm, OpenShift, ROSA, RHACS, StackRox, OpenShift Lightspeed, Claude, Anthropic, GitHub and AWS are
> trademarks of their respective owners; kube-noob is independent and not endorsed by them.

## Video

| | Value |
|---|---|
| Master | 3840x2160, 30 fps, H.264 High, `yuv420p`, BT.709; rendered once per release and attached to it |
| Web | 1920x1080, scaled from the master |
| Sound | Voice: Kokoro-82M `af_heart`. Music: the kube-noob motif (C, G, high C) at -12 dB under the voice. Loudness -16 LUFS integrated (within 0.5 LU), true peak at most -1.5 dBTP; music alone -20 LUFS. AAC 320 kb/s, 48 kHz |
| Captions | WebVTT from the voice-over timings, for the website, YouTube and LinkedIn (which autoplay muted) |
| End card | Icon, wordmark, tagline, platforms, surfaces, install command, kube-noob.com, credits |
| Formats | 16:9. Square (1:1) and vertical (9:16) need their own layout, not a crop of the 16:9 frame: planned |

Scripts: [demos/ai-video-prompts.md](../../demos/ai-video-prompts.md) (the animated videos) and
[demos/youtube-walkthrough.md](../../demos/youtube-walkthrough.md) (the walkthrough and its YouTube metadata).
