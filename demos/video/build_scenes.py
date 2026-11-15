"""Turn real kube-noob output into the scene list the video player animates.

Usage (from the repo root):
  python demos/video/build_scenes.py walkthrough <out-dir>
      runs `kube-noob demo <scenario>` and `kube-noob selftest` (kube-noob on PATH) -> <out-dir>/walkthrough.html
  python demos/video/build_scenes.py mcp <claude-stream.jsonl> <out-dir>
      a real Claude Code session with the plugin (`claude -p ... --output-format stream-json --verbose`), with the
      prompt saved next to it as <name>.prompt.txt -> <out-dir>/mcp.html
  python demos/video/build_scenes.py sidecar <transcript.txt> <out-dir>
      the transcript scripts/demo_sidecar_kind.sh records on a kind cluster in CI -> <out-dir>/sidecar.html
Every line on screen is output that a command or a session actually produced.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

HERE = Path(__file__).parent

CHAPTERS = [
    ("audit", "1. Audit for the platform you run", 16),
    ("diagnose", "2. Diagnose before you change anything", 12),
    ("protocol", "3. Blueprint to audited ROSA HCP manifests", 8),
    ("learn", "4. Learn Kubernetes objects, graded offline", 10),
    ("learning", "5. Remember what your team fixed", 6),
    ("posture", "6. No AI inside, no network calls: prove it", 9),
]

# The title and end cards carry the tagline, platforms, surfaces and kube-noob.com from docs/brand/tokens.json
# (player.html reads them through brand.js); these are only the lines that differ per video. Plain text.
WALKTHROUGH_META = {
    "titleSub": "Recorded from the real output of kube-noob {version}, offline",
    "brand": "kube-noob · offline · read-only",
    "endTitle": "Try it in 30 seconds",
    "endCodes": ["uv tool install kube-noob", "kube-noob demo --list"],
}
MCP_META = {
    "titleSub": "In Claude, end to end: Claude does the thinking, kube-noob supplies the rules",
    "brand": "real Claude Code session",
    "endTitle": "Add it to Claude",
    "endCodes": ["/plugin marketplace add kube-noob/kube-noob", "/plugin install kube-noob@kube-noob"],
}
SIDECAR_META = {
    "titleSub": "As a sidecar on Kubernetes and OpenShift: your app calls it on 127.0.0.1, nothing else can",
    "brand": "kube-noob sidecar · recorded on a kind cluster in CI",
    "endTitle": "Run it next to your app",
    "endCodes": ["deploy/sidecar/app-with-kube-noob-sidecar.yaml"],
}
LICENSE_CREDIT = "kube-noob is open source (Apache-2.0)"
END_CARD_MS = 12_000
MUSIC_CREDIT = "Music: generated for kube-noob"


def _run(*args: str) -> str:
    return subprocess.run(["kube-noob", *args], capture_output=True, text=True, check=False).stdout  # noqa: S607


def parse_transcript(text: str, max_out: int) -> list[dict[str, object]]:
    """`# caption` / `$ command` / output lines, the format of `kube-noob demo` and demo_sidecar_kind.sh."""
    steps: list[dict[str, object]] = []
    cur: dict[str, Any] | None = None
    for line in text.splitlines():
        if line.startswith("# "):
            cur = {"caption": line[2:], "command": "", "output": []}
            steps.append(cur)
        elif line.startswith("$ ") and cur is not None:
            cur["command"] = line[2:]
        elif cur is not None and cur["command"] and not line.startswith("=="):
            cur["output"].append(line)
    for s in steps:
        out: list[str] = s["output"]  # type: ignore[assignment]
        while out and not out[-1].strip():
            out.pop()
        s["output"] = out[:max_out] + ([f"… {len(out) - max_out} more lines"] if len(out) > max_out else [])
    return steps


def selftest_total(output: str) -> int:
    """The number of questions in `kube-noob selftest` output ("kube-noob self-test: 63/63 passed")."""
    m = re.search(r"self-test: \d+/(\d+) passed", output)
    if not m:
        raise SystemExit(f"unexpected `kube-noob selftest` output: {output[:200]!r}")
    return int(m.group(1))


def walkthrough() -> list[dict[str, Any]]:
    scenes: list[dict[str, Any]] = [
        {"id": n, "chapter": title, "steps": parse_transcript(_run("demo", n), keep)} for n, title, keep in CHAPTERS
    ]
    selftest = _run("selftest")
    scenes.append(
        {
            "id": "selftest",
            "chapter": "7. Check it yourself",
            "steps": [
                {
                    "caption": f"{selftest_total(selftest)} real questions across Kubernetes, Helm, OpenShift 4.22, "
                    "ROSA HCP and RHACS",
                    "command": "kube-noob selftest",
                    "output": selftest.splitlines(),
                }
            ],
        }
    )
    return scenes


def _wrap(text: str, width: int = 100) -> list[str]:
    lines: list[str] = []
    for para in text.splitlines():
        lines.extend(textwrap.wrap(para, width) or [""])
    return lines


def _tool_summary(name: str, result: dict[str, Any]) -> list[str]:
    if name.endswith("audit_manifests"):
        c = result["summary"]["counts"]
        lines = [f"score {result['summary']['score']}/100 | high={c['high']} medium={c['medium']} low={c['low']}"]
        for f in [f for f in result["findings"] if f["severity"] in {"critical", "high"}][:4]:
            lines.append(f"[{f['severity'].upper():8}] {f['ruleId']} line {f['line']}: {f['message']}")
        return lines
    if name.endswith("fix_manifests"):
        lines = [f"{len(result['changes'])} safe fixes; score {result['after']['score']}/100 after"]
        lines += [f"  + {ch['path']}: {ch['reason']}" for ch in result["changes"][:5]]
        lines += [f"  left for a human: {m[:90]}" for m in result.get("manualFollowUps", [])[:2]]
        return lines
    return _wrap(json.dumps(result)[:400])


def mcp(stream: Path) -> list[dict[str, Any]]:
    rows = [json.loads(line) for line in stream.read_text().splitlines() if line.strip()]
    init = next(r for r in rows if r.get("type") == "system" and r.get("subtype") == "init")
    server = next(s for s in init["mcp_servers"] if "kube-noob" in s["name"])
    # stream-json does not echo the prompt; `claude -p` sessions recorded for a video keep it in <name>.prompt.txt
    prompt_file = stream.with_suffix(".prompt.txt")
    if not prompt_file.is_file():
        raise SystemExit(f"write the prompt you gave claude -p to {prompt_file}")
    prompt = prompt_file.read_text().strip()
    calls: dict[str, dict[str, Any]] = {}
    tool_steps: list[dict[str, Any]] = []
    answer = ""
    for r in rows:
        content = r.get("message", {}).get("content") if r.get("type") in {"assistant", "user"} else None
        if not isinstance(content, list):
            continue
        for c in content:
            if r["type"] == "assistant" and c.get("type") == "tool_use" and "kube-noob" in c["name"]:
                calls[c["id"]] = c
            elif r["type"] == "assistant" and c.get("type") == "text":
                answer = c["text"]
            elif r["type"] == "user" and c.get("type") == "tool_result" and c.get("tool_use_id") in calls:
                call = calls[c["tool_use_id"]]
                raw = (
                    c["content"] if isinstance(c["content"], str) else "".join(x.get("text", "") for x in c["content"])
                )
                tool = call["name"].split("__")[-1]
                args = {k: v for k, v in call["input"].items() if k != "manifests"}
                tool_steps.append(
                    {
                        "caption": "Claude calls kube-noob: deterministic rules, no model inside",
                        "prompt": "tool ›",
                        "command": f"{tool}({', '.join(f'{k}={v!r}' for k, v in args.items())})",
                        "output": _tool_summary(tool, json.loads(raw)),
                    }
                )
    # The prose part of the answer (before any YAML), without Markdown markup.
    prose = answer.split("```")[0]
    prose = "\n".join(ln for ln in prose.splitlines() if not ln.lstrip().startswith("## Fixed"))
    prose = prose.replace("**", "").replace("`", "").replace("## ", "")
    answer_lines = _wrap(prose.strip())
    return [
        {
            "id": "connect",
            "chapter": "1. The plugin starts kube-noob on your machine",
            "steps": [
                {
                    "caption": "Claude Code loads the plugin; its MCP server runs locally from the bundled source",
                    "command": "/plugin install kube-noob@kube-noob",
                    "output": [
                        f"MCP server {server['name']}: {server['status']}",
                        "web access: off   cluster access: off   model calls: none",
                    ],
                }
            ],
        },
        {
            "id": "ask",
            "chapter": "2. Ask in your own words",
            "steps": [
                {"caption": "A Deployment that works on a laptop", "prompt": "you ›", "command": prompt, "output": []}
            ],
        },
        {"id": "tools", "chapter": "3. Claude calls kube-noob's tools", "steps": tool_steps},
        {
            "id": "answer",
            "chapter": "4. Claude explains, citing rule ids",
            "steps": [
                {
                    "caption": "The answer comes from the rules kube-noob returned",
                    "prompt": "Claude ›",
                    "command": answer_lines[0] if answer_lines else "",
                    "output": answer_lines[1:22],
                }
            ],
        },
        {
            "id": "who",
            "chapter": "5. Who did what",
            "steps": [
                {
                    "caption": "No AI inside kube-noob: the model is Claude; the checks are kube-noob's",
                    "prompt": "#",
                    "command": "this session",
                    "output": [
                        f"model:     {init.get('model', 'Claude')} (Anthropic), reading your prompt and writing the answer",
                        f"kube-noob: {len(tool_steps)} tool calls, rules and fixes computed on your machine",
                        "network:   kube-noob made none (web off); your prompt went to Claude as in any chat",
                    ],
                }
            ],
        },
    ]


def sidecar(transcript: Path) -> list[dict[str, Any]]:
    steps = parse_transcript(transcript.read_text(), 18)
    chapters = [
        ("1. Check it, then deploy it next to your app", steps[:3]),
        ("2. The app calls kube-noob on 127.0.0.1", steps[3:5]),
        ("3. Private, small and locked down", steps[5:]),
    ]
    return [{"id": f"s{i}", "chapter": t, "steps": s} for i, (t, s) in enumerate(chapters) if s]


def write(out_dir: Path, name: str, scenes: list[dict[str, Any]], meta: dict[str, Any]) -> Path:
    narration = out_dir / "narration.json"  # written by audio_kit.py narrate: hold each scene until its line ends
    credit = MUSIC_CREDIT
    if narration.is_file():
        info = json.loads(narration.read_text())
        meta = {**meta, "minMs": {scene_id: line["minMs"] for scene_id, line in info["lines"].items()}}
        credit = info["credit"]
    # The end card stays long enough to be a YouTube chapter (10 s) and to carry YouTube's end screen (5-20 s).
    hold = meta.get("minMs", {})
    meta = {**meta, "minMs": {**hold, "end": max(END_CARD_MS, hold.get("end", 0))}}
    version = _run("--version").split()[-1] if "{version}" in meta["titleSub"] else ""
    meta = {**meta, "titleSub": meta["titleSub"].format(version=version), "credit": f"{LICENSE_CREDIT} · {credit}"}
    html = (
        (HERE / "player.html")
        .read_text()
        .replace("__SCENES__", json.dumps(scenes))
        .replace("__META__", json.dumps(meta))
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}.html"
    path.write_text(html)
    return path


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "walkthrough":
        print(write(Path(argv[1]), "walkthrough", walkthrough(), WALKTHROUGH_META))
    elif len(argv) == 3 and argv[0] == "mcp":
        print(write(Path(argv[2]), "mcp", mcp(Path(argv[1])), MCP_META))
    elif len(argv) == 3 and argv[0] == "sidecar":
        print(write(Path(argv[2]), "sidecar", sidecar(Path(argv[1])), SIDECAR_META))
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
