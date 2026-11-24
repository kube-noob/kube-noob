#!/usr/bin/env python3
"""Voice-over, music and timing for one animated video in videos.json, made locally and for free.

Usage: python voiceover.py <video> <out-dir> [--engine kokoro|piper] [--voice af_heart] [--speed 1.0]
                           [--speaker N] [--music-db -12] [--sidecar <transcript.txt>]

videos.json is checked against videos.schema.json first, and every number and terminal recording in it is filled from
the code (../facts.py); the sidecar video needs the transcript recorded in CI (--sidecar or KN_SIDECAR_TRANSCRIPT).

Writes <out-dir>/timeline.json (scene start times and lengths, read by stage.html), kube-noob-<video>.vtt (captions
from the voice-over timings), the stems voice.wav and music.wav, and audio.wav (48 kHz stereo: the voice-over over
the kube-noob brand music, plus a few sound effects, normalised to the brand loudness). The voice and the music
come from ../audio_kit.py: Kokoro-82M (Apache-2.0) with the af_heart voice by default, downloaded once from GitHub
and hash-checked. To change only the music level later, without rendering the picture
again:
  python demos/video/audio_kit.py remix <out-dir> --music-db -18 --video <out-dir>/kube-noob-<video>.mp4
Needs: python3 with numpy and kokoro-onnx (or piper-tts for --engine piper), and ffmpeg on PATH.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import audio_kit as ak  # noqa: E402
import captions  # noqa: E402
import facts as vfacts  # noqa: E402
from video_script import load, names  # noqa: E402

RATE = ak.RATE
VO_LEAD = 0.45
VO_TAIL = 0.75
FPS = 30


def samples(seconds: float) -> int:
    return round(seconds * RATE)


def tone(freq: float, n: int, harmonics: int) -> np.ndarray:
    t = np.arange(n) / RATE
    return np.asarray(sum(np.sin(2 * np.pi * freq * k * t) / k**1.3 for k in range(1, harmonics + 1)))


def envelope(n: int, attack: float, release: float) -> np.ndarray:
    env = np.ones(n)
    a, r = min(n, int(attack * RATE)), min(n, int(release * RATE))
    if a:
        env[:a] = np.linspace(0, 1, a) ** 2
    if r:
        env[-r:] *= np.linspace(1, 0, r) ** 2
    return env


# ---------------------------------------------------------------- story sound effects


def alarm(total: float, start: float, end: float) -> np.ndarray:
    """The 2 a.m. page in the teaser: a low hum with a repeating beep."""
    n = samples(total)
    out = np.zeros(n)
    a, b = int(start * RATE), min(n, int(end * RATE))
    m = b - a
    t = np.arange(m) / RATE
    hum = tone(55.0, m, 6) * (0.55 + 0.45 * np.sin(2 * np.pi * 1.6 * t) ** 2)
    beep = np.sin(2 * np.pi * 659.25 * t) * ((t % 1.25) < 0.16) * 0.25
    out[a:b] = 0.55 * np.tanh(1.6 * (hum + beep)) * envelope(m, 0.4, 1.2)
    return out


def whoosh(total: float, at: float, length: float = 1.4, seed: int = 3) -> np.ndarray:
    n = samples(total)
    out = np.zeros(n)
    p = int(at * RATE)
    m = min(int(length * RATE), n - p)
    noise = np.random.default_rng(seed).standard_normal(m)
    y = np.zeros(m)
    state = 0.0
    for i in range(m):  # one-pole low-pass whose cutoff sweeps up, then down
        alpha = 0.02 + 0.5 * np.sin(np.pi * i / m) ** 2
        state += alpha * (noise[i] - state)
        y[i] = state
    out[p : p + m] = y * np.sin(np.pi * np.linspace(0, 1, m)) ** 1.5 * 0.9
    return out


def blip(total: float, at: float) -> np.ndarray:
    n = samples(total)
    out = np.zeros(n)
    p = int(at * RATE)
    m = min(int(0.16 * RATE), n - p)
    t = np.arange(m) / RATE
    freq = 880 + 520 * t / 0.16
    out[p : p + m] = np.sin(2 * np.pi * np.cumsum(freq) / RATE) * np.exp(-t * 22) * 0.35
    return out


# ---------------------------------------------------------------- timeline


def build(
    video: str,
    out: Path,
    voice: ak.Voice,
    music_db: float | None,
    facts: vfacts.Facts | None = None,
    spec: dict[str, Any] | None = None,
) -> dict[str, Any]:
    # spec is an already loaded and checked script (compliance.py passes one from its own file); otherwise videos.json.
    v = spec if spec is not None else load(video, facts or vfacts.Facts())
    scenes = [dict(s) for s in v["scenes"]]
    clips = iter([voice.say(s.get("say") or s["vo"]) for s in scenes if s.get("vo")])
    t = 0.0
    vo_track: list[tuple[float, np.ndarray]] = []
    for s in scenes:
        s["start"] = round(t, 3)
        if s.get("vo"):
            clip = next(clips)
            s["voStart"] = VO_LEAD
            s["voDur"] = round(len(clip) / RATE, 3)
            vo_track.append((t + VO_LEAD, clip))
            dur = max(s["min"], VO_LEAD + s["voDur"] + VO_TAIL)
        else:
            dur = s["min"]
        s["dur"] = round(round(dur * FPS) / FPS, 3)
        t += s["dur"]
    total = round(t, 3)
    n = samples(total)

    speech = np.zeros(n)
    for at, clip in vo_track:
        p = int(at * RATE)
        speech[p : p + len(clip)] += clip[: n - p]

    kinds = {s["kind"]: s for s in scenes}
    music_start = 0.0
    story = np.zeros(n)  # sound effects that tell the story
    if "alarm" in kinds:
        d = kinds["dust"]
        story += alarm(total, 0.0, d["start"] + d["dur"] + 0.6)
        music_start = kinds["arrive"]["start"] - 0.2
        story += whoosh(total, kinds["arrive"]["start"] + 0.2)
    if "beam" in kinds:
        story += whoosh(total, kinds["beam"]["start"] + 0.5, 1.1, seed=5)
    if "loopback" in kinds:
        lb = kinds["loopback"]
        for i in range(5):
            story += blip(total, lb["start"] + 1.4 + i * 1.15) * 0.5
    if "explain" in kinds:
        ex = kinds["explain"]
        for i in range(3):
            story += blip(total, ex["start"] + 1.6 + i * 1.3)
    music = ak.business_bed(total, music_start, end_sting=kinds["end"]["start"] + 0.15)[:n]
    # Story effects ride with the voice, so --music-db moves only the music.
    fx = ak.reverb(np.stack([story, np.roll(story, int(0.007 * RATE))], axis=1), 1.4, 0.3) * 0.5
    foreground = np.stack([speech, speech], axis=1) * 0.92 + fx
    ak.write_stems(out, foreground, music, music_db)

    timeline = {
        "video": video,
        "title": v["title"],
        "cta": v["cta"],
        "credit": f"kube-noob is open source (Apache-2.0) · {voice.credit}",
        "fps": FPS,
        "duration": total,
        "scenes": scenes,
    }
    (out / "timeline.json").write_text(json.dumps(timeline, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    # Captions from the same timings: the written line (vo), shown while the voice speaks it.
    cues = [c for s in scenes if s.get("vo") for c in captions.cues(s["vo"], s["start"] + s["voStart"], s["voDur"])]
    captions.write(out / f"kube-noob-{video}.vtt", cues, total)
    return timeline


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    # The video set lives in videos.json. A second copy here meant adding a video left a renderer that could
    # not render it, and `videos.json` is the file the workflow matrix and the tests already read.
    ap.add_argument("video", choices=sorted(names()))
    ap.add_argument("out", type=Path)
    ap.add_argument("--engine", choices=sorted(ak.CREDITS), default="kokoro")
    ap.add_argument("--voice", default=ak.DEFAULT_VOICE, help="Kokoro voice, e.g. af_heart, af_bella, am_michael")
    ap.add_argument("--speed", type=float, default=1.0)
    ap.add_argument("--speaker", type=int, default=ak.PIPER_SPEAKER, help="LibriTTS speaker id for --engine piper")
    ap.add_argument(
        "--music-db",
        type=ak.parse_music_db,
        default=ak.DEFAULT_MUSIC_DB,
        help="music level against the voice in dB (default -12), or off",
    )
    ap.add_argument(
        "--sidecar",
        type=Path,
        help="the sidecar transcript recorded in CI (scripts/demo_sidecar_kind.sh); default $KN_SIDECAR_TRANSCRIPT",
    )
    a = ap.parse_args()
    facts = vfacts.Facts(a.sidecar)
    load(a.video, facts)  # every fact and the schema are checked before the voice model loads
    tl = build(a.video, a.out, ak.Voice(a.engine, a.voice, a.speed, a.speaker), a.music_db, facts)
    print(f"{a.video}: {tl['duration']:.1f} s, {len(tl['scenes'])} scenes -> {a.out}/timeline.json, audio.wav")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
