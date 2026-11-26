#!/usr/bin/env bash
# Render the animated videos videos.json defines without a video model, for free:
# a Kokoro voice-over, the kube-noob brand music, and Chromium frames of stage.html (the look of the Grok teaser).
#
# Usage: demos/video/stage/build.sh <out-dir> [<a video in videos.json>|all] [--voice af_heart] [--music-db -12]
#        (also --engine piper, --speed, --speaker, --sidecar <transcript>; see voiceover.py)
# Writes <out-dir>/<video>/kube-noob-<video>.mp4 (3840x2160, 30 fps, AAC 320k at -16 LUFS; KN_SCALE=1 for
# 1920x1080) and the stems voice.wav and music.wav. Each video is checked before it renders (videos.schema.json,
# every number filled from the code, the layout rules of capture.js --check) and its sound is measured after
# (audio_kit.py verify). The sidecar video needs the transcript recorded in CI: KN_SIDECAR_TRANSCRIPT=<file>.
# Change only the music level afterwards, without rendering again:
#   python3 demos/video/audio_kit.py remix <out-dir>/<video> --music-db -18 --video <out-dir>/<video>/kube-noob-<video>.mp4
# Needs: python3 with numpy, jsonschema and kokoro-onnx (pip install kokoro-onnx numpy), Node with the playwright
# package and Chromium, and ffmpeg. The first run downloads Kokoro-82M (Apache-2.0) from GitHub, hash-checked.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
if [ $# -lt 1 ]; then
  sed -n '2,14p' "$0"
  exit 2
fi
out="$(mkdir -p "$1" && cd "$1" && pwd)"
which_video="${2:-all}"
shift $(( $# >= 2 ? 2 : 1 ))
# The videos are the ones videos.json defines, read from it: a list written here went stale when #125 added `scan`
# to videos.json and the release matrix, and the release's `render (scan)` leg would have stopped on "unknown
# video: scan" -- on the tag's own copy of this file, so no re-run could fix it (G414).
videos="$("${PYTHON:-python3}" -c 'import json, sys; print(" ".join(json.load(open(sys.argv[1], encoding="utf-8"))["videos"]))' "$here/videos.json")"
case " $videos all " in *" $which_video "*) ;; *) echo "unknown video: $which_video (known: $videos)" >&2; exit 2;; esac
for v in $videos; do
  if [ "$which_video" != all ] && [ "$which_video" != "$v" ]; then
    continue
  fi
  "${PYTHON:-python3}" "$here/voiceover.py" "$v" "$out/$v" "$@"
  node "$here/capture.js" "$out/$v" --check
  node "$here/capture.js" "$out/$v" --scale "${KN_SCALE:-2}"
  "${PYTHON:-python3}" "$here/../audio_kit.py" verify "$out/$v/kube-noob-$v.mp4"
done
