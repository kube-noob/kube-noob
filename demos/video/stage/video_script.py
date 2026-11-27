"""One animated video's script from videos.json, checked against videos.schema.json, with every {fact} and @recording
filled from the code (../facts.py). voiceover.py speaks and times it; the tests load it without the voice."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import jsonschema

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import facts as vfacts  # noqa: E402

TEXT_FIELDS = ("caption", "vo", "say", "bubble")


def names() -> list[str]:
    """The videos videos.json defines, in its own order. The one list; see `voiceover.py` for why."""
    return list(json.loads((HERE / "videos.json").read_text(encoding="utf-8"))["videos"])


def load(video: str, facts: vfacts.Facts) -> dict[str, Any]:
    """One video from videos.json, checked against videos.schema.json, with every {fact} and @recording filled in."""
    spec = json.loads((HERE / "videos.json").read_text(encoding="utf-8"))
    schema = json.loads((HERE / "videos.schema.json").read_text(encoding="utf-8"))
    errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(spec), key=lambda e: list(e.path))
    if errors:
        raise SystemExit("videos.json: " + "; ".join(f"{e.json_path}: {e.message}" for e in errors[:5]))
    if video not in spec["videos"]:
        raise SystemExit(f"videos.json has no video {video!r}")
    v = json.loads(json.dumps(spec["videos"][video]))
    try:
        v["title"], v["cta"] = facts.fill(v["title"]), facts.fill(v["cta"])
        for s in v["scenes"]:
            for k in TEXT_FIELDS:
                if k in s:
                    s[k] = facts.fill(s[k])
            if "term" in s:
                s["term"] = facts.lines(s["term"])
            if s.get("kind") == "payoff":
                s["payoff"] = facts.payoff()
            if s.get("kind") == "hops":
                s["hops"] = facts.walk(s["walk"])
            if "answer" in s:
                s["answer"] = [facts.fill(a) for a in s["answer"]]
            if "gauge" in s:
                g = s["gauge"]
                g["value"], g["limit"] = float(facts.fill(g["value"])), float(facts.fill(g["limit"]))
                if not 0 < g["value"] <= g["limit"]:
                    raise SystemExit(f"{video} gauge: {g['value']} {g['unit']} is not within its limit {g['limit']}")
    except vfacts.FactError as e:
        raise SystemExit(f"{video}: {e}") from None
    return v
