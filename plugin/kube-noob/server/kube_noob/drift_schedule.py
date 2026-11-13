"""The daily drift report job of ``kube-noob serve`` (``posture.reportEnabled``). Kept apart from kube_noob.drift so
the Claude plugin, which ships drift for the ``posture_report`` tool, does not ship the scheduler."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kube_noob.drift import collect_live, snapshot, write_report


def start_background(settings: Any, rng: Any = None) -> Any:
    """``kube-noob serve`` with ``posture.reportEnabled``: one report a day, the first after a random delay."""
    import logging
    import random
    import threading

    from kube_noob.debug.cluster import get_backend
    from kube_noob.sources.pacing import jittered_interval, start_delay

    log = logging.getLogger("kube_noob.drift")
    stop = threading.Event()
    r = rng or random.Random()  # noqa: S311 - pacing, not crypto
    first = start_delay(r)
    state_dir = Path(settings.data_dir) / "posture"

    def loop() -> None:
        if stop.wait(first):
            return
        while not stop.is_set():
            try:
                objects, not_read = collect_live(get_backend(settings), list(settings.posture.namespaces))
                snap = snapshot(
                    objects,
                    source="live",
                    platform=settings.default_platform or "kubernetes",
                    not_read=not_read,
                )
                report, _ = write_report(state_dir, snap, settings.posture.keep)
                f = report["findings"]
                log.info(
                    "posture report: %d changed, %d added, %d removed; %d new and %d fixed findings%s",
                    len(report["objects"]["changed"]),
                    len(report["objects"]["added"]),
                    len(report["objects"]["removed"]),
                    len(f["new"]),
                    len(f["fixed"]),
                    f"; {len(not_read)} not read ({'; '.join(not_read[:3])})" if not_read else "",
                )
            except Exception:  # one failed run must not stop the service
                log.exception("posture report failed")
            stop.wait(jittered_interval(24 * 3600, r))

    threading.Thread(target=loop, name="kube-noob-posture-report", daemon=True).start()
    stop.first_delay = first  # type: ignore[attr-defined]
    return stop
