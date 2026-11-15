"""What the HTTP server lets into memory and into the report slots, and how long it waits for either (G274).

Two bounded resources, each waited for on the event loop and never by blocking a worker thread:

* **Large bodies.** A request body over ``LARGE_BODY_BYTES`` holds a ticket from the moment that many bytes are
  actually in memory until it is handed to its tool -- or, for an Alertmanager report, until it holds a report slot,
  because a report waiting for its slot keeps its whole payload. At most ``MAX_LARGE_BODIES`` tickets exist; a request
  that needs one waits for it until its read deadline and is then answered 503. Counting declared lengths instead let
  eight connections that sent ten bytes each refuse every large post on every route for as long as they trickled.
* **Report slots** (``Toolkit.report_slots``): the reports built at once by the REST receiver and the MCP tool
  together. Taken by polling, because the slots are a thread semaphore the CLI also uses and an event loop must never
  block on one; a worker thread waiting on it for 5 s each stalled every other tool's thread (G274).

A body must arrive within ``READ_SECONDS``: a sender that trickles is answered 408 and holds nothing afterwards.
"""

from __future__ import annotations

import time
from contextvars import ContextVar
from typing import Any

import anyio

#: A body this large is counted while it is in memory.
LARGE_BODY_BYTES = 256 * 1024
#: Large bodies in memory at once, before their tool (or their report slot) takes them.
MAX_LARGE_BODIES = 8
#: How long a request body may take to arrive, including any wait for a large-body ticket.
READ_SECONDS = 10.0
#: What a refusal for want of room tells the sender to wait before it retries.
RETRY_AFTER_SECONDS = 5
POLL_SECONDS = 0.05


class Ticket:
    """One large body's place in memory. Releasing is idempotent: the tool that takes the body releases it, and the
    request's end releases it again in case nothing did."""

    def __init__(self, owner: LargeBodies) -> None:
        self._owner: LargeBodies | None = owner

    def release(self) -> None:
        if self._owner is not None:
            self._owner.in_use -= 1
            self._owner = None

    @property
    def held(self) -> bool:
        return self._owner is not None


class LargeBodies:
    """The large-body tickets of one server. Used only from its event loop, so a plain counter needs no lock."""

    def __init__(self) -> None:
        self.in_use = 0

    async def take(self, wait: float) -> Ticket | None:
        deadline = time.monotonic() + max(wait, 0.0)
        while self.in_use >= MAX_LARGE_BODIES:
            if time.monotonic() >= deadline:
                return None
            await anyio.sleep(POLL_SECONDS)
        self.in_use += 1
        return Ticket(self)


#: The large-body ticket of the request being handled, set by whoever read its body (``http.BodyLimit`` or the REST
#: receiver) so the tool that takes the body can release it (``mcp_app``'s tool wrapper, ``rest``).
CURRENT: ContextVar[Ticket | None] = ContextVar("kube_noob_large_body", default=None)
#: When the request arrived, on the clock a report's time budget is read on (``alert_report._now``).
RECEIVED: ContextVar[float | None] = ContextVar("kube_noob_received", default=None)


def release_current() -> None:
    ticket = CURRENT.get()
    if ticket is not None:
        ticket.release()


async def take_slot(slots: Any, wait: float) -> bool:
    """One of ``slots`` (``alert_report.Slots``) within ``wait`` seconds, polled on the event loop, or False."""
    deadline = time.monotonic() + max(wait, 0.0)
    while not slots.try_acquire():
        if time.monotonic() >= deadline:
            return False
        await anyio.sleep(POLL_SECONDS)
    return True
