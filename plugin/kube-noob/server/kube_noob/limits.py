"""How much manifest text one run reads, and the one refusal for more.

Two limits, because there are two kinds of caller. A request to the MCP server or a REST route carries its
manifests in the request body, so its cap (``MAX_REQUEST_CHARS``) is a request-size guard. A command line reads
files that are already on the machine, and its cap (``MAX_LOCAL_BYTES``) only has to keep one run bounded. They
were the same number, so `kube-noob audit -f rendered.yaml` refused every chart that ships its CRDs as templates:
four of the 25 charts in ``bench/charts.yaml`` render to more than a megabyte (G447).

``MAX_LOCAL_BYTES`` is measured, not guessed. The largest of those four, kyverno 3.10.0, renders to 5,916,202
bytes (``helm template bench <chart> --namespace bench --kube-version 1.35.0``); argo-cd 10.20.0 to 2,133,868,
external-secrets 2.15.0 to about 2,044,000 and cloudnative-pg 0.29.2 to 1,307,969. Sixteen million bytes is 2.7
times the largest. It stays a bound a laptop meets: `kube-noob audit` on 15,274,241 bytes of those renders took
53 seconds and `verify` 103, and no command used more than 361 MB.

The request cap is the default everywhere. Only the command line asks for the local one (``local_files``), and
``tool_runner.call`` -- the one door the MCP tools, the REST routes and the Agent Skill go through -- sets the
request cap again whatever its caller holds, so a server started from the command line accepts what it always did.

Over either limit nothing is read: the answer is ``InputTooLarge``, one line with the size, the limit and what to
do. A size cap that cuts the text instead would audit the objects before the cut and say nothing of the rest.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from contextvars import ContextVar
from typing import Any

from pydantic import GetCoreSchemaHandler, GetJsonSchemaHandler
from pydantic_core import core_schema

from kube_noob.errors import InputTooLarge

#: Characters of manifest text in one MCP or REST argument.
MAX_REQUEST_CHARS = 1_000_000
#: UTF-8 bytes of manifest text one command-line run reads, from every file together.
MAX_LOCAL_BYTES = 16_000_000

_REQUEST, _LOCAL, _DEFERRED = "request", "local", "deferred"
_MODE: ContextVar[str] = ContextVar("kube_noob_input_limit", default=_REQUEST)


@contextmanager
def _mode(value: str) -> Iterator[None]:
    token = _MODE.set(value)
    try:
        yield
    finally:
        _MODE.reset(token)


def local_files() -> AbstractContextManager[None]:
    """Inside: manifest text was read from this machine's own files, so ``MAX_LOCAL_BYTES`` applies."""
    return _mode(_LOCAL)


def request() -> AbstractContextManager[None]:
    """Inside: the text arrived in a request, so ``MAX_REQUEST_CHARS`` applies whatever the caller had set."""
    return _mode(_REQUEST)


def deferred() -> AbstractContextManager[None]:
    """Inside: ``Sized`` fields are not measured, because the same arguments are about to be validated again by
    the tool's own model under ``request``. For the MCP SDK's copy of a tool's arguments only: the SDK reports a
    validator that raises anything but a ValidationError as a crash with no message, so the refusal has to come
    from ``tool_runner.call``, where it reaches the client as the one line it is."""
    return _mode(_DEFERRED)


def is_local() -> bool:
    return _MODE.get() == _LOCAL


def utf8_len(text: str) -> int:
    """The size of ``text`` in UTF-8 bytes; a lone surrogate counts as the one byte it is replaced with."""
    return len(text) if text.isascii() else len(text.encode("utf-8", errors="replace"))


def too_large_local(size: int, what: str = "the input", limit: int | None = None) -> InputTooLarge:
    """The refusal for local files that are ``size`` bytes together."""
    return InputTooLarge(
        f"{what} is {size:,} bytes and one run reads at most {limit or MAX_LOCAL_BYTES:,}, so none of it was audited: "
        "split it into smaller files and audit each, or audit the chart by part "
        "(`helm template <release> <chart> --show-only templates/<file>` for each template)"
    )


def too_large_request(size: int, what: str = "the input") -> InputTooLarge:
    """The refusal for a request argument of ``size`` characters."""
    return InputTooLarge(
        f"{what} is {size:,} characters and one request carries at most {MAX_REQUEST_CHARS:,}, so none of it was "
        "audited: split it into several calls, or audit the chart by part (one template or one group of objects "
        f"per call); `kube-noob audit -f <file>` on the machine that has the files reads up to {MAX_LOCAL_BYTES:,} "
        "bytes"
    )


def check(text: str, what: str = "the input", *, local_allowed: bool = True) -> str:
    """``text`` unchanged, or ``InputTooLarge``. Never a shorter text: a cut is an object nobody read."""
    mode = _MODE.get()
    if mode == _DEFERRED:
        return text
    if local_allowed and mode == _LOCAL:
        # Characters never outnumber bytes, so most inputs are decided without encoding them.
        if len(text) > MAX_LOCAL_BYTES or (len(text) * 4 > MAX_LOCAL_BYTES and utf8_len(text) > MAX_LOCAL_BYTES):
            raise too_large_local(utf8_len(text))
        return text
    if len(text) > MAX_REQUEST_CHARS:
        raise too_large_request(len(text), what)
    return text


class Sized:
    """Annotation for a model field that holds manifest text: ``Annotated[str, Sized("manifests")]``.

    It replaces ``max_length``. pydantic's own length check answered with a ValidationError, which every surface
    printed whole: four lines, a slice of the caller's input and a link to pydantic's documentation. This check
    raises ``InputTooLarge`` instead -- not a ValueError, so pydantic passes it through untouched and each surface
    reports it as it reports any refusal. The JSON schema still says ``maxLength``, so what an MCP client is told
    has not changed.

    ``local=False`` is for text that is not manifests (a Containerfile, a receipt, an answer to an exercise):
    the same clean refusal, and the request cap on every surface.
    """

    def __init__(self, what: str, *, local: bool = True) -> None:
        self.what, self.local = what, local

    def _check(self, value: str) -> str:
        return check(value, f"`{self.what}`", local_allowed=self.local)

    def __get_pydantic_core_schema__(self, source: Any, handler: GetCoreSchemaHandler) -> core_schema.CoreSchema:
        return core_schema.no_info_after_validator_function(self._check, handler(source))

    def __get_pydantic_json_schema__(self, schema: core_schema.CoreSchema, handler: GetJsonSchemaHandler) -> Any:
        out = handler(schema)
        out["maxLength"] = MAX_REQUEST_CHARS
        return out
