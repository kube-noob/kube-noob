"""Typed access to fields of untrusted YAML, for readers that walk manifests by hand (G276).

A manifest is whatever the user pasted: `spec: 7`, `volumes: x` and `to: [1]` all parse. A reader that assumes the
shape the schema promises raises `TypeError` or `AttributeError` on them, and before G276 that escaped the CLI as exit
1, the code for "findings at or above --fail-on". These accessors make the assumption explicit and fail with ONE
exception type that names the field, so a reader can catch exactly that -- a wrong shape -- and report the object as
not read, without a broad `except` that would also swallow a real bug.

    spec = shape.mapping(obj.get("spec"), f"{ref} spec")        # None -> {}, a dict -> itself, else WrongShape
    for v in shape.sequence(spec.get("volumes"), f"{ref} spec.volumes"):
        ...
"""

from __future__ import annotations

from typing import Any


class WrongShape(ValueError):
    """A field whose value has a type the reader cannot use. The message names the field and what it held."""

    def __init__(self, where: str, want: str, got: Any) -> None:
        super().__init__(f"{where} is {type(got).__name__}, not {want}")
        self.where = where


def mapping(value: Any, where: str) -> dict[str, Any]:
    """``value`` when it is a mapping, ``{}`` when it is absent (None), else ``WrongShape``."""
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    raise WrongShape(where, "a mapping", value)


def sequence(value: Any, where: str) -> list[Any]:
    """``value`` when it is a list, ``[]`` when it is absent (None), else ``WrongShape``."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    raise WrongShape(where, "a list", value)


def scalar(value: Any, where: str) -> str | int | float | bool | None:
    """``value`` when it is a string, number, boolean or None (anything hashable a lookup can use), else
    ``WrongShape``."""
    if value is None or isinstance(value, str | int | float | bool):
        return value
    raise WrongShape(where, "a string or number", value)
