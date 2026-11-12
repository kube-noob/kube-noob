"""The example files the README and the docs name as ``examples/...``: ``kube-noob examples list`` and ``copy``.

They ship inside the wheel (``kube_noob/data/examples``), but a command line names a path on disk, so after a brew
or uv install ``-f examples/netpol-admin-tiers.yaml`` answered "No such file or directory" (G277). ``copy`` writes
them to a directory the user names. It refuses to replace a file unless asked, never writes through a symbolic link
(the target directory is the user's; what is inside it is checked file by file), checks every file before writing
any, and creates files with the permissions the umask gives any new file. Same install, same bytes.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from kube_noob.errors import ConfigError

# What each bundled file is for, in one line. tests/test_first_run.py holds the keys equal to the bundled files, so a
# new example cannot ship without saying what it is.
DESCRIPTIONS = {
    "alertmanager-etcd.json": "an Alertmanager webhook for etcd leader changes (diagnose, insight, memory match)",
    "blueprint.yaml": "an application blueprint for the 7-step protocol (protocol --blueprint)",
    "denial-multi.txt": "one Deployment rejected by five admission systems, each in its own words (policy explain)",
    "events-crashloop.txt": "describe output of a pod killed for memory (diagnose, insight)",
    "events-scc.txt": "events of pods rejected by OpenShift SecurityContextConstraints (diagnose, policy explain)",
    "exercise-answer.yaml": "a first attempt at a graded exercise (learn submit)",
    "insecure-deployment.yaml": "a Deployment that runs on a laptop but not on OpenShift (audit, fix)",
    "kube-noob-exceptions.yaml": "a risk-acceptance list with owners and expiry dates (exceptions check, gate)",
    "netpol-admin-tiers.yaml": "AdminNetworkPolicy, NetworkPolicy and BaselineAdminNetworkPolicy tiers (policy reach)",
    "netpol-shop.yaml": "NetworkPolicies and Deployments for a small shop (policy reach)",
    "problems.yaml": "your own problems as test cases with expected answers (selftest --cases)",
}

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class ExamplesError(ConfigError):
    """The examples could not be written as asked; nothing was written."""


def _source() -> Path:
    from kube_noob.demo import examples_dir

    return examples_dir()


def names() -> list[str]:
    """The bundled example files, sorted."""
    return sorted(p.name for p in _source().iterdir() if p.is_file() and not p.is_symlink())


def listing() -> list[dict[str, Any]]:
    return [{"name": n, "what": DESCRIPTIONS.get(n, "")} for n in names()]


def copy(dest: Path, overwrite: bool = False) -> list[Path]:
    """Write every bundled example into ``dest`` (created if missing); returns the paths written, sorted.

    Checks every target before writing any: a symbolic link is refused even with ``overwrite``, and so is anything
    that is not a regular file; an existing file is refused unless ``overwrite``.
    """
    if dest.exists() and not dest.is_dir():
        raise ExamplesError(f"{dest} exists and is not a directory")
    src = _source()
    files = names()
    problems: list[str] = []
    for name in files:
        target = dest / name
        try:
            st = target.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(st.st_mode):
            problems.append(f"{target} is a symbolic link; it is never written through")
        elif not stat.S_ISREG(st.st_mode):
            problems.append(f"{target} exists and is not a regular file")
        elif not overwrite:
            problems.append(f"{target} exists")
    if problems:
        more = "; pass --force to replace existing files" if any(p.endswith(" exists") for p in problems) else ""
        raise ExamplesError("nothing was written: " + "; ".join(problems) + more)
    dest.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name in files:
        target = dest / name
        flags = os.O_WRONLY | os.O_CREAT | _NOFOLLOW | (os.O_TRUNC if overwrite else os.O_EXCL)
        try:
            fd = os.open(target, flags, 0o666)  # the umask decides, as for any file the user creates
        except OSError as exc:  # a link or file that appeared after the check
            raise ExamplesError(f"{target}: {exc.strerror or exc}; stopped after {len(written)} files") from exc
        with os.fdopen(fd, "wb") as fh:
            fh.write((src / name).read_bytes())
        written.append(target)
    return written
