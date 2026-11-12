"""The example files the README and the docs name as ``examples/...``: ``kube-noob examples list`` and ``copy``.

They ship inside the wheel (``kube_noob/data/examples``), but a command line names a path on disk, so after a brew
or uv install ``-f examples/netpol-admin-tiers.yaml`` answered "No such file or directory" (G277). ``copy`` writes
them to a directory the user names. It refuses to replace a file unless asked, never writes through a symbolic link
(the target directory is the user's; what is inside it is checked file by file), checks every file before writing
any, and creates files with the permissions the umask gives any new file. Same install, same bytes.
"""

from __future__ import annotations

import contextlib
import errno
import os
import secrets
import stat
import unicodedata
from pathlib import Path
from typing import Any

from kube_noob.errors import ConfigError, KubeNoobError

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
    """The examples were not written as asked (a target exists, is a link or is not a file); nothing was written."""


class ExamplesWriteError(KubeNoobError):
    """Writing failed part way (a full disk, a permission); every file this run wrote has been removed again."""


def _source() -> Path:
    from kube_noob.demo import examples_dir

    return examples_dir()


def names() -> list[str]:
    """The bundled example files, sorted."""
    return sorted(p.name for p in _source().iterdir() if p.is_file() and not p.is_symlink())


def listing() -> list[dict[str, Any]]:
    return [{"name": n, "what": DESCRIPTIONS.get(n, "")} for n in names()]


def _check_dest(dest: Path) -> None:
    text = str(dest)
    if any(unicodedata.category(c) == "Cc" for c in text):
        raise ExamplesError("the directory name holds a control character (a newline, a tab, an escape); pick another")
    for p in (dest, *dest.parents):  # `demo --keep LINK` writes LINK/examples: a dangling parent is the same refusal
        if p.is_symlink() and not p.exists():
            raise ExamplesError(f"{p} is a symbolic link to nothing; name a directory")
    if dest.exists() and not dest.is_dir():
        raise ExamplesError(f"{text} exists and is not a directory")


def _write_temp(dest: Path, name: str, data: bytes) -> Path:
    """``data`` in a new file beside the target, under a name no one can predict; the umask sets its mode."""
    tmp = dest / f".{name}.{secrets.token_hex(8)}.kube-noob-tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o666)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return tmp


def _place(tmp: Path, target: Path, replace: bool) -> None:
    """Move ``tmp`` to ``target``: replacing a regular file only when ``replace``; never through a link."""
    if replace:
        os.replace(tmp, target)  # replaces the name itself; a link put there meanwhile is replaced, not followed
        return
    try:
        os.link(tmp, target)  # fails if anything now has that name: no check-then-write race
    except OSError as exc:
        if exc.errno not in {errno.EPERM, errno.ENOTSUP, errno.EXDEV, errno.EOPNOTSUPP, errno.EMLINK}:
            raise
        if os.path.lexists(target):  # a file system without hard links: check, then rename
            raise FileExistsError(errno.EEXIST, "appeared while copying", str(target)) from exc
        os.rename(tmp, target)
        return
    tmp.unlink()


def copy_report(dest: Path, overwrite: bool = False) -> dict[str, list[Path]]:
    """Write every bundled example into ``dest`` (created if missing). Returns ``written`` (new or replaced) and
    ``present`` (already there, byte for byte, so left alone: running it twice is not an error).

    Every target is checked before any is written: a symbolic link is refused even with ``overwrite``, and so is
    anything that is not a regular file; a file that differs is refused unless ``overwrite``. Files are written to
    unpredictable temporary names first and moved into place only when all of them were written, and a failure
    part way removes what this run wrote, so "nothing was written" is true when it is said.
    """
    _check_dest(dest)
    src = _source()
    problems: list[str] = []
    plan: list[tuple[str, bytes, bool]] = []  # name, bytes, replaces an existing file
    present: list[Path] = []
    for name in names():
        target = dest / name
        data = (src / name).read_bytes()
        try:
            st = target.lstat()
        except FileNotFoundError:
            plan.append((name, data, False))
            continue
        except OSError as exc:
            raise ExamplesError(f"{target}: {exc.strerror or exc}; nothing was written") from exc
        if stat.S_ISLNK(st.st_mode):
            problems.append(f"{target} is a symbolic link; it is never written through")
        elif not stat.S_ISREG(st.st_mode):
            problems.append(f"{target} exists and is not a regular file")
        elif st.st_size == len(data) and target.read_bytes() == data:
            present.append(target)
        elif not overwrite:
            problems.append(f"{target} exists and differs")
        else:
            plan.append((name, data, True))
    if problems:
        more = "; pass --force to replace files that differ" if any(p.endswith(" differs") for p in problems) else ""
        raise ExamplesError("nothing was written: " + "; ".join(problems) + more)
    if not plan:
        return {"written": [], "present": present}
    made = not dest.exists()
    temps: list[tuple[Path, Path, bool]] = []
    placed: list[tuple[Path, bool]] = []
    try:
        dest.mkdir(parents=True, exist_ok=True)
        for name, data, replaces in plan:
            temps.append((_write_temp(dest, name, data), dest / name, replaces))
        for tmp, target, replaces in temps:
            _place(tmp, target, replaces)
            placed.append((target, replaces))
    except OSError as exc:
        for tmp, _, _ in temps:
            tmp.unlink(missing_ok=True)
        replaced = [t.name for t, r in placed if r]
        for target, replaces in placed:
            if not replaces:
                target.unlink(missing_ok=True)
        if made:
            with contextlib.suppress(OSError):
                dest.rmdir()
        detail = f"{exc.strerror or exc}" + (f" ({exc.filename})" if getattr(exc, "filename", None) else "")
        tail = f"; already replaced and not restorable: {', '.join(replaced)}" if replaced else "; nothing was written"
        raise ExamplesWriteError(f"copying the examples to {dest} failed: {detail}{tail}") from exc
    return {"written": sorted(t for t, _ in placed), "present": present}


def copy(dest: Path, overwrite: bool = False) -> list[Path]:
    """Every example's path in ``dest`` after ``copy_report``: written now or already there, sorted."""
    r = copy_report(dest, overwrite)
    return sorted([*r["written"], *r["present"]])
