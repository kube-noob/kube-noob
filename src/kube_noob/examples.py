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
    from kube_noob.sanitize import visible

    text = str(dest)
    if visible(text) != text:
        raise ExamplesError(
            "the directory name holds a control or invisible character (a newline, an escape, a bidi or zero-width "
            "character); pick a name that shows as it is"
        )
    for p in (dest, *dest.parents):  # `demo --keep LINK` writes LINK/examples: a dangling parent is the same refusal
        if p.is_symlink() and not p.exists():
            raise ExamplesError(f"{p} is a symbolic link to nothing; name a directory")
    if dest.exists() and not dest.is_dir():
        raise ExamplesError(f"{text} exists and is not a directory")


_FLAGS_DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _NOFOLLOW
# A file system without hard links answers one of these; the file is then renamed into place after a check.
_NO_LINKS = frozenset({errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EXDEV, errno.EMLINK, errno.ENOSYS})


def _write_temp(dir_fd: int, name: str, data: bytes) -> str:
    """``data`` in a new file beside the target, under a name no one can predict; the umask sets its mode."""
    tmp = f".{name}.{secrets.token_hex(8)}.kube-noob-tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o666, dir_fd=dir_fd)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp, dir_fd=dir_fd)
        raise
    return tmp


def _exists(dir_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _place(dir_fd: int, tmp: str, name: str, replace: bool) -> None:
    """Move ``tmp`` to ``name`` inside the directory already opened: replacing a regular file only when
    ``replace``; never through a link, and never into a directory swapped in after the check."""
    if replace:
        os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        return
    try:
        os.link(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)  # fails if the name exists
    except OSError as exc:
        if exc.errno not in _NO_LINKS:
            raise
        if _exists(dir_fd, name):
            raise FileExistsError(errno.EEXIST, "appeared while copying", name) from exc
        os.rename(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        return
    os.unlink(tmp, dir_fd=dir_fd)


def _read(dir_fd: int, name: str, size: int) -> bytes:
    fd = os.open(name, os.O_RDONLY | _NOFOLLOW, dir_fd=dir_fd)
    with os.fdopen(fd, "rb") as fh:
        return fh.read(size + 1)


def copy_report(dest: Path, overwrite: bool = False) -> dict[str, list[Path]]:
    """Write every bundled example into ``dest`` (created if missing). Returns ``written`` (new or replaced) and
    ``present`` (already there, byte for byte, so left alone: running it twice is not an error).

    The directory is opened once, without following a link, and every check, write and rename happens relative to
    that open directory, so a directory swapped for a link after the check is not followed. Every target is checked
    before any is written: a symbolic link is refused even with ``overwrite``, and so is anything that is not a
    regular file; a file that differs is refused unless ``overwrite``. Files go to unpredictable temporary names
    first and are moved into place only when all were written; any failure -- a full disk, Ctrl-C -- removes what
    this run wrote before it is reported, so "nothing was written" is true when it is said.
    """
    _check_dest(dest)
    src = _source()
    made = not os.path.lexists(dest)
    try:
        dest.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ExamplesWriteError(f"cannot create {dest}: {exc.strerror or exc}; nothing was written") from exc
    try:
        dir_fd = os.open(dest, _FLAGS_DIR)
    except OSError as exc:
        raise ExamplesError(
            f"{dest} cannot be opened as a directory without following a link ({exc.strerror or exc}); "
            "name the directory itself"
        ) from exc
    try:
        return _copy_into(dir_fd, dest, src, overwrite, made)
    finally:
        os.close(dir_fd)


def _copy_into(dir_fd: int, dest: Path, src: Path, overwrite: bool, made: bool) -> dict[str, list[Path]]:
    problems: list[str] = []
    plan: list[tuple[str, bytes, bool]] = []  # name, bytes, replaces an existing file
    present: list[Path] = []
    for name in names():
        data = (src / name).read_bytes()
        try:
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            plan.append((name, data, False))
            continue
        except OSError as exc:
            raise ExamplesError(f"{dest / name}: {exc.strerror or exc}; nothing was written") from exc
        if stat.S_ISLNK(st.st_mode):
            problems.append(f"{dest / name} is a symbolic link; it is never written through")
        elif not stat.S_ISREG(st.st_mode):
            problems.append(f"{dest / name} exists and is not a regular file")
        elif st.st_size == len(data) and _read(dir_fd, name, len(data)) == data:
            present.append(dest / name)
        elif not overwrite:
            problems.append(f"{dest / name} exists and differs")
        else:
            plan.append((name, data, True))
    if problems:
        _forget(dest, made)
        more = "; pass --force to replace files that differ" if any(p.endswith(" differs") for p in problems) else ""
        raise ExamplesError("nothing was written: " + "; ".join(problems) + more)
    temps: list[tuple[str, str, bool]] = []
    placed: list[tuple[str, bool]] = []
    try:
        for name, data, replaces in plan:
            temps.append((_write_temp(dir_fd, name, data), name, replaces))
        for tmp, name, replaces in temps:
            _place(dir_fd, tmp, name, replaces)
            placed.append((name, replaces))
    except BaseException as exc:  # a full disk, a permission, or Ctrl-C: undo this run, then report or re-raise
        for tmp, _, _ in temps:
            with contextlib.suppress(OSError):
                os.unlink(tmp, dir_fd=dir_fd)
        for name, replaces in placed:
            if not replaces:
                with contextlib.suppress(OSError):
                    os.unlink(name, dir_fd=dir_fd)
        _forget(dest, made)
        if not isinstance(exc, OSError):
            raise
        replaced = [n for n, r in placed if r]
        detail = f"{exc.strerror or exc}" + (f" ({exc.filename})" if getattr(exc, "filename", None) else "")
        tail = f"; already replaced and not restorable: {', '.join(replaced)}" if replaced else "; nothing was written"
        raise ExamplesWriteError(f"copying the examples to {dest} failed: {detail}{tail}") from exc
    return {"written": sorted(dest / n for n, _ in placed), "present": present}


def _forget(dest: Path, made: bool) -> None:
    """Remove the directory this run created, if it is still empty."""
    if made:
        with contextlib.suppress(OSError):
            dest.rmdir()


def copy(dest: Path, overwrite: bool = False) -> list[Path]:
    """Every example's path in ``dest`` after ``copy_report``: written now or already there, sorted."""
    r = copy_report(dest, overwrite)
    return sorted([*r["written"], *r["present"]])
