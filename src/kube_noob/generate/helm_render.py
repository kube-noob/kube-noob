"""Render a Helm chart with the `helm` binary and audit the output (``kube-noob helm-audit`` and the gate).

Kept apart from ``kube_noob.generate.helm`` so the Claude plugin, which offers chart generation and the metadata lint
but never renders with `helm`, ships no subprocess call (``scripts/sync_plugin_server.py`` leaves this module out).
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from kube_noob.audit.engine import analyze
from kube_noob.audit.model import Report
from kube_noob.errors import KubeNoobError
from kube_noob.generate.helm import lint_chart_metadata

#: Rendered output larger than this is not read: a chart is not supposed to be a 5 MB bundle, and the audit after it
#: has to finish inside a hook's time budget.
MAX_RENDERED = 5_000_000
MAX_CHART_FILES = 5_000


def project_root(start: Path) -> Path:
    """The tree under review that holds ``start``: the nearest directory with a `.git` above it, else ``start``."""
    start = start.resolve()
    for d in [start, *start.parents]:
        if (d / ".git").exists():
            return d
    return start


def helm_binary(project: Path | None = None) -> str | None:
    """The `helm` on PATH, looked up only in absolute PATH entries outside the project tree.

    `shutil.which("helm")` honoured a relative PATH entry (`bin`, `.`) and so ran a `helm` the checked-out
    repository supplies -- a program from the tree under review, run by the tool reviewing it (G280). The tree is
    the project's (its git root, else the directory itself), never just "wherever the command runs": with the
    working directory at $HOME or `/`, excluding everything under it excluded every helm on the machine. A tree that
    IS $HOME or `/` excludes nothing, because it is the machine, not a repository."""
    import os

    root = project_root(project if project is not None else Path.cwd())
    broad = {Path("/"), Path.home().resolve()}
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            continue
        p = Path(entry).resolve()
        if root not in broad and (p == root or p.is_relative_to(root)):
            continue
        found = shutil.which("helm", path=str(p))
        if found:
            return found
    return None


def chart_problem(chart: Path, root: Path | None = None) -> str | None:
    """Why a chart directory is not rendered: a symbolic link anywhere in it (helm would follow it out of the
    tree), more than 5,000 files, or a directory outside ``root``."""
    import os

    chart = Path(chart)
    if root is not None and not chart.resolve().is_relative_to(root.resolve()):
        return "the chart is outside the working directory"
    count = 0
    for dirpath, dirnames, filenames in os.walk(chart, followlinks=False):
        for name in [*dirnames, *filenames]:
            count += 1
            if count > MAX_CHART_FILES:
                return f"the chart has more than {MAX_CHART_FILES} files"
            if Path(dirpath, name).is_symlink():
                return f"{Path(dirpath, name).relative_to(chart)} is a symbolic link; helm would follow it"
    return None


def kube_version_arg(platform: str, version: str | None) -> str | None:
    """The Kubernetes version to pass to ``helm template --kube-version``, or None when the caller named none.

    An OpenShift version is mapped with the table the removed-API checks already use. No version means no flag:
    Helm's own default (v1.20 on Helm 4.0.0) must not be replaced with one kube-noob invented.
    """
    if not version:
        return None
    from kube_noob.catalog import k8s_version_for

    try:
        minor = k8s_version_for(platform, version)
    except ValueError:
        return None
    return minor if minor.count(".") >= 2 else f"{minor}.0"


def render_chart(
    chart_dir: str | Path,
    values_files: list[str] | None = None,
    namespace: str = "default",
    release: str = "release",
    timeout: float = 60.0,
    kube_version: str | None = None,
    set_values: list[tuple[str, str]] | None = None,
    project: Path | None = None,
) -> str:
    """``set_values``: (flag, value) pairs for --set, --set-string, --set-json or --set-literal, passed as argv.
    ``project``: the tree under review; a `helm` inside it is never run, and a chart with a link in it is refused."""
    helm = helm_binary(project)
    if helm is None:
        raise KubeNoobError(
            "The `helm` binary is not on PATH (absolute PATH entries outside the working directory only); install "
            "Helm 3.8+ to render charts (https://helm.sh/docs/intro/install/)."
        )
    chart = Path(chart_dir)
    if not (chart / "Chart.yaml").is_file():
        raise KubeNoobError(f"{chart} is not a chart directory (no Chart.yaml)")
    problem = chart_problem(chart, project)
    if problem:
        raise KubeNoobError(f"{chart}: {problem}")
    args = [helm, "template", release, str(chart), "--namespace", namespace]
    if kube_version:
        args += ["--kube-version", kube_version]
    for vf in values_files or []:
        args += ["--values", vf]
    for flag, value in set_values or []:
        if flag not in {"--set", "--set-string", "--set-json", "--set-literal"} or "\n" in value or "\x00" in value:
            raise KubeNoobError(f"{flag} {value[:40]!r} is not passed to helm")
        args += [flag, value]
    with tempfile.TemporaryDirectory() as home:
        env = {"HELM_CACHE_HOME": home, "HELM_CONFIG_HOME": home, "HELM_DATA_HOME": home, "PATH": "/usr/bin:/bin"}
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env, check=False)
    if proc.returncode != 0:
        raise KubeNoobError(f"helm template failed: {proc.stderr.strip()[:2000]}")
    if len(proc.stdout) > MAX_RENDERED:
        raise KubeNoobError(f"helm template rendered more than {MAX_RENDERED:,} characters; not read")
    return proc.stdout


def audit_chart(
    chart_dir: str | Path,
    platform: str = "kubernetes",
    version: str | None = None,
    values_files: list[str] | None = None,
    namespace: str = "default",
) -> tuple[Report, list[str]]:
    rendered = render_chart(chart_dir, values_files, namespace, kube_version=kube_version_arg(platform, version))
    return analyze(rendered, platform=platform, version=version), lint_chart_metadata(chart_dir)
