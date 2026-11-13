"""Which installed OLM operators the OpenShift release notes name in a reported issue (R5).

This is a lookup in the release notes, not a vulnerability check, and not a gate on "do my operators have known
issues". What the bundled corpus can support decides what it is. ``kube_noob/data/known_issues`` holds the known and
fixed issues of the OpenShift 4.20-4.22 release notes, one record per issue and release: an issue id, ``kind``, the
OpenShift ``minor`` and ``version``, the release-note text and its source file, and for five records an OpenShift
``fixedIn``. No record carries a component, a package or an operator version (``tests/test_operator_known_issues.py``
and ``scripts/vendor_known_issues.py --check`` both fail if one appears, so the join gets upgraded rather than
ignoring it). On 2026-11-12, 957 records (921 issue ids).

So the join is the one the data can populate, and it says so:

- **Package to name, through an explicit table, in two tiers.** ``ALIASES`` maps an OLM package to the product names
  the release notes use for it (``names``, the strong tier, shown as ``named``) and to component names and
  abbreviations that only that operator's stack uses (``mentions``, the weak tier, shown as ``mentioned``, never
  merged into ``named``). Both are whole phrases, case-sensitive, at word boundaries; a name followed by an API group
  suffix, a path or the word namespace is not the product. A named issue that also names another package, or a
  platform component (``PLATFORM_TERMS``), is demoted to ``mentioned`` with that reason: it is about where the two
  meet, and its fix may be in the platform. "Named" means the notes name the product, not that it is affected.
- **A package with no entry is ``no-alias``; one the inventory could not read is ``package-unknown``.** Neither is
  clean; neither is guessed from the CSV's name. Both count as not matched, and ``allMatched`` is false.
- **Only Red Hat's build is what the notes describe.** The default catalogs are ``redhat-operators`` (Red Hat
  products, built by Red Hat), ``certified-operators`` (ISV builds), ``community-operators`` and the retired
  ``redhat-marketplace`` (openshift-docs a28e76ff ``modules/olm-rh-catalogs.adoc``). An operator from one of the last
  three is ``not-determined``. One from any other catalog -- a mirror, a custom one, or none named -- keeps its
  matches but is ``catalogKind: unknown`` and is not counted as matched, because kube-noob cannot tell its build.
- **Narrowed by the cluster's OpenShift release.** The release is given (``--openshift-version``), or read from the
  ClusterVersion named ``version`` (the newest Completed history entry; if none completed, ``status.desired``, said
  so). Both are read when both exist, and a disagreement is a caveat; the given one wins. An update in progress
  searches both releases and the answer is incomplete, whether or not a version is given. A known issue from an
  earlier indexed release still applies until the fix it lists (``known_issues.Index._applies``, the rule
  ``known-issues`` uses), even when that fix is in a later release, and one with no fix is labelled as listed for that
  release. A cluster whose API does not serve ClusterVersion is not OpenShift, and an OKD version (an ``okd``
  pre-release suffix) is not OpenShift Container Platform: the notes do not apply to either.
- **One list says whether the answer is complete.** ``complete`` is ``not incompleteBecause``, and ``allMatched`` is
  true only for ``matched``: every installed operator looked up, none from an unverified catalog, at least one.
- **A fix is an OpenShift release, never an operator version.** The notes list "fixed in 4.22.3"; they do not say
  whether the fix ships in the payload or in the operator's bundle, so ``installedHasFix`` is ``not-determined``.
  ``fixReleaseVsCluster`` says only whether the listed release is at or before the cluster's version.

Package names were read where a Subscription, a mirror config or the code that subscribes to them names them (the
commit is the citation): openshift/openshift-docs a28e76ff671df01eb6d75f305153dc6a01039c60 ``modules/<file>``, and
openshift/cluster-ingress-operator 8e4c40f161d8341d640659ca2779a4294960c183 (release-4.20).
"""

from __future__ import annotations

import functools
import re
import threading
import weakref
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from kube_noob import operators as ops
from kube_noob import versions
from kube_noob.known_issues import Index, Issue, get_index, vkey

DOCS = "openshift/openshift-docs a28e76ff671df01eb6d75f305153dc6a01039c60 modules/"


@dataclass(frozen=True)
class Alias:
    """The names the release notes use for one package, and where the package name was read. ``names`` are the
    product's names (strong); ``mentions`` are component names and abbreviations only its stack uses (weak);
    ``not_followed_by`` is a pattern after a name that means another product (OpenShift Service Mesh 2.x is not
    ``servicemeshoperator3``)."""

    names: tuple[str, ...]
    source: str
    mentions: tuple[str, ...] = ()
    not_followed_by: str = ""


_OSSM2 = r"(?:\s*\(OSSM\))?\s+(?:version\s+)?2(?![0-9])"

#: package -> the names the release notes use for it. Every name and mention must occur in the bundled corpus and no
#: name may match another package's (tests/test_operator_known_issues.py, scripts/vendor_known_issues.py --check).
#: Words the notes use for the platform feature rather than the OLM operator ("SR-IOV virtual functions", "managed by
#: NMState", "Tekton Pipelines") have no entry. Each mention was checked against every record it hits (2026-11-12).
ALIASES: dict[str, Alias] = {
    "clusterresourceoverride": Alias(
        ("Cluster Resource Override Operator",), DOCS + "nodes-cluster-resource-override-deploy-cli.adoc"
    ),
    "cluster-logging": Alias(("Cluster Logging Operator",), DOCS + "cluster-logging-deploy-cli.adoc"),
    "dpu-operator": Alias(("DPU Operator",), DOCS + "nw-dpu-installing-operator-cli.adoc"),
    "ingress-node-firewall": Alias(
        ("Ingress Node Firewall",), DOCS + "nw-infw-operator-installing-cli.adoc", mentions=("IngressNodeFirewall",)
    ),
    "metallb-operator": Alias(("MetalLB Operator",), DOCS + "nw-metalLB-basic-upgrade-operator.adoc"),
    "multicluster-engine": Alias(
        ("multicluster engine (MCE) for Kubernetes", "multicluster engine for Kubernetes"),
        DOCS + "oc-mirror-image-set-config-examples.adoc (redhat-operator-index packages)",
    ),
    "netobserv-operator": Alias(
        ("Network Observability Operator",),
        DOCS + "troubleshooting-network-observability-controller-manager-pod-out-of-memory.adoc",
    ),
    "numaresources-operator": Alias(
        ("NUMA Resources Operator",), DOCS + "cnf-installing-numa-resources-operator-cli.adoc"
    ),
    "openshift-cert-manager-operator": Alias(("cert-manager",), DOCS + "cert-manager-install-cli.adoc"),
    "openshift-external-secrets-operator": Alias(
        ("External Secrets Operator",), DOCS + "external-secrets-operator-install-cli.adoc"
    ),
    "ptp-operator": Alias(
        ("Precision Time Protocol (PTP) Operator", "PTP Operator"),
        DOCS + "nw-ptp-installing-operator-cli.adoc",
        mentions=("linuxptp-daemon", "cloud-event-proxy", "ts2phc", "phc2sys", "ptp4l", "PTP"),
    ),
    "servicemeshoperator3": Alias(
        ("OpenShift Container Platform Service Mesh", "OpenShift Service Mesh"),
        "openshift/cluster-ingress-operator 8e4c40f161d8341d640659ca2779a4294960c183 "
        "pkg/operator/controller/gatewayclass/subscription.go (Package servicemeshoperator3)",
        mentions=("OSSM", "Istio"),
        not_followed_by=_OSSM2,
    ),
    "vertical-pod-autoscaler": Alias(
        ("Vertical Pod Autoscaler",), DOCS + "nodes-pods-vertical-autoscaler-moving-vpa.adoc"
    ),
}

#: Platform components the release notes name. An issue matched by a product name that also names one of these is
#: shown as a mention: it is where the operator meets the platform (the console installing it, the Cluster Ingress
#: Operator managing its Subscription, Hub RDS creating its resources, FRR-K8s under MetalLB), and the fix may be
#: in the platform. A list of components, not of records.
PLATFORM_TERMS = (
    "Cluster Ingress Operator",
    "Ingress Operator",
    "web console",
    "OperatorHub",
    "Operator Lifecycle Manager",
    "Control Plane Operator",
    "Machine Config Operator",
    "Cluster Version Operator",
    "Hub RDS",
    "FRR-K8s",
    "kubelet",
    "CRI-O",
)

#: openshift-docs a28e76ff modules/olm-rh-catalogs.adoc: the catalogs installed by default in openshift-marketplace.
#: Only redhat-operators holds Red Hat's own builds, which are what the release notes describe.
MARKETPLACE_NAMESPACE = "openshift-marketplace"
RED_HAT_CATALOG = "redhat-operators"
OTHER_DEFAULT_CATALOGS = frozenset({"certified-operators", "community-operators", "redhat-marketplace"})

MAX_ISSUES_PER_PACKAGE = 200
DEFAULT_ISSUES_PER_PACKAGE = 50
MUST_GATHER_ISSUES_PER_PACKAGE = 5
#: What the tools accept, in the form pydantic's validator takes: the one grammar in ``kube_noob.versions``.
VERSION_FIELD_PATTERN = versions.VERSION_FIELD_PATTERN

OpVerdict = Literal[
    "named", "mentioned", "none-named", "no-alias", "package-unknown", "not-determined", "not-installed"
]
VERDICTS: tuple[OpVerdict, ...] = (
    "named",
    "mentioned",
    "none-named",
    "not-determined",
    "no-alias",
    "package-unknown",
    "not-installed",
)
MATCHED = frozenset({"named", "mentioned", "none-named"})
Surface = Literal["cli", "must-gather", "mcp"]

FIX_NOTE = (
    "A fix is listed for an OpenShift release. The release notes do not say whether it ships in the OpenShift "
    "payload or in the operator's own bundle, which OLM updates from its catalog on its own schedule, so whether this "
    "operator has it is not determined. fixReleaseVsCluster compares only the listed release with the cluster's "
    "version: at-or-before, after, or unknown when either has no update number."
)


def method_note() -> str:
    return (
        "A release-note lookup, not a vulnerability check: each operator's package is looked up in a table of the "
        "names the OpenShift release notes use for it, and the issues whose text uses them are listed -- 'named' for "
        "the product's name, 'mentioned' for a component name or an issue that also names another product or the "
        "platform. The notes key issues by OpenShift release and text, not by operator or operator version, so an "
        "issue that uses none of those names is not found, 'named' says the notes name it, not that it is affected, "
        "and whether an installed operator carries a fix is not determined."
    )


# ------------------------------------------------------------------------------------------------- names ----


@functools.cache
def name_pattern(name: str, not_followed_by: str = "") -> re.Pattern[str]:
    """A name as a whole phrase: case-sensitive; not inside a longer word, a hyphenated or dotted name or a path
    (``cert-manager.io/v1``, ``jetstack/cert-manager``); not the name of a namespace; a trailing full stop, a
    possessive and backticks are fine."""
    tail = rf"(?!{not_followed_by})" if not_followed_by else ""
    return re.compile(
        rf"(?<![A-Za-z0-9_./-])(?<!namespace )(?<!namespace `){re.escape(name)}"
        rf"(?![A-Za-z0-9_/-]|\.[A-Za-z0-9])(?!`? namespace){tail}"
    )


def _terms(alias: Alias) -> list[tuple[str, str]]:
    return [(n, "name") for n in alias.names] + [(m, "mention") for m in alias.mentions]


def _hit(alias: Alias, text: str) -> tuple[str, str] | None:
    for term, kind in _terms(alias):
        if name_pattern(term, alias.not_followed_by).search(text):
            return term, kind
    return None


def alias_problems(issues: list[Issue], aliases: dict[str, Alias] | None = None) -> list[str]:
    """What is wrong with the table against a corpus: a name or mention no record uses (the corpus was regenerated
    and it went away), and a name that matches another package's name. Empty when the table is sound."""
    table = ALIASES if aliases is None else aliases
    problems: list[str] = []
    if not issues:  # an empty corpus is a problem in itself, not a table every name of which went unchecked
        problems.append("the corpus holds no release-note issues, so no alias name could be checked")
    used = {
        term
        for alias in table.values()
        for term, _ in _terms(alias)
        for i in issues
        if name_pattern(term, alias.not_followed_by).search(i.text)
    }
    owner: dict[str, str] = {}
    for package, alias in sorted(table.items()):
        for term, kind in _terms(alias):
            if term in owner and owner[term] != package:
                problems.append(f"{term!r} is listed for two packages, {owner[term]} and {package}")
            owner.setdefault(term, package)
            if term not in used:
                problems.append(f"{package}: no release-note issue uses the {kind} {term!r}")
    for a, pa in sorted(owner.items()):
        for b, pb in sorted(owner.items()):
            if pa != pb and name_pattern(a).search(b):
                problems.append(f"{a!r} ({pa}) matches inside {b!r} ({pb}): one name would match two packages")
    return problems


def alias_report(issues: list[Issue]) -> list[str]:
    """Per package: how many records each term hits, and in the newest release; and records two packages share
    (an issue about where two products meet). For ``scripts/vendor_known_issues.py --check``, so a regeneration that
    drops coverage is visible."""
    corpus = _Corpus(issues)
    newest = max((i.minor for i in issues), key=vkey, default="")
    lines = []
    for package, alias in sorted(ALIASES.items()):
        for term, kind in _terms(alias):
            recs = [i for i in issues if name_pattern(term, alias.not_followed_by).search(i.text)]
            lines.append(
                f"{package}: {kind} {term!r} -- {len(recs)} record(s), {sum(i.minor == newest for i in recs)} "
                f"in {newest}"
            )
    for key, packages in sorted(corpus.shared.items()):
        lines.append(f"shared: {key} is matched for {', '.join(sorted(packages))}")
    return lines


# ------------------------------------------------------------------------------------------------- corpus ----


@dataclass(frozen=True)
class _Hit:
    issue: Issue
    term: str
    tier: Literal["named", "mentioned"]
    why: str


class _Corpus:
    """What one loaded index says about every aliased package: the hits with their tier, the terms that hit
    nothing in THIS index (a refreshed local copy can drop a name), and the newest update listed per release."""

    def __init__(self, issues: list[Issue]) -> None:
        raw: dict[str, list[tuple[Issue, str, str]]] = {}
        by_record: dict[tuple[str, str, str], set[str]] = {}
        used: set[tuple[str, str]] = set()
        for package, alias in ALIASES.items():
            terms = _terms(alias)
            patterns = [(t, k, name_pattern(t, alias.not_followed_by)) for t, k in terms]
            for issue in issues:
                matched = [(t, k) for t, k, rx in patterns if rx.search(issue.text)]  # in table order: names first
                if matched:
                    used.update((package, t) for t, _ in matched)
                    raw.setdefault(package, []).append((issue, matched[0][0], matched[0][1]))
                    by_record.setdefault((issue.id, issue.minor, issue.version), set()).add(package)
        self.shared = {f"{k[0]} ({k[1]})": v for k, v in by_record.items() if len(v) > 1}
        self.hits: dict[str, list[_Hit]] = {}
        for package, found in raw.items():
            out = []
            for issue, term, kind in found:
                others = sorted(by_record[(issue.id, issue.minor, issue.version)] - {package})
                platform = next((p for p in PLATFORM_TERMS if name_pattern(p).search(issue.text)), None)
                if kind == "mention":
                    out.append(
                        _Hit(
                            issue,
                            term,
                            "mentioned",
                            f"uses {term!r}, a component name or abbreviation, not the product's name",
                        )
                    )
                elif others:
                    out.append(
                        _Hit(
                            issue, term, "mentioned", f"also names {', '.join(others)}: it may be about where they meet"
                        )
                    )
                elif platform:
                    out.append(
                        _Hit(issue, term, "mentioned", f"also names the platform's {platform}: the fix may be there")
                    )
                else:
                    out.append(_Hit(issue, term, "named", "names the product"))
            self.hits[package] = out
        self.dead = {
            package: [t for t, _ in _terms(alias) if (package, t) not in used] for package, alias in ALIASES.items()
        }
        self.newest: dict[str, str] = {}
        for i in issues:
            if i.kind == "fixed" and (i.minor not in self.newest or vkey(i.version) > vkey(self.newest[i.minor])):
                self.newest[i.minor] = i.version


_corpus_lock = threading.Lock()
_corpus_cache: weakref.WeakKeyDictionary[Index, _Corpus] = weakref.WeakKeyDictionary()


def _corpus(index: Index) -> _Corpus:
    with _corpus_lock:
        if index not in _corpus_cache:
            _corpus_cache[index] = _Corpus(index.issues)
        return _corpus_cache[index]


# ------------------------------------------------------------------------------------------------ versions ----


def parse_version(value: Any) -> str | None:
    """An OpenShift version as given (4.21, 4.21.9 or 4.21.0-rc.1), read by the one grammar every surface shares
    (``kube_noob.versions``): ASCII digits, no leading zeros, no white space. Else None."""
    return value if versions.is_version(value) else None


def is_okd(version: str | None) -> bool:
    """An OKD version: OKD, the community distribution built from the same sources, writes an ``okd`` token in its
    build (``4.20.0-okd-scos.0`` in okd.io's 4.20 release notes; ``4.20.0-0.okd-scos-<date>`` in its
    ``4.20.0-0.okd-scos`` release stream). The bundled index is OpenShift Container Platform's release notes, which do
    not describe OKD's builds."""
    cv = versions.read_version(version)
    return bool(cv and cv.okd)


def okd_note(version: str) -> str:
    """Why an OKD version is not answered from the bundled index: one sentence every surface shares (``operators
    issues``, the tools and the must-gather report), so they cannot disagree about it."""
    return f"{version} is an OKD version, not OpenShift Container Platform: the indexed release notes are OpenShift's"


def okd_version(release: Release) -> str | None:
    """The OKD version the release says the cluster runs (the given one, then the detected one), else None. The one
    decision ``assess`` and the must-gather report both use."""
    return next((v for v in (parse_version(release.given), release.detected) if is_okd(v)), None)


def _release(version: str) -> str:
    cv = versions.read_version(version)
    if cv is None:  # callers pass parse_version output only
        raise ValueError(version)
    return cv.minor


def _exact(version: str | None) -> tuple[int, int, int] | None:
    """major, minor, update -- only for a version that has all three and no pre-release suffix (a release-image
    architecture, ``4.21.3-x86_64``, is the release 4.21.3)."""
    cv = versions.read_version(version)
    if cv is None or not cv.has_z or cv.build:
        return None
    major, minor, z = (int(p) for p in cv.numeric.split("."))
    return major, minor, z


@dataclass
class Release:
    """What is known about the cluster's OpenShift version. ``given`` is what the caller said; ``detected`` what a
    ClusterVersion said (``detected_from`` must-gather or live); ``from_desired`` when no update had completed and
    the version is the one the cluster is moving to; ``updating_to`` when an update is in progress."""

    given: str | None = None
    detected: str | None = None
    detected_from: str | None = None
    from_desired: bool = False
    updating_to: str | None = None
    not_openshift: bool = False
    notes: list[str] = field(default_factory=list)


def _from_history(first: Any, completed: Any, desired: Any, source: str) -> Release:
    """``first`` is the newest history entry, ``completed`` the newest Completed entry's version as written (or
    None), ``desired`` status.desired.version as written."""
    rel = Release(detected_from=source)
    want = parse_version(desired)
    if completed is not None:
        rel.detected = parse_version(completed)
        if rel.detected is None:
            rel.notes.append(
                "the newest completed entry in the ClusterVersion history is not a version this reads, so the "
                "cluster's version is not determined (an older entry or status.desired would be a guess)"
            )
            return rel
    elif want:
        rel.detected, rel.from_desired = want, True
        rel.notes.append(
            f"no update has completed in the ClusterVersion history: {want} is status.desired, the version the "
            "cluster is moving to"
        )
        return rel
    else:
        rel.notes.append("the ClusterVersion holds no version in the form this reads")
        return rel
    head = first if isinstance(first, dict) else {}
    moving = parse_version(head.get("version")) if head.get("state") != "Completed" else None
    target = moving or want
    if target and target != rel.detected:
        rel.updating_to = target
    return rel


def live_release(backend: Any) -> Release:
    """The ClusterVersion named ``version``, read live. A 404 in the backends' words for a missing resource type
    (``operators._not_served``) means the cluster is not OpenShift; anything else that fails leaves it unknown."""
    from kube_noob.errors import KubeNoobError

    try:
        cv = backend.get("clusterversions", name="version")
    except KubeNoobError as exc:
        message = str(exc)
        # the exception, not its message: it carries the full stderr or the HTTP status (G279)
        if ops._not_served("clusterversions", exc, group="config.openshift.io", version="v1"):
            return Release(
                detected_from="live",
                not_openshift=True,
                notes=[
                    "the cluster does not serve ClusterVersion (404): it is not OpenShift, so the OpenShift "
                    "release notes do not apply to it"
                ],
            )
        return Release(
            detected_from="live", notes=[f"the ClusterVersion could not be read ({ops._text(message, 200)})"]
        )
    status = ops._d(ops._d(cv).get("status"))
    history = [h for h in ops._l(status.get("history"))[:200] if isinstance(h, dict)]
    completed = next((h.get("version") for h in history if h.get("state") == "Completed"), None)
    return _from_history(
        history[0] if history else None, completed, ops._d(status.get("desired")).get("version"), "live"
    )


def must_gather_release(cluster: dict[str, Any]) -> Release:
    """From ``must-gather analyze``'s cluster block (the analyser reads the ClusterVersion named ``version`` only)."""
    if cluster.get("clusterVersionNote"):
        return Release(detected_from="must-gather", notes=[str(cluster["clusterVersionNote"])])
    if "desiredVersion" not in cluster:
        return Release(detected_from="must-gather", notes=["the must-gather holds no ClusterVersion"])
    history = cluster.get("history") or []
    completed = cluster.get("completedVersion")
    return _from_history(history[0] if history else None, completed, cluster.get("desiredVersion"), "must-gather")


# ------------------------------------------------------------------------------------------------ the join ----


def catalog_kind(catalog: Any, namespace: Any) -> Literal["red-hat", "not-red-hat-build", "unknown"]:
    if namespace == MARKETPLACE_NAMESPACE and catalog == RED_HAT_CATALOG:
        return "red-hat"
    if namespace == MARKETPLACE_NAMESPACE and catalog in OTHER_DEFAULT_CATALOGS:
        return "not-red-hat-build"
    return "unknown"


def _issue_number(issue_id: str) -> tuple[str, int]:
    prefix, _, num = issue_id.rpartition("-")
    return prefix, int(num) if num.isdigit() else 0


def _neg(v: str | None) -> tuple[int, ...]:
    return tuple(-x for x in vkey(v or "0"))


@dataclass
class _Ctx:
    versions: list[str]  # the versions searched (one, or two during an update); empty when not known
    releases: list[str]
    running: str | None
    as_of: Any


def _rows(hits: list[_Hit], ctx: _Ctx) -> list[dict[str, Any]]:
    """One row per issue id, from the records that apply to the cluster: open issues first, named before
    mentioned, newest release, newest fix, then the issue number (numerically)."""
    groups: dict[str, list[_Hit]] = {}
    for h in hits:
        i = h.issue
        # a record of a searched release, or a known issue from an earlier one not yet fixed at the cluster's version
        # (a fix listed in a later release's z-stream keeps it listed until that fix)
        applies = (
            not ctx.versions
            or i.minor in ctx.releases
            or (i.kind == "known" and any(Index._applies(i, v) for v in ctx.versions))
        )
        if applies:
            groups.setdefault(i.id, []).append(h)
    rows = []
    for issue_id, group in groups.items():
        group.sort(key=lambda h: (_neg(h.issue.minor), _neg(h.issue.version)))
        rep = group[0].issue
        listed_fixes = {h.issue.version if h.issue.kind == "fixed" else h.issue.fixed_in for h in group}
        fixes = sorted((f for f in listed_fixes if f), key=vkey)
        in_release = [f for f in fixes if ctx.running and _release(ctx.running) == ".".join(f.split(".")[:2])]
        fix: str | None = (in_release or fixes)[0] if (in_release or fixes) else None
        releases = sorted({h.issue.minor for h in group}, key=vkey)
        named = [h for h in group if h.tier == "named"]
        best = (named or group)[0]
        running = _exact(ctx.running)
        listed = None
        if not fix and ctx.running and all(vkey(r) < vkey(_release(ctx.running)) for r in releases):
            listed = f"listed for OpenShift {', '.join(releases)}; no fix listed since"
        row: dict[str, Any] = {
            "id": issue_id,
            "url": rep.url,
            "class": "fixed" if fix else "open",
            "tier": best.tier,
            "via": best.term,
            "tierWhy": best.why,
            "releases": releases,
            "fixedInOpenShift": fix,
            "fixReleaseVsCluster": (
                "unknown"
                if not fix or running is None or _exact(fix) is None
                else "at-or-before"
                if _exact(fix) <= running  # type: ignore[operator]
                else "after"
            ),
            "installedHasFix": "not-determined" if fix else "no-fix-listed",
            "summary": ops._text(rep.summary, 300),
            "workaround": ops._text(rep.workaround, 300) or None,
            "source": rep.source,
            "knownIssuesAsOf": ctx.as_of,
        }
        if len(rep.ids) > 1:
            row["ids"] = list(rep.ids)
        if listed:
            row["listed"] = listed
        rows.append(row)
    rows.sort(
        key=lambda r: (
            r["class"] != "open",
            r["tier"] != "named",
            _neg(r["releases"][-1]),
            _neg(r["fixedInOpenShift"]),
            _issue_number(r["id"]),
        )
    )
    return rows


def _hints(surface: Surface) -> dict[str, str]:
    """What a reader can do next, worded for where they read it (one renderer for every surface)."""
    if surface == "must-gather":
        run = "run kube-noob operators issues --must-gather <path>"
        return {
            "version": f"{run} --openshift-version <x.y.z> to give it",
            "issues": f"{run} --issues {MAX_ISSUES_PER_PACKAGE} to see up to {MAX_ISSUES_PER_PACKAGE} per package",
            "operators": f"{run} --top 500 to see more",
        }
    if surface == "mcp":
        return {
            "version": "pass openshift_version to give it",
            "issues": "pass a larger issues_per_package to see more",
            "operators": "pass a larger top to see more",
        }
    return {
        "version": "pass --openshift-version to give it",
        "issues": f"pass --issues (up to {MAX_ISSUES_PER_PACKAGE}) to see more",
        "operators": "pass --top (up to 500) to see more",
    }


def assess(
    collected: ops.Collected,
    *,
    release: Release | None = None,
    surface: Surface = "cli",
    top: int = ops.MAX_OPERATORS,
    issues_per_package: int = DEFAULT_ISSUES_PER_PACKAGE,
    data_dir: Path | None = None,
    index: Index | None = None,
) -> dict[str, Any]:
    """The installed operators of ``collected`` (the inventory's own collection), each looked up in the release
    notes of the cluster's OpenShift release. Deterministic: built from the sorted inventory and sorted again."""
    rel = release or Release()
    hints = _hints(surface)
    inv = ops.inventory(collected, top=ops.MAX_OPERATORS)  # every operator the inventory holds, up to its cap
    idx = index if index is not None else get_index(data_dir)
    knowledge = idx.knowledge()
    corpus = _corpus(idx)
    as_of = knowledge.get("knownIssuesAsOf")
    releases_indexed: list[str] = list(knowledge.get("openshiftReleases") or [])
    caveats: list[str] = []
    incomplete: list[str] = []

    # -- which release(s) to search
    given = parse_version(rel.given)
    version = given or rel.detected
    detected = rel.detected
    for note in rel.notes:
        caveats.append(note)
    if (
        given
        and detected
        and (given != detected if _exact(given) and _exact(detected) else _release(given) != _release(detected))
    ):
        caveats.append(
            f"the given version {given} disagrees with the ClusterVersion's {detected} ({rel.detected_from}); the "
            "given one is used"
        )
    okd = okd_version(rel)
    versions = [version] if version else []
    if rel.updating_to and _release(rel.updating_to) != _release(version or rel.updating_to):
        versions.append(rel.updating_to)  # an update in progress is a fact about the cluster, given a version or not
    wanted = sorted({_release(v) for v in versions}, key=vkey)
    outside = [r for r in wanted if r not in releases_indexed]
    running = versions[0] if versions else None
    run_release = _release(running) if running else None
    not_indexed = bool(run_release and run_release in outside)
    versions = [v for v in versions if _release(v) not in outside]
    narrowed = [r for r in wanted if r not in outside]
    # reasons the answer is incomplete because of the release; they count only when there is something to look up
    release_gaps: list[str] = []
    if rel.not_openshift:
        release_gaps.append(
            "the cluster is not OpenShift (it does not serve ClusterVersion): the OpenShift release notes do not "
            "apply, so no operator was looked up"
        )
    if okd:
        release_gaps.append(f"{okd_note(okd)}, so no operator was looked up")
        caveats.append(
            f"the cluster runs OKD ({okd}), the community distribution: the indexed release notes are OpenShift "
            "Container Platform's and do not describe OKD's builds, so every operator is not determined"
        )
    if not_indexed:
        release_gaps.append(
            f"OpenShift {run_release} is not in the indexed release notes ({', '.join(releases_indexed)}), so no "
            "operator was looked up"
        )
    elif outside:
        release_gaps.append(f"OpenShift {', '.join(outside)} is not indexed")
    if rel.updating_to:
        release_gaps.append(f"the cluster is updating to {rel.updating_to}")
    if rel.from_desired and not given:
        release_gaps.append("the version is status.desired: no update has completed")
    applicable = not (rel.not_openshift or okd or not_indexed)
    newest = _exact(corpus.newest.get(run_release or ""))
    now = _exact(running)
    if applicable and newest is not None and now is not None and now > newest:
        caveats.append(
            f"the cluster is at {running}, past the newest {run_release} update in the index "
            f"({corpus.newest.get(run_release or '')}): issues reported after {as_of} are not included"
        )
    if rel.not_openshift:
        pass
    elif not version:
        release_gaps.append("the cluster's OpenShift version is not known: issues were not narrowed to a release")
        caveats.append(
            f"the cluster's OpenShift version is not known: every indexed release ({', '.join(releases_indexed)}) "
            f"was searched; {hints['version']}"
        )
    elif not_indexed:
        caveats.append(
            f"OpenShift {version} (release {run_release}) is outside the indexed release notes "
            f"({', '.join(releases_indexed)}, as of {as_of}): every operator is not determined"
        )
    update_at = len(caveats)  # the update's caveat says what was searched, which is known after the lookups
    if knowledge.get("recordsRejected"):
        caveats.append(
            f"{knowledge['recordsRejected']} record(s) of the loaded release notes were not usable and were left "
            f"out: {'; '.join(ops._text(x, 120) for x in knowledge.get('rejectedRecords', []))}"
        )
    if knowledge.get("localCopyNote"):
        caveats.append(str(knowledge["localCopyNote"]))
    ctx = _Ctx(versions, narrowed, running, as_of)

    # -- every operator
    package_rows: dict[str, list[dict[str, Any]]] = {}
    entries: list[dict[str, Any]] = []
    dead_seen: set[str] = set()
    looked_up = False
    for op in inv["operators"]:
        entry: dict[str, Any] = {
            k: op[k]
            for k in (
                "namespace",
                "csv",
                "package",
                "packageFrom",
                "version",
                "versionFrom",
                "catalog",
                "catalogNamespace",
            )
            if k in op
        }
        entry["inventoryState"] = op["state"]
        kind = catalog_kind(op.get("catalog"), op.get("catalogNamespace"))
        entry["catalogKind"] = kind
        notes: list[str] = []
        package = op.get("package")
        state = op["state"]
        if state in ops.UNDETERMINED_STATES:
            notes.append("whether this operator is installed was not determined by the inventory")
        rows: list[dict[str, Any]] = []
        verdict: OpVerdict
        if state == "not-installed":
            verdict, reason = "not-installed", "subscribed to but nothing is installed, so it was not looked up"
        elif state == "csv-missing":
            verdict = "not-determined"
            reason = "its Subscription names an installed CSV that was not read: whether it is installed is not known"
        elif state in ("csv-not-read", "status-not-read"):
            verdict = "not-determined"
            reason = (
                f"whether it is installed was not read (inventory state {state}), so it was not looked up: a "
                "Subscription is not an installed operator"
            )
        elif rel.not_openshift:
            verdict, reason = "not-determined", "the cluster is not OpenShift: the OpenShift release notes do not apply"
        elif okd:
            verdict = "not-determined"
            reason = "the cluster runs OKD: the OpenShift Container Platform release notes do not describe its builds"
        elif not_indexed:
            verdict = "not-determined"
            reason = f"OpenShift {run_release} is not in the indexed release notes ({', '.join(releases_indexed)})"
        elif not package:
            verdict = "package-unknown"
            reason = (
                "its package is not known (no Subscription or olm.package property names it), so it was not looked "
                "up; the CSV's name is not used to guess it"
            )
        elif package not in ALIASES:
            verdict = "no-alias"
            reason = (
                "not matched against the release notes (no alias): kube-noob has no entry saying what name the notes "
                "use for this package, which is not the same as no reported issue"
            )
        elif kind == "not-red-hat-build":
            verdict = "not-determined"
            reason = (
                f"it comes from {op.get('catalog')}, not {RED_HAT_CATALOG}: the release notes describe Red Hat's build "
                "of this package, not this one"
            )
        else:
            looked_up = True
            if package not in package_rows:
                package_rows[package] = _rows(corpus.hits.get(package, []), ctx)
            rows = package_rows[package]
            dead = corpus.dead.get(package, [])
            where = f"OpenShift {', '.join(narrowed)}" if narrowed else "every indexed release (release not known)"
            named_n = sum(r["tier"] == "named" for r in rows)
            if named_n:
                verdict = "named"
                reason = f"the {where} release notes name this product in {named_n} issue(s)"
                if len(rows) > named_n:
                    reason += f" and only mention it in {len(rows) - named_n} more"
            elif rows:
                verdict = "mentioned"
                reason = f"the {where} release notes only mention it, in {len(rows)} issue(s)"
            elif dead:
                verdict = "not-determined"
                reason = (
                    f"the loaded release notes no longer use {', '.join(repr(d) for d in dead)}, a name kube-noob "
                    "looks for: an issue about it may be written another way"
                )
                if package not in dead_seen:
                    dead_seen.add(package)
                    caveats.append(f"{package}: the loaded release notes use none of {', '.join(map(repr, dead))}")
            elif not version:
                verdict = "not-determined"
                reason = "no indexed release notes name it, and the cluster's release is not known"
            else:
                verdict = "none-named"
                reason = (
                    f"no issue in the {where} release notes uses a name kube-noob has for it; that says the notes "
                    "do not name it, not that it has no reported issue"
                )
            if rows and dead and package not in dead_seen:
                dead_seen.add(package)
                caveats.append(f"{package}: the loaded release notes use none of {', '.join(map(repr, dead))}")
            if kind == "unknown":
                notes.append(
                    f"it comes from {'catalog ' + str(op['catalog']) if op.get('catalog') else 'a catalog not named'}"
                    f", not {RED_HAT_CATALOG} in {MARKETPLACE_NAMESPACE}: the release notes describe Red Hat's build, "
                    "and kube-noob cannot tell whether this is it (a mirror of it would be)"
                )
        entry["verdict"] = verdict
        entry["reason"] = reason
        entry["issues"] = {
            "open": sum(r["class"] == "open" for r in rows),
            "fixed": sum(r["class"] == "fixed" for r in rows),
            "named": sum(r["tier"] == "named" for r in rows),
            "mentioned": sum(r["tier"] == "mentioned" for r in rows),
        }
        entry["notes"] = notes
        entries.append(entry)

    entries.sort(
        key=lambda e: (VERDICTS.index(e["verdict"]), e["namespace"], e.get("package") or "", e.get("csv") or "")
    )
    counts = Counter(e["verdict"] for e in entries)
    assessable = len(entries) - counts["not-installed"]
    matched = sum(counts[v] for v in MATCHED)
    unverified = sum(1 for e in entries if e["verdict"] in MATCHED and e["catalogKind"] == "unknown")
    not_matched = assessable - matched
    not_assessed = int(inv.get("notShown", 0))
    if not inv["complete"]:
        incomplete.append(f"the inventory is {inv['verdict']}")
    if not_assessed:
        incomplete.append(
            f"{not_assessed} operator(s) past the inventory's cap of {ops.MAX_OPERATORS} were not assessed"
        )
    if counts_missing := sum(1 for e in entries if e["inventoryState"] == "csv-missing"):
        incomplete.append(f"{counts_missing} operator(s) name a CSV that was not read")
    if assessable:  # with nothing to look up, the release it would have been looked up in is not a gap
        incomplete.extend(release_gaps)
    # what was searched: the cluster's release(s), or every indexed one when the release is not known -- and nothing
    # when no operator reached the lookup
    searched = (narrowed if version else list(releases_indexed)) if looked_up else []
    if rel.updating_to:
        said = f"searched OpenShift {', '.join(searched)}" if searched else "no release was searched"
        if outside:
            said += (
                f"; OpenShift {', '.join(outside)} is not in the indexed release notes ({', '.join(releases_indexed)})"
            )
        caveats.insert(update_at, f"an update to {rel.updating_to} is in progress: {said}")
    caveats = [f"inventory: {c}" for c in inv["caveats"]] + caveats
    if counts["no-alias"]:
        caveats.append(
            f"{counts['no-alias']} operator(s) have no alias and were not matched against the release notes; that is "
            "not the same as having no reported issue"
        )
    if foreign := sum(
        1 for e in entries if e["catalogKind"] == "not-red-hat-build" and e["verdict"] == "not-determined"
    ):
        caveats.append(
            f"{foreign} operator(s) come from {', '.join(sorted(OTHER_DEFAULT_CATALOGS))}, which are not Red Hat's "
            "builds: the release notes do not describe them, so they were not looked up"
        )
    if counts["package-unknown"]:
        caveats.append(f"{counts['package-unknown']} operator(s) have no known package and were not matched")
    if unverified:
        caveats.append(
            f"{unverified} operator(s) come from a catalog other than {RED_HAT_CATALOG}: their matches describe "
            "Red Hat's build, which kube-noob cannot confirm they are"
        )
    undetermined = [e for e in entries if e["inventoryState"] in ops.UNDETERMINED_STATES]
    if undetermined:
        names = ", ".join(f"{e['namespace']}/{e.get('csv') or e.get('package') or '?'}" for e in undetermined[:10])
        caveats.append(f"the inventory could not say whether these are installed: {names}")

    complete = not incomplete  # one list decides it, so the flag and the reasons cannot disagree
    if inv["verdict"] in ("not-determined", "no-olm"):
        answer = inv["verdict"]
    elif assessable == 0 and complete:
        answer = "nothing-to-match"
    elif assessable and not applicable:
        answer = "not-determined"
    elif not complete:
        answer = "partial"
    elif not_matched == 0 and unverified == 0:
        answer = "matched"
    elif matched == 0:
        answer = "not-matched"
    else:
        answer = "partly-matched"
    if rel.not_openshift:
        inapplicable = (
            f"the cluster is not OpenShift, so the OpenShift release notes do not apply to its {len(entries)} "
            "operator(s)"
        )
    elif okd:
        inapplicable = (
            f"the cluster runs OKD ({okd}), and the indexed release notes are OpenShift Container Platform's, so none "
            f"of the {len(entries)} operator(s) was looked up"
        )
    else:
        inapplicable = (
            f"OpenShift {run_release} is not in the indexed release notes ({', '.join(releases_indexed)}, as of "
            f"{as_of}), so none of the {len(entries)} operator(s) was looked up"
        )

    issues_out: dict[str, Any] = {}
    for package, rows in sorted(package_rows.items()):
        shown = rows[:issues_per_package]
        block: dict[str, Any] = {
            "open": sum(r["class"] == "open" for r in rows),
            "fixed": sum(r["class"] == "fixed" for r in rows),
            "rows": shown,
        }
        cut = {c: sum(r["class"] == c for r in rows) - sum(r["class"] == c for r in shown) for c in ("open", "fixed")}
        if any(cut.values()):
            block["withheld"] = cut
        issues_out[package] = block
    shown_entries = entries[:top]
    open_total = sum(b["open"] for b in issues_out.values())
    fixed_total = sum(b["fixed"] for b in issues_out.values())
    out: dict[str, Any] = {
        "verdict": answer,
        "complete": complete,
        "allMatched": answer == "matched",  # at least one operator, every one looked up, none unverified
        "summary": _summary(
            answer,
            inv,
            counts,
            assessable,
            not_matched,
            unverified,
            narrowed,
            as_of,
            open_total,
            fixed_total,
            incomplete,
            inapplicable,
            len(entries),
            not_assessed,
        ),
        "incompleteBecause": incomplete,
        "cluster": {
            "openshiftVersion": version,
            "versionFrom": (
                "given"
                if given
                else ("clusterversion-desired" if rel.from_desired else "clusterversion")
                if version
                else None
            ),
            "detectedFrom": rel.detected_from,
            "detectedVersion": detected,
            "updatingTo": rel.updating_to,
            "releasesSearched": searched,
            "indexed": None if not version or rel.not_openshift else not not_indexed,
            "notOpenShift": rel.not_openshift,
            "okd": okd is not None,
        },
        "knowledge": {
            "knownIssuesAsOf": as_of,
            "openshiftReleases": releases_indexed,
            "source": "OpenShift release notes (openshift/openshift-docs), known and fixed issues",
            **{k: knowledge[k] for k in ("recordsRejected", "localCopyNote") if k in knowledge},
        },
        "counts": {
            "operators": len(entries),
            "assessable": assessable,
            "notMatched": not_matched,
            "catalogUnverified": unverified,
            "named": counts["named"],
            "mentioned": counts["mentioned"],
            "noneNamed": counts["none-named"],
            "noAlias": counts["no-alias"],
            "packageUnknown": counts["package-unknown"],
            "notDetermined": counts["not-determined"],
            "notInstalled": counts["not-installed"],
            "notAssessed": not_assessed,
            "openIssues": open_total,
            "fixedIssues": fixed_total,
        },
        "operators": shown_entries,
        "operatorsTotal": len(entries),
        "issues": issues_out,
    }
    if len(entries) > len(shown_entries):
        out["notShown"] = len(entries) - len(shown_entries)
    out["inventory"] = {k: inv[k] for k in ("source", "verdict", "complete", "summary")}
    out["caveats"] = caveats
    out["hints"] = hints
    out["fixNote"] = FIX_NOTE
    out["method"] = method_note()
    return out


def for_must_gather(
    collected: ops.Collected, cluster: dict[str, Any], surface: Surface = "must-gather", data_dir: Path | None = None
) -> dict[str, Any]:
    """The answer inside a must-gather analysis: the analyser's ClusterVersion narrows it, and each package carries
    at most ``MUST_GATHER_ISSUES_PER_PACKAGE`` issues, with what was withheld per class."""
    return assess(
        collected,
        release=must_gather_release(cluster),
        surface=surface,
        issues_per_package=MUST_GATHER_ISSUES_PER_PACKAGE,
        data_dir=data_dir,
    )


def _summary(
    answer: str,
    inv: dict[str, Any],
    counts: Counter[str],
    assessable: int,
    not_matched: int,
    unverified: int,
    searched: list[str],
    as_of: Any,
    open_total: int,
    fixed_total: int,
    incomplete: list[str],
    inapplicable: str,
    total: int,
    not_assessed: int,
) -> str:
    tail = " (a release-note lookup, not a vulnerability check)"
    if answer == "no-olm":
        return "not an OLM cluster: there are no OLM-installed operators to look up, and nothing was evaluated"
    if inv["verdict"] == "not-determined":
        return (
            f"not determined: the installed operators could not be read ({inv['summary']}). That does not mean no "
            "operator has a reported issue."
        )
    if answer == "not-determined":
        return f"not determined: {inapplicable}"
    if answer == "nothing-to-match":
        return f"no installed operator to look up ({total} subscribed, none installed)" + tail
    where = f"the OpenShift {', '.join(searched)} release notes" if searched else "the indexed release notes"
    unverified_said = (
        f"{unverified} of them only from a catalog kube-noob cannot verify as Red Hat's build ({RED_HAT_CATALOG})"
    )
    if not_matched:
        lead = f"{not_matched} of {assessable} installed operator(s) were not matched against the release notes"
    elif unverified:
        lead = f"all {assessable} installed operator(s) were looked up, {unverified_said}"
    else:
        lead = f"all {assessable} installed operator(s) were looked up"
    parts = [
        lead,
        f"{counts['named']} named and {counts['mentioned']} only mentioned in {where} as of {as_of} ({open_total} "
        f"open, {fixed_total} fixed issue(s))",
        f"{counts['none-named']} looked up and named in no issue",
    ]
    if unverified and not_matched:
        parts.append(f"{unverified} matched only from a catalog kube-noob cannot verify as Red Hat's build")
    head = "; ".join(parts)
    if not_assessed:
        head += f"; {not_assessed} operator(s) not assessed"
    if incomplete:
        head += " -- incomplete: " + "; ".join(incomplete)
    return head + tail


# ------------------------------------------------------------------------------------------------- text ----


def render_text(out: dict[str, Any]) -> str:
    """The text view: every operator with every field the JSON gives it, every issue with its link, source and the
    corpus date, and every caveat and hint the JSON carries (G221)."""
    c, cl, k = out["counts"], out["cluster"], out["knowledge"]
    if cl["openshiftVersion"]:
        product = "OKD, not OpenShift Container Platform:" if cl.get("okd") else "OpenShift"
        version = f"{product} {cl['openshiftVersion']} ({cl['versionFrom']})"
    else:
        version = "OpenShift version not known"
    if cl["detectedVersion"] and cl["detectedVersion"] != cl["openshiftVersion"]:
        version += f"; the ClusterVersion says {cl['detectedVersion']}"
    if cl["updatingTo"]:
        version += f"; updating to {cl['updatingTo']}"
    lines = [
        f"operator known issues ({out['inventory']['source']}): {out['verdict']} -- {out['summary']}",
        f"complete: {'yes' if out['complete'] else 'no'}; all matched: {'yes' if out['allMatched'] else 'no'}",
        f"cluster: {version}; searched {', '.join(cl['releasesSearched']) or 'no release'}",
        f"release notes: {k['source']}, OpenShift {', '.join(k['openshiftReleases'])}, as of {k['knownIssuesAsOf']}"
        + (f"; {k['recordsRejected']} record(s) left out as unusable" if k.get("recordsRejected") else ""),
        f"counts: {c['operators']} operator(s), {c['assessable']} installed, {c['notMatched']} not matched, "
        f"{c['named']} named, {c['mentioned']} mentioned, {c['noneNamed']} named in no issue, {c['noAlias']} no "
        f"alias, {c['packageUnknown']} package unknown, {c['notDetermined']} not determined, {c['notInstalled']} not "
        f"installed, {c['catalogUnverified']} catalog unverified, {c['notAssessed']} not assessed, {c['openIssues']} "
        f"open and {c['fixedIssues']} fixed issue(s)",
    ]
    shown_packages: set[str] = set()
    for op in out["operators"]:
        package = op.get("package") or "unknown"
        if op.get("packageFrom"):
            package += f" (from the {op['packageFrom']})"
        version_text = f"{op['version']} ({op.get('versionFrom')})" if op.get("version") else "unknown"
        catalog = op.get("catalog") or "not named"
        if op.get("catalogNamespace"):
            catalog += f" in {op['catalogNamespace']}"
        lines.append(f"  {op['namespace']}/{op.get('csv') or '?'}  {op['verdict']}: {op['reason']}")
        lines.append(
            f"      package {package}  version {version_text}  state {op['inventoryState']}  catalog {catalog} "
            f"({op['catalogKind']})"
        )
        for note in op["notes"]:
            lines.append(f"      note: {note}")
        block = out["issues"].get(op.get("package") or "")
        if block is None:
            continue
        if op["package"] in shown_packages:
            lines.append(f"      issues: as listed above for {op['package']}")
            continue
        shown_packages.add(op["package"])
        lines.append(f"      issues: {block['open']} open, {block['fixed']} fixed")
        for row in block["rows"]:
            head = f"      {row['id']} [{row['class']}, {row['tier']}, OpenShift {', '.join(row['releases'])}]"
            if row.get("ids"):
                head += f" (ids {', '.join(row['ids'])})"
            lines.append(head + (f" {row['listed']}" if row.get("listed") else ""))
            lines.append(f"        {row['summary']}")
            lines.append(f"        via {row['via']!r}: {row['tierWhy']}")
            if row.get("workaround"):
                lines.append(f"        workaround: {row['workaround']}")
            if row["fixedInOpenShift"]:
                lines.append(
                    f"        fix listed for OpenShift {row['fixedInOpenShift']}; cluster at "
                    f"{cl['openshiftVersion'] or 'an unknown version'}: {row['fixReleaseVsCluster']}; in this "
                    f"operator: {row['installedHasFix']}"
                )
            else:
                lines.append(f"        no fix listed (installedHasFix: {row['installedHasFix']})")
            lines.append(f"        {row['url']}  source {row['source']}  (as of {row['knownIssuesAsOf']})")
        if block.get("withheld"):
            w = block["withheld"]
            lines.append(f"      and {w['open']} open and {w['fixed']} fixed more: {out['hints']['issues']}")
    if out.get("notShown"):
        lines.append(f"  and {out['notShown']} more operator(s): {out['hints']['operators']}")
    lines.append(f"inventory: {out['inventory']['verdict']} -- {out['inventory']['summary']}")
    for reason in out["incompleteBecause"]:
        lines.append(f"incomplete: {reason}")
    for caveat in out["caveats"]:
        lines.append(f"caveat: {caveat}")
    lines.append(f"fix: {out['fixNote']}")
    lines.append(f"method: {out['method']}")
    return "\n".join(lines)
