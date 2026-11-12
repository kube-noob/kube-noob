"""Which installed OLM operators the OpenShift release notes name in a reported issue (R5).

What the bundled corpus can support decides what this is. ``kube_noob/data/known_issues`` holds the known and fixed
issues of the OpenShift 4.20-4.22 release notes, one record per issue and release: an issue id, ``kind``, the
OpenShift ``minor`` and ``version``, the release-note text and its source file, and for five records an OpenShift
``fixedIn``. No record carries a component, a package or an operator version (``tests/test_operator_known_issues.py``
measures that, so a corpus that grows such a field fails a test instead of being ignored). On 2026-11-12, 957 records
(921 issue ids); 186 name some "<Name> Operator", most of them platform operators the cluster version operator runs
(Machine Config, Ingress, Cluster Version), which OLM does not install; one issue names an operator version, in prose
(multicluster engine 2.11.0, as the version that broke, not the one that fixed it).

So the join is the one the data can populate, and it says so:

- **Package to name, through an explicit table.** ``ALIASES`` maps an OLM package name to the product names the
  release notes use for it, each matched as a whole phrase, case-sensitively, at word boundaries -- never a fuzzy
  substring of the text. A package with no entry is "not matched (no alias)": listed and counted, never clean. A
  package that is not known (no Subscription, no ``olm.package`` property) is not guessed from the CSV's name.
- **Narrowed by the cluster's OpenShift release** (a flag, the must-gather's ClusterVersion, or the live one): only
  that release's notes are searched. A release outside the indexed ones is "not determined" for every operator, as
  ``upgrade_risks`` and ``known_issues`` treat a version they hold nothing for; an unknown version searches every
  indexed release and the answer says it was not narrowed.
- **A fix is an OpenShift release, never an operator version.** The notes say "fixed in 4.22.3"; an OpenShift-shipped
  operator's own version is ``4.y.0-<build>`` (openshift-docs a28e76ff671df01eb6d75f305153dc6a01039c60
  ``modules/nw-dpu-operator-uninstall.adoc``: ``dpu-operator.v4.20.0-202503130333``, VERSION
  ``4.20.0-202503130333``; ``modules/update-updating-the-olm-operators.adoc``: ``metallb-operator.v4.16.0-
  202409202304``), and OLM updates it from its catalog, not with the cluster. Comparing the two would put every
  such build "before the fix". So whether the installed operator carries a fix is always ``not-determined``, with
  the reason; a known issue with no fix says ``no-fix-listed``.

"Named" means the release notes name this operator's product in that issue: the issue may be in the operator, or in
the platform where the operator meets it (the console installing it, the ingress operator managing its Subscription).
Each row carries the issue's summary, link, release-notes source and the corpus date, so the reader judges which.

Every package name below was read in a Subscription, a mirror config or the code that creates one (the commit is the
citation): openshift/openshift-docs a28e76ff671df01eb6d75f305153dc6a01039c60 (the 4.20 commit the corpus itself cites)
``modules/<file>``, and openshift/cluster-ingress-operator 8e4c40f161d8341d640659ca2779a4294960c183 (release-4.20).
"""

from __future__ import annotations

import functools
import re
import threading
import weakref
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from kube_noob import operators as ops
from kube_noob.known_issues import Index, Issue, get_index, vkey

DOCS = "openshift/openshift-docs a28e76ff671df01eb6d75f305153dc6a01039c60 modules/"


@dataclass(frozen=True)
class Alias:
    """The product names the release notes use for one package, and where the package name was read."""

    names: tuple[str, ...]
    source: str


#: package -> the names the release notes use for it. Every name must occur in the bundled corpus and no name may
#: match another package's (tests/test_operator_known_issues.py, scripts/vendor_known_issues.py --check). Operators
#: the notes name only in passing words ("SR-IOV virtual functions", "managed by NMState") have no entry: those words
#: are about the platform feature, not the OLM operator, and a name that does not mean the operator would be a
#: false match.
ALIASES: dict[str, Alias] = {
    "clusterresourceoverride": Alias(
        ("Cluster Resource Override Operator",), DOCS + "nodes-cluster-resource-override-deploy-cli.adoc"
    ),
    "cluster-logging": Alias(("Cluster Logging Operator",), DOCS + "cluster-logging-deploy-cli.adoc"),
    "dpu-operator": Alias(("DPU Operator",), DOCS + "nw-dpu-installing-operator-cli.adoc"),
    "ingress-node-firewall": Alias(("Ingress Node Firewall",), DOCS + "nw-infw-operator-installing-cli.adoc"),
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
        ("Precision Time Protocol (PTP) Operator", "PTP Operator"), DOCS + "nw-ptp-installing-operator-cli.adoc"
    ),
    "servicemeshoperator3": Alias(
        ("OpenShift Container Platform Service Mesh", "OpenShift Service Mesh"),
        "openshift/cluster-ingress-operator 8e4c40f161d8341d640659ca2779a4294960c183 "
        "pkg/operator/controller/gatewayclass/subscription.go (Package servicemeshoperator3)",
    ),
    "vertical-pod-autoscaler": Alias(
        ("Vertical Pod Autoscaler",), DOCS + "nodes-pods-vertical-autoscaler-moving-vpa.adoc"
    ),
}

MAX_ISSUES_PER_OPERATOR = 20
_OCP = re.compile(r"^(\d{1,3})\.(\d{1,3})(?:\.(\d{1,5}))?(?:[-+][0-9A-Za-z.-]{1,64})?\Z")
NOT_INSTALLED = frozenset({"not-installed", "csv-missing"})

OpVerdict = Literal["named", "none-named", "no-alias", "package-unknown", "not-determined", "not-installed"]
VERDICTS: tuple[OpVerdict, ...] = (
    "named",
    "none-named",
    "no-alias",
    "package-unknown",
    "not-determined",
    "not-installed",
)


def method_note() -> str:
    return (
        "Matched by name: each operator's package is looked up in a table of the product names the OpenShift release "
        "notes use for it, and the issues whose text names that product are listed. The notes key issues by "
        "OpenShift release and text, not by operator or operator version, so an issue that does not use the "
        "product's name is not found, and whether an installed operator carries a fix is not determined."
    )


@functools.cache
def name_pattern(name: str) -> re.Pattern[str]:
    """A product name as a whole phrase: case-sensitive, not inside a longer word or hyphenated name."""
    return re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(name)}(?![A-Za-z0-9_-])")


def alias_problems(issues: list[Issue], aliases: dict[str, Alias] | None = None) -> list[str]:
    """What is wrong with the table against a corpus: a name no record uses (the corpus was regenerated and the name
    went away), and a name that matches another package's name. Empty when the table is sound."""
    table = ALIASES if aliases is None else aliases
    problems: list[str] = []
    if not issues:  # an empty corpus is a problem in itself, not a table every name of which went unchecked
        problems.append("the corpus holds no release-note issues, so no alias name could be checked")
    used = {
        name for alias in table.values() for name in alias.names for i in issues if name_pattern(name).search(i.text)
    }
    owner: dict[str, str] = {}
    for package, alias in sorted(table.items()):
        for name in alias.names:
            if name in owner:
                problems.append(f"{name!r} is listed for two packages, {owner[name]} and {package}")
            owner.setdefault(name, package)
            if name not in used:
                problems.append(f"{package}: no release-note issue uses the name {name!r}")
    for a, pa in sorted(owner.items()):
        for b, pb in sorted(owner.items()):
            if pa != pb and name_pattern(a).search(b):
                problems.append(f"{a!r} ({pa}) matches inside {b!r} ({pb}): one name would match two packages")
    return problems


_named_lock = threading.Lock()
_named_cache: weakref.WeakKeyDictionary[Index, dict[str, list[tuple[Issue, str]]]] = weakref.WeakKeyDictionary()


def _named(index: Index) -> dict[str, list[tuple[Issue, str]]]:
    """package -> (issue, the name it used), for every issue in the index; computed once per index."""
    with _named_lock:
        if index not in _named_cache:
            out: dict[str, list[tuple[Issue, str]]] = {}
            for package, alias in ALIASES.items():
                for issue in index.issues:
                    hit = next((n for n in alias.names if name_pattern(n).search(issue.text)), None)
                    if hit:
                        out.setdefault(package, []).append((issue, hit))
            _named_cache[index] = out
        return _named_cache[index]


def parse_version(value: Any) -> str | None:
    """An OpenShift version as given (4.21 or 4.21.9, a pre-release suffix allowed), or None."""
    return value if isinstance(value, str) and _OCP.match(value) else None


def _release(version: str) -> str:
    m = _OCP.match(version)
    if m is None:  # parse_version accepted it, so this cannot happen
        raise ValueError(version)
    return f"{int(m.group(1))}.{int(m.group(2))}"


def live_openshift_version(backend: Any) -> tuple[str | None, str]:
    """The version the cluster runs: the newest Completed entry of ClusterVersion ``status.history`` (the rule the
    must-gather analyser uses), else ``status.desired.version``. Returns (None, why) when it could not be read."""
    from kube_noob.errors import KubeNoobError

    try:
        cv = backend.get("clusterversions", name="version")
    except KubeNoobError as exc:
        return None, f"the ClusterVersion could not be read ({ops._text(str(exc), 200)})"
    status = ops._d(ops._d(cv).get("status"))
    history = [h for h in ops._l(status.get("history"))[:200] if isinstance(h, dict)]
    current = next((h.get("version") for h in history if h.get("state") == "Completed"), None)
    version = parse_version(current) or parse_version(ops._d(status.get("desired")).get("version"))
    if version is None:
        return None, "the ClusterVersion held no version in the form this reads"
    return version, ""


# ------------------------------------------------------------------------------------------------- the join ----


def _row(issue: Issue, name: str, package: str, as_of: Any) -> dict[str, Any]:
    """One issue as shown. Every field from the corpus passes ``ops._text``: a local copy written by ``corpus
    known-issues`` is data from outside, like the objects it is joined with."""
    raw_fix = issue.fixed_in if issue.kind == "known" else issue.version
    fix = ops._text(raw_fix, 40) or None
    minor = ops._text(issue.minor, 20)
    if issue.kind == "known":
        status = f"known issue in OpenShift {minor}" + (
            f"; the release notes list a fix in OpenShift {fix}" if fix else "; the release notes list no fix"
        )
    else:
        status = f"listed as fixed in OpenShift {fix}"
    if fix:
        has_fix, why = (
            "not-determined",
            f"the release notes state the fix as an OpenShift release ({fix}), not a version of {package}: the "
            "installed operator's version cannot be compared with it, and OLM updates the operator from its catalog, "
            "not with the cluster",
        )
    else:
        has_fix, why = "no-fix-listed", "the release notes list no fix for this issue"
    return {
        "id": ops._text(issue.id, 40),
        "url": ops._text(issue.url, 200),
        "kind": issue.kind if issue.kind in ("known", "fixed") else ops._text(issue.kind, 20),
        "release": minor,
        "fixedInOpenShift": fix,
        "status": status,
        "summary": ops._text(issue.summary, 300),
        "workaround": ops._text(issue.workaround, 300) or None,
        "matchedName": name,
        "installedHasFix": has_fix,
        "why": why,
        "source": ops._text(issue.source, 300),
        "knownIssuesAsOf": as_of,
    }


def _issue_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (vkey(row["release"]), row["kind"], row["id"], vkey(row["fixedInOpenShift"] or "0"), row["source"])


def assess(
    collected: ops.Collected,
    *,
    openshift_version: str | None,
    version_from: str | None,
    version_note: str = "",
    top: int = ops.MAX_OPERATORS,
    issues_per_operator: int = MAX_ISSUES_PER_OPERATOR,
    data_dir: Path | None = None,
    index: Index | None = None,
) -> dict[str, Any]:
    """The installed operators of ``collected`` (the same collection the inventory uses), each matched against the
    release notes of the cluster's OpenShift release. Deterministic: sorted, and built from the sorted inventory."""
    inv = ops.inventory(collected, top=ops.MAX_OPERATORS)  # every operator the inventory holds, up to its cap
    idx = index if index is not None else get_index(data_dir)
    knowledge = idx.knowledge()
    as_of = ops._text(knowledge.get("knownIssuesAsOf"), 40) or None
    releases: list[str] = [ops._text(r, 20) for r in knowledge.get("openshiftReleases") or []]
    version = parse_version(openshift_version)
    release = _release(version) if version else None
    indexed = None if release is None else release in releases
    named = _named(idx)

    entries: list[dict[str, Any]] = []
    for op in inv["operators"]:
        entry: dict[str, Any] = {
            k: op[k] for k in ("namespace", "csv", "package", "packageFrom", "version", "versionFrom") if k in op
        }
        entry["inventoryState"] = op["state"]
        notes: list[str] = []
        rows: list[dict[str, Any]] = []
        package = op.get("package")
        if op["state"] in ops.UNDETERMINED_STATES:
            notes.append("whether this operator is installed was not determined by the inventory")
        if op["state"] in NOT_INSTALLED:
            verdict: OpVerdict = "not-installed"
            reason = "the inventory shows it subscribed to but not installed, so it was not assessed"
        elif indexed is False:
            verdict = "not-determined"
            reason = (
                f"OpenShift {release} is not in the indexed release notes ({', '.join(releases)}), so whether they "
                "name this operator for the release the cluster runs is not determined"
            )
        elif not package:
            verdict = "package-unknown"
            reason = (
                "its package is not known (no Subscription or olm.package property names it), so it was not matched "
                "against the release notes; the CSV's name is not used to guess it"
            )
        elif package not in ALIASES:
            verdict = "no-alias"
            reason = (
                "not matched against the release notes (no alias): kube-noob has no entry saying what name the "
                "release notes use for this package, which is not the same as no reported issue"
            )
        else:
            for issue, name in named.get(package, []):
                if release is None or issue.minor == release:
                    rows.append(_row(issue, name, package, as_of))
            rows = sorted({_issue_key(r): r for r in rows}.values(), key=_issue_key)
            if rows:
                verdict = "named"
                where = f"OpenShift {release}" if release else f"OpenShift {', '.join(releases)} (not narrowed)"
                reason = f"the {where} release notes name this operator in {len(rows)} issue(s)"
            elif release is None:
                verdict = "not-determined"
                reason = "no indexed release notes name it, and the cluster's release is not known"
            else:
                verdict = "none-named"
                reason = (
                    f"no issue in the OpenShift {release} release notes names this operator; that says the notes "
                    "do not name it, not that it has no reported issue"
                )
        entry["verdict"] = verdict
        entry["reason"] = reason
        entry["issuesTotal"] = len(rows)
        entry["issues"] = rows[:issues_per_operator]
        entry["notes"] = notes
        entries.append(entry)

    entries.sort(
        key=lambda e: (VERDICTS.index(e["verdict"]), e["namespace"], e.get("package") or "", e.get("csv") or "")
    )
    counts = Counter(e["verdict"] for e in entries)
    not_assessed = inv.get("notShown", 0)
    caveats = [f"inventory: {c}" for c in inv["caveats"]]
    if not_assessed:
        caveats.append(f"{not_assessed} operator(s) past the inventory's cap of {ops.MAX_OPERATORS} were not assessed")
    if version is None:
        caveats.append(
            "the cluster's OpenShift version is not known"
            + (f" ({version_note})" if version_note else "")
            + f": issues were not narrowed to its release, and every indexed release ({', '.join(releases)}) was "
            "searched; pass --openshift-version to narrow them"
        )
    elif indexed is False:
        caveats.append(
            f"OpenShift {version} (release {release}) is outside the indexed release notes ({', '.join(releases)}, as "
            f"of {as_of}): every operator is not determined"
        )
    if counts["no-alias"]:
        caveats.append(
            f"{counts['no-alias']} operator(s) have no alias and were not matched against the release notes; that is "
            "not the same as having no reported issue"
        )
    if counts["package-unknown"]:
        caveats.append(f"{counts['package-unknown']} operator(s) have no known package and were not matched")
    undetermined = [e for e in entries if e["inventoryState"] in ops.UNDETERMINED_STATES]
    if undetermined:
        names = ", ".join(f"{e['namespace']}/{e.get('csv') or e.get('package') or '?'}" for e in undetermined[:10])
        caveats.append(f"the inventory could not say whether these are installed: {names}")

    if inv["verdict"] in ("not-determined", "no-olm"):
        answer = inv["verdict"]
    elif indexed is False:
        answer = "not-determined"
    elif inv["complete"] and version is not None and not not_assessed:
        answer = "assessed"
    else:
        answer = "partial"
    complete = answer in {"no-olm", "assessed"}
    shown = entries[:top]
    out: dict[str, Any] = {
        "verdict": answer,
        "complete": complete,
        "summary": _summary(answer, inv, counts, len(entries), release, releases, as_of),
        "cluster": {
            "openshiftVersion": version,
            "versionFrom": version_from if version else None,
            "release": release,
            "indexed": indexed,
        },
        "knowledge": {
            "knownIssuesAsOf": as_of,
            "openshiftReleases": releases,
            "source": "OpenShift release notes (openshift/openshift-docs), known and fixed issues",
        },
        "counts": {
            "operators": len(entries),
            "named": counts["named"],
            "noneNamed": counts["none-named"],
            "noAlias": counts["no-alias"],
            "packageUnknown": counts["package-unknown"],
            "notDetermined": counts["not-determined"],
            "notInstalled": counts["not-installed"],
            "issues": sum(e["issuesTotal"] for e in entries),
        },
        "operators": shown,
        "operatorsTotal": len(entries),
    }
    if len(entries) > len(shown):
        out["notShown"] = len(entries) - len(shown)
    out["inventory"] = {k: inv[k] for k in ("source", "verdict", "complete", "summary")}
    out["caveats"] = caveats
    out["method"] = method_note()
    return out


MUST_GATHER_ISSUES_PER_OPERATOR = 5  # inside a must-gather analysis, which already carries findings and inventory


def for_must_gather(collected: ops.Collected, version: Any, data_dir: Path | None = None) -> dict[str, Any]:
    """The answer for a must-gather already analysed: its ClusterVersion's completed version narrows the issues, and
    each operator carries at most ``MUST_GATHER_ISSUES_PER_OPERATOR`` of them (``issuesTotal`` says how many)."""
    parsed = parse_version(version)
    return assess(
        collected,
        openshift_version=parsed,
        version_from="must-gather" if parsed else None,
        version_note="" if parsed else "the must-gather holds no ClusterVersion with a completed version",
        issues_per_operator=MUST_GATHER_ISSUES_PER_OPERATOR,
        data_dir=data_dir,
    )


def _summary(
    verdict: str,
    inv: dict[str, Any],
    counts: Counter[str],
    total: int,
    release: str | None,
    releases: list[str],
    as_of: Any,
) -> str:
    if verdict == "no-olm":
        return "not an OLM cluster: there are no OLM-installed operators to match, and nothing was evaluated"
    if inv["verdict"] == "not-determined":
        return (
            f"not determined: the installed operators could not be read ({inv['summary']}). That does not mean no "
            "operator has a reported issue."
        )
    if verdict == "not-determined":
        return (
            f"not determined: OpenShift {release} is not in the indexed release notes ({', '.join(releases)}, as of "
            f"{as_of}), so none of the {total} operator(s) was assessed"
        )
    where = f"the OpenShift {release} release notes" if release else "the indexed release notes (release not known)"
    head = (
        f"{counts['named']} of {total} operator(s) named in {where} as of {as_of}; {counts['none-named']} named in "
        f"none; {counts['no-alias']} operator(s) have no alias"
    )
    extra = [
        f"{counts[k]} {label}"
        for k, label in (
            ("package-unknown", "without a known package"),
            ("not-determined", "not determined"),
            ("not-installed", "not installed"),
        )
        if counts[k]
    ]
    if extra:
        head += "; " + ", ".join(extra)
    if verdict == "partial":
        head += " -- incomplete" if inv["complete"] else f" -- incomplete: the inventory is {inv['verdict']}"
        if release is None:
            head += "; the cluster's release is not known"
    return head


# ------------------------------------------------------------------------------------------------- text ----


def render_text(out: dict[str, Any]) -> str:
    """The text view: every operator, every issue with its link, source and the corpus date, and every caveat the
    JSON carries (G221)."""
    c, cl, k = out["counts"], out["cluster"], out["knowledge"]
    version = (
        f"OpenShift {cl['openshiftVersion']} (from the {cl['versionFrom']})"
        if cl["openshiftVersion"]
        else ("OpenShift version not known")
    )
    lines = [
        f"operator known issues ({out['inventory']['source']}): {out['verdict']} -- {out['summary']}",
        f"cluster: {version}; release notes of OpenShift {', '.join(k['openshiftReleases'])} as of "
        f"{k['knownIssuesAsOf']}",
        f"counts: {c['operators']} operator(s), {c['named']} named, {c['noneNamed']} named in none, {c['noAlias']} "
        f"no alias, {c['packageUnknown']} package unknown, {c['notDetermined']} not determined, {c['notInstalled']} "
        f"not installed, {c['issues']} issue(s)",
    ]
    for op in out["operators"]:
        name = op.get("csv") or "?"
        version_text = op.get("version") or "unknown"
        if op.get("versionFrom") == "derived-from-name":
            version_text += " (derived from the name)"
        lines.append(
            f"  {op['namespace']}/{name}  package {op.get('package') or 'unknown'}  version {version_text}  "
            f"{op['verdict']}: {op['reason']}"
        )
        for note in op["notes"]:
            lines.append(f"      note: {note}")
        for row in op["issues"]:
            lines.append(f"      {row['id']} [{row['kind']}, OpenShift {row['release']}] {row['status']}")
            lines.append(f"        {row['summary']}")
            lines.append(
                f"        named as {row['matchedName']!r}; fix in the installed operator: "
                f"{row['installedHasFix']} ({row['why']})"
            )
            lines.append(f"        {row['url']}  source {row['source']}  (corpus as of {row['knownIssuesAsOf']})")
        if op["issuesTotal"] > len(op["issues"]):
            lines.append(f"      and {op['issuesTotal'] - len(op['issues'])} more issue(s) (see --format json)")
    if out.get("notShown"):
        lines.append(f"  and {out['notShown']} more operator(s) (see --format json)")
    lines.append(f"inventory: {out['inventory']['verdict']} -- {out['inventory']['summary']}")
    for caveat in out["caveats"]:
        lines.append(f"caveat: {caveat}")
    lines.append(f"method: {out['method']}")
    return "\n".join(lines)
