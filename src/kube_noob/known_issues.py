"""Is this a reported issue? Match an error against the OpenShift release notes and the local Red Hat Jira copy.

The index holds every known issue (open in a release) and every fixed issue (fixed in a release or update) that the
release notes link to an issue id, for the minor releases in the bundled snapshot. The query is the text plus the
terms of the signals it carries or implies (``kube_noob.signals``: an alert name, an event reason, "leader changed"
for etcd leader elections). A match is returned only when the text itself shares rare words with the issue, backed by
more rare words, a strong score or the signal's terms, so a generic error (OOMKilled, ImagePullBackOff) does not pull
in an unrelated bug. The frozen eval ``data/evals/known_issue_recall.yaml`` gates recall and precision. Each match
carries the issue link, the release-notes file it came from, whether a fix exists, and what that means for the
version the user runs.

Data: ``kube_noob/data/known_issues/*.json`` (refreshed with ``scripts/vendor_known_issues.py``) plus, when present,
a newer copy in ``<dataDir>/known_issues/`` written by ``kube-noob corpus known-issues --online``.

When the install keeps a local copy of Red Hat's public Jira (``kube-noob corpus jira --online``), tickets that match
are added with what became of them: fixed and in which release, still open, or closed as not a bug, won't fix or a
duplicate (see ``kube_noob.tickets``). A release-note issue that is also in the copy gains the ticket's current state.
"""

from __future__ import annotations

import functools
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from kube_noob import sanitize
from kube_noob.catalog import OPENSHIFT_FAMILY
from kube_noob.knowledge.store import Chunk, KnowledgeStore, builtin_chunks, tokenize
from kube_noob.versions import read_version, shown_version

MIN_RARE_TERMS = 3  # rare words shared with the issue text before it counts as a match
RARE_SHARE = 0.03  # a word in at most 3% of issues is rare
MIN_SCORE = 20.0  # BM25 score floor, set from tests/test_known_issues.py
GENERAL_MAX_CHUNKS = 2  # and in at most 2 sections of the bundled docs (a count: new documents never make more
# words rare, which a share of sections would; a count of documents was measured and made 22 test-half rows name
# an unrelated bug)
RELATIVE_FLOOR = 0.75  # further matches must score at least 75% of the best one
STRONG_SCORE = 40.0  # a score this high with two rare shared words, or one and a clear lead, is a match
DOMINANCE = 2.0  # "a clear lead": at least twice the next applicable issue's score
QUOTE_WORDS = 7  # a run of this many words copied from an issue's text, one of them rare, is a quotation of it
_WORD = re.compile(r"[a-z0-9]+(?:[._/-][a-z0-9]+)*")


@functools.cache
def _templates() -> tuple[re.Pattern[str], ...]:
    from kube_noob.signals.vocab import MESSAGE_TEMPLATES

    return tuple(re.compile(t) for t in MESSAGE_TEMPLATES)


def strip_templates(text: str) -> str:
    """``text`` with the fixed wording of known component messages replaced by their variable parts
    (``kube_noob.signals.vocab.MESSAGE_TEMPLATES``): "Unable to retrieve some image pull secrets (regcred); ..." keeps
    "regcred" only."""
    for rx in _templates():
        text = rx.sub(lambda m: " ".join(g for g in m.groups() if g), text)
    return text


def stems(text: str, known: Callable[[str], bool] | None = None) -> str:
    """Light stems so "restarted", "draining" and "uncordoning" meet "restart", "drain" and "uncordon": the word
    without -ed or -ing, or with a final e ("updated" -> "update"). With ``known``, only stems that are real words
    of the corpus are kept, so "exceed" never becomes "exce"."""
    out: set[str] = set()
    for tok in tokenize(text[:200_000]):
        if not tok.isalpha() or len(tok) < 6 or tok.endswith("eed"):
            continue
        for suffix in ("ing", "ed"):
            if tok.endswith(suffix) and len(tok) - len(suffix) >= 4:
                stem = tok[: -len(suffix)]
                if len(stem) >= 4 and stem[-1] == stem[-2] and stem[-1] not in "aeiouls":
                    stem = stem[:-1]  # "running" -> "run"
                for candidate in (stem, stem + "e"):
                    if known is None or known(candidate):
                        out.add(candidate)
    return " ".join(sorted(out))


# Words and names only OpenShift (and its Red Hat family) uses. A text without one, and no platform given, is not
# matched against OpenShift release notes: on 25,292 community questions (Stack Overflow, GitHub, forums) matching
# them anyway put an OpenShift bug at the top of 6,177 answers about other platforms (scripts/eval_questions.py).
_OPENSHIFT_CONTEXT = re.compile(
    r"(?i)\b(?:openshift|okd|ocp|rhocp|ocpbugs|rosa|aro|hypershift|hosted control planes?|rhcos|red hat|redhat|rhel|"
    r"oc(?:\s+(?:adm|get|describe|logs|rsh|debug|apply|create|delete|patch|edit|login|project|new-app|"
    r"rollout|whoami|mirror|image|import-image|start-build)\b)|oc-mirror|must-gather|machineconfig(?:pool)?s?|"
    r"machine-config(?:-operator|-daemon)?|clusteroperators?|clusterversions?|cluster-version-operator|"
    r"securitycontextconstraints?|security context constraints?|scc|application is not available|egressips?|"
    r"ovn-kubernetes|ovnkube|openshift-sdn|olm|operatorhub|catalogsources?|"
    r"clusterserviceversions?|ingresscontrollers?|imagestreams?|buildconfigs?|deploymentconfigs?|routes?\.route|"
    r"route\.openshift\.io|odf|ocs|noobaa|rhacs|stackrox|quay\.io/openshift|registry\.redhat\.io|"
    r"cluster-etcd-operator|kube-apiserver-operator|ibm cloud satellite|microshift|openshift-[a-z0-9-]{1,60}|"
    r"(?<![a-z0-9.-])[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){0,3}\.openshift\.io|consolequickstarts?|consoleplugins?|consolelinks?|helmchartrepositor(?:y|ies)|"
    r"baremetalhosts?|bmh|metal3|machinesets?|machine-api|controlplanemachinesets?|nmstate|sriov|"
    r"cluster-logging|clusterlogforwarder|lokistack|compliance-operator|file-integrity-operator)\b"
)


# Everyday English in bug reports and questions (base forms and common inflections). In the small release-note corpus
# these look rare, and three of them ("deployed", "following", "plugin") were enough to match an unrelated issue.
EVERYDAY_WORDS = frozenset(
    """
    too took long time times very much many few linux enterprise red hat rpm package packages os kubernetes
    kubernete k8s yaml json follow following cause causes caused deploy deployed deploying deployment plugin plugins
    mirror mirrors replace replaced change changed update updated install installed upgrade upgraded add added
    remove removed delete deleted run runs ran work works worked try tried need needs want see show shows display
    return returns report reports expect expected happen happens happened issue issues problem problems question
    questions example examples case cases way ways step steps thing things something anything nothing everything
    someone user users team project projects application applications app apps setup setting settings option options
    feature features support supported allow allows enable enabled disable disabled include includes contain
    contains provide provides require requires required apply applied configure configured configuration manage
    managed handle handled send sent receive received access load loaded save saved store stored open opened close
    closed test tests tested testing check checked find found create created build built release released new old
    different same multiple several other another correct correctly incorrect incorrectly wrong right properly
    successful successfully always never sometimes already instead without within between during because however
    even here what which who why how where whether able unable possible impossible current currently latest previous
    next first second third last main help thanks thank please hello hi regards anyone idea ideas tips solution
    solutions fix fixed fixes fixing behavior behaviour result results output input information details detail list
    lists page pages view views field fields name names label labels tag tags type types mode format line lines
    number numbers size make local through come custom component components private clean cleaned confirm confirmed
    verify verified understand trying mean means meant actual actually specific being beside besides document
    documented retrieve whole entire simple simply really although though
    """.split()  # noqa: SIM905 - a word list reads better as text
)


def openshift_context(text: str) -> bool:
    """Whether the text says it is about OpenShift or the Red Hat products around it."""
    return bool(_OPENSHIFT_CONTEXT.search(text[:200_000]))


# Red Hat names that run on any Kubernetes or none: a Kubespray cluster on RHEL, RHACS on EKS, an image from
# registry.redhat.io. They count for the bug matcher (openshift_context) but do not make the cluster OpenShift.
_NOT_THE_CLUSTER = frozenset({"rhel", "red hat", "redhat", "rhacs", "stackrox", "registry.redhat.io"})


_RHACS_TEXT = re.compile(r"(?i)\b(?:rhacs|stackrox|roxctl|roxie|ROX-\d+|advanced cluster security)\b")


def openshift_cluster_context(text: str) -> bool:
    """Whether the text says the cluster itself is OpenShift (or ROSA, ARO, OKD...): what decides OpenShift steps and
    causes. "RHEL", "Red Hat" or RHACS alone do not."""
    return any(m.group(0).lower() not in _NOT_THE_CLUSTER for m in _OPENSHIFT_CONTEXT.finditer(text[:200_000]))


def _forms(token: str) -> tuple[str, ...]:
    """The base forms an English inflection may come from: "deployed" -> "deploy", "following" -> "follow",
    "causes" -> "cause", "mirrors" -> "mirror", "libraries" -> "library"."""
    out = [token]
    for suffix, add in (
        ("ies", "y"),
        ("es", ""),
        ("s", ""),
        ("ed", ""),
        ("ed", "e"),
        ("ing", ""),
        ("ing", "e"),
        ("ly", ""),
    ):
        if token.endswith(suffix) and len(token) - len(suffix) >= 3:
            out.append(token[: -len(suffix)] + add)
    return tuple(out)


_SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z(`])")
_lock = threading.RLock()  # re-entrant: building an index builds the general store too
_cache: dict[str, Index] = {}
_general: dict[str, KnowledgeStore] = {}


def vkey(version: str) -> tuple[int, ...]:
    # Bounded: a 5,000-digit number in a label is not a version, and int() of it raises past Python's digit limit.
    return tuple(int(p[:9]) for p in re.findall(r"\d+", version[:200])[:6])


def _minor(version: str) -> str:
    return ".".join(version.split(".")[:2])


@dataclass(frozen=True)
class Issue:
    id: str
    ids: tuple[str, ...]
    kind: str  # "known" (open in `minor`) or "fixed" (fixed in `version`)
    minor: str
    version: str
    text: str
    source: str
    issued: str | None
    fixed_in: str | None

    @property
    def summary(self) -> str:
        first = _SENTENCE.split(self.text, maxsplit=1)[0]
        return first if len(first) <= 280 else first[:277].rsplit(" ", 1)[0] + "..."

    @property
    def workaround(self) -> str | None:
        if self.kind != "known":
            return None
        for sentence in _SENTENCE.split(self.text):
            if re.match(r"(?i)(as a workaround|to work around|you can avoid|to avoid this|workaround:)", sentence):
                return sentence
        return "There is no supported workaround." if re.search(r"(?i)no (supported )?workaround", self.text) else None

    @property
    def url(self) -> str:
        return f"https://redhat.atlassian.net/browse/{self.id}"

    def status(self, running: str | None, advise: bool = True, shown: str | None = None) -> str:
        """What the issue is, and, when ``advise`` (the index can answer for ``running``), what it means for that
        version. Without ``advise`` the fix release is stated and no update path is suggested: a release the index
        does not hold may have the fix as a backport, which these release notes cannot show (G277)."""
        named = shown or running
        if running and running.count(".") == 1:
            # 4.21 names no z-stream: whether the cluster is before or after a 4.21.z fix is not known from it.
            named, advise_z = f"{named} (no z-stream given)", False
        else:
            advise_z = True
        if self.kind == "known":
            if self.fixed_in:
                msg = f"Known issue in OpenShift {self.minor}; fixed in {self.fixed_in}."
                if running and advise and advise_z and vkey(running) < vkey(self.fixed_in):
                    msg += f" You run {named}: updating to {self.fixed_in} or later fixes it."
                elif running and advise and not advise_z and _minor(self.fixed_in) == running:
                    msg += f" You run {named}: {self.fixed_in} or later has the fix."
            else:
                msg = f"Known issue in OpenShift {self.minor}; the release notes list no fix yet."
            if running and not advise:
                msg += f" Whether {named} has it, or a fix for it, is not determined from these release notes."
            return msg
        msg = f"Reported and fixed in OpenShift {self.version}."
        if running and advise and not advise_z:
            msg += f" You run {named}: {self.version} or later has the fix."
        elif running and advise and vkey(running) < vkey(self.version):
            msg += f" You run {named}: updating to {self.version} or later fixes it."
        elif running and not advise:
            msg += (
                f" Not update advice for {named}: whether it has this fix is not determined from these release "
                "notes (a backport may exist)."
            )
        return msg

    def as_dict(
        self, running: str | None, score: float, advise: bool = True, shown: str | None = None
    ) -> dict[str, Any]:
        return {
            "id": self.id,
            "url": self.url,
            "kind": self.kind,
            "foundIn": self.minor if self.kind == "known" else None,
            "fixedIn": self.fixed_in if self.kind == "known" else self.version,
            "status": self.status(running, advise, shown),
            "summary": self.summary,
            "workaround": self.workaround,
            "source": self.source,
            "score": round(score, 2),
        }


class Index:
    def __init__(self, issues: list[Issue], meta: dict[str, Any]) -> None:
        self.issues = issues
        self.meta = meta
        raw: set[str] = set()
        for i in issues:
            raw.update(tokenize(f"{i.summary} {i.text}"))
        general = _general_store()
        self.known = lambda t: t in raw or general.doc_frequency(t) > 0
        self.store = KnowledgeStore(
            Chunk(
                chunk_id=f"{i.id}@{i.version}#{n}",
                doc_id=i.id,
                title=i.summary,
                heading="",
                text=f"{i.text}\n{stems(i.text, self.known)}",
                url=i.url,
                license="Apache-2.0",
                origin="known-issues",
                source_id=f"release-notes:{i.minor}",
                version=i.version,
            )
            for n, i in enumerate(issues)
        )
        self.by_chunk = {f"{i.id}@{i.version}#{n}": i for n, i in enumerate(issues)}
        self._token_cache: dict[str, set[str]] = {}
        self._newest: dict[str, str] | None = None

    def knowledge(self) -> dict[str, Any]:
        minors = sorted({i.minor for i in self.issues}, key=vkey)
        out: dict[str, Any] = {
            "knownIssuesAsOf": self.meta.get("retrievedAt"),
            "openshiftReleases": minors,
            "issues": len(self.issues),
        }
        rejected = self.meta.get("_rejected") or []
        if rejected:  # every consumer returns this dict, so a record left out is never silent
            out["recordsRejected"] = len(rejected)
            out["rejectedRecords"] = list(rejected[:MAX_REJECTED_SHOWN])
        if self.meta.get("_localNote"):
            out["localCopyNote"] = self.meta["_localNote"]
        return out

    def newest(self) -> dict[str, str]:
        """The newest z-stream release each indexed minor's notes reach (``4.22`` -> ``4.22.18``)."""
        if self._newest is None:
            out: dict[str, str] = {}
            for i in self.issues:
                for v in (i.version, i.fixed_in or ""):
                    if v.count(".") == 2 and _minor(v) == i.minor and vkey(v) > vkey(out.get(i.minor, "0.0.0")):
                        out[i.minor] = v
            self._newest = out
        return self._newest

    def coverage(self, version: str | None) -> dict[str, Any]:
        """Whether the index can answer for ``version`` (see ``version_coverage``)."""
        k = self.knowledge()
        return version_coverage(version, k["openshiftReleases"], k["knownIssuesAsOf"], self.newest())

    def _tokens(self, issue: Issue) -> set[str]:
        key = f"{issue.id}@{issue.version}"
        if key not in self._token_cache:
            text = f"{issue.summary} {issue.text}"
            self._token_cache[key] = set(tokenize(text)) | set(tokenize(stems(text, self.known)))
        return self._token_cache[key]

    def _rare(self, shared: set[str]) -> list[str]:
        """Words that are rare among issues and in general Kubernetes writing and are not everyday status vocabulary,
        so `spec`, `pod`, `deadline exceeded` or `securitycontext` never make a match on their own."""
        from kube_noob.tickets import GENERIC_WORDS

        general = _general_store()
        return sorted(
            t
            for t in shared
            if len(t) > 2
            and not any(f in GENERIC_WORDS or f in EVERYDAY_WORDS for f in _forms(t))
            and self.store.doc_frequency(t) <= RARE_SHARE
            and general.doc_count(t) <= GENERAL_MAX_CHUNKS
        )

    def _rare_shared(self, query_tokens: set[str], issue: Issue) -> list[str]:
        return self._rare(query_tokens & self._tokens(issue))

    def _quotes(self, text: str) -> set[str]:
        """Runs of ``QUOTE_WORDS`` words from ``text`` with a rare word in them: an error copied from the product
        quotes the issue that describes it, even when it shares fewer rare words than ``MIN_RARE_TERMS``."""
        words = _WORD.findall(text.lower())[:3000]
        rare = {w for w in set(words) if self._rare(set(tokenize(w)))}
        return {
            " ".join(words[i : i + QUOTE_WORDS])
            for i in range(len(words) - QUOTE_WORDS + 1)
            if rare.intersection(words[i : i + QUOTE_WORDS])
        }

    def _quoted(self, quotes: set[str], issue: Issue) -> bool:
        body = f" {' '.join(_WORD.findall(issue.text.lower()))} "
        return any(f" {q} " in body for q in quotes)

    def match(
        self,
        text: str,
        platform: str | None = None,
        version: str | None = None,
        limit: int = 3,
        require_context: bool = False,
    ) -> dict[str, Any]:
        """Issues that describe ``text``. Candidates come from text search on the words and on the signals the text
        carries or implies (``kube_noob.signals``: an alert name, or "leader changed" for etcd leader elections);
        a candidate counts only with rare shared words from the text itself, backed by more rare words, a strong
        score or support from the signal's terms."""
        out: dict[str, Any] = {"knowledge": self.knowledge(), "matches": []}
        if platform and platform not in OPENSHIFT_FAMILY:
            out["note"] = "The index holds OpenShift release-note issues; it does not apply to plain Kubernetes."
            return out
        if require_context and not platform and not openshift_context(text):
            out["note"] = (
                "The text does not say it is about OpenShift, so the OpenShift release notes were not searched; give "
                "the platform (openshift, rosa-hcp) to search them."
            )
            return out
        if (
            require_context
            and not platform
            and _RHACS_TEXT.search(text[:200_000])
            and not openshift_cluster_context(text)
        ):
            # A RHACS ticket (roxctl, Scanner, Central, the UI) that never says the cluster is OpenShift: OpenShift
            # release-note issues matched it only on shared words (community graders, 2026-10-28).
            out["note"] = (
                "The text is about RHACS and does not say the cluster is OpenShift, so the OpenShift release notes "
                "were not searched; give the platform (openshift, rosa-hcp) to search them."
            )
            return out
        from kube_noob.signals import extract
        from kube_noob.signals.catalogue import infer, terms_for

        # One reading of the version for the coverage statement and the matching alike (G277): a version that is
        # cleaned for the one and raw for the other answered "determined" while matching nothing.
        cv = read_version(version)
        out["versionCoverage"] = self.coverage(version)
        advise = out["versionCoverage"]["status"] == "determined"
        if len(text) > MATCH_TEXT:
            # The end, as diagnose and insight read it: the head of a long paste once decided alone, so an issue
            # described at the end of 105,515 characters answered "no reported issue" (G277).
            out["inputTruncated"] = truncation(len(text))
            out["versionCoverage"] = cut_coverage(out["versionCoverage"], out["inputTruncated"])
            text = text[-MATCH_TEXT:]
        running = cv.numeric if cv else None
        shown = cv.shown if cv else None
        signals = [x for x in extract(text) if x.kind in {"alert", "event_reason", "pod_reason"}] + infer(text)
        sig_terms = terms_for(signals)
        text = strip_templates(text)  # the fixed words of component messages are not evidence for any one issue
        query = f"{text}\n{stems(text, self.known)}"
        q_tokens = set(tokenize(query))
        sig_tokens = set(tokenize(" ".join(sig_terms))) - q_tokens
        scores: dict[str, tuple[float, float]] = {}  # chunk id -> (score on the text, score with signal terms)
        for hit in self.store.search(query, limit=40):
            scores[hit.chunk.chunk_id] = (hit.score, hit.score)
        if sig_terms:
            for hit in self.store.search(f"{query}\n{' '.join(sig_terms)}", limit=40):
                own = scores.get(hit.chunk.chunk_id, (0.0, 0.0))[0]
                scores[hit.chunk.chunk_id] = (own, max(hit.score, own))
        quotes = self._quotes(text)
        rows: list[tuple[float, Issue, list[str], list[str]]] = []
        best: dict[str, float] = {}
        for chunk_id, (own, expanded) in scores.items():
            issue = self.by_chunk[chunk_id]
            if running and not self._applies(issue, running):
                continue
            doc = self._tokens(issue)
            r_text, r_sig = _distinct(self._rare(q_tokens & doc)), _distinct(self._rare(sig_tokens & doc))
            score = expanded if r_sig else own
            if score <= best.get(issue.id, -1.0):
                continue
            best[issue.id] = score
            rows.append((score, issue, r_text, r_sig))
        rows = sorted((r for r in rows if best[r[1].id] == r[0]), key=lambda r: (-r[0], r[1].id))
        top = 0.0
        for n, (score, issue, r_text, r_sig) in enumerate(rows):
            runner_up = rows[n + 1][0] if n + 1 < len(rows) else 0.0
            if score < MIN_SCORE or (top and score < RELATIVE_FLOOR * top):
                continue
            quoted = bool(r_text) and self._quoted(quotes, issue)
            accepted = (
                quoted
                or len(r_text) >= MIN_RARE_TERMS
                or (len(r_text) >= 1 and len(r_text) + len(r_sig) >= MIN_RARE_TERMS)
                or (len(r_text) >= 2 and score >= STRONG_SCORE)
                or (len(r_text) >= 1 and score >= STRONG_SCORE and score >= DOMINANCE * runner_up)
            )
            if not accepted:
                continue
            top = top or score
            match = {
                **issue.as_dict(running, score, advise, shown),
                "sharedTerms": (r_text + r_sig)[:8],
                "exactError": quoted,
            }
            if r_sig:
                match["signals"] = sorted({f"{x.kind}:{x.name}" for x in signals})[:5]
            out["matches"].append(match)
            if len(out["matches"]) >= limit:
                break
        if not out["matches"] and out["versionCoverage"]["status"] == "not-determined":
            out["note"] = (
                f"Nothing in the indexed release notes ({', '.join(out['knowledge']['openshiftReleases'])}) matches "
                f"this text, and that is not an answer for {shown}: see versionCoverage."
            )
        elif not out["matches"]:
            out["note"] = (
                "No reported issue in the OpenShift release notes matches this text closely. "
                f"The index covers OpenShift {', '.join(out['knowledge']['openshiftReleases'])} "
                f"as of {out['knowledge']['knownIssuesAsOf']}."
            )
        return out

    @staticmethod
    def _applies(issue: Issue, running: str) -> bool:
        """Could this issue affect a cluster on `running`? Known: same or earlier minor and not yet fixed there.
        Fixed: the fix is in the same minor and the cluster is older than it."""
        if issue.kind == "known":
            if vkey(_minor(running)) < vkey(issue.minor):
                return False
            return not (issue.fixed_in and vkey(running) >= vkey(issue.fixed_in))
        if _minor(issue.version) != _minor(running):
            return False
        return vkey(running) < vkey(issue.version)


COVERAGE = ("determined", "not-determined", "not-narrowed")
MATCH_TEXT = 100_000  # characters of a paste the matcher reads: the END, where diagnose and insight also look


def truncation(total: int, read: int = MATCH_TEXT) -> dict[str, Any]:
    """What a result says when only the end of the text was matched."""
    return {
        "characters": total,
        "read": read,
        "why": f"the text is {total:,} characters and only the last {read:,} were matched against the release "
        "notes (failures are usually at the end), so an issue described before them can be missed",
    }


def cut_coverage(cov: dict[str, Any], cut: dict[str, Any]) -> dict[str, Any]:
    """``cov`` when the matcher read only part of the text: whatever the version, the list is not the whole answer."""
    return {
        **cov,
        "status": "not-determined",
        "inputTruncated": cut,
        "why": f"Known issues NOT DETERMINED for this text: {cut['why']}. " + str(cov.get("why", "")),
    }


def version_coverage(
    version: str | None, releases: list[str], as_of: str | None, newest: dict[str, str] | None = None
) -> dict[str, Any]:
    """Whether "no match" can mean "no reported issue" for ``version``: three-valued, never left to a note.

    ``determined``: an OpenShift release whose minor is in the index and whose z-stream the notes reach, so issues
    that cannot affect it were left out and an empty list is an answer for it. ``not-determined``: the index cannot
    answer for it -- its minor is not indexed, its z-stream is newer than the newest one the notes reach, or it is a
    pre-release, nightly or OKD build that the OpenShift release notes do not describe; matches are still narrowed
    by its minor and z, but no list here is the whole answer. ``not-narrowed``: no version, or text that is not one,
    so the answer covers every indexed release, including issues a cluster may already have the fix for.
    """
    held = ", ".join(releases) or "no release"
    dated = f" as of {as_of}" if as_of else ""
    shown = shown_version(version)
    cv = read_version(version)
    if shown is None:
        return {
            "status": "not-narrowed",
            "why": f"No version was given, so the answer is not narrowed by version: it covers every indexed release "
            f"({held}{dated}), including issues already fixed in yours. Give the version to leave those out.",
        }
    if cv is None:
        # The grammar (kube_noob.versions, shared with `operators issues`) takes the value exactly as typed: one with
        # white space or a hidden character around it is not read as the version it looks like, and this says so
        # rather than calling a clean-looking value "not a version".
        padded = read_version(shown) is not None
        what = (
            f"{shown} was given with white space or a hidden character around it, which is not a version"
            if padded
            else f"{shown} is not an OpenShift version (x.y or x.y.z, optionally with a build such as -rc.1)"
        )
        return {
            "status": "not-narrowed",
            "version": shown,
            "why": f"{what}, so the answer is not narrowed by version: it covers every indexed release "
            f"({held}{dated}).",
        }
    minor = cv.minor
    fix = f"Read the OpenShift {minor} release notes, or refresh the index (kube-noob corpus known-issues --online)."

    def undetermined(reason: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "status": "not-determined",
            "version": shown,
            **(extra or {}),
            "why": f"Known issues NOT DETERMINED for OpenShift {shown}: {reason} {fix}",
        }

    if minor not in releases:
        newer = bool(releases) and vkey(minor) > vkey(releases[-1])
        return undetermined(
            f"the index holds the release notes of {held}{dated}, and {minor} is not one of them. "
            + (
                f"Issues still open in an older release are listed, but {minor}'s own release notes were not read."
                if newer
                else "No match here does not mean no reported issue."
            )
        )
    if cv.okd:
        return undetermined(
            f"{shown} is an OKD build, and the index holds OpenShift Container Platform release notes, which do "
            f"not say which OKD build carries a fix. Matches are narrowed as for {cv.numeric}; none of them, and no "
            "absence of them, is an answer for this build."
        )
    if cv.build:
        return undetermined(
            f"{shown} is a pre-release or nightly build, and release notes describe released versions. Matches are "
            f"narrowed as for {cv.numeric}, but whether a fix listed for {cv.numeric} or later is in this build is "
            "not known."
        )
    through = (newest or {}).get(minor)
    if cv.has_z and through and vkey(cv.numeric) > vkey(through):
        return undetermined(
            f"the {minor} release notes in the index reach {through}{dated}, and {shown} is newer. Issues fixed in "
            f"{through} or earlier are left out correctly, but an open issue listed here may have been fixed after "
            f"{through}, and issues first reported after {through} are not in the index.",
            {"indexedThrough": through},
        )
    return {
        "status": "determined",
        "version": shown,
        "why": f"OpenShift {minor} is in the index ({held}{dated}): issues that cannot affect {shown} are left "
        "out, so no match means none of its reported issues matches.",
    }


def coverage(version: str | None, data_dir: Path | None = None) -> dict[str, Any]:
    """``version_coverage`` against the index ``data_dir`` selects."""
    return get_index(data_dir).coverage(version)


def coverage_line(cov: dict[str, Any] | None, listed: bool = True) -> str | None:
    """The sentence a text view prints, or ``None`` when there is nothing to warn about: the version was covered, or
    no version was given and (``listed`` false) nothing was listed that a version would have left out. A version
    that WAS given and could not be used is always said: a supplied value is never dropped silently."""
    if not cov or cov.get("status") == "determined":
        return None
    if cov.get("status") == "not-narrowed" and "version" not in cov and "versionUnreadable" not in cov and not listed:
        return None
    return str(cov["why"])


def issue_status(issue: Issue, version: str | None, data_dir: Path | None = None) -> str:
    """``issue.status`` for a version from outside (a ticket key looked up directly): advice only where the index
    can answer for that version."""
    cv = read_version(version)
    advise = get_index(data_dir).coverage(version)["status"] == "determined"
    return issue.status(cv.numeric if cv else None, advise, cv.shown if cv else None)


def _distinct(words: list[str]) -> list[str]:
    """One word per base form and per compound: "item" and "items", "openshift-etcd" and "etcd", or a prefixed name
    and the bare name after its slash, are one piece of evidence, not two."""
    out: list[str] = []
    seen: set[str] = set()
    for w in sorted(words, key=lambda t: (-len(t), t)):  # compounds first, so their parts are recognised as seen
        forms = set(_forms(w))
        parts = {f for p in re.split(r"[-._/]", w) if p for f in _forms(p)} if re.search(r"[-._/]", w) else set()
        parts |= {f for p in w.split("/")[1:] if p for f in _forms(p)}
        if forms & seen:
            continue
        seen |= forms | parts
        out.append(w)
    return sorted(out)


def _general_store() -> KnowledgeStore:
    """The bundled general docs, to tell everyday Kubernetes words from words specific to one issue."""
    with _lock:
        if "__general__" not in _general:
            _general["__general__"] = KnowledgeStore(builtin_chunks())
        return _general["__general__"]


# What a record may hold. The bundled snapshot is written by scripts/vendor_known_issues.py; a newer copy in
# <dataDir>/known_issues is written by `corpus known-issues --online` and is data from outside like any other, so
# every field is checked before it can become a link, a version or a line of output. ASCII digits only ([0-9], not
# \d, which accepts every script's digits) and no leading zeros, so "4.09" never sorts as 4.9.
_ISSUE_KEY = re.compile(r"^[A-Z][A-Z0-9]{0,15}-[1-9][0-9]{0,8}\Z")
_NUM = r"(?:0|[1-9][0-9]{0,2})"
_MINOR = re.compile(rf"^{_NUM}\.{_NUM}\Z")
_RELEASE = re.compile(rf"^{_NUM}\.{_NUM}(?:\.(?:0|[1-9][0-9]{{0,4}}))?\Z")
_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_COMMIT = re.compile(r"^[0-9a-f]{40}\Z")
_DOC_PATH = r"[A-Za-z0-9_][A-Za-z0-9_./-]{0,200}\.adoc"
_RELATIVE_SOURCE = re.compile(rf"^{_DOC_PATH}\Z")
_ABSOLUTE_SOURCE = re.compile(rf"^https://github\.com/openshift/openshift-docs/blob/[0-9a-f]{{40}}/{_DOC_PATH}\Z")
MAX_TEXT = 50_000
MAX_REJECTED_SHOWN = 10


def valid_date(value: Any) -> bool:
    """A calendar date written YYYY-MM-DD. Whether it is in the future cannot be decided deterministically (there is
    no clock in a pure function), so only its form and its existence on the calendar are checked."""
    import datetime

    if not isinstance(value, str) or not _DATE.match(value):
        return False
    try:
        datetime.date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _record_problem(r: Any, commits: dict[str, Any]) -> str | None:
    """Why a record cannot be used, or None."""
    if not isinstance(r, dict):
        return "not an object"
    for key, rx in (("id", _ISSUE_KEY), ("minor", _MINOR), ("version", _RELEASE)):
        if not isinstance(r.get(key), str) or not rx.match(r[key]):
            return f"{key} is not in the form the release notes use"
    if r.get("kind") not in ("known", "fixed"):
        return "kind is neither known nor fixed"
    if ".".join(r["version"].split(".")[:2]) != r["minor"]:
        return "version is not in its minor release"
    ids = r.get("ids")
    if ids is not None and not (
        isinstance(ids, list) and 0 < len(ids) <= 20 and all(isinstance(i, str) and _ISSUE_KEY.match(i) for i in ids)
    ):
        return "ids are not issue keys"
    fixed_in = r.get("fixedIn")
    if fixed_in is not None and not (isinstance(fixed_in, str) and _RELEASE.match(fixed_in)):
        return "fixedIn is not a release"
    if r.get("issued") is not None and not valid_date(r["issued"]):
        return "issued is not a date"
    if not isinstance(r.get("text"), str) or not r["text"].strip() or len(r["text"]) > MAX_TEXT:
        return "text is missing or too long"
    source = r.get("source")
    if not isinstance(source, str) or ".." in source:
        return "source is not a release-notes file"
    if _ABSOLUTE_SOURCE.match(source):
        return None
    if not _RELATIVE_SOURCE.match(source):
        return "source is not a release-notes file"
    commit = commits.get(r["minor"])
    if commit is not None and not (isinstance(commit, str) and _COMMIT.match(commit)):
        return "the commit for its release is not a commit id"
    return None


def _parse(doc: dict[str, Any], rejected: list[str] | None = None) -> list[Issue]:
    """The records that are what they claim to be. Each one that is not is left out and, when ``rejected`` is given,
    named there (its position and why, never its content)."""
    raw_commits = doc.get("commits")
    commits: dict[str, Any] = raw_commits if isinstance(raw_commits, dict) else {}
    out = []
    records = doc.get("records")
    for n, r in enumerate(records if isinstance(records, list) else []):
        problem = _record_problem(r, commits)
        if problem is not None:
            if rejected is not None:
                rejected.append(f"record {n + 1}: {problem}")
            continue
        source = r["source"]
        if not source.startswith("https://"):
            commit = commits.get(r["minor"], f"enterprise-{r['minor']}")
            source = f"https://github.com/openshift/openshift-docs/blob/{commit}/{source}"
        out.append(
            Issue(
                id=r["id"],
                ids=tuple(r.get("ids") or [r["id"]]),
                kind=r["kind"],
                minor=r["minor"],
                version=r["version"],
                text=r["text"],
                source=source,
                issued=r.get("issued"),
                fixed_in=r.get("fixedIn"),
            )
        )
    return out


def _read_parts(files: list[Any]) -> tuple[list[Issue], dict[str, Any]]:
    issues: list[Issue] = []
    meta: dict[str, Any] = {}
    rejected: list[str] = []
    for f in sorted(files, key=lambda p: p.name):
        doc = sanitize.loads_bounded(f.read_text(encoding="utf-8"), sanitize.MAX_JSON_DEPTH_FILE)
        if not isinstance(doc, dict):
            rejected.append(f"{f.name}: not a JSON object")
            continue
        before = len(rejected)
        issues.extend(_parse(doc, rejected))
        rejected[before:] = [f"{f.name} {x}" for x in rejected[before:]]
        meta = {k: v for k, v in doc.items() if k != "records"} or meta
    if rejected:
        meta["_rejected"] = rejected
    return issues, meta


def bundled() -> tuple[list[Issue], dict[str, Any]]:
    root = resources.files("kube_noob").joinpath("data", "known_issues")
    return _read_parts([f for f in root.iterdir() if f.name.endswith(".json")])


def get_index(data_dir: Path | None = None) -> Index:
    """The bundled snapshot, or a newer one in ``<dataDir>/known_issues`` (from ``corpus known-issues``)."""
    key = str(data_dir) if data_dir else ""
    with _lock:
        if key not in _cache:
            issues, meta = bundled()
            local = data_dir / "known_issues" if data_dir else None
            if local and local.is_dir():
                files = sorted(local.glob("*.json"))
                if files:
                    l_issues, l_meta = _read_parts(files)
                    if not valid_date(l_meta.get("retrievedAt")):
                        # a date that does not parse would otherwise win the string comparison below and replace
                        # the whole bundled snapshot ("2099-01-01 <b>" sorts after every real date)
                        meta = {
                            **meta,
                            "_localNote": "a local copy in known_issues/ was not used: its retrievedAt is not a date",
                        }
                    elif not l_issues:
                        meta = {
                            **meta,
                            "_localNote": "a local copy in known_issues/ was not used: it held no usable record",
                        }
                    elif str(l_meta["retrievedAt"]) >= str(meta.get("retrievedAt", "")):
                        issues, meta = l_issues, l_meta
                    else:  # a valid but older copy loses to the bundled one, and says so like the other two
                        meta = {
                            **meta,
                            "_localNote": f"a local copy in known_issues/ was not used: its retrievedAt "
                            f"{l_meta['retrievedAt']} is older than the bundled release notes "
                            f"({meta.get('retrievedAt')})",
                        }
            _cache[key] = Index(issues, meta)
        return _cache[key]


def match(
    text: str,
    platform: str | None = None,
    version: str | None = None,
    limit: int = 3,
    data_dir: Path | None = None,
    require_context: bool = False,
) -> dict[str, Any]:
    """Reported issues for ``text``. ``require_context``: with no platform given, search the OpenShift release notes
    only when the text says it is about OpenShift (diagnose, insight and the watch pass it: their text can be about
    any platform; ``known-issues`` asks about OpenShift by definition)."""
    from kube_noob import tickets

    out = get_index(data_dir).match(text, platform, version, limit, require_context)
    found = tickets.match(text, platform, version, limit, data_dir)
    if not found.get("available"):
        if found.get("note"):
            out["ticketsNote"] = found["note"]
        return out
    out["knowledge"]["jiraTickets"] = found["knowledge"]
    by_id = {m["id"]: m for m in out["matches"]}
    for m in found["matches"]:
        if m["id"] in by_id:  # the release notes name it; the ticket says what became of it since
            by_id[m["id"]]["ticket"] = {
                k: m[k] for k in ("verdict", "jiraStatus", "resolution", "fixVersions", "status", "remarks")
            }
        else:
            out["matches"].append(m)
    if out["matches"]:
        out.pop("note", None)
    elif found.get("note"):
        out["note"] = f"{out.get('note', '')} {found['note']}".strip()
    return out
