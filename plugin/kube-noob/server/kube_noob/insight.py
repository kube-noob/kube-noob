"""One entry point for anything pasted: ``kube-noob insight`` and the ``kubenoob_insight`` tool.

``recognise`` names what the input is (several kinds at once are normal: events next to a denial next to a manifest)
by rules, with the evidence for each kind. ``insight`` then runs every analyser that applies, each on its own size
budget: diagnosis with reported issues, team memory, policy denials and Ceph health codes (events, pod status, logs,
alerts, Ceph health output, build logs, tickets, questions), the audit with its schema and removed-API checks
(manifests), the documentation index (questions) and the denial explainer. Kinds whose analyser is still to come
(Containerfile, SBOM and scanner reports, packet captures, must-gather paths) are named with what to run today. The
answer merges every finding with its source, the read-only next steps, and what was skipped and why. Rules only: no
model, deterministic.
"""

from __future__ import annotations

import functools
import json
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

from kube_noob import sanitize

MAX_TEXT = 2_000_000
ANALYSER_TEXT = 200_000  # characters each text analyser reads (the end of the input, where failures usually are)

KINDS = (
    "alert-payload",
    "ceph-health",
    "events",
    "pod-status",
    "logs",
    "ticket",
    "manifests",
    "helm-chart",
    "policy-denial",
    "build-log",
    "containerfile",
    "sbom",
    "scanner-report",
    "packet-capture",
    "must-gather",
    "question",
)
# What a person can paste for each kind, said when nothing was recognised (one line each, in KINDS order). A test
# holds the keys equal to KINDS, so a kind added to the router cannot go missing from the hint.
KIND_DESCRIPTIONS = {
    "alert-payload": "an Alertmanager webhook or alerts JSON, or a firing alert's text",
    "ceph-health": "ceph health detail or ceph status output, or a CephCluster status",
    "events": "kubectl/oc get events or the Events section of describe",
    "pod-status": "kubectl/oc get pods, or describe pod output",
    "logs": "timestamped log lines or a stack trace",
    "ticket": "a Jira or ServiceNow ticket, or an OCPBUGS-style key",
    "manifests": "Kubernetes or OpenShift YAML (apiVersion and kind)",
    "helm-chart": "a Helm template or Chart.yaml",
    "policy-denial": "an admission or authorization denial (forbidden, webhook denied, PodSecurity, SCC)",
    "build-log": "a CI or OpenShift build log",
    "containerfile": "a Containerfile or Dockerfile",
    "sbom": "an SPDX or CycloneDX SBOM",
    "scanner-report": "a Trivy, Grype, SARIF or RHACS scan",
    "packet-capture": "a .pcap file or tcpdump text",
    "must-gather": "a list of must-gather paths",
    "question": "a question, or a one-line symptom that names a Kubernetes thing (a pod, a route, etcd)",
}
UNRECOGNISED_EXAMPLE = "events-scc.txt"  # a bundled example the hint shows working (kube-noob examples copy)
PENDING = {
    "packet-capture": "packet capture analysis (queue N2) is not built yet; tcpdump text is read as logs",
    "must-gather": "a list of must-gather paths is not the must-gather itself: kube-noob must-gather analyze <dir or "
    ".tar.gz> opens it safely and ranks what is wrong (the MCP tool is queue G5); paste the pod's events and logs "
    "for a diagnosis",
}
UNREAD = {  # recognised, but in a form the vulnerability reader does not take
    "sbom": "only JSON SBOMs are read: export SPDX 2.3 or CycloneDX JSON (syft -o spdx-json, trivy image -f "
    "cyclonedx) and run kube-noob vuln report -r <file>",
    "scanner-report": "scanner tables are not read here: give the JSON (trivy image -f json "
    "--list-all-pkgs, grype -o json) to kube-noob vuln report -r <file>",
}

# Every line pattern starts with [ \t]* (never \s*, which crosses newlines and backtracks quadratically on blank lines)
_EVENT_TABLE = re.compile(
    r"^[ \t]*(?:Type[ \t]+Reason[ \t]+Age[ \t]+From[ \t]+Message|LAST SEEN[ \t]+TYPE[ \t]+REASON[ \t]+OBJECT|"
    r"NAMESPACE[ \t]+LAST SEEN[ \t]+TYPE[ \t]+REASON)",
    re.M,
)
_EVENT_LINE = re.compile(r"^[ \t]*(?:\S+[ \t]+){0,2}(?:Normal|Warning)[ \t]+[A-Z][A-Za-z]+[ \t]+\S+", re.M)
_POD_TABLE = re.compile(r"^(?:NAMESPACE[ \t]+)?NAME[ \t]+READY[ \t]+STATUS[ \t]+RESTARTS[ \t]+AGE\b", re.M)
_POD_ROW = re.compile(
    r"^[ \t]*(?:[a-z0-9][-a-z0-9]*[ \t]+)?[a-z0-9][-a-z0-9.]*[ \t]+\d+/\d+[ \t]+(?:Running|Pending|Completed|"
    r"CrashLoopBackOff|ImagePullBackOff|ErrImagePull|Error|OOMKilled|ContainerCreating|Terminating|Init:[\w/:]+|"
    r"CreateContainerConfigError|Evicted|Unknown)\b",
    re.M,
)
_DESCRIBE_POD = re.compile(r"^(?:Name|Namespace|Node|Status|Containers|Conditions|Controlled By):", re.M)
_CONTAINER_STATE = re.compile(r"(?:Last State|State):\s+(?:Waiting|Terminated|Running)|Reason:\s+[A-Z][A-Za-z]+", re.M)
_LOG_LINE = re.compile(
    r"^[ \t]*(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|[IWEF]\d{4} \d{2}:\d{2}:\d{2}\.\d+|time=\"?\d{4}-|"
    r"level=(?:info|warn|warning|error|fatal|debug)|\{\"(?:level|ts|time|msg)\"|"
    r"[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2})",
    re.M,
)
_STACK = re.compile(r"^(?:Traceback \(most recent call last\):|[ \t]+at [\w.$]+\(|panic: |goroutine \d+ \[)", re.M)
_TICKET = re.compile(
    r"\b(?:[A-Z][A-Z0-9_]{1,15}-\d{1,7}|INC\d{7}|RITM\d{7}|CHG\d{7})\b.{0,200}?(?:Summary|Description|Status|"
    r"short_description|Priority|Assignee|Resolution)\b|\"(?:issues|short_description|fields)\"\s*:|"
    r"^(?:Issue key|Summary|number),",
    re.S | re.M,
)
_DENIAL = re.compile(
    r"admission webhook \".{1,200}\" denied|(?:would )?violate[s]? PodSecurity|"
    r"unable to validate against any security context constraint|exceeded quota|\[denied by |"
    r"ValidatingAdmissionPolicy .{1,120} denied|is forbidden: |"
    r"policy .{1,120} (?:blocked|violation)",
    re.I,
)
_BUILD = re.compile(
    r"^(?:\d{4}-\d{2}-\d{2}T[\d:.]+Z[ \t])?(?:STEP \d+/\d+: |Step \d+/\d+ : |#\d+ \[[\w.-]+(?: \d+/\d+)?\]|"
    r"\[Pipeline\]|##\[(?:error|group|warning)\]|Cloning \"https?://|error building image|Pushing image |"
    r"error: build error|\[step-[\w-]+\]|\[[\w-]+ : [\w-]+\] |Run actions/|Error: Process completed with exit code|"
    r"\[INFO\] BUILD FAILURE|BUILD FAILED|npm ERR! |\[\+\] Building \d)",
    re.M,
)
_DOCKER_INSTRUCTION = re.compile(  # instructions are case-insensitive in Dockerfiles and Containerfiles
    r"^(?:FROM|RUN|COPY|ADD|USER|ENTRYPOINT|CMD|WORKDIR|ENV|ARG|EXPOSE|LABEL|HEALTHCHECK|VOLUME)[ \t]", re.M | re.I
)
_SBOM_TEXT = re.compile(r"^SPDXVersion: SPDX-\d|<bom [^>]{0,200}xmlns=\"http://cyclonedx\.org", re.M)
_ACCESS_LOG = re.compile(r"^\S+ \S+ \S+ \[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] \"", re.M)
_YAML_HEAD = re.compile(r"^(?:---\n)?(?:#.*\n)*apiVersion: [\w./-]+\nkind: [A-Z]\w+\n", re.M)
_TECH = re.compile(
    r"\b(?:pods?|nodes?|deploy\w*|crash\w*|errors?|fail\w*|oom\w*|images?|pull\w*|routes?|ingress\w*|services?|"
    r"namespaces?|pvcs?|volumes?|helm|operators?|clusters?|etcd|upgrad\w*|rbac|forbidden|denied|timeouts?|timed out|"
    r"certificat\w*|x509|dns|network\w*|containers?|kube\w*|kubectl|oc|openshift|rosa|rhacs|stackrox|secrets?|"
    r"configmaps?|probes?|restart\w*|pending|evict\w*|quota|scc|webhooks?|api|tls|memory|cpu|disk|storage|latency|"
    r"[45]\d\d)\b",
    re.I,
)
_ASKED_LINE = re.compile(  # a line of words that asks something, next to a paste
    r"^(?![ \t]*[$#>|{\[])[^\n]{0,240}?\b(?:how|why|what|when|where|which|can|could|should|would|is|are|does|do|did|"
    r"will|has|have|anyone|any idea)\b[^\n]{0,240}\?[ \t]*$",
    re.M | re.I,
)
_CAMEL = re.compile(r"\b[A-Z][a-z]+(?:[A-Z][a-z0-9]*)+\b")
_ASKED_SENTENCE = re.compile(  # "Is there a way to use kubectl to ...?" inside a paragraph
    r"(?i)\b(?:how (?:do|can|to|should)|is there (?:a|any) way|can (?:i|you|we)|is it possible|does anyone|"
    r"what is the (?:best|right|correct) way)\b[^.?!\n]{0,200}\?"
)
_TCPDUMP = re.compile(  # tcpdump (any -t format, interface prefix) and tshark summary lines
    r"^(?:\d{4}-\d{2}-\d{2} )?\d{2}:\d{2}:\d{2}\.\d+[ \t]+(?:\S+[ \t]+(?:In|Out|P|M)[ \t]+)?(?:IP6?|ARP),?[ \t]+"
    r"\S+ > \S+: |^[ \t]*\d+[ \t]+\d+\.\d{6,9}[ \t]+\S+[ \t]+(?:→|->)[ \t]+\S+[ \t]+[A-Z][A-Z0-9v.]{1,10}[ \t]+\d+",
    re.M,
)
_SCANNER_TABLE = re.compile(
    r"Total: \d+ \((?:UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL)|"
    r"^NAME[ \t]+INSTALLED[ \t]+FIXED[- ]IN[ \t]+TYPE[ \t]+VULNERABILITY|"
    r"(?:Library|COMPONENT|PACKAGE)[ \t│|]+(?:Vulnerability|VERSION|INSTALLED)",
    re.M | re.I,
)
_CVE_ROW = re.compile(r"CVE-\d{4}-\d{4,7}.{0,120}?\b(?:CRITICAL|HIGH|MEDIUM|LOW|Important|Moderate|Critical)\b", re.M)
_ALERT_TEXT = re.compile(r"\[FIRING:\d+\]|\[RESOLVED\]|\balertname=\w+|^ALERTS\{alertname=", re.M)
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
SAMPLE = 200_000  # characters from each end of a long paste the line patterns read
_MUST_GATHER = re.compile(
    r"must-gather\.local\.|cluster-scoped-resources/|namespaces/openshift-[\w-]+/pods/|"
    r"^\[must-gather[\w -]*\] (?:OUT|POD) |"
    r"quay-io-openshift-release-dev-ocp-v4-0-art-dev-sha256-",
    re.M,
)
_EVENT_FIELDS = re.compile(
    r"\"type\":\s{0,4}\"(?:Warning|Normal)\"[^{}]{0,400}?\"reason\":\s{0,4}\"[A-Z][A-Za-z]+\"|"
    r"\"reason\":\s{0,4}\"[A-Z][A-Za-z]+\"[^{}]{0,400}?\"type\":\s{0,4}\"(?:Warning|Normal)\""
)
_QUESTION = re.compile(r"^(?:how|why|what|when|where|which|can|could|should|is|are|does|do|will|my|i )\b", re.I)
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
# A typed question about moving between two OpenShift releases. Only a full x.y.z is trusted (the risk snapshot is
# keyed on exact patch versions and a wrong one is worse than no answer); "4.14 to 4.15" with no patch is named in
# ``skipped`` instead of guessed. Scoped to short typed questions only (never a pasted log full of chart/image tags).
_UPGRADE_WORD = re.compile(r"(?i)\b(?:upgrad(?:e|ing|ed|e path)|updat(?:e|ing|ed))\b")
_VERSION3 = re.compile(r"\b(\d{1,4}\.\d{1,4}\.\d{1,6})\b")
_VERSION_LOOSE = re.compile(r"\b\d{1,4}\.\d{1,4}(?:\.\d{1,6})?\b")


def _asks_last(text: str) -> bool:
    """A paragraph of prose that quotes a snippet and ends by asking ("... I call {{ template "x" }}. What is
    wrong?"): its last sentence is a question, however long the paragraph before it."""
    last = _SENTENCE_END.split(text[-400:].rstrip())[-1].strip()
    return last.endswith("?") and len(last) <= 240 and bool(_QUESTION.match(last)) and bool(_WORD.search(last))


_WORD = re.compile(r"[A-Za-z]{3}")
_HELM = re.compile(
    r"\{\{-?\s*(?:\.Values|\.Release|include |template |if |range )|^apiVersion: v2\n(?:.*\n){0,6}name: ", re.M
)


@dataclass(frozen=True)
class Kind:
    kind: str
    evidence: str

    def as_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "evidence": self.evidence}


def _json(text: str) -> Any:
    """The JSON document the paste is, or starts with after a line or two of words ("got paged for this:"), read
    up to its end even when log lines follow it."""
    s = text.lstrip()
    if not s.startswith(("{", "[")):
        start = s.find("{", 0, 2000)
        if start < 0 or "\n" not in s[:start]:
            return None
        s = s[start:]
    if not sanitize.json_nesting_ok(s):
        return None
    try:
        return json.JSONDecoder().raw_decode(s)[0]
    except (ValueError, RecursionError):
        return None


def _yaml_docs(text: str) -> list[Any]:
    """The documents, through the audit's guarded loader (size, count, depth and alias budgets); [] if not YAML."""
    if "apiVersion" not in text or "kind" not in text:
        return []
    from kube_noob.errors import ManifestError
    from kube_noob.yamlio import load_documents

    try:
        docs = [d.data for d in load_documents(text)]
    except ManifestError:
        return []
    return docs if all(isinstance(d, dict) for d in docs) else []


_YAMLISH = re.compile(r"^(?:\s|-\s|-$|#|---|\.\.\.|[A-Za-z_][\w./-]*:(?:\s|$))")
_YAML_START = re.compile(r"^(?:apiVersion|kind):\s*\S")
MAX_SEGMENTS = 50


def manifest_segments(text: str) -> list[str]:
    """The Kubernetes YAML inside a mixed paste (events, then a manifest, then a denial): each run of lines that
    starts with ``apiVersion:`` or ``kind:`` at the margin, continues while lines look like YAML, and parses as
    documents that all carry apiVersion and kind. Shrinks a run to its last blank line or ``---`` when the whole run
    does not parse."""
    lines = text.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines) and len(out) < MAX_SEGMENTS:
        if not _YAML_START.match(lines[i]):
            i += 1
            continue
        start = i - 1 if i and lines[i - 1].strip() == "---" else i
        j = i + 1
        while j < len(lines) and (not lines[j].strip() or _YAMLISH.match(lines[j])):
            j += 1
        ends = [j] + [k for k in range(j - 1, i, -1) if not lines[k].strip() or lines[k].strip() == "---"][:20]
        for end in ends:
            chunk = "\n".join(lines[start:end]).strip("\n")
            docs = _yaml_docs(chunk)
            if docs and all("apiVersion" in d and "kind" in d for d in docs):
                out.append(chunk)
                break
        i = j
    return out


def normalise(text: str) -> str:
    """Terminal colour codes and CRLF line ends removed: pastes from kubecolor, Windows terminals and CI logs."""
    return _ANSI.sub("", text.replace("\r\n", "\n").replace("\r", "\n")) if ("\x1b" in text or "\r" in text) else text


def recognise(text: str) -> list[Kind]:
    """Every kind the input looks like, with the evidence; empty for text that is none of them. Structured parses
    read the whole input (each with its own caps); line patterns read the first and last ``SAMPLE`` characters, so
    the time stays linear in the input whatever it holds."""
    text = normalise(text[:MAX_TEXT])
    found: dict[str, str] = {}
    doc = _json(text)
    s = text.lstrip()
    if isinstance(doc, dict):
        if "spdxVersion" in doc or doc.get("bomFormat") == "CycloneDX":
            found["sbom"] = "SPDX or CycloneDX document"
        if ("Results" in doc and "SchemaVersion" in doc) or ("matches" in doc and "descriptor" in doc):
            found["scanner-report"] = "Trivy or Grype report"
        runs = doc.get("runs")
        sarif_schema = "sarif" in str(doc.get("$schema", "")).lower()
        # $schema is optional in SARIF 2.1.0: version "2.1.0" with runs[].tool.driver is enough
        sarif_shape = (
            str(doc.get("version", "")) == "2.1.0"
            and isinstance(runs, list)
            and any(
                isinstance(r, dict) and isinstance(r.get("tool"), dict) and "driver" in r["tool"] for r in runs[:20]
            )
        )
        if "runs" in doc and (sarif_schema or sarif_shape):
            found["scanner-report"] = "SARIF report"
        if isinstance(doc.get("scan"), dict) and isinstance(doc["scan"].get("components"), list):
            found["scanner-report"] = "RHACS image scan"
        if doc.get("kind") in {"EventList", "Event"}:
            found["events"] = f"{doc.get('kind')} JSON"
        if doc.get("kind") == "Pod" and "status" in doc:
            found["pod-status"] = "Pod JSON with status"
        if doc.get("kind") == "Status" and isinstance(doc.get("message"), str):  # what the API server answered
            found["policy-denial" if _DENIAL.search(doc["message"]) else "logs"] = "an API server Status response"
        if "issues" in doc or "fields" in doc or "short_description" in s[:5000]:
            found["ticket"] = "ticket export JSON"
        items = doc.get("items")
        if (
            doc.get("kind") in {"List", "EventList"}
            and isinstance(items, list)
            and items
            and all(isinstance(i, dict) and (i.get("kind") == "Event" or "involvedObject" in i) for i in items[:50])
        ):
            found["events"] = f"{len(items)} events (JSON list)"
    from kube_noob.signals import alertmanager, ceph

    if alertmanager.parse(text) is not None or (
        isinstance(doc, (dict, list)) and alertmanager._alerts(doc) is not None
    ):
        found["alert-payload"] = "Alertmanager webhook or API alerts"
    if isinstance(doc, dict) and ceph.json_checks(doc):
        found["ceph-health"] = "Ceph health JSON (ceph health detail, ceph status or a CephCluster's details)"
    docs = _yaml_docs(text) if not found else []
    whole = bool(docs) and all("apiVersion" in d and "kind" in d for d in docs)
    if not whole and not found:
        docs = [d for seg in manifest_segments(text) for d in _yaml_docs(seg)]
    if docs and all(d.get("kind") == "Status" for d in docs):
        docs = []  # an API response, not a manifest
    if docs and all(d.get("kind") == "Event" for d in docs):
        found.setdefault("events", f"{len(docs)} Event objects")
        docs = []
    if not docs and not found and _YAML_HEAD.search(text[:5000]):
        found["manifests"] = "Kubernetes YAML that does not parse (cut short or mis-indented)"
    if docs and all("apiVersion" in d and "kind" in d for d in docs):
        where = "" if whole else " inside the paste"
        found["manifests"] = (
            f"{len(docs)} Kubernetes document(s){where}: {', '.join(sorted({str(d['kind']) for d in docs}))}"
        )
        if any(d.get("kind") == "Pod" and isinstance(d.get("status"), dict) for d in docs):
            found["pod-status"] = "Pod with status"
        if any(d.get("kind") == "EventList" for d in docs):
            found["events"] = "EventList"
        if any(d.get("kind") == "CephCluster" and ceph.json_checks(d) for d in docs):
            found["ceph-health"] = "a Rook CephCluster with health codes in its status"
    whole_text = text
    if len(text) > 2 * SAMPLE:
        text = text[:SAMPLE] + "\n" + text[-SAMPLE:]
    health_output = ceph.looks_like_health_output(text)
    if health_output:
        found.setdefault("ceph-health", health_output)
    if _HELM.search(text):
        found["helm-chart"] = "Helm template or Chart.yaml"
        found.pop("manifests", None)
    if _EVENT_TABLE.search(text) or _EVENT_LINE.search(text):
        found.setdefault("events", "event lines (Normal or Warning with a reason)")
    elif _EVENT_FIELDS.search(text):
        found.setdefault("events", "event fields in JSON (type and reason)")
    if len(_DESCRIBE_POD.findall(text)) >= 3 or _CONTAINER_STATE.search(text):
        found.setdefault("pod-status", "pod status or describe output")
    if _POD_TABLE.search(text) or len(_POD_ROW.findall(text)) >= 2:
        found.setdefault("pod-status", "a get pods table")
    if _ALERT_TEXT.search(text):
        found.setdefault("alert-payload", "alert notification text")
    if _SCANNER_TABLE.search(text) or len(_CVE_ROW.findall(text)) >= 2:
        found.setdefault("scanner-report", "scanner table (Trivy, Grype or roxctl)")
    if len(_LOG_LINE.findall(text)) >= 2 or _STACK.search(text) or len(_ACCESS_LOG.findall(text)) >= 2:
        found["logs"] = "timestamped log lines or a stack trace"
    if _TICKET.search(text[:20_000]):
        found.setdefault("ticket", "ticket key with ticket fields")
    if _DENIAL.search(text):
        found["policy-denial"] = "an admission or authorization denial"
    if _BUILD.search(text):
        found["build-log"] = "build or pipeline steps"
        if not _STACK.search(text):
            found.pop("logs", None)  # CI timestamps make a build log look like logs; it is read as one either way
    if _SBOM_TEXT.search(text):
        found["sbom"] = "SPDX tag-value or CycloneDX XML"
    instructions = _DOCKER_INSTRUCTION.findall(text)
    if len(instructions) >= 2 and re.match(r"(?:[ \t\n]*#.*\n|[ \t\n]*ARG\s.*\n)*[ \t\n]*FROM\s", text, re.I):
        found["containerfile"] = f"{len(instructions)} Containerfile instructions"
    if len(_TCPDUMP.findall(text)) >= 2:
        found["packet-capture"] = "tcpdump text"
    if _MUST_GATHER.search(text):
        found["must-gather"] = "must-gather paths"
    stripped = whole_text.strip()
    one_line = "\n" not in stripped and 3 <= len(stripped) <= 300 and bool(_WORD.search(stripped))
    asked = stripped.endswith("?") or bool(_QUESTION.match(stripped))
    technical = bool(_TECH.search(stripped[:300]) or _CAMEL.search(stripped[:300]))
    # A forum post: a title line that asks, then the body (asked by its title or by a line that asks).
    title = stripped.split("\n", 1)[0].strip()
    posted = (
        not found
        and "\n" in stripped
        and technical
        and (
            title.endswith("?")
            or bool(_QUESTION.match(title))
            or bool(_ASKED_LINE.search(stripped[:3000]))
            or bool(_ASKED_SENTENCE.search(stripped[:1000]))
        )
    )
    if (not found and (asked or (one_line and technical) or posted)) or (
        asked and one_line and set(found) <= {"policy-denial", "ticket"}
    ):
        found["question"] = "a question or symptom in words"
    elif found and (_ASKED_LINE.search(stripped[:3000]) or _asks_last(stripped)):
        found["question"] = "a question next to what was pasted"
    keys = _ticket_keys(stripped[:20_000])
    if keys and "ticket" not in found:
        found["ticket"] = f"Red Hat Jira key {keys[0]}"
    return [Kind(k, found[k]) for k in KINDS if k in found]


def recognise_bytes(data: bytes) -> list[Kind]:
    """For a file: packet captures by their magic number, else the text inside."""
    if data[:4] in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}:
        return [Kind("packet-capture", "pcap file")]
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        return [Kind("packet-capture", "pcapng file")]
    if b"\x00" in data[:8192]:
        return []  # some other binary file: nothing to read as text
    return recognise(data.decode("utf-8", errors="replace"))


_SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
BUDGET_SECONDS = 20.0  # each analyser's time budget; one that runs longer is reported as skipped
MAX_TICKETS = 5
ALONE = {
    "diagnose": "kube-noob diagnose -f <file>",
    "search": "kube-noob search '<question>'",
    "audit": "kube-noob audit -f <file>",
    "tickets": "kube-noob ticket <KEY>",
}
GATHER = (
    ("{cli} get pods -n {ns} -o wide", "which pods are not Running or not Ready, and on which node"),
    ("{cli} describe pod <pod> -n {ns}", "the State, Last State and Events sections name the reason"),
    ("{cli} get events -n {ns} --sort-by=.lastTimestamp", "recent warnings in the namespace"),
    ("{cli} logs <pod> -n {ns} --previous --tail=200", "the last run's logs when the container restarted"),
)
GATHER_NOTE = " Nothing here was evidence enough to diagnose: run the steps and paste what they print."
NO_CLUSTER_NOTE = (
    " The text names no Kubernetes or OpenShift object, so no cluster steps are suggested: paste the error, events or "
    "logs from the cluster, or give the platform."
)
# Words that say the text is about a cluster (the generic gather steps read pods, events and logs).
_CLUSTER_WORDS = re.compile(
    r"(?i)\b(?:pods?|kubectl|oc|kubernetes|k8s|openshift|ocp|rosa|kubelet|namespaces?|deployments?|statefulsets?|"
    r"daemonsets?|replicasets?|containers?|nodes?|clusters?|helm|ingress|services?|configmaps?|secrets?|pvcs?|"
    r"crashloopbackoff|imagepullbackoff|pending)\b"
)
# A typed question that asks what something is or why the platform behaves a certain way, not "here is my error".
_CONCEPTUAL = re.compile(
    r"(?i)^(?:what(?:'s| is| are| does| do| decides)|why (?:do|does|is|are)|how does|explain|what is the difference)\b"
)
_ERRORISH = re.compile(r"(?i)\b(?:error|failed|failure|denied|forbidden|refused|timeout|cannot|can't)\b|\w+: \w+")
WEAK_PLAYBOOK = 0.4  # a playbook below this confidence matched on a word or two, not on an error
#: `\b` treats `-`, `/`, `:` and `.` as word boundaries, so a route word inside a Kubernetes NAME matched it: a
#: pod called `ci-runner-gate-5`, a Deployment called `upgrade-checker`, a namespace called `evidence`. Every
#: route pattern below is written with `\b` for readability and compiled with this instead, which requires a
#: character that cannot appear in a resource name on each side (G237).
_NAME_SAFE_BOUNDARY = r"(?:(?<![\w/.:-])(?=\w)|(?<=\w)(?![\w/.:-]))"


def _jira_projects() -> tuple[str, ...]:
    from kube_noob.jira_catalog import DEFAULT_PROJECTS

    return tuple(k for k in DEFAULT_PROJECTS if k.isalpha())


def _route(source: str) -> re.Pattern[str]:
    """Compile a route pattern: name-safe boundaries, and anchored so the cost is linear.

    The anchor is the performance half. Every pattern is a series of `(?=.*word)` lookaheads, and `search`
    retries the whole series from each of up to 600 start positions, which measured 75-92 ms per call on a
    600-character line that matches nothing -- paid on every one-line paste, on every surface. Anchored at the
    start the lookaheads scan forward once: 0.3-0.9 ms. Each pattern must therefore begin with a lookahead or
    `.*?`, which is checked below rather than left to whoever adds the next one.
    """
    # `raise`, not `assert`: an assertion is stripped under `python -O`, and these are the two structural
    # invariants that keep a route from firing on one word or costing 80 ms a call. A broken route stops the
    # import, which is loud and immediate, rather than shipping a quietly wrong answer.
    if not source.startswith("(?i)"):
        raise ValueError(f"a route pattern must start with (?i): {source[:40]}")
    body = source[4:]
    # A negative lookahead may lead: `\A(?!.*word)` scans forward once, exactly like a positive one, so the
    # linear-cost invariant holds -- and a route that has to say what it is NOT about needs somewhere to say
    # it (G247).
    if not body.startswith(("(?=", "(?!", ".*")):
        raise ValueError(f"an anchored pattern must start with a lookahead, a negative lookahead or .*: {source[:40]}")
    _refuse_a_word_in_two_groups(source)
    return re.compile("(?i)\\A" + body.replace(r"\b", _NAME_SAFE_BOUNDARY))


def _refuse_a_word_in_two_groups(source: str) -> None:
    """A word may not appear in two of a route's lookahead groups, checked at import.

    Every over-matching defect in this table has been the same one. `fail` was in both halves of the CI route, so
    a Helm render error that says it twice matched on one word pretending to be two. Then `gate` was, so the bare
    word `gate` matched. Then `takeover` and `blast radius` in the exposure route, so `takeover` alone matched.
    Then `evidence` in the compliance route. Each was found by someone attacking the table; a word in two groups
    makes the route fire on a single word, which is precisely what requiring two groups was meant to prevent, so
    it is refused here rather than left for the next reviewer to notice (G237).
    """
    groups = re.findall(r"\(\?=(.*?)\)(?=\(\?=|\Z)", source.replace("\n", ""), re.S)
    if len(groups) < 2:
        return
    words = [_literal_words(group) for group in groups]
    for i, mine in enumerate(words):
        for j, theirs in enumerate(words):
            if i == j:
                continue
            for word in mine:
                # Equal, or CONTAINED as a whole word in a phrase of the other group. The containment half is
                # the generalisation: the catalogue route required `rules?` in one group and the phrase
                # `every rule` in another, and "every rule" on its own satisfied both -- a word in two groups
                # by another spelling, which is the same defect this guard exists for (G252).
                hit = next((t for t in theirs if t == word or re.search(rf"\b{re.escape(word)}\b", t)), None)
                if hit is not None:
                    raise ValueError(
                        f"{word!r} is in two lookahead groups of a route (as {hit!r}), so one phrase matches both"
                    )


#: How many expansions one lookahead group may produce. A nested alternation multiplies, and a guard that can
#: be made to hang on a pathological pattern is a guard somebody removes.
_MAX_EXPANSIONS = 400


def _expand(source: str) -> set[str]:
    """Every literal string a (simple) regex alternative can match, as words.

    Hand-stripping the syntax was not enough. `rules?` came out as "rules" and never as "rule", and
    `reach(?:es|ed|able)?` came out as "reach es" -- so the guard could not see that the catalogue route's
    group of phrases contained the very word its other group required, and `every rule` alone satisfied both
    halves of a route that was written to need two things (G252). This expands the two constructs the table
    actually uses: a nested `(?:a|b)` alternation, and a `?` that makes the preceding character or group
    optional.
    """
    out = {source}
    for _ in range(12):  # each pass resolves the leftmost construct; the table nests two deep at most
        grown: set[str] = set()
        changed = False
        for item in out:
            m = re.search(r"\((?:\?:)?([^()]*)\)(\?)?", item)
            if m is None:
                grown.add(item)
                continue
            changed = True
            head, tail = item[: m.start()], item[m.end() :]
            options = m.group(1).split("|")
            if m.group(2):  # the whole group is optional
                options = [*options, ""]
            grown.update(head + opt + tail for opt in options)
        out = grown
        if not changed or len(out) > _MAX_EXPANSIONS:
            break
    # A `?` on a bare character: both spellings, so `rules?` is `rule` and `rules`.
    for _ in range(6):
        grown = set()
        changed = False
        for item in out:
            m = re.search(r"(?<!\\)(.)\?", item)
            if m is None:
                grown.add(item)
                continue
            changed = True
            head, tail = item[: m.start()], item[m.end() :]
            grown.update((head + m.group(1) + tail, head + tail))
        out = grown
        if not changed or len(out) > _MAX_EXPANSIONS:
            break
    return out


def _literal_words(group: str) -> set[str]:
    """The literal words a lookahead group matches on, with its alternations and optionals expanded."""
    words: set[str] = set()
    for item in _expand(group.replace(r"\b", " ")):
        # What is left of the syntax: character classes, escapes and quantifiers become a space, which keeps
        # `fine-?tun\w*` from reading as one word with the quantifier inside it.
        cleaned = re.sub(r"\\[a-zA-Z]|[*+?.\[\]{}^$]|\d", " ", item)
        for part in cleaned.split("|"):
            word = " ".join(part.split())
            # Two letters is enough to be a word here (`ci`, `pr`), and a two-letter word in both groups would
            # make the route fire on it alone just as surely as a long one.
            if len(word) >= 2 and all(c.isalpha() or c in " -" for c in word):
                words.add(word.lower())
    return words


#: What answers a typed question that names a job this product does. Each row is (what the question is asking,
#: the command that answers it, what to give it).
#:
#: Why this exists: asked "which of our exposed services could reach a node?" the router ran the generic
#: evidence-gathering steps -- `get pods`, `describe pod`, `get events` -- and returned no findings. Those steps
#: answer "something is broken, what is it", which is a different question, and `posture scan` answers the one
#: that was asked. Eight of eighteen realistic questions came back with nothing at all and no next step, in a
#: product whose adoption story is "paste anything" (G235).
#:
#: Deterministic, keyword-matched and capped at two suggestions. Each pattern must be specific enough that it
#: fires on the question it is for and not on a pasted log that happens to share a word, so each one requires at
#: least two of the asking words rather than any one of them. A test holds every command here to being a command
#: that exists.
#: The Jira projects the local corpus actually syncs, as an alternation. Derived, not retyped: `STOR-1234`
#: and `SPLAT-1234` look exactly like a key and are in no synced project, so routing them to `kube-noob
#: ticket` promised an answer the command cannot give (G252).
_JIRA_PROJECTS = "|".join(sorted(_jira_projects(), key=len, reverse=True))


CAPABILITY_ROUTES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    # First, and above the exposure route on purpose: a secret in a repository is a question about files, and
    # the attack-path scan reads a cluster. Asked "which secrets are exposed in the public repo?" the router
    # sent `posture scan`, which would go looking for Routes and ServiceAccounts (G247).
    (
        _route(
            r"(?i)(?=.*\b(?:secrets?|credential|credentials|password|passwords|token|tokens|api ?keys?|"
            r"private ?key)\b)"
            r"(?=.*\b(?:repo|repos|repositor\w+|git|github|gitlab|commit\w*|source ?control|"
            r"version ?control|pushed)\b)"
        ),
        "kube-noob audit -f <dir>",
        "secret material committed in a manifest is KN-S018 and a credential in a ConfigMap is KN-S026; "
        "kube-noob never reads a Secret's contents from a cluster",
    ),
    (
        _route(
            # G247 put a negative lookahead for repository words here, to keep "which secrets are exposed in
            # the public repo?" off this route. It silenced real questions instead -- "are the github actions
            # runner pods exposed to the internet?", "which exposed services in the gitops repo could reach a
            # node?", and anything with the word "committed" in it -- and the justification was wrong anyway:
            # this command reads a DIRECTORY, which is usually a repository checkout. The secrets route above
            # comes first in the table, so the repository question gets the right answer first and this one
            # second, which is what the cap of two is for (G252).
            r"(?i)(?=.*\b(?:exposed?|exposure|route|ingress|loadbalancer|nodeport|lateral|"
            r"blast ?radius|attack ?paths?|reach(?:es|ed|able)?|takeover|escape)\b)"
            # "pods" is NOT enough on its own here: "can a pod in shop reach a pod in payments" is a
            # NetworkPolicy question, and this route was answering it before `policy reach` did. The
            # internet-exposure words are PHRASES and `publicly`, not the bare nouns `internet` and `public`:
            # those two sat in the first group, where they made "exposed to the internet" -- the plainest form
            # of the question this command answers -- match nothing at all, and bare `public` matched a
            # namespace called public (G247).
            r"(?=.*(?:\b(?:node|nodes|secrets?|cluster-admin|escalat\w*|what can|what could)\b"
            r"|\binternet[- ]?facing\b|\bpublicly\b|\b(?:to|from) the internet\b|\bfrom outside\b"
            r"|\boutside the cluster\b))"
        ),
        "kube-noob posture scan -f <dir>",
        "ranks every path from a Route, Ingress, LoadBalancer or NodePort to what the pods it reaches can do",
    ),
    (
        _route(
            # Not an admission denial: "my pod is being denied by pod security admission" has `pod` twice --
            # once in `pod security` -- so `\bpod\b.*\bpod\b` matched and the reachability checker answered a
            # question `policy explain` answers (G247). The guard is the DENIAL PHRASE, not the bare nouns:
            # naming a webhook, a quota or Kyverno is ordinary in a reachability question ("can a pod in shop
            # reach the kyverno webhook pod?"), and those nouns silenced it (G252).
            r"(?i)(?!.*\b(?:denied|refused|rejected|blocked|forbidden) by\b.{0,40}"
            r"\b(?:scc|podsecurity|pod ?security|psa|kyverno|gatekeeper|admission|webhook|quota|limitrange)\b)"
            r"(?=.*\b(?:reach|talk to|connect to|allowed|denied|blocked)\b)"
            # ONE lookahead over the whole alternation. Flat it parsed as `(?=(.*A)|(B)|(C))`, where only the
            # first branch had `.*` and the other two worked only because `search` scanned the string; anchored,
            # they would silently never match (G237).
            # The gaps are bounded. Unbounded, `\bfrom\b.*\bto\b.*\bnamespace\b` cost 32 ms on a 600-character
            # line of "from to from to", paid on every one-line paste: three nested `.*` over one string is
            # the cost the anchoring was meant to remove, and a real question keeps its clauses short (G252).
            r"(?=.*(?:\bnetwork ?polic\w+|\bfrom\b.{0,60}\bto\b.{0,60}\bnamespace\b|\bpod\b.{0,80}\bpod\b))"
        ),
        "kube-noob policy reach --from <ns>/<pod> --to <ns>/<pod> --port <port> -f <dir>",
        "names the deciding tier, policy and rule, and why every other rule did not match",
    ),
    # Above `upgrade-risks`: "which CVEs matter before we upgrade to 4.18?" is a CVE question (G237).
    (
        _route(
            r"(?i)(?=.*\b(?:cve|cves|vulnerabilit\w+|vulns?)\b)"
            r"(?=.*\b(?:matter|priorit\w+|which|reachable|exploitable|rank|first|actually|real)\b)"
        ),
        "kube-noob vuln report -r <scanner.json>",
        "normalises the scanner's output, applies Red Hat VEX and ranks what is left; add `-m <dir>` to rank by "
        "whether the pods that run the image are reachable",
    ),
    (
        # The second group is an OpenShift signal and nothing else. `upgrade-risks` answers from a snapshot of
        # targets in OpenShift 4.18 and later -- `--to 1.31.0` returns "0 declared risks ... 1.31.0 is older, so
        # it was not looked up" -- so matching on "version", "release", "risky" or "breaks" sent `Error: UPGRADE
        # FAILED`, a Calico-to-Cilium question and a cert-manager version question all here, each of which would
        # have been answered confidently with nothing (G237).
        _route(
            r"(?i)(?=.*(?:\b(?:upgrade|upgrading|update|migrat\w+|moving|move)\b|\bgoing from\b))"
            r"(?=.*\b(?:4\.\d+|openshift|ocp|rosa)\b)"
        ),
        "kube-noob upgrade-risks --from <x.y.z> --to <x.y.z>",
        "the known risks between two releases, from the bundled corpus",
    ),
    (
        _route(
            r"(?i)(?=.*\bkyverno\b)(?=.*\b(?:1\.\d+|migrat\w+|drop\w*|remov\w*|deprecat\w*|"
            r"affected|still work)\b)"
        ),
        "kube-noob policy migrate-check -f <dir>",
        "which of your Kyverno policies use types the next release removes",
    ),
    (
        _route(
            r"(?i)(?=.*\b(?:fedramp|ksi|20x|nist|800-53|control|controls|compliance|evidence|auditor)\b)"
            r"(?=.*\b(?:which|what|indicators?|speak|map|maps|cover\w*|show|report|produce)\b)"
        ),
        "kube-noob ksi -f <dir>",
        "the FedRAMP 20x indicators your findings are evidence about, and the ones nothing here evidences",
    ),
    (
        _route(
            # Not "accept" or "temporarily": "how do I accept the risk of the node going down temporarily?" is
            # an availability question, and this route is about the exception FILE (G237).
            r"(?i)(?=.*\b(?:suppress|waive|waiver|exception|exempt|silence)\b)"
            r"(?=.*\b(?:rule|finding|kn-[a-z]?\d+|namespace|until|quarter|expiry|owner)\b)"
        ),
        "kube-noob exceptions check <file>",
        "an exception needs an owner, a reason, a scope no wider than a namespace and an expiry; this refuses "
        "the ones that do not",
    ),
    (
        # No lookahead of its own, so it needs the leading `.*?` the anchored form requires.
        _route(r"(?i).*?\bKN-[A-Z]{0,2}\d{3}\b"),
        "kube-noob explain <rule-id>",
        "what the rule checks, why it matters, the NIST controls it is evidence about and how to fix it",
    ),
    (
        _route(
            r"(?i)(?=.*\b(?:rhacs|stackrox|acs)\b)(?=.*\b(?:compare|overlap|gap|gaps|differ\w*|instead|"
            r"gives|cover\w*|what does|what do|do not|does not|miss\w*)\b)"
        ),
        "kube-noob rhacs compare -f <policies-export.json>",
        "the overlap, the related policies, the gaps each tool leaves and what is outside kube-noob's scope",
    ),
    # Above `gate`: "why did the build fail in the CI pipeline?" asks why it failed (G237).
    (
        # Not bare "image": `ImagePullBackOff: ... failed to pull and unpack image` is a runtime pull failure and
        # was being answered with the build analyser.
        _route(
            r"(?i)(?=.*\b(?:build|builds|building|buildconfig|containerfile|dockerfile|buildah)\b)"
            # Not "why": "the build deployment keeps restarting, why" is a diagnosis question about a workload
            # that happens to be called build, not a question about a build log (G237). `check`, `audit`,
            # `review`, `lint` and `wrong` reach the other half of this command, which audits the image a
            # Containerfile would produce -- "what is wrong with my Dockerfile?" had no route at all (G247).
            r"(?=.*\b(?:fail\w*|error|broke|debug|log|logs|check|audit|review|lint|wrong)\b)"
        ),
        "kube-noob build diagnose -f <log>",
        "why the build failed, from the log; `kube-noob build audit -f Containerfile` audits the image it would "
        "produce",
    ),
    (
        # Neither group may hold a word the other holds. "fail" came out of the first group because a Helm render
        # error says it twice; `gate` came out of it too, because `gate` alone -- the bare word, a Deployment
        # called `gate`, a pod called `gate-7d9f` -- routed here, which is the same defect one word over (G237).
        _route(
            # Bare "ci" and "pipeline" are ordinary nouns: "deployment gate in ci is failing readiness" matched
            # both groups and got the CI gate instead of a diagnosis. CI intent, or `ci` next to a CI noun.
            r"(?i)(?=.*(?:\b(?:pull request|github action|merge|gating|before deploy|in ci)\b"
            r"|\bci\b.{0,24}\b(?:check|job|step|pipeline)\b))"
            r"(?=.*\b(?:fail|block|gate|critical|threshold|annotat\w*|stop|audit|scan)\b)"
        ),
        "kube-noob gate -f <dir> --fail-on high",
        "one command for CI: audit, admission policy and Containerfiles, with SARIF and pull-request annotations",
    ),
    (
        _route(
            # Not bare "new": "new cluster" and "a new VPC" are not questions about what changed (G237).
            r"(?i)(?=.*\b(?:changed|change|drift|since|yesterday|last week|regress\w*|diff|compare)\b)"
            r"(?=.*\b(?:cluster|namespace|posture|findings?|control|snapshot|snapshots)\b)"
        ),
        "kube-noob posture snapshot --live -o today.json && kube-noob posture diff yesterday.json today.json",
        "what changed between two snapshots: objects, findings opened and fixed, and which controls had nothing "
        "evaluated",
    ),
    # Above `helm-audit`, because the cap is two and table order decides which comes first: "scaffold a
    # Helm chart" was being answered with the auditor (G237).
    (
        _route(r"(?i)(?=.*\b(?:scaffold|bootstrap|start|new|skeleton)\b)(?=.*\b(?:chart|helm)\b)"),
        "kube-noob helm-chart --name <app> --platform openshift",
        "a chart that already passes the audit for that platform, rather than one to fix afterwards",
    ),
    (
        _route(
            r"(?i)(?=.*\bhelm\b)(?=.*\b(?:fail\w*|error|render\w*|upgrade|install|template|values|"
            r"chart)\b)"
        ),
        "kube-noob helm-audit <chart>",
        "renders the chart and audits what it produces; a pasted Helm error is decoded by the diagnosis above "
        "this, not by the audit",
    ),
    (
        _route(r"(?i)(?=.*\bmust-?gather\b)"),
        "kube-noob must-gather analyze <path>",
        "opens the bundle safely and routes what it finds to the analysers, without reading Secrets",
    ),
    (
        # Needs the phrase, not the bare noun: "threats" alone, and an app CALLED threats, matched this.
        _route(r"(?i)(?=.*\b(?:threat ?model|threat ?modell?ing|stride|what could go wrong)\b)"),
        "kube-noob vuln threat -f <dir>",
        "the threats for each application, with the finding that is evidence for each one",
    ),
    (
        _route(
            r"(?i)(?=.*\b(?:teach|learn|lesson|tutorial|exercise|practi[cs]e|study|beginner|"
            r"explain how to)\b)(?=.*\b(?:me|about|kubernetes|openshift|networkpolicy|rbac|track)\b)"
        ),
        "kube-noob learn tracks",
        "the tracks and their lessons, offline, with each exercise's answer checked rather than described",
    ),
    (
        _route(
            r"(?i)(?=.*\b(?:generate|write|give me|create)\b)"
            r"(?=.*\b(?:polic\w+|kyverno|gatekeeper|vap|validatingadmissionpolicy|admission)\b)"
        ),
        "kube-noob policy generate --engine kyverno",
        "Kyverno or ValidatingAdmissionPolicy (`--engine vap`) for the rules that can be enforced at admission",
    ),
    (
        _route(
            r"(?i)(?=.*\b(?:fix|harden|correct|repair)\b)(?=.*\b(?:manifest|yaml|deployment|chart|"
            r"for me|automatically)\b)"
        ),
        "kube-noob fix -f <dir>",
        "the manifest change for each finding it can fix, re-audited afterwards so what is left is visible",
    ),
    # Added after a red team found questions with a precise answer and no route at all (G237). Each is narrow:
    # a product name, a file format or a verb that only this job uses.
    (
        _route(
            r"(?i)(?=.*\b(?:known|reported|seen this|anyone else)\b)"
            r"(?=.*\b(?:bug|bugs|issue|issues|before)\b)"
        ),
        "kube-noob known-issues '<symptom>' --version <x.y.z>",
        "the reported OpenShift bugs whose text matches, with the releases each is fixed in",
    ),
    (
        _route(
            r"(?i)(?=.*\b(?:scc|podsecurity|pod security|psa|kyverno|gatekeeper|quota|limitrange|webhook)\b)"
            r"(?=.*\b(?:denied|deny|reject\w*|refus\w*|blocked|forbidden|why)\b)"
        ),
        "kube-noob policy explain -f <denial.txt>",
        "which admission tier refused it, the rule that did, and what to change",
    ),
    (
        _route(
            r"(?i)(?=.*\b(?:semgrep|codeql|bandit|spotbugs|eslint|sarif)\b)(?=.*\b(?:which|matter|worth|"
            r"shipped|real|priorit\w*|triage)\b)"
        ),
        "kube-noob code report -s <findings.sarif> -m <dir>",
        "the code findings whose file ships in an image a pod actually runs, ranked by that",
    ),
    (
        _route(
            r"(?i)(?=.*\b(?:red ?team|attacker|adversar\w+)\b)(?=.*\b(?:manifest|manifests|yaml|chart|"
            r"what would|scenario|scenarios)\b)"
        ),
        "kube-noob redteam -f <dir>",
        "the scenarios an attacker could run against these manifests, each with the findings that enable it",
    ),
    (
        _route(r"(?i)(?=.*\b(?:removed|deprecated|retired)\b)(?=.*\b(?:api|apis|apiversion|kind|kinds)\b)"),
        "kube-noob audit -f <dir> --version <x.y>",
        "the APIs in these manifests that the target release has removed or deprecated, with what replaces them",
    ),
    # Added after a third sweep of realistic questions (G247). Each of these had an exact command answer and
    # no route at all, which on a product whose pitch is "paste anything" reads as "it cannot do that".
    (
        # A ticket key is an anchor the way a KN- rule id is: nothing else looks like it. The projects come
        # from `jira_catalog.DEFAULT_PROJECTS` rather than a list retyped here, because a key the corpus does
        # not sync would route to a command that answers "not in the local copy" (G252).
        _route(rf"(?i).*?\b(?:{_JIRA_PROJECTS})-\d{{3,7}}\b"),
        "kube-noob ticket <KEY>",
        "what became of that ticket in the local copy of Red Hat's public Jira: status, fix versions, workaround",
    ),
    (
        _route(
            # Not bare "recorded": "events in the cluster are recorded in etcd" and "the request was recorded
            # by the apiserver" are statements about storage, not questions about the audit policy (G252).
            r"(?i)(?=.*\b(?:audit ?log\w*|audit ?polic\w+|audit ?profile|api ?requests?|log ?requests?|"
            r"detection ?coverage)\b)"
            r"(?=.*\b(?:cluster|apiserver|api ?server|turned ?on|enabled|disabled|off|who|events?)\b)"
        ),
        "kube-noob audit -f apiserver.yaml --platform openshift",
        "auditing turned off, for everyone or for one group, is KN-S035, and the report states which categories "
        "of API activity the configuration can and cannot record",
    ),
    (
        _route(
            # Not a pull failure: "image pull failed from quay" is a malfunction with a cause, and the
            # diagnosis answers it. This route is about which registries are approved (G247).
            r"(?i)(?!.*\b(?:fail\w*|backoff|unauthoriz\w*|denied|forbidden|not found|timeout|"
            r"refused|err\w*)\b)"
            r"(?=.*\b(?:registry|registries|quay|dockerhub|docker ?hub|unapproved|approved|allowlist|"
            r"whitelist|digest|pinned|mutable)\b)"
            r"(?=.*\b(?:images?|pull\w*|tags?|where ?from|provenance)\b)"
        ),
        "kube-noob audit -f <dir>",
        "every image is measured against audit.allowedRegistries by KN-S036, and a tag that can move under you "
        "is KN-S012; both read the reference the way a runtime does",
    ),
    (
        _route(
            r"(?i)(?=.*\b(?:kserve|inferenceservice|kubeflow|seldon|raycluster|rayjob|rayservice|"
            r"servingruntime|notebook)\b)"
            r"(?=.*\b(?:audit\w*|check\w*|read\w*|see|support\w*|cover\w*|container|containers|"
            r"privileged|hostnetwork|miss\w*)\b)"
        ),
        "kube-noob audit -f <dir>",
        "the pod specs inside those CRDs are audited like any other, including the containers written as a "
        "field rather than a list, and an unread one is named in the report's assumptions",
    ),
    (
        _route(
            # `watch` needs an object, not the bare verb: "the namespace has a watch annotation" matched it.
            # Not bare "happened": "what happened to my pods?" is a diagnosis question, and the playbooks
            # answer it. A time word or the word `incident` is what makes it a question about the watch (G252).
            r"(?i)(?=.*(?:\b(?:incidents?|overnight|last ?night|while I was|watching)\b"
            r"|\bhappened (?:in|overnight|last|while|yesterday)\b|\bwatch (?:a|the|my|this|for)\b"
            r"|\bkeep an eye\b))"
            r"(?=.*\b(?:namespace|namespaces|cluster|pods?|workload|remember|record|ledger)\b)"
        ),
        "kube-noob watch -n <namespace> --once",
        "opens an incident for what it sees read-only, explains it and remembers it; `kube-noob incidents list` "
        "shows what the watch recorded",
    ),
    (
        _route(
            # The second group is PHRASES, not the words `every`, `all`, `which` and `what`: with those,
            # "check all pods", "which checks failed in CI" and "liveness check failed on all replicas" all
            # asked for the rule catalogue. A question about the catalogue says so (G247).
            # One group names the thing, the other asks for it, and NEITHER contains the other's words --
            # which the import guard now enforces by containment, because "every rule" alone used to satisfy
            # both halves of this route (G252).
            r"(?i)(?=.*\b(?:rules?|checks?|catalogue|catalog)\b)"
            r"(?=.*(?:\bdo you have\b|\bdo you support\b|\bdoes kube-?noob\b|\bhow many\b"
            r"|\blist the\b|\blist all\b|\blist every\b|\bsee every\b|\bshow me\b|\bwhat are\b"
            r"|\bare there\b))"
        ),
        "kube-noob rules",
        "every rule with its stage, severity, family and the NIST controls it is evidence about",
    ),
    (
        _route(
            # Not the bare words `train` and `grade`: "train the agent on namespaces" and "deploy a production
            # grade model" are not questions about the training bench (G252).
            r"(?i)(?=.*(?:\b(?:fine-?tun\w*|reward|rewards|benchmark|bench)\b"
            # Not bare `grade`: "deploy a production grade model" is not a question about grading (G252).
            r"|\breinforcement learning\b|\bgrade (?:the|its|an|my) \w+\b|\bgrading\b))"
            r"(?=.*\b(?:model|models|llm|agent|dataset|tasks?|deterministic|score)\b)"
        ),
        "kube-noob train bench --tasks all",
        "the deterministic tasks and their scoring, so a model's answer is graded against the rules rather than "
        "against another model",
    ),
    # Last, because almost any of the above is a better answer when it matches. This one catches the broadest
    # ask there is -- "is this all right to ship" -- which was getting the generic pod-triage steps.
    (
        _route(
            r"(?i)(?=.*\b(?:safe|ok|okay|all right|alright|wrong|review|check|problems?|issues?|"
            r"production[- ]ready|good)\b)"
            # Not "this" or bare "pod": "ok this", "check this", "wrong pod" and "is this cluster ok?" all
            # matched, because the second group was true of almost any sentence (G237).
            r"(?=.*\b(?:manifest|manifests|yaml|deployment|deployments|statefulset|daemonset|chart|"
            r"helm|workload|workloads|ship|deploy|apply)\b)"
        ),
        "kube-noob audit -f <dir>",
        "every rule in the catalogue over your manifests -- schema, removed APIs, security, RBAC, network, "
        "storage, reliability -- each finding naming the field that proves it",
    ),
)
#: A sentence that reports a MALFUNCTION is a diagnosis, whatever else it says. "service ingress-nginx in
#: namespace public crashes on the new node" shares words with the exposure route, and "what is the blast radius
#: of losing one node?" shares them with the attack-path route, but neither is asking what either command
#: answers: the first wants a cause and the second is about availability. The playbooks and the audit answer
#: those, and they already run. Deliberately NOT including bare "fail" or "error": "my image build failed" and
#: "why did my helm upgrade fail" are exactly the questions two routes exist for (G237).
_A_MALFUNCTION = re.compile(
    r"(?i)\b(?:crashloopbackoff|imagepull\w*|oomkilled|evicted|unschedulable|terminating|crash(?:es|ing|ed)?|"
    r"restart(?:s|ed|ing)?|stuck|pending|not ready|unready|failing readiness|degraded|flapping|hung|hanging|"
    r"losing|lose|goes down|went down|outage|unavailable|stack ?trace|traceback|"
    # A pasted connection failure, which shares every word with the exposure and reachability routes: "Failed
    # to reach the node ... no route to host" was answered with an attack-path scan (G252).
    r"failed to reach|unable to reach|no route to host|i/o timeout|connection refused)\b"
)

MAX_ROUTES = 2


def capability_routes(text: str) -> list[dict[str, str]]:
    """The kube-noob commands that answer this question, most specific first, at most `MAX_ROUTES`.

    Only for short typed text. A pasted log or manifest is not a question, and matching one would put advice
    about `upgrade-risks` under somebody's stack trace.
    """
    # `\r` counts: a manifest with old Mac line endings has no `\n` at all and was being read as one question.
    if len(text) > 600 or any(ch in text for ch in "\n\r"):
        return []
    if _A_MALFUNCTION.search(text):
        return []
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for pattern, command, why in CAPABILITY_ROUTES:
        # One command, once. Four routes answer with `kube-noob audit -f <dir>` now, and a question that hit
        # two of them printed the same command twice with two explanations -- which reads as two suggestions
        # and is one (G252).
        if command in seen or not pattern.search(text):
            continue
        seen.add(command)
        out.append({"command": command, "why": why})
        if len(out) == MAX_ROUTES:
            break
    return out


NOT_YET: dict[str, str] = {}


def gather_steps(platform: str | None, namespace: str | None) -> list[dict[str, str]]:
    """Read-only commands that collect the evidence a diagnosis needs, for input that carries none yet."""
    from kube_noob.catalog import OPENSHIFT_FAMILY

    cli = "oc" if platform in OPENSHIFT_FAMILY else "kubectl"
    ns = namespace or "<namespace>"
    return [{"command": c.format(cli=cli, ns=ns), "why": why} for c, why in GATHER]


class _Budget:
    """Runs each analyser in a worker thread and stops waiting after ``BUDGET_SECONDS``. A late analyser's result
    is dropped and the answer says so; the size limits already bound how long any of them can take."""

    def __init__(self, skipped: list[dict[str, str]], ran: list[str]) -> None:
        self.skipped, self.ran = skipped, ran

    def run(self, name: str, fn: Any) -> Any:
        import concurrent.futures

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"insight-{name}")
        future = pool.submit(fn)
        try:
            out = future.result(timeout=BUDGET_SECONDS)
        except concurrent.futures.TimeoutError:
            self.skipped.append(
                {"kind": name, "why": f"took longer than {BUDGET_SECONDS:g} s; run it alone: {ALONE.get(name, name)}"}
            )
            return None
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        self.ran.append(name)
        return out


MAX_CEPH_FINDINGS = 10


def _ceph_findings(health: dict[str, Any]) -> list[dict[str, Any]]:
    """One finding per Ceph health code (cause first, then errors before warnings, as ``signals.ceph`` orders them)
    and per alert that names no single code. They rank after policy, build and team memory findings and before
    playbooks: the code is the cluster's own word for what is wrong. Toolbox commands stay with their finding, marked as
    needing approval; the answer's read-only steps never include them."""
    out: list[dict[str, Any]] = []
    for i, e in enumerate(health.get("entries", [])[:MAX_CEPH_FINDINGS]):
        out.append(
            {
                "source": "ceph-health",
                "id": e["code"],
                "title": e["meaning"],
                **({"severity": e["severity"]} if e.get("severity") else {}),
                "cause": e["likelyCauses"][0],
                "fix": e["fix"],
                **({"escalate": e["escalate"]} if e.get("escalate") else {}),
                "diagnosticCommands": e.get("diagnosticCommands", [])[:3],
                "rank": 6 + i / 100,
            }
        )
    for i, a in enumerate(health.get("alerts", [])[:3]):
        out.append(
            {
                "source": "ceph-health",
                "id": a["alert"],
                "title": a["meaning"],
                "diagnosticCommands": a.get("diagnosticCommands", [])[:3],
                "rank": 6.5 + i / 100,
            }
        )
    return out


def _ticket_keys(text: str) -> list[str]:
    from kube_noob.jira_catalog import DEFAULT_PROJECTS

    projects = "|".join(sorted(DEFAULT_PROJECTS, key=len, reverse=True))
    keys = re.findall(rf"\b(?:{projects})-\d{{1,9}}\b", text[:ANALYSER_TEXT])
    return list(dict.fromkeys(keys))[:MAX_TICKETS]


def _ticket_findings(kit: Any, keys: list[str], version: str | None) -> list[dict[str, Any]]:
    from kube_noob import known_issues as ki
    from kube_noob import toolkit as tk

    out: list[dict[str, Any]] = []
    index = {i.id: i for i in ki.get_index(kit.settings.data_dir).issues}
    for key in keys:
        t = kit.ticket(tk.TicketIn(key=key, version=version))
        if t.get("found"):
            out.append(
                {
                    "source": "ticket",
                    "id": key,
                    "title": t.get("title"),
                    "verdict": t.get("verdict") or t.get("status"),
                    "url": t.get("url"),
                    "rank": 3,
                }
            )
        elif key in index:
            issue = index[key]
            out.append(
                {
                    "source": "reported-issue",
                    "id": key,
                    "title": issue.summary,
                    "verdict": ki.issue_status(issue, version, kit.settings.data_dir),
                    "url": issue.url,
                    "rank": 3,
                }
            )
        else:
            out.append(
                {
                    "source": "ticket",
                    "id": key,
                    "title": "not in the local copy or the release notes",
                    "verdict": t.get("note"),
                    "rank": 40,
                }
            )
    return out


def _vulnerabilities(kit: Any, text: str) -> dict[str, Any] | str:
    from pydantic import ValidationError

    from kube_noob import toolkit as tk

    try:
        return dict(kit.vuln_report(tk.VulnReportIn(reports=[text[: tk.MAX_SCAN_REPORT]], top=10)))
    except (ValueError, ValidationError) as exc:
        return f"not read: {str(exc).splitlines()[0][:300]}"


def _code(kit: Any, text: str) -> dict[str, Any] | str:
    from pydantic import ValidationError

    from kube_noob import toolkit as tk

    try:
        return dict(kit.code_report(tk.CodeReportIn(sarif=[text[: tk.MAX_SCAN_REPORT]], top=10)))
    except (ValueError, ValidationError) as exc:
        return f"not read: {str(exc).splitlines()[0][:300]}"


def _containerfile(kit: Any, text: str) -> dict[str, Any] | str:
    from kube_noob import toolkit as tk

    try:
        return dict(kit.containerfile_audit(tk.ContainerfileIn(containerfile=text[: tk.MAX_MANIFEST_CHARS])))
    except ValueError as exc:
        return f"not audited: {str(exc).splitlines()[0][:300]}"


def _upgrade_risk(kit: Any, a: str, b: str) -> dict[str, Any] | str:
    """The two x.y.z versions found in the question, tried as (current, target) and then swapped: a phrasing like
    "upgrading to 4.15.20 from 4.14.30" names the target first, and only one order can ever be a real upgrade (the
    model rejects current >= target), so trying both costs nothing and never risks the wrong direction."""
    from kube_noob import toolkit as tk

    reason = "not evaluated"
    for current, target in ((a, b), (b, a)):
        try:
            req = tk.UpgradeRisksIn(current=current, target=target)
        except ValueError as exc:
            reason = str(exc).splitlines()[0][:200]
            continue
        return dict(kit.upgrade_risks(req))
    return reason


def _policy_migrate(kit: Any, manifests: str) -> dict[str, Any] | str:
    from kube_noob import toolkit as tk

    try:
        req = tk.PolicyMigrateCheckIn(policies=manifests[: tk.MAX_MANIFEST_CHARS])
    except ValueError as exc:
        return str(exc).splitlines()[0][:300]
    return dict(kit.policy_migrate_check(req))


# A document is offered for a pasted post only when it shares at least this many specific words with it (base forms,
# not everyday English or everyday Kubernetes words, not version numbers): measured on 25,292 community questions
# (scripts/eval_questions.py), documents sharing one incidental word answered almost none of them. A one-line question
# typed to kube-noob needs one shared word that is not everyday English ("why does my pod stay Pending?" -> pending).
MIN_DOC_TERMS = 2
LONG_POST = 300  # characters: past a title and a sentence or two, a post repeats its subject's name in passing
_STOP = frozenset(
    """
    the and for with from that this these those there their they them what when where which while does doing done
    have having would could should will shall about into onto your yours just only also some such each other more
    most than then very
    """.split()  # noqa: SIM905 - a word list reads better as text
)


_ROSA_ONLY = frozenset({"rosa-classic", "rosa-hcp"})
# Products with their own documentation that kube-noob does not carry. A question that names one is about it: a
# document that never mentions that product does not answer it, however many Kubernetes words they share (measured on
# the community-questions eval: Istio, Argo CD and Trivy questions drew Ingress, scheduling and RHACS documents).
_OTHER_TOOLS = re.compile(
    r"(?i)\b(istio|argo ?cd|argo-cd|argocd|argo workflows|trivy|karpenter|flux ?cd|fluxcd|flux2|flux|helmrelease|"
    r"helm-controller|chart\.js|chartjs|aws lambda|lambda function|security hub|falco|neuvector|aro|"
    r"azure red hat openshift|terraform|talos|"
    r"rancher|rke2|k3s|microk8s|minikube|kind cluster|docker desktop|docker compose|docker-compose|podman|"
    r"traefik|cilium|calico|envoy|keda|vault|jenkins|gitlab|github actions|tekton|skaffold|helmfile|metallb|"
    r"cert-manager|external-secrets|crossplane|longhorn|openebs|velero|knative|linkerd|kong|haproxy|"
    r"spring boot|django|laravel|wordpress|grafana|loki)\b"
)


class _DocFit:
    """Whether a knowledge doc may answer this text, beyond shared words. With no platform given, a doc written only
    for OpenShift or ROSA needs the text to say it is OpenShift or ROSA (the playbooks' rule, G83); with a platform
    given, the doc must cover it. A doc's ``requires`` groups each need one of their words in the text, and a text
    that names another product (Istio, Argo CD, Trivy...) is answered only by a doc that mentions it."""

    def __init__(self, text: str, platform: str | None) -> None:
        self.platform = platform
        self._text = text
        self._ctx: tuple[bool, bool] | None = None
        self.tools = {re.sub(r"[\s-]", "", m.lower()) for m in _OTHER_TOOLS.findall(text[:2_000])}

    def _context(self) -> tuple[bool, bool]:
        if self._ctx is None:
            from kube_noob.debug.diagnose import _ROSA_CONTEXT
            from kube_noob.known_issues import openshift_context

            self._ctx = (openshift_context(self._text), bool(_ROSA_CONTEXT.search(self._text[:200_000])))
        return self._ctx

    def __call__(self, chunk: Any, words: set[str]) -> bool:
        if chunk is None:
            return True
        extra = getattr(chunk, "extra", None) or {}
        plats = {str(p) for p in extra.get("platforms") or []}
        if plats and self.platform and self.platform not in plats:
            return False
        if plats and not self.platform and "kubernetes" not in plats:
            openshift, rosa = self._context()
            if not (rosa if plats <= _ROSA_ONLY else openshift or rosa):
                return False
        if self.tools:
            named = " ".join(extra.get("worksWith") or [])
            raw = f"{getattr(chunk, 'title', '')} {getattr(chunk, 'text', '')} {named}".lower()
            body = re.sub(r"[\s-]", "", raw)
            # a short name ("aro", "kong", "loki") must be a word of the document, not part of one ("around")
            if not any(t in body if len(t) > 5 else re.search(rf"\b{re.escape(t)}\b", raw) for t in self.tools):
                return False  # the question is about a product this document never mentions
        return all(any(w in words for w in group) for group in extra.get("requires") or [])


# A policy engine and the playbook for its denials (debug/policy.py ENGINES; Kyverno and Gatekeeper have none).
_ENGINE_PLAYBOOK = {
    "validating-admission-policy": "DBG-VAP",
    "openshift-scc": "DBG-SCC",
    "pod-security": "DBG-PSA",
    "rhacs": "DBG-STACKROX-ADMISSION",
}


# The asker wants to change or get around the policy itself, not their object: "Should I just edit restricted-v2?",
# "how do I make it friendlier?", "What are my options?".
_POLICY_SIDE = re.compile(
    r"(?i)\b(?:edit|modify|disable|bypass|exempt\w*|exceptions?|turn (?:it )?off|loosen|relax|override|options|"
    r"friendlier|clearer|message(?:Expression)?|break[- ]?glass)\b"
)

# A legacy Kyverno policy document (not already the CEL types, whose apiGroup is policies.kyverno.io): a pasted
# ClusterPolicy, Policy, ClusterCleanupPolicy, CleanupPolicy or PolicyException is worth checking against the CEL
# migration, since Kyverno v1.19 is the last release with full support for the legacy group. Checked as two separate
# lines (not one anchored block) because kind: can come before or after apiVersion: and several documents may be
# concatenated; a false match only costs one extra call, since policy_migrate_check itself lists and skips anything
# that is not a legacy Kyverno policy.
_LEGACY_KYVERNO_API = re.compile(r"(?m)^apiVersion:\s*kyverno\.io/v\S+\s*$")
_LEGACY_KYVERNO_KIND = re.compile(r"(?m)^kind:\s*(?:Cluster)?(?:Cleanup)?Policy(?:Exception)?\s*$")
_MIGRATE_RANK = {"blocked": 2, "manual": 3, "inverted": 14, "direct": 16}


def _engine_playbook_first(findings: list[dict[str, Any]], text: str) -> None:
    """The policy explainer (which policy, what it means, the change to the object) comes first, except when the
    denying engine's own playbook matched and either the explainer has no change to offer or the question asks about
    the policy itself (editing, bypassing or exempting it, its message, the options): then the playbook, which covers
    the policy side, comes first and the explainer right after it. The owner delegated this call (2026-10-28)."""
    asked = " ".join(s for s in _SENTENCE_END.split(text[-2000:]) if s.rstrip().endswith("?"))
    policy_side = bool(_POLICY_SIDE.search(asked))
    ranks = {f["id"]: f["rank"] for f in findings if f["source"] == "playbook"}
    words = _specific_terms(asked, kubernetes_words=True)
    for f in findings:
        if f["source"] != "policy":
            continue
        pid = _ENGINE_PLAYBOOK.get(str(f.get("id") or "").split("/", 1)[0])
        if pid in ranks and (policy_side or not f.get("fix")):
            f["rank"] = ranks[pid] + 0.5
        elif pid is None and policy_side:
            # Kyverno and Gatekeeper have no playbook of their own: the document section on the asked mechanism
            # (a PolicyException, an exempt namespace) answers a question about the policy itself.
            doc = next(
                (
                    d
                    for d in sorted(findings, key=lambda d: d["rank"])
                    if d["source"] == "doc"
                    and len(words & _specific_terms(str(d.get("title") or ""), kubernetes_words=True)) >= 2
                ),
                None,
            )
            if doc is not None:
                doc["rank"] = f["rank"] - 0.5


def _explain_first(findings: list[dict[str, Any]], query: str, asked: set[str]) -> None:
    """A typed conceptual question ("What is the difference between Degraded and Available...") whose only playbook
    is a weak word match gets the document section that explains it first, when the section's heading shares two
    specific words with the question. A question that quotes an error keeps the playbook first."""
    if "\n" in query or not _CONCEPTUAL.match(query.strip()) or _ERRORISH.search(query):
        return
    playbooks = [f for f in findings if f["source"] == "playbook"]
    if not playbooks or any(float(f.get("confidence") or 0) >= WEAK_PLAYBOOK for f in playbooks):
        return
    for f in findings:
        if f["source"] != "doc":
            continue
        heading = str(f.get("title") or "").split(" > ", 1)[-1]
        if len(asked & _specific_terms(heading, kubernetes_words=True)) >= 2:
            f["rank"] = 9  # before the playbooks (10 and up), after policy and build findings
            return


def _closest(options: list[str], text: str, hint: str = "") -> str:
    """The option that shares the most specific words with ``text``, then with ``hint`` at half weight (the first on
    a tie): a playbook lists every cause and fix it knows, and the finding should show the one this input points at.
    Each shared word counts by how rare it is across all playbook text ("minikube" says much, "pull" little)."""
    if not options:
        return ""
    df = _playbook_word_counts()
    want = _specific_terms(text, kubernetes_words=True)
    also = _specific_terms(hint, kubernetes_words=True) - want if hint else set()

    def score(option: str) -> float:
        ts = _specific_terms(option, kubernetes_words=True)
        return sum(1.0 / df.get(t, 1) for t in want & ts) + sum(0.5 / df.get(t, 1) for t in also & ts)

    scores = [score(o) for o in options]
    return options[max(range(len(options)), key=lambda n: (scores[n], -n))]


@functools.lru_cache(maxsize=1)
def _playbook_word_counts() -> dict[str, int]:
    """In how many playbook causes, checks and fixes each specific word appears."""
    from kube_noob.debug.playbooks import PLAYBOOKS

    counts: Counter[str] = Counter()
    for pb in PLAYBOOKS:
        for line in (*pb.root_causes, *pb.checks, *pb.fixes):
            counts.update(_specific_terms(line, kubernetes_words=True))
    return dict(counts)


def _specific_terms(text: str, *, kubernetes_words: bool = False) -> set[str]:
    """Words of ``text`` in base form that carry meaning: not stop words or everyday English and, unless
    ``kubernetes_words``, not everyday Kubernetes words either (pod, node, error, pending)."""
    from kube_noob.knowledge.store import tokenize
    from kube_noob.known_issues import EVERYDAY_WORDS, _forms
    from kube_noob.tickets import GENERIC_WORDS

    out: set[str] = set()
    for t in tokenize(text[:20_000]):
        if len(t) <= 3 or not any(ch.isalpha() for ch in t):
            continue
        forms = _forms(t)
        if any(f in _STOP or f in EVERYDAY_WORDS or (not kubernetes_words and f in GENERIC_WORDS) for f in forms):
            continue
        out.add(min(forms, key=len))
    return out


def insight(kit: Any, text: str, platform: str | None = None, version: str | None = None) -> dict[str, Any]:
    """Recognise the input, run every analyser that applies (each on its own size and time budget) and merge
    what they found into one answer."""
    from kube_noob import toolkit as tk

    text = text[:MAX_TEXT]
    kinds = recognise(text)
    names = {k.kind for k in kinds}
    findings: list[dict[str, Any]] = []
    steps: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    ran: list[str] = []
    budget = _Budget(skipped, ran)
    tail = text[-ANALYSER_TEXT:]
    textual = {
        "alert-payload",
        "ceph-health",
        "events",
        "pod-status",
        "logs",
        "ticket",
        "build-log",
        "question",
        "policy-denial",
    }
    context: dict[str, Any] = {}
    signals: list[Any] = []
    # Whether "no reported issue" is an answer for the version asked (G277): the first analyser that consulted the
    # known-issue index says so, and the merged answer keeps it rather than dropping it with the analyser's output.
    ki_coverage: dict[str, Any] | None = None
    payload_input: dict[str, Any] = {}  # an Alertmanager payload's own version, kept beside a --version (G277)

    doc = _json(text)
    if isinstance(doc, dict) and doc.get("kind") == "Status" and isinstance(doc.get("message"), str):
        # the denial as the API server wrote it, quotes unescaped; a lone surrogate from a JSON escape is not text
        tail = f"{sanitize.replace_surrogates(doc['message'])}\n{tail}"
    if names & textual or not names:
        d = budget.run(
            "diagnose", lambda: kit.diagnose(tk.DiagnoseIn(text=tail, platform=platform, version=version, limit=5))
        )
        d = d or {}
        ki_coverage = d.get("knownIssuesCoverage")
        payload_input = d.get("input") or {}
        signals = list(d.get("signals") or [])
        for i, x in enumerate(d.get("diagnoses", [])[:3]):
            if "likelyCause" in x:  # cause-linked triage: the cause the input points at and its own fix
                likely = str(x["likelyCause"])
                fix = str((x.get("likelyFixes") or [""])[0])
            else:
                likely = _closest(x.get("rootCauses") or [], tail)
                fix = _closest([c.get("change", "") for c in x.get("proposedChanges") or []], tail, likely)
            findings.append(
                {
                    "source": "playbook",
                    "id": x["id"],
                    "title": x["title"],
                    "confidence": x["confidence"],
                    "cause": likely,
                    "fix": fix,
                    "rank": 10 + i,
                }
            )
            if i == 0:
                steps += x.get("readOnlyNextSteps", [])[:6]
        for m in d.get("knownIssues", [])[:3]:
            findings.append(
                {
                    "source": "reported-issue",
                    "id": m.get("id"),
                    "title": m.get("title") or m.get("summary"),
                    "verdict": m.get("verdict") or m.get("status"),
                    "url": m.get("url"),
                    "rank": 20,
                }
            )
        for m in d.get("memory", [])[:3]:
            findings.append(
                {
                    "source": "team-memory",
                    "id": m.get("id"),
                    "title": m.get("symptom"),
                    "cite": m.get("citation"),
                    "rank": 5,
                }
            )
        for den in d.get("policyDenials", [])[:3]:
            findings.append(
                {
                    "source": "policy",
                    "id": "/".join(str(x) for x in (den.get("engine"), den.get("policy"), den.get("rule")) if x),
                    "title": den.get("meaning") or den.get("message"),
                    # every change the requester can make; exceptions and new permissions stay with the policy owner
                    "fix": " ".join(
                        str(c.get("change", ""))
                        for c in (den.get("proposedChanges") or [])[:4]
                        if not c.get("needsPolicyOwner")
                    )[:800],
                    "rank": 1,
                }
            )
            steps = [*den.get("readOnlyNextSteps", [])[:3], *steps]
        findings += _ceph_findings(d.get("cephHealth") or {})
        if d.get("cephHealth"):
            # The CephCluster status (codes without a shell in the toolbox), then the first code's own reads.
            first = (d["cephHealth"].get("entries") or [{}])[0]
            steps = [*d["cephHealth"].get("readOnlyNextSteps", []), *first.get("readOnlyNextSteps", [])[:3], *steps]
        context = d.get("context") or {}
    if "build-log" in names:
        b = budget.run(
            "build",
            lambda: kit.build_diagnose(
                tk.BuildDiagnoseIn(log=text[-tk.MAX_BUILD_LOG :], platform=platform, version=version)
            ),
        )
        if b:
            ki_coverage = ki_coverage or b.get("knownIssuesCoverage")
            cause = b.get("cause") or {}
            step = b.get("failingStep") or {}
            findings.append(
                {
                    "source": "build",
                    "id": cause.get("class") or "build-failure",
                    "title": f"{b['system']}: step {step.get('name', '?')} failed"
                    + (f": {cause['meaning']}" if cause else ""),
                    "confidence": cause.get("confidence"),
                    "evidence": [e["text"] for e in b.get("evidence", [])[:2]],
                    "fix": b.get("fix", [])[:3],
                    "rank": 2,
                }
            )
            for m in b.get("knownIssues", [])[:2]:
                if m.get("id") not in {f.get("id") for f in findings}:
                    findings.append(
                        {
                            "source": "reported-issue",
                            "id": m.get("id"),
                            "title": m.get("title") or m.get("summary"),
                            "verdict": m.get("verdict") or m.get("status"),
                            "url": m.get("url"),
                            "rank": 20,
                        }
                    )
            steps = [{"command": c, "why": "read the failed run"} for c in b.get("readOnlyNextSteps", [])[:3]] + steps
    if "containerfile" in names:
        rep = budget.run(
            "containerfile",
            lambda: _containerfile(kit, text),
        )
        if isinstance(rep, str):
            ran.remove("containerfile")
            skipped.append({"kind": "containerfile", "why": rep})
        elif rep:
            for f in rep["findings"][:10]:
                findings.append(
                    {
                        "source": "rule",
                        "id": f["ruleId"],
                        "title": f["message"],
                        "severity": f["severity"],
                        "resource": f"Containerfile line {f['line']}" if f.get("line") else "Containerfile",
                        "rank": 15 - _SEVERITY.get(str(f.get("severity")), 0),
                    }
                )
    vuln_kinds = names & {"sbom", "scanner-report"}
    unread = set(vuln_kinds)
    is_sarif = isinstance(doc, dict) and isinstance(doc.get("runs"), list) and "Results" not in doc
    if "scanner-report" in vuln_kinds and is_sarif:
        vuln_kinds = vuln_kinds - {"scanner-report"}
        unread.discard("scanner-report")
        rep_code = budget.run("code", lambda: _code(kit, text))
        if isinstance(rep_code, str):
            ran.remove("code")
            skipped.append({"kind": "scanner-report", "why": rep_code})
        elif rep_code:
            for r in rep_code["ranking"]["ranked"][:10]:
                f = r["finding"]
                loc = f["location"]
                findings.append(
                    {
                        "source": "code",
                        "id": f["cwe"][0] if f["cwe"] else f["sources"][0]["ruleId"],
                        "title": f"{f['title'][:120]} ({', '.join(f['tools'])})",
                        "severity": f["severity"],
                        "resource": f"{loc['path']}:{loc.get('line', '?')}",
                        "rank": 12 - _SEVERITY.get(str(f["severity"]), 0),
                    }
                )
            c = rep_code["counts"]
            context["code"] = {k: c[k] for k in ("results", "findings", "excluded", "quality")}
    if vuln_kinds and isinstance(doc, dict):
        rep = budget.run("vulnerabilities", lambda: _vulnerabilities(kit, text))
        if isinstance(rep, str):
            ran.remove("vulnerabilities")
            for k in sorted(vuln_kinds):
                skipped.append({"kind": k, "why": rep})
            unread = set()
        elif rep:
            unread = set()
            for r in rep["ranking"]["ranked"][:10]:
                f = r["finding"]
                findings.append(
                    {
                        "source": "vulnerability",
                        "id": f["cve"],
                        "title": f"{f['package']['name']} {f['package']['version']}: "
                        + (f"fixed in {f['fixVersion']}" if f["fixVersion"] else "no fix yet")
                        + (" (known exploited)" if f["knownExploited"] else ""),
                        "severity": {"negligible": "info", "unknown": "medium"}.get(f["severity"], f["severity"]),
                        "resource": r["image"],
                        "rank": 12 - _SEVERITY.get(str(f["severity"]), 0) - (2 if f["knownExploited"] else 0),
                    }
                )
            c = rep["counts"]
            context["vulnerabilities"] = {k: c[k] for k in ("reported", "excludedByVex", "findings", "fixable")}
    for k in sorted(unread):
        skipped.append({"kind": k, "why": UNREAD[k]})
    keys = _ticket_keys(text)
    if keys:
        known = {f["id"] for f in findings}
        fresh = [k for k in keys if k not in known]
        if fresh:
            findings += budget.run("tickets", lambda: _ticket_findings(kit, fresh, version)) or []
    if "question" in names:
        from kube_noob.knowledge.store import tokenize
        from kube_noob.known_issues import _forms

        query = text.strip()[:500]
        res = budget.run("search", lambda: kit.search(tk.SearchIn(query=query, limit=8)))
        seen: set[str] = set()
        typed = "\n" not in query  # a question typed to kube-noob, not a pasted post
        long_post = not typed and len(text.strip()) > LONG_POST
        asked = _specific_terms(query, kubernetes_words=typed)
        words = {f for t in tokenize(query) for f in _forms(t)}
        need = MIN_DOC_TERMS
        store = kit.store()
        if typed:
            from kube_noob.known_issues import EVERYDAY_WORDS

            unknown = [
                t
                for t in tokenize(query)
                if len(t) > 3
                and t.isalpha()
                and not any(f in _STOP or f in EVERYDAY_WORDS for f in _forms(t))
                and all(store.doc_frequency(f) == 0 for f in _forms(t))  # "quotas" is known as "quota"
            ]
            if unknown:
                # It names something the knowledge has never seen ("Talos", "batchMaxDuration", "Trivy"): it is
                # about that, and a document sharing two of its other words ("node", "pool") is not.
                need = MIN_DOC_TERMS + 1
            elif len(asked) <= 2:
                need = 1  # a short question needs one shared word
        fits = _DocFit(text, platform)
        for h in (res or {}).get("results", []):
            doc = h["chunkId"].split("#", 1)[0]
            if doc in seen or len(seen) == 3:
                continue
            chunk = store.get(h["chunkId"])
            body = chunk.text if chunk is not None else h.get("text") or ""  # the whole chunk: search results are cut
            shared = asked & _specific_terms(f"{h.get('title') or ''} {body}", kubernetes_words=typed)
            # The first word group a document requires names its subject ("rook", "ceph", "kyverno"): every post
            # about that subject shares those words, so in a long pasted post they say nothing about which section
            # answers it (a typed question or a title with one line is short: each of its words counts).
            subject = set(((getattr(chunk, "extra", None) or {}).get("requires") or [[]])[0]) if long_post else set()
            if len(shared - subject) < need:  # one incidental shared word does not make a document an answer
                continue
            if not fits(chunk, words):
                continue
            seen.add(doc)
            findings.append(
                {
                    "source": "doc",
                    "id": h["chunkId"],
                    "title": h.get("title"),
                    "sharedTerms": sorted(shared)[:6],
                    # A pasted post is answered by its evidence; a document that shares its words is related reading
                    # (QA4: word-matched documents answered 2 of 30 pasted posts).
                    **({} if typed else {"related": True}),
                    "rank": 30 + len(seen),
                }
            )
        _explain_first(findings, query, asked)
        if typed and _UPGRADE_WORD.search(query):
            versions = _VERSION3.findall(query)
            if len(versions) >= 2:
                rep = budget.run("upgrade-risk", lambda: _upgrade_risk(kit, versions[0], versions[1]))
                if isinstance(rep, str):
                    ran.remove("upgrade-risk")
                    skipped.append({"kind": "upgrade-risk", "why": rep})
                elif rep:
                    edge = rep["edge"]
                    counts = rep["counts"]
                    title = (
                        f"{edge['from']} to {edge['to']}: {counts['applies']} risk(s) always apply, "
                        f"{counts['check']} need a fact checked"
                        if rep["covered"]
                        else f"{edge['from']} to {edge['to']}: {rep.get('note') or 'not in the bundled snapshot'}"
                    )
                    findings.append(
                        {
                            "source": "upgrade-risk",
                            "id": f"{edge['from']}->{edge['to']}",
                            "title": title,
                            "fix": "kube-noob upgrade-risks for the per-risk evidence and the read-only check for "
                            "each one that needs a fact about the cluster.",
                            "rank": 2 if counts["applies"] else (4 if counts["check"] else 16),
                        }
                    )
                    context["upgradeRisk"] = rep
            elif _VERSION_LOOSE.search(query):
                skipped.append(
                    {
                        "kind": "upgrade-risk",
                        "why": "name the exact patch version on both sides (x.y.z, e.g. 4.14.30 to 4.15.20): the "
                        "risk snapshot is keyed on patch versions and a guessed one could hide or invent a risk.",
                    }
                )
    if "manifests" in names:
        from kube_noob.errors import ManifestError

        docs = _yaml_docs(text)
        manifests = text if docs and all("apiVersion" in x and "kind" in x for x in docs) else None
        manifests = manifests or "\n---\n".join(manifest_segments(text)) or text  # YAML that does not parse: the
        # audit's loader says why
        where = {k: v for k, v in (("platform", platform), ("version", version)) if v}

        def audit() -> Any:
            try:
                return kit.audit(tk.AuditIn(manifests=manifests[: tk.MAX_MANIFEST_CHARS], **where))
            except (ManifestError, ValueError) as exc:
                return ManifestError(str(exc).splitlines()[0][:300])

        rep = budget.run("audit", audit)
        if isinstance(rep, ManifestError):
            ran.remove("audit")
            skipped.append({"kind": "manifests", "why": f"not audited: {rep}"})
            rep = None
        ordered = sorted((rep or {}).get("findings", []), key=lambda f: -_SEVERITY.get(str(f.get("severity")), 0))
        for f in ordered[:10]:
            findings.append(
                {
                    "source": "rule",
                    "id": f["ruleId"],
                    "title": f["message"],
                    "severity": f["severity"],
                    "resource": f.get("resource"),
                    "rank": 15 - _SEVERITY.get(str(f.get("severity")), 0),
                }
            )
        if re.search(r"^kind:\s*NetworkPolicy\s*$", manifests, re.M):
            skipped.append(
                {
                    "kind": "network-policy",
                    "why": "reachability needs a source, a destination and a port: kube-noob policy reach --from "
                    "<ns>/<workload> --to <ns>/<workload> --port <port> -f <file>",
                }
            )
        if _LEGACY_KYVERNO_API.search(manifests) and _LEGACY_KYVERNO_KIND.search(manifests):
            mig = budget.run("policy-migrate", lambda: _policy_migrate(kit, manifests))
            if isinstance(mig, str):
                ran.remove("policy-migrate")
                skipped.append({"kind": "policy-migrate", "why": mig})
            elif mig:
                for p in mig["policies"][:10]:
                    findings.append(
                        {
                            "source": "policy-migrate",
                            "id": p["policy"],
                            "title": f"{p['policy']}: {p['verdict']} mapping to "
                            + (", ".join(p.get("targets") or []) or "no CEL type"),
                            "fix": "kube-noob policy migrate-check for the field-by-field mapping and draft CEL "
                            "policy; Kyverno v1.19 is the last release with full ClusterPolicy/Policy support.",
                            "rank": _MIGRATE_RANK.get(str(p["verdict"]), 16),
                        }
                    )
                context["policyMigrate"] = mig["summary"]
    if "helm-chart" in names:
        skipped.append(
            {
                "kind": "helm-chart",
                "why": "templates are audited after rendering: helm template <release> <chart> | kube-noob audit -f -",
            }
        )
    for k in sorted(names & (set(PENDING) | set(NOT_YET))):
        skipped.append({"kind": k, "why": PENDING.get(k) or NOT_YET[k]})
    evidence = {
        "playbook",
        "policy",
        "ceph-health",
        "rule",
        "ticket",
        "reported-issue",
        "team-memory",
        "build",
        "vulnerability",
        "code",
    }
    about_a_cluster = bool(platform) or bool(_CLUSTER_WORDS.search(text[:20_000]))
    # Only a QUESTION is routed. `capability_routes` sees the text, not what was recognised in it, and on its own
    # that sent a pasted Event whose pod was called `gate-7d9f` to the CI gate, a Deployment named `upgrade` to
    # `upgrade-risks`, and an SBOM with a component called `gate` to the gate again. A subset test rather than
    # `"question" in names`, because `recognise` finds NO kind at all for several real typed questions
    # ("produce an OSCAL assessment for our auditor"), and requiring the kind would silence those (G237).
    answered_by = capability_routes(text) if names <= {"question"} else []
    if (
        not steps
        and not any(f["source"] in evidence for f in findings)
        and (names & textual or not names)
        and about_a_cluster
        # The generic gather steps answer "something is broken, what is it". When the question has a direct
        # answer and nothing was diagnosed, printing `get pods` under it is the very noise G235 is about.
        and not (answered_by and not findings)
    ):
        ns = context.get("namespace")
        steps = gather_steps(platform, ns if isinstance(ns, str) else None)
        ran.append("gather")
    _engine_playbook_first(findings, text)
    findings.sort(key=lambda f: (f["rank"], str(f.get("id"))))
    for f in findings:
        f.pop("rank", None)
    return {
        "kinds": [k.as_dict() for k in kinds] or [{"kind": "unknown", "evidence": "nothing recognised"}],
        "ran": ran,
        "findings": findings,
        "signals": signals,
        "readOnlyNextSteps": steps[:8],
        # What in kube-noob answers the question, when the question names a job it does. Separate from
        # readOnlyNextSteps, which are commands against the CLUSTER to collect evidence: those answer "something
        # is broken, what is it", and a question like "which exposed services could reach a node" is not that
        # (G235).
        "answeredBy": answered_by,
        "context": context,
        "skipped": skipped,
        **({"knownIssuesCoverage": ki_coverage} if ki_coverage else {}),
        **{k: v for k, v in payload_input.items() if k in {"payloadVersion", "payloadVersionFrom", "versionConflict"}},
        # What to paste instead, for a caller that reads JSON as well as for the text view (G277).
        **({} if kinds else {"recognises": [{"kind": k, "what": KIND_DESCRIPTIONS[k]} for k in KINDS]}),
        "approach": "Read-only first: every step listed here only reads; changes come from the playbook or rule "
        "with a person's approval."
        + (GATHER_NOTE if "gather" in ran else "")
        + (" What this product can answer directly is under answeredBy." if answered_by and not findings else "")
        + ("" if about_a_cluster or findings or answered_by else NO_CLUSTER_NOTE),
    }
