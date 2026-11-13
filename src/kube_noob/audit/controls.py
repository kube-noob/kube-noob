"""NIST SP 800-53 Rev. 5 controls each audit rule gives evidence for.

FedRAMP (Rev5 baselines and the 20x Key Security Indicators) and most US federal frameworks are expressed in NIST SP
800-53 controls. Mapping every rule to the controls it supports lets an audit report double as configuration evidence
for CM-6, AC-6, SC-7 and the rest. A mapping says which control a finding is evidence about; it is not an assessment
and does not make a system compliant.

Source: NIST SP 800-53 Rev. 5 (https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final), control titles as published.
"""

from __future__ import annotations

from typing import Any

CATALOG = "NIST SP 800-53 Rev. 5"
CATALOG_URL = "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"

TITLES: dict[str, str] = {
    "AC-3": "Access Enforcement",
    "AC-4": "Information Flow Enforcement",
    "AC-5": "Separation of Duties",
    "AC-6": "Least Privilege",
    "AC-6(5)": "Least Privilege | Privileged Accounts",
    "AC-6(10)": "Least Privilege | Prohibit Non-privileged Users from Executing Privileged Functions",
    "AC-14": "Permitted Actions Without Identification or Authentication",
    # AU arrives with KN-S035: the first rule in this catalogue that reads audit CONFIGURATION rather
    # than inferring the state of logging from the absence of a log. Nothing here reads an audit event.
    "AU-2": "Event Logging",
    "AU-12": "Audit Record Generation",
    "CM-2": "Baseline Configuration",
    "CM-3(2)": "Configuration Change Control | Testing, Validation, and Documentation of Changes",
    "CM-6": "Configuration Settings",
    "CM-7": "Least Functionality",
    "CP-10": "System Recovery and Reconstitution",
    "IA-5": "Authenticator Management",
    "IA-5(7)": "Authenticator Management | No Embedded Unencrypted Static Authenticators",
    "SA-22": "Unsupported System Components",
    "SC-4": "Information in Shared System Resources",
    "SC-5": "Denial-of-service Protection",
    "SC-6": "Resource Availability",
    "SC-7": "Boundary Protection",
    "SC-7(5)": "Boundary Protection | Deny by Default — Allow by Exception",
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-8(1)": "Transmission Confidentiality and Integrity | Cryptographic Protection",
    "SC-28": "Protection of Information at Rest",
    "SC-28(1)": "Protection of Information at Rest | Cryptographic Protection",
    "SC-36": "Distributed Processing and Storage",
    "SC-39": "Process Isolation",
    "SI-2": "Flaw Remediation",
    "SI-7": "Software, Firmware, and Information Integrity",
    "SI-10": "Information Input Validation",
}

_VALIDATION = ("CM-3(2)", "CM-6")

RULE_CONTROLS: dict[str, tuple[str, ...]] = {
    # Security context and workload privileges
    "KN-S001": ("AC-6", "CM-7", "SC-39"),
    "KN-S002": ("AC-6", "AC-6(10)", "CM-7"),
    "KN-S003": ("AC-6", "CM-6"),
    "KN-S004": ("CM-6", "AC-6"),
    "KN-S005": ("AC-6", "CM-7"),
    "KN-S006": ("AC-6", "CM-7"),
    "KN-S007": ("CM-7", "SI-7"),
    "KN-S008": ("CM-6", "CM-7", "SC-39"),
    "KN-S009": ("SC-39", "AC-6"),
    "KN-S010": ("AC-6", "SC-39"),
    "KN-S011": ("SC-7", "CM-7"),
    "KN-S012": ("CM-2", "SI-7"),
    "KN-S036": ("CM-2", "SI-7"),  # provenance of the artifact that runs, like KN-S012's half of the reference
    "KN-S013": ("IA-5(7)", "SC-28"),
    "KN-S014": ("AC-6", "IA-5", "CM-7"),
    "KN-S015": ("AC-3", "AC-6"),
    "KN-S016": ("AC-6", "AC-6(5)"),
    "KN-S017": ("AC-3", "AC-5", "AC-6"),
    "KN-S018": ("IA-5(7)", "SC-28"),
    "KN-S019": ("AC-6", "CM-7", "SC-39"),
    "KN-S020": ("SC-39", "CM-7"),
    "KN-S029": ("SC-7", "CM-7"),  # the kubelet is made to cross a boundary on the pod's behalf
    "KN-S030": ("CM-7", "SI-7"),  # a control the cluster believes it has is skipped when the hook is down
    "KN-S021": ("SI-2", "CM-7", "SC-39"),  # a deprecated volume driver with a published breakout
    "KN-S022": ("SI-2", "SC-39", "CM-7"),
    "KN-S023": ("SI-2", "SC-39"),
    "KN-S024": ("SI-2", "SA-22"),  # a component below its fixed releases, from a retired project
    "KN-S025": ("SI-2", "SI-10", "SC-39"),  # shell syntax in a path kubelet handed to PowerShell
    "KN-S026": ("IA-5(7)", "SC-28"),
    "KN-S027": ("IA-5", "AC-6"),  # a non-expiring token in a readable object
    "KN-S028": ("AC-14", "AC-3", "AC-6"),
    # Network exposure
    "KN-N001": ("SC-7", "SC-7(5)", "AC-4"),
    "KN-N002": ("SC-8", "SC-8(1)"),
    "KN-N003": ("SC-8", "SC-8(1)"),
    "KN-N004": ("SC-7", "AC-4"),
    "KN-N005": ("SC-7", "CM-7"),
    "KN-N006": ("SC-7", "SC-7(5)", "AC-4"),
    "KN-N007": ("SC-7", "SC-7(5)", "AC-4"),
    "KN-N008": ("SC-7", "SC-8", "AC-4"),  # externalIPs let a Service intercept traffic in transit
    "KN-N009": ("CM-7", "SI-2", "SC-7"),
    "KN-N010": ("CM-6", "CM-7", "SI-2"),
    "KN-N011": ("SI-2", "SI-10", "CM-7"),
    "KN-N012": ("SC-7", "SC-7(5)", "AC-4"),  # a policy that selects no pod enforces nothing
    "KN-N013": ("SC-7", "CP-10"),  # egress denied without DNS: the workload cannot resolve and stops serving
    "KN-N014": ("SC-7", "SC-7(5)", "AC-4"),
    # Storage
    "KN-ST001": ("CM-6",),
    "KN-ST002": ("CM-6", "CP-10"),
    "KN-ST003": ("SC-36", "CM-6"),
    "KN-ST004": ("CM-6",),
    "KN-ST005": ("CM-6", "SC-6"),
    "KN-ST006": ("SI-2", "SI-10", "AC-6"),
    # Reliability and capacity
    "KN-C001": ("CP-10",),
    "KN-C002": ("CP-10",),
    "KN-C003": ("CP-10", "SC-5"),
    "KN-C004": ("SC-6",),
    "KN-C005": ("SC-5", "SC-6"),
    "KN-C006": ("CM-6",),
    "KN-C007": ("CP-10", "SC-36"),
    "KN-C008": ("CP-10",),
    "KN-C009": ("SI-2", "CP-10"),  # a PDB that blocks every eviction blocks node patching
    "KN-C010": ("SC-36",),
    "KN-C011": ("CP-10",),
    "KN-C012": ("SC-6",),
    "KN-C013": ("CM-6",),
    "KN-C014": ("CM-6", "SC-6"),  # each apply resets the capacity the autoscaler set
    # Validation: changes are tested before they reach the cluster
    "KN-V001": _VALIDATION,
    "KN-V002": _VALIDATION,
    "KN-V003": _VALIDATION,
    "KN-V004": _VALIDATION,
    "KN-V005": ("CM-3(2)", "SA-22"),
    "KN-V006": ("SA-22",),
    "KN-V008": ("SA-22",),
    "KN-V009": _VALIDATION,
    "KN-V010": _VALIDATION,
    "KN-V011": _VALIDATION,
    "KN-V012": _VALIDATION,
    "KN-V023": _VALIDATION,
    "KN-V014": _VALIDATION,
    "KN-V015": ("SC-7", "CM-6"),  # an EgressFirewall not named 'default' is ignored: no egress control at all
    "KN-V016": ("SC-8", "CM-6"),
    "KN-V017": ("CM-6",),
    "KN-V018": _VALIDATION,
    "KN-V019": ("SA-22",),  # the retired ingress-nginx receives no fixes
    "KN-V020": _VALIDATION,
    "KN-V021": _VALIDATION,
    "KN-V022": _VALIDATION,
    "KN-C015": ("CM-6",),  # a claim that does not exist: the workload never schedules
    "KN-S031": ("AC-6", "SC-4"),  # device access across tenants, and the device keeps prior state
    "KN-S032": ("AC-6", "CM-6"),  # the pod security level the namespace enforces
    "KN-S033": ("SI-2",),  # a paused pool stops receiving OS and runtime patches
    "KN-S034": ("CM-3(2)",),  # an operator upgrade nobody reviewed
    "KN-S035": ("AU-2", "AU-12"),  # audit turned off, for everyone or for one group
    "KN-C016": ("SC-5", "SC-6"),  # one namespace can take the cluster's capacity
    # The control plane and its trust boundaries (G272)
    "KN-S037": ("SC-8", "SC-8(1)", "CM-6"),  # the aggregator does not authenticate the server it forwards to
    "KN-S038": ("AC-3", "AC-14", "CM-6"),  # every request authorized, or requests with no identity accepted
    "KN-S039": ("SC-8", "SC-8(1)", "AC-3"),  # the store of every Secret, reachable in plaintext or by anyone
    "KN-S040": ("SC-28", "SC-28(1)"),  # Secrets written to etcd as they are
    "KN-S041": ("SC-8", "SC-8(1)", "IA-5"),  # passwords sent to the directory in plaintext
}


def controls_for(rule_id: str) -> list[str]:
    return list(RULE_CONTROLS.get(rule_id, ()))


def describe(rule_id: str) -> list[dict[str, str]]:
    return [{"id": c, "title": TITLES[c]} for c in RULE_CONTROLS.get(rule_id, ())]


def summary(
    rule_ids: list[str],
    excepted_rule_ids: list[str] | None = None,
    evaluated_rule_ids: list[str] | None = None,
    fired_rule_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Controls touched by a set of findings, most findings first: for an audit report.

    ``excepted_rule_ids`` are the rules whose findings an exceptions file accepted. They are counted separately
    and they still put their controls in the list. An exception is a reviewed, owned, expiring decision about a
    control -- it is evidence *about* that control, so a control held only by excepted findings must stay named.
    Dropping it would make a control somebody signed off on indistinguishable from a control nothing evaluated,
    which is the one confusion a compliance record must not create.

    ``evaluated_rule_ids`` is every rule that actually ran. With it, that same confusion is resolved for the
    other direction too: a control whose rules ran and found nothing is reported with ``clean``, and one whose
    rules did not run at all is reported with ``notEvaluated``, instead of both being absent from the list.
    Without it the older shape is kept, so a caller that cannot say what ran does not get a coverage claim it
    has not earned.

    ``fired_rule_ids`` is every rule that produced a finding BEFORE the caller's severity filter. Without it,
    `--min-severity high` moved every rule whose finding was withheld into ``clean``: CP-10 went from "3
    findings, 6 clean" to "0 findings, 9 clean", and the record then said nine rules ran and found nothing when
    three of them had found something. Those rules are counted as ``withheld`` instead -- not a finding in this
    view, and emphatically not clean (G199).
    """
    counts: dict[str, int] = {}
    excepted: dict[str, int] = {}
    for rid in rule_ids:
        for c in RULE_CONTROLS.get(rid, ()):
            counts[c] = counts.get(c, 0) + 1
    for rid in excepted_rule_ids or ():
        for c in RULE_CONTROLS.get(rid, ()):
            excepted[c] = excepted.get(c, 0) + 1
    clean: dict[str, int] = {}
    unevaluated: dict[str, int] = {}
    partly: dict[str, int] = {}
    withheld: dict[str, int] = {}
    not_evaluated_rules: list[str] = []
    partly_evaluated_rules: list[str] = []
    if evaluated_rule_ids is not None:
        ran = set(evaluated_rule_ids)
        with_findings = set(rule_ids) | set(excepted_rule_ids or ())
        hidden = set(fired_rule_ids or ()) - with_findings
        for rid, cs in RULE_CONTROLS.items():
            if (rid in with_findings or rid in hidden) and rid not in ran:
                # It found something AND declined somewhere: the finding counts as a finding, and the rule is
                # named, because before G272's third review it was named nowhere -- neither clean nor in the
                # not-evaluated list, so the declined objects read as covered.
                partly_evaluated_rules.append(rid)
                for c in cs:
                    partly[c] = partly.get(c, 0) + 1
            if rid in with_findings:
                continue  # already counted as a finding or an accepted exception
            if rid in hidden:
                bucket = withheld  # it ran and it DID find something; this view just does not show it
            else:
                bucket = clean if rid in ran else unevaluated
                if rid not in ran:
                    not_evaluated_rules.append(rid)
            for c in cs:
                bucket[c] = bucket.get(c, 0) + 1
    ordered = sorted(
        set(counts) | set(excepted) | set(clean) | set(unevaluated) | set(withheld),
        key=lambda c: (-counts.get(c, 0), -excepted.get(c, 0), c),
    )
    controls: list[dict[str, Any]] = []
    for c in ordered:
        entry: dict[str, Any] = {"id": c, "title": TITLES[c], "findings": counts.get(c, 0)}
        if excepted.get(c):
            entry["excepted"] = excepted[c]
        if evaluated_rule_ids is not None:
            entry["clean"] = clean.get(c, 0)
            entry["notEvaluated"] = unevaluated.get(c, 0)
            if partly.get(c):
                entry["partlyEvaluated"] = partly[c]
            if fired_rule_ids is not None:
                entry["withheld"] = withheld.get(c, 0)
        controls.append(entry)
    out: dict[str, Any] = {"catalog": CATALOG, "controls": controls}
    if evaluated_rule_ids is not None:
        # The counts said HOW MANY rules of a control did not run; nothing said WHICH, outside the KSI view, so a
        # rule that declined quietly was invisible in the text view and the SARIF (G272).
        out["notEvaluatedRules"] = sorted(not_evaluated_rules)
        # Rules that found something on some objects and declined on others (`declined` names those objects).
        # Disjoint from notEvaluatedRules, so every rule that was not evaluated in full is in exactly one (G272).
        out["partlyEvaluatedRules"] = sorted(partly_evaluated_rules)
    note = "Findings are evidence about these controls; an assessment decides whether a control is met."
    if excepted:
        note += (
            " A control with `excepted` had findings an exceptions file accepted: the decision is recorded, not"
            " that the control is clean."
        )
    if withheld:
        note += (
            " A control with `withheld` had findings from rules that ran and reported, which this view's"
            " severity filter removed: those rules are not clean."
        )
    out["note"] = note
    return out
