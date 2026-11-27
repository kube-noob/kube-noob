"""An ingress rule that names ports and no `from` admits every source on those ports (G432).

`from` is optional in a NetworkPolicy ingress rule, and "if this field is empty or missing, this rule matches all
sources". KN-N007 read "no peers" and then asked whether the rule also named no ports; a rule that named a port
was passed over, so the most common open rule there is -- `ingress: [{ports: [{port: 8080}]}]` -- was evaluated
and clean, and the NetworkPolicy lesson held "no rule here is open to every source" on it.

Measured (G432) with `kube_noob.audit.engine.analyze`: one Deployment and one NetworkPolicy selecting it in a
whole namespace, KN-N007 only. "all" is `admits all sources on all ports`, "ports" is `no `from``:

| ingress rule                                   | before             | after              |
|------------------------------------------------|--------------------|--------------------|
| `from` a pod selector, with ports              | -                  | -                  |
| `{}`                                           | all                | all                |
| `from: []`                                     | all                | all                |
| `ports: []`                                    | all                | all                |
| `ports` and no `from`                          | -                  | ports              |
| `ports` and `from: []`                         | -                  | ports              |
| `ports` and `from: null`                       | -                  | ports              |
| two rules, one with a peer, one ports only     | -                  | ports, on rule 1   |
| `from: [{namespaceSelector: {}}]`              | namespaceSelector  | namespaceSelector  |
| `from: [{ipBlock: {cidr: 0.0.0.0/0}}]`         | ipBlock            | ipBlock            |
| `from: [{podSelector: {}}]` (this namespace)   | -                  | -  (a limit, G421) |
| `ingress: []`, or no `ingress` key (deny)      | -                  | -                  |
| `from: "x"` (not a list) with ports            | - (KN-V007)        | - (KN-V007)        |
| no NetworkPolicy in the input                  | notEvaluated: no networking.k8s.io NetworkPolicy (both) |

The mirrored egress case was measured too, and is deliberately in NO rule:

| egress rule (policyTypes: [Egress])            | KN-N007 | any KN-N rule                         |
|------------------------------------------------|---------|---------------------------------------|
| `to` a pod selector, with ports, and DNS       | -       | -                                     |
| `{}` (every destination, every port)           | -       | -                                     |
| `to: []`                                       | -       | -                                     |
| `ports` and no `to`                            | -       | -                                     |
| `ports: [53/UDP, 53/TCP]` and no `to`          | -       | -                                     |
| `to: [{ipBlock: {cidr: 0.0.0.0/0}}]`           | -       | -                                     |
| `egress: []` (deny)                            | -       | KN-N013 (no route to cluster DNS)     |

Why it belongs nowhere today. KN-N007's subject is ingress -- its title, its description, its controls and its
generated admission policy all say so -- and no rule in this build owns "egress is open": `egress: [{}]` and
`to: 0.0.0.0/0` are silent as well, so reporting only the ports-without-`to` shape would flag the narrowest open
egress rule while passing the two wider ones. And the shape is the usual way to keep DNS: `ports: [53]` with no
`to` is what KN-N013 accepts as a route to cluster DNS (measured: silent), so a finding on it would be one rule
objecting to what another asks for. Open egress needs a rule of its own, decided as one subject; until then the
rows above pin that nothing claims it.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest
import yaml

from kube_noob.audit.engine import analyze

P = [{"port": 8080, "protocol": "TCP"}]
PEER = [{"podSelector": {"matchLabels": {"app": "web"}}}]
DNS = [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}]
ALL = "admits all sources on all ports"
PORTS = "no `from`"
WORKLOAD: dict[str, Any] = {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {"name": "api", "namespace": "shop"},
    "spec": {
        "replicas": 2,
        "selector": {"matchLabels": {"app": "api"}},
        "template": {
            "metadata": {"labels": {"app": "api"}},
            "spec": {"containers": [{"name": "c", "image": "registry.example.com/a@sha256:" + "a" * 64}]},
        },
    },
}


def _policy(**spec: object) -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "api", "namespace": "shop"},
        "spec": {"podSelector": {"matchLabels": {"app": "api"}}, **copy.deepcopy(spec)},
    }


def _report(*docs: dict[str, Any]) -> dict[str, Any]:
    return analyze("---\n".join(yaml.safe_dump(d, sort_keys=False) for d in docs), "kubernetes", None).as_dict()


def _n007(report: dict[str, Any]) -> list[tuple[str, str]]:
    return [(f["path"], f["message"]) for f in report["findings"] if f["ruleId"] == "KN-N007"]


#: case -> (the ingress rules, [(path, words in the message)])
INGRESS: dict[str, tuple[list[Any], list[tuple[str, str]]]] = {
    "peer-and-ports": ([{"from": PEER, "ports": P}], []),
    "empty-rule": ([{}], [("spec.ingress[0]", ALL)]),
    "from-empty-list": ([{"from": []}], [("spec.ingress[0]", ALL)]),
    "ports-empty-list": ([{"ports": []}], [("spec.ingress[0]", ALL)]),
    "ports-and-no-from": ([{"ports": P}], [("spec.ingress[0]", PORTS)]),
    "ports-and-from-empty-list": ([{"from": [], "ports": P}], [("spec.ingress[0]", PORTS)]),
    "ports-and-from-null": ([{"from": None, "ports": P}], [("spec.ingress[0]", PORTS)]),
    "second-rule-ports-only": ([{"from": PEER, "ports": P}, {"ports": P}], [("spec.ingress[1]", PORTS)]),
    "any-namespace": (
        [{"from": [{"namespaceSelector": {}}], "ports": P}],
        [("spec.ingress[0].from[0].namespaceSelector", "every pod in every namespace")],
    ),
    "any-address": (
        [{"from": [{"ipBlock": {"cidr": "0.0.0.0/0"}}], "ports": P}],
        [("spec.ingress[0].from[0].ipBlock", "every source address")],
    ),
    "any-pod-of-this-namespace": ([{"from": [{"podSelector": {}}], "ports": P}], []),
    "deny-all": ([], []),
    "from-not-a-list": ([{"from": "x", "ports": P}], []),
}


@pytest.mark.parametrize("case", sorted(INGRESS))
def test_the_ingress_table_still_holds(case: str) -> None:
    rules, want = INGRESS[case]
    report = _report(WORKLOAD, _policy(policyTypes=["Ingress"], ingress=rules))
    got = _n007(report)
    assert [path for path, _ in got] == [path for path, _ in want], got
    for (_, message), (_, words) in zip(got, want, strict=True):
        assert words in message, message
    assert "KN-N007" not in (report.get("notEvaluated") or {})
    if case == "from-not-a-list":
        assert [f for f in report["findings"] if f["ruleId"] == "KN-V007"], "the schema stage reports the type"


def test_no_ingress_key_is_a_deny_and_no_policy_is_no_verdict() -> None:
    assert _n007(_report(WORKLOAD, _policy(policyTypes=["Ingress"]))) == []
    report = _report(WORKLOAD)
    assert _n007(report) == []
    assert "no networking.k8s.io NetworkPolicy in the input" in report["notEvaluated"]["KN-N007"]


def test_the_finding_is_about_the_policy_and_names_the_ports() -> None:
    report = _report(WORKLOAD, _policy(policyTypes=["Ingress"], ingress=[{"ports": [*P, {"port": "metrics"}]}]))
    (finding,) = [f for f in report["findings"] if f["ruleId"] == "KN-N007"]
    assert finding["resource"] == "NetworkPolicy/shop/api"
    assert "every source" in finding["message"] and "8080" in finding["message"] and "metrics" in finding["message"]


def test_a_port_list_the_message_cannot_read_is_still_a_finding() -> None:
    """The ports are only shown. A port entry of another shape must not turn the finding off, or crash it."""
    for ports in ([{"protocol": "UDP"}], [{"port": {"a": 1}}], ["x"], [{"port": 1, "endPort": 9}] * 30):
        report = _report(WORKLOAD, _policy(policyTypes=["Ingress"], ingress=[{"ports": ports}]))
        got = _n007(report)
        assert [path for path, _ in got] == ["spec.ingress[0]"], (ports, got)
        assert len(got[0][1]) < 400 and "\n" not in got[0][1]


#: case -> the egress rules. Every one of them is silent on KN-N007; the last is KN-N013's.
EGRESS: dict[str, list[Any]] = {
    "peer-ports-and-dns": [{"to": PEER, "ports": P}, {"ports": DNS}],
    "empty-rule": [{}],
    "to-empty-list": [{"to": []}],
    "ports-and-no-to": [{"ports": P}, {"ports": DNS}],
    "dns-ports-and-no-to": [{"ports": DNS}],
    "any-address": [{"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}], "ports": P}, {"ports": DNS}],
    "deny-all": [],
}


@pytest.mark.parametrize("case", sorted(EGRESS))
def test_the_mirrored_egress_shapes_are_in_no_rule_and_that_is_pinned(case: str) -> None:
    report = _report(WORKLOAD, _policy(policyTypes=["Egress"], egress=EGRESS[case]))
    network = sorted({f["ruleId"] for f in report["findings"] if f["ruleId"].startswith("KN-N")})
    assert network == (["KN-N013"] if case == "deny-all" else []), report["findings"]
    assert "KN-N007" not in (report.get("notEvaluated") or {}), "it read the policy, and egress is not its subject"


def test_the_rule_says_in_its_own_words_that_it_reads_ingress_only() -> None:
    from kube_noob.audit.engine import explain_rule

    described = explain_rule("KN-N007")
    assert "ingress" in str(described["title"]).lower()
    assert "no `from`" in str(described["description"]) and "egress" in str(described["description"]).lower()


@pytest.mark.parametrize("case", sorted(set(INGRESS) - {"from-not-a-list"}))
def test_the_generated_admission_policy_refuses_what_the_audit_reports(case: str) -> None:
    """The ValidatingAdmissionPolicy generated for KN-N007 carried the same gap as an explicit clause: a rule
    with no `from` passed whenever it named a port."""
    from kube_noob.generate import policies as pol
    from tests.policy_cel import failures

    rules, want = INGRESS[case]
    policy = pol.documents(pol.checks_for("kubernetes", None, ())["KN-N007"], "vap", "enforce", "kubernetes")[0]
    refused = failures(policy, _policy(policyTypes=["Ingress"], ingress=rules))
    assert bool(refused) == bool(want), (case, refused)
