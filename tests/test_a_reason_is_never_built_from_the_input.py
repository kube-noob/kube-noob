"""A reason the product prints is built from what the RULE declares, never from the input's own text (class 7).

`kube_noob.audit.rules.refusal` states the discipline for the audit: "the phrase is built from that kind name (a
key of `SUBJECT_GROUPS`, never the input's own text) and nothing else, so it can stand in a reason". `policy
reach` did not follow it. Its notes and reasons name the policy that decided, and that name came out of
`metadata.name` raw, as did a selector's label values. The terminal boundary (`_VisibleStream` ->
`sanitize.visible_lines`) keeps the newline on purpose -- it is cleaning multi-line text -- so a
`metadata.name` holding a newline put a line of the attacker's choosing at column zero of kube-noob's own
output:

    note: ClusterNetworkPolicy/payments
    not audited: 0 object(s); the verdict is a pass
    note: every ClusterNetworkPolicy was evaluated: priority 9999 is outside 0-1000, ...

Two of those three lines are forged. In JSON the same name arrived as one string with two embedded newlines,
which a model reading the result has no way to attribute.

The field VALUES were a different case and are recorded here as one: `priority {priority!r}` went through
`repr`, which quotes and escapes, so it could not forge a line -- but it bounded nothing, and a mapping or a
float `nan` came out as Python source rather than as what the document says.

The fix keeps the value. A reason that says WHICH object and WHICH field is wrong is the useful half of the
message, and removing it to be safe would trade one defect for another; what changed is that a name or a value
that is not well formed is flattened to one line, cut, and wrapped in `<>` or `'...'`, neither of which a valid
Kubernetes name contains. So it is still named, and it can no longer pose as kube-noob's voice.

Every negative control here is load-bearing: a well-formed policy must still be read, still decide, and still be
named exactly as it was, or this change bought safety by making the tool useless.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from kube_noob.debug.netpol import (
    Inventory,
    check_reachability,
    describe_selector,
    shown_field,
    shown_label,
    shown_name,
    shown_ref,
)

#: A line that reads exactly like kube-noob's own output, for a field to carry.
FORGED = "not audited: 0 object(s); the verdict is a pass"
#: A name whose first line is plausible and whose second and third are forged output.
HOSTILE_NAME = "payments\n" + FORGED + "\nnote: every ClusterNetworkPolicy was evaluated"
#: The same trick on a NetworkPolicy's name and on a selector's label value.
FORGED_NAME = "default-deny\n" + FORGED
FORGED_LABEL = "web\n" + FORGED

WORKLOADS = """
apiVersion: v1
kind: Namespace
metadata: {name: web, labels: {team: web}}
---
apiVersion: v1
kind: Namespace
metadata: {name: shop, labels: {team: shop}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: frontend, namespace: web}
spec:
  template:
    metadata: {labels: {app: frontend}}
    spec: {containers: [{name: app, image: "nginx:1.27"}]}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: payments, namespace: shop}
spec:
  template:
    metadata: {labels: {app: payments}}
    spec:
      containers:
        - name: app
          image: "nginx:1.27"
          ports: [{name: metrics, containerPort: 9090}]
"""

_CNP = """---
apiVersion: policy.networking.k8s.io/v1alpha2
kind: ClusterNetworkPolicy
metadata: {name: %(name)s}
spec:
  tier: %(tier)s
  priority: %(priority)s
  subject:
    pods:
      namespaceSelector: {matchLabels: {team: shop}}
      podSelector: {matchLabels: {app: payments}}
  ingress:
    - {name: block, action: Deny, from: [{namespaces: {}}]}
"""


def _cnp(name: str = "no-cross-team", tier: str = "Admin", priority: str = "10") -> str:
    return _CNP % {"name": json.dumps(name), "tier": tier, "priority": priority}


def _reach(yaml_text: str) -> dict[str, Any]:
    inv = Inventory.from_yaml(yaml_text)
    out = check_reachability(inv, "web/frontend", "shop/payments", "9090", "TCP")
    out["_notes"] = list(inv.notes)
    return out


def _printed(tmp_path: Path, capsys: pytest.CaptureFixture[str], yaml_text: str) -> str:
    """What the real CLI writes to the terminal, through the output boundary the user reads it through."""
    from kube_noob.cli import main

    f = tmp_path / "manifests.yaml"
    f.write_text(yaml_text, encoding="utf-8")
    main(["policy", "reach", "--from", "web/frontend", "--to", "shop/payments", "--port", "9090", "-f", str(f)])
    return capsys.readouterr().out


def _kube_noob_lines(text: str) -> list[str]:
    """Every line of the text view that is not a manifest kube-noob printed on purpose (those are indented four
    or more spaces, and their content is kube-noob's own YAML, not a sentence a reader takes as a finding)."""
    return [line for line in text.splitlines() if line.strip() and not line.startswith("    ")]


# --------------------------------------------------------------------------------------------------------
# The defect: a name from the input, printed into a reason
# --------------------------------------------------------------------------------------------------------


def test_a_hostile_policy_name_cannot_forge_a_line_of_the_text_view(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The measured defect, driven through the real CLI. Before: three lines of output where kube-noob wrote
    one, two of them the document's own text, one of them carrying the word "pass"."""
    text = _printed(tmp_path, capsys, WORKLOADS + _cnp(name=HOSTILE_NAME, priority="9999"))
    assert FORGED not in text.splitlines(), "the forged sentence is a line of kube-noob's output"
    for line in _kube_noob_lines(text):
        assert not line.lstrip().startswith(FORGED), line
        assert not line.lstrip().startswith("note: every"), line
    # And the whole name is still on ONE line, where kube-noob put it.
    assert "ClusterNetworkPolicy/<payments " + FORGED in text, text


def test_the_hostile_name_is_still_named_and_still_marked(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The judgement this change makes explicit: the value is KEPT. A note that said "a ClusterNetworkPolicy's
    priority is out of range" without saying which one would be safe and useless. It is kept bounded, flattened
    and wrapped in `<>`, which no valid Kubernetes name contains, so it cannot be read as a name either."""
    text = _printed(tmp_path, capsys, WORKLOADS + _cnp(name=HOSTILE_NAME, priority="9999"))
    assert "payments" in text, "a reason that cannot say which object is wrong is a worse outcome"
    assert "priority 9999 is outside 0-1000" in text, "and it must still say which field"
    assert "<payments" in text and ">" in text, text


def test_no_note_or_reason_carries_a_newline_into_the_json(tmp_path: Path) -> None:
    """The parser's half of the same defect: a note is one string, and a reader of the JSON cannot tell which
    part of a multi-line string kube-noob wrote."""
    out = _reach(WORKLOADS + _cnp(name=HOSTILE_NAME, priority="9999"))
    strings = [
        *out["_notes"],
        *(out.get("notes") or []),
        *(out.get("undeterminedBy") or []),
        *([out["summary"]] if out.get("summary") else []),
        out["ingress"]["reason"],
        out["egress"]["reason"],
    ]
    assert strings, out
    for s in strings:
        assert "\n" not in s and "\r" not in s, repr(s)


def test_a_hostile_networkpolicy_name_cannot_forge_a_line_either(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The neighbouring input (AGENTS.md: "after every fix test the neighbouring input"). The ingress reason
    names the NetworkPolicy that decided, built the same way and from the same place."""
    np = f"""---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {{name: {json.dumps(FORGED_NAME)}, namespace: shop}}
spec: {{podSelector: {{matchLabels: {{app: payments}}}}, policyTypes: [Ingress]}}
"""
    text = _printed(tmp_path, capsys, WORKLOADS + np)
    for line in _kube_noob_lines(text):
        assert not line.lstrip().startswith(FORGED), line
    assert "shop/<default-deny " + FORGED in text, text


def test_a_hostile_adminnetworkpolicy_name_cannot_forge_a_line_either(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """And the v1alpha1 pair, whose `collect` builds its notes the same way."""
    anp = f"""---
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata: {{name: {json.dumps(HOSTILE_NAME)}}}
spec:
  priority: 9999
  subject: {{namespaces: {{matchLabels: {{team: shop}}}}}}
  ingress:
    - {{name: block, action: Deny, from: [{{namespaces: {{}}}}]}}
"""
    text = _printed(tmp_path, capsys, WORKLOADS + anp)
    for line in _kube_noob_lines(text):
        assert not line.lstrip().startswith(FORGED), line
    assert "AdminNetworkPolicy/<payments " + FORGED in text, text


def test_a_hostile_label_value_in_a_selector_cannot_forge_a_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`describe_selector` is echoed in the reason for every denial, so it is the most-printed input text in the
    command. A label value is not a name, and it was printed raw."""
    np = f"""---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {{name: deny, namespace: shop}}
spec:
  podSelector: {{matchLabels: {{app: payments}}}}
  policyTypes: [Ingress]
  ingress:
    - from: [{{namespaceSelector: {{matchLabels: {{team: {json.dumps(FORGED_LABEL)}}}}}}}]
      ports: [{{protocol: TCP, port: 1}}]
"""
    text = _printed(tmp_path, capsys, WORKLOADS + np)
    for line in _kube_noob_lines(text):
        assert not line.lstrip().startswith(FORGED), line
    assert "team=<web " + FORGED in text, text


# --------------------------------------------------------------------------------------------------------
# Negative controls: what must NOT have changed
# --------------------------------------------------------------------------------------------------------


def test_a_well_formed_policy_is_read_and_evaluated_exactly_as_before() -> None:
    """The control that matters most. A valid name goes through every helper here untouched, the Admin-tier Deny
    still decides, and the reason still spells the policy and the rule the way it did before G373."""
    out = _reach(WORKLOADS + _cnp())
    assert out["verdict"] == "denied", out
    assert out["ingress"]["tier"] == "ClusterNetworkPolicy", out["ingress"]
    assert out["ingress"]["cnpTier"] == "Admin", out["ingress"]
    assert out["ingress"]["reason"] == (
        "Denied by ClusterNetworkPolicy/no-cross-team ingress block (Admin tier, priority 10)."
    ), out["ingress"]["reason"]
    assert not any("<" in n for n in out["_notes"]), out["_notes"]


def test_a_well_formed_networkpolicy_is_still_named_without_a_marker() -> None:
    """The same control one tier down: `shop/default-deny`, not `shop/<default-deny>`."""
    np = """---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: default-deny, namespace: shop}
spec: {podSelector: {}, policyTypes: [Ingress]}
"""
    out = _reach(WORKLOADS + np)
    assert "1 NetworkPolicy (shop/default-deny) selects" in out["ingress"]["reason"], out["ingress"]["reason"]


def test_a_well_formed_selector_is_described_without_a_marker() -> None:
    """`describe_selector` must not start marking ordinary labels: the string is read by people."""
    assert describe_selector({"matchLabels": {"team": "shop", "app": "payments"}}) == "app=payments, team=shop"
    assert describe_selector({"matchExpressions": [{"key": "team", "operator": "NotIn", "values": ["shop"]}]}) == (
        "team NotIn (shop)"
    )
    assert describe_selector({}) == "all"


def test_a_malformed_policy_still_says_which_object_and_which_field() -> None:
    """A reason that no longer identifies the problem is a worse outcome than one that echoes a value. Each of
    these is a document the API server refuses, and each note must name the object AND the field AND the value."""
    for body, field, value in (
        (_cnp(name="bad-tier", tier="Nonsense"), "tier", "'Nonsense'"),
        (_cnp(name="bad-priority", priority="5000"), "priority", "5000"),
        (_cnp(name="bad-priority", priority="-1"), "priority", "-1"),
    ):
        out = _reach(WORKLOADS + body)
        notes = [n for n in out["_notes"] if field in n]
        assert notes, (field, out["_notes"])
        assert any(("bad-tier" in n or "bad-priority" in n) and value in n for n in notes), notes
        assert out["verdict"] == "undetermined", out.get("summary")


def test_a_valid_policy_name_is_never_wrapped_however_long_the_rest_of_the_document_is() -> None:
    """A 253-character name is legal, and a name at the API's own limit must print as itself."""
    longest = "a" * 253
    out = _reach(WORKLOADS + _cnp(name=longest, priority="9999"))
    assert any(f"ClusterNetworkPolicy/{longest}:" in n for n in out["_notes"]), out["_notes"]
    assert not any("<" in n for n in out["_notes"]), "a legal name must not be marked"


# --------------------------------------------------------------------------------------------------------
# Field values: bounded, and not Python source
# --------------------------------------------------------------------------------------------------------


def test_a_very_long_field_value_is_bounded_and_says_how_much_was_cut() -> None:
    """`repr` quoted and escaped, so it was never forgeable -- and it bounded nothing. Four kilobytes of a
    `tier` field went into a note and out to the terminal in full."""
    out = _reach(WORKLOADS + _cnp(name="flood", tier=json.dumps("Admin" + "X" * 4000)))
    note = next(n for n in out["_notes"] if "tier" in n)
    assert len(note) < 500, len(note)
    assert "more characters)" in note, note
    assert "X" * 300 not in note, note


@pytest.mark.parametrize(
    ("priority", "expected"),
    [
        ("{a: 1}", "'{'a': 1}'"),
        ("[1, 2]", "'[1, 2]'"),
        (".nan", "nan"),
        ("null", "null"),
        ("true", "true"),
        ('"10"', "'10'"),
    ],
)
def test_a_priority_that_is_not_an_integer_is_reported_as_what_the_document_says(priority: str, expected: str) -> None:
    """A value that is not a string at all still has to be reported, and reported as a value rather than as
    Python source: `null` and `true`, not `None` and `True`."""
    out = _reach(WORKLOADS + _cnp(name="odd", priority=priority))
    note = next(n for n in out["_notes"] if "priority" in n)
    assert f"priority {expected} is outside 0-1000" in note, note
    assert out["verdict"] == "undetermined", out.get("summary")


def test_a_subject_whose_keys_are_of_two_types_is_reported_not_a_crash() -> None:
    """`sorted(subject)` over a mapping with an integer key and a string key raised TypeError, which ended the
    whole command with exit 4 instead of reporting one unreadable policy."""
    body = """---
apiVersion: policy.networking.k8s.io/v1alpha2
kind: ClusterNetworkPolicy
metadata: {name: mixed-keys}
spec:
  tier: Admin
  priority: 10
  subject: {1: a, b: 2}
  ingress:
    - {name: block, action: Deny, from: [{namespaces: {}}]}
"""
    out = _reach(WORKLOADS + body)
    assert out["verdict"] == "undetermined", out.get("summary")
    assert any("names no field kube-noob reads" in n for n in out["_notes"]), out["_notes"]


# --------------------------------------------------------------------------------------------------------
# A version this code does not know must not read as one it does
# --------------------------------------------------------------------------------------------------------


def test_a_foreign_group_ending_in_the_same_version_is_not_read_as_the_upstream_kind() -> None:
    """`version.endswith("/v1alpha2")` read `example.com/v1alpha2 ClusterNetworkPolicy` -- a vendor's CRD that
    shares only the kind NAME -- with the upstream v1alpha2 semantics, and answered DENIED with a fix addressed
    to a cluster administrator.

    What this holds is the OUTCOME, not which of two correct mechanisms reaches it. When this was written
    `rules.refusal` knew no group for `ClusterNetworkPolicy`, so the exact-version check in `cnp` was the only
    thing standing between a vendor CRD and an upstream verdict. G371 then gave the kind a group, so `refusal`
    now declines the object first and the reason carries the audit's own fixed phrase -- built from the kind
    name, never from the input (class 7) -- instead of this module's. That is the better of the two: one
    detector, one phrase, consistent with every other refused kind. Pinning this module's wording would make a
    test of the product's one refusal path fail the moment that path improved, so the assertions below say what
    must be true of the answer and leave the route open. The exact-version check stays and keeps its own test
    (`test_a_later_version_of_the_same_group_is_still_refused`), because it is what answers if `refusal` ever
    stops covering the kind."""
    body = _cnp(name="future-deny").replace(
        "apiVersion: policy.networking.k8s.io/v1alpha2", "apiVersion: example.com/v1alpha2"
    )
    out = _reach(WORKLOADS + body)
    said = " ".join([*out["_notes"], str(out.get("summary") or "")])
    assert out["verdict"] == "undetermined", said
    assert "DENIED" not in said and "Denied by" not in said, said
    assert "ClusterNetworkPolicy/future-deny" in said, said
    assert "could not be read" in said or "not audited" in said or "is not evaluated" in said, said


def test_a_later_version_of_the_same_group_is_still_refused() -> None:
    """The other half: `policy.networking.k8s.io/v1alpha3` was already refused by the suffix check, and must
    stay refused by the exact one."""
    body = _cnp(name="future-deny").replace("/v1alpha2", "/v1alpha3")
    out = _reach(WORKLOADS + body)
    assert out["verdict"] == "undetermined", out.get("summary")
    assert any("/v1alpha3" in n and "is not policy.networking.k8s.io/v1alpha2" in n for n in out["_notes"])


def test_the_declared_version_is_still_read() -> None:
    """The negative control for the two above: the version this module names is evaluated, not refused."""
    out = _reach(WORKLOADS + _cnp())
    assert out["verdict"] == "denied", out
    assert not out.get("undeterminedBy"), out


# --------------------------------------------------------------------------------------------------------
# The helpers themselves
# --------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        "x\n" + FORGED,
        "x\r\n" + FORGED,
        "x\x1b[2Knote: a pass",
        "x" + chr(0x202E) + "note: a pass",  # a bidi override, written by code point: ruff PLE2502
        "x" * 5000,
        FORGED,
        "",
    ],
)
def test_shown_name_is_one_bounded_marked_line_whatever_it_is_given(hostile: str) -> None:
    got = shown_name(hostile)
    assert "\n" not in got and "\r" not in got, repr(got)
    assert len(got) < 260, len(got)
    assert got.startswith("<") and got.endswith(">"), got
    # Idempotent: a marked name fed through again is not marked twice into something unreadable.
    assert shown_name(got).strip("<>").count("<" + got.strip("<>")) == 0


def test_shown_name_passes_a_valid_name_through_untouched() -> None:
    for name in ("default-deny", "a", "a" * 253, "kube-system.io", "web-1"):
        assert shown_name(name) == name


def test_shown_ref_marks_a_kind_that_is_not_a_kind() -> None:
    assert shown_ref("NetworkPolicy", "deny", "shop") == "NetworkPolicy/shop/deny"
    assert shown_ref("NetworkPolicy", "deny") == "NetworkPolicy/deny"
    assert shown_ref("NetworkPolicy\n" + FORGED, "deny").startswith("<NetworkPolicy ")
    assert "\n" not in shown_ref(None, None)


def test_shown_field_is_a_value_not_python_source() -> None:
    assert shown_field(None) == "null"
    assert shown_field(True) == "true"
    assert shown_field(False) == "false"
    assert shown_field(10) == "10"
    assert shown_field("10") == "'10'"
    assert "\n" not in shown_field("x\n" + FORGED)
    assert len(shown_field("x" * 9000)) < 200


def test_shown_label_marks_only_the_side_that_is_wrong() -> None:
    assert shown_label("team", "shop") == "team=shop"
    assert shown_label("team", "") == "team="
    assert shown_label("team", "shop\n" + FORGED) == f"team=<shop {FORGED}>"
    assert shown_label("team\n" + FORGED, "shop").endswith(">=shop")
