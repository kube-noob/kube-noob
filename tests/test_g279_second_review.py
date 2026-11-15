"""G279 under a second adversarial review: twelve more defects, each a test named for the behaviour that must hold.

D1 documents bypass the text boundary and stay lossless; D2 admission rules that need an unread list are not
evaluated; D3 the CNI is identified or the admin tier is not decided; D4 only the API server's own 404 is "not
served"; D5 an unread NetworkPolicy list leaves its direction undetermined; D6 escapes become nothing and servers are
not wrapped; D7 one character rule for `visible` and `clean`, with markers inside names; D8 MCP text content is
cleaned; D9 a list is a list of the kind asked for, complete; D10 a malformed `policyTypes` is not a policy; D12 the
rule costs one regular-expression pass on text with nothing to change.
"""

from __future__ import annotations

import copy
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import pytest
import yaml

from kube_noob import sanitize
from kube_noob.debug.netpol import check_reachability, inventory_from_cluster
from kube_noob.errors import ClusterAccessError

ZWSP, RLM, SHY, ZWJ, ZWNJ = "\u200b", "\u200f", "\u00ad", "\u200d", "\u200c"
HOSTILE = (
    "a\x1b[2Jb\x1b]52;c;ZWNobyBwd25k\x07c\u202ed\u061ce\U000e0041f\u2066g\u3164h\u034fi\ufe0fj\U000e0100k"
    "\u2065l\ufff0m\ufffen\ue0b0o\u2028p\x85q\u2800r"
)


def _run(argv: list[str]) -> tuple[int, bytes, bytes]:
    """main() with byte-level stdout and stderr, the way a shell redirection sees them."""
    from kube_noob.cli import main

    out_b, err_b = io.BytesIO(), io.BytesIO()
    out = io.TextIOWrapper(out_b, encoding="utf-8", errors="strict", newline="")
    err = io.TextIOWrapper(err_b, encoding="utf-8", errors="strict", newline="")
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(argv)
        out.flush()
        err.flush()
    return rc, out_b.getvalue(), err_b.getvalue()


# ------------------------------------------------------------------------------------------- D1: documents


LEGIT_CM = {
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {"name": "ui", "namespace": "shop"},
    "data": {
        "de": "Donau" + SHY + "dampf" + SHY + "schiff",
        "he": "\u05e9\u05dc\u05d5\u05dd " + RLM + "ABC" + RLM,
        "fa": "Iran" + ZWNJ + "ian",
        "emoji": "dev \U0001f469" + ZWJ + "\U0001f4bb",
        "pua": "\ue0b0 prompt",
        "cr": "line1\rline2",
        "tab": "a\tb",
        "cjk": "\u6771\u4eac",
        "hostile": HOSTILE,
    },
}


@pytest.mark.parametrize("fmt", ["text", "yaml", "json"])
def test_fix_prints_exactly_the_document_it_writes_with_o(fmt: str, tmp_path: Path) -> None:
    """`fix -f cm.yaml > out.yaml` rewrote the data: private-use glyphs became spaces, the soft hyphen, RLM and
    ZWNJ vanished. A document is data; the bytes on stdout are the bytes -o writes."""
    src = tmp_path / "cm.yaml"
    src.write_text(yaml.safe_dump(LEGIT_CM, allow_unicode=True), encoding="utf-8")
    out_file = tmp_path / "out.yaml"
    rc1, stdout, _ = _run(["--format", fmt, "fix", "-f", str(src)])
    rc2, _, _ = _run(["--format", fmt, "fix", "-f", str(src), "-o", str(out_file)])
    assert rc1 == rc2 == 0
    assert stdout == out_file.read_bytes()
    loaded = list(yaml.safe_load_all(stdout.decode("utf-8")))
    assert loaded[0]["data"] == LEGIT_CM["data"]  # lossless, hostile string included
    for ch in ("\x1b", "\u202e", "\u061c", "\U000e0041", "\x85", "\u2028"):
        assert ch not in stdout.decode("utf-8"), hex(ord(ch))  # and terminal-safe


@pytest.mark.parametrize(
    "value", [HOSTILE, LEGIT_CM["data"]["emoji"], "1" + ZWJ + "x", "\u2764\ufe0f" + ZWJ + "\U0001f525"]
)
@pytest.mark.parametrize("fmt", ["yaml", "json"])
def test_the_yaml_and_json_views_are_lossless_and_terminal_safe(
    value: str, fmt: str, capsys: pytest.CaptureFixture[str]
) -> None:
    from kube_noob.cli import _emit

    _emit({"name": value, value: [value]}, fmt)
    text = capsys.readouterr().out
    data = json.loads(text) if fmt == "json" else yaml.safe_load(text)
    assert data == {"name": value, value: [value]}
    assert not sanitize.has_invisible(text, keep="\n\t") or text.isascii(), ascii(text)[:200]


def test_the_policy_generate_document_on_stdout_equals_the_file(tmp_path: Path) -> None:
    out_file = tmp_path / "p.yaml"
    _, stdout, _ = _run(["policy", "generate", "--engine", "kyverno"])
    _run(["policy", "generate", "--engine", "kyverno", "-o", str(out_file)])
    assert stdout == out_file.read_bytes()


# ------------------------------------------------------------------------------------------- D2: admission


def test_a_cross_object_rule_is_not_evaluated_on_a_list_that_was_never_read() -> None:
    """NetworkPolicies forbidden from the first refresh: KN-N001 ("no NetworkPolicy selects this") denied a
    clean Deployment, because a list that was never read read as "none exist"."""
    from kube_noob.admission import Config, Lookups, review

    class Backend:
        name = "fake"

        def get(self, resource: str, namespace: str | None = None, **_: Any) -> dict[str, Any]:
            if resource == "networkpolicies":
                raise ClusterAccessError('Error from server (Forbidden): networkpolicies is forbidden: User "u"')
            return {"kind": "List", "items": []}

    lookups = Lookups(Backend(), sleep=lambda _s: None)
    lookups("shop")
    lookups.refresh()
    assert "networkpolicies" in lookups.unread("shop")
    cfg = Config(lookups=True, enforce=frozenset({"KN-N001"}))
    deploy = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "web", "namespace": "shop"},
        "spec": {
            "selector": {"matchLabels": {"app": "web"}},
            "template": {
                "metadata": {"labels": {"app": "web"}},
                "spec": {"containers": [{"name": "c", "image": "registry.example/web@sha256:" + "a" * 64}]},
            },
        },
    }
    req = {"request": {"uid": "u1", "operation": "CREATE", "namespace": "shop", "object": deploy}}
    resp = review(req, cfg, lookups)["response"]
    assert resp["allowed"] is True
    warnings = " ".join(resp.get("warnings", []))
    assert "KN-N001" not in warnings or "not evaluated" in warnings
    assert "networkpolicies" in warnings and "not evaluated" in warnings


def test_a_namespace_never_refreshed_has_every_context_list_unread() -> None:
    from kube_noob.admission import CONTEXT_RESOURCES, Lookups

    lookups = Lookups(object(), sleep=lambda _s: None)
    assert set(lookups.unread("new-ns")) >= set(CONTEXT_RESOURCES)


# ------------------------------------------------------------------------------------------- the live stub

NS = [
    {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "shop", "labels": {"tier": "app"}}},
    {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "monitoring", "labels": {"tier": "platform"}}},
]


def _dep(name: str, ns: str, app: str, port: int | None = None) -> dict[str, Any]:
    c: dict[str, Any] = {"name": "c", "image": f"{app}:1"}
    if port:
        c["ports"] = [{"containerPort": port}]
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": ns},
        "spec": {"template": {"metadata": {"labels": {"app": app}}, "spec": {"containers": [c]}}},
    }


WL = [_dep("orders", "shop", "orders", 8080), _dep("prometheus", "monitoring", "prometheus")]
ALLOW_ALL = {
    "apiVersion": "networking.k8s.io/v1",
    "kind": "NetworkPolicy",
    "metadata": {"name": "allow", "namespace": "shop"},
    "spec": {"podSelector": {"matchLabels": {"app": "orders"}}, "policyTypes": ["Ingress"], "ingress": [{}]},
}
DENY_ALL = {
    "apiVersion": "networking.k8s.io/v1",
    "kind": "NetworkPolicy",
    "metadata": {"name": "deny", "namespace": "shop"},
    "spec": {"podSelector": {}, "policyTypes": ["Ingress"]},
}
ANP = {
    "apiVersion": "policy.networking.k8s.io/v1alpha1",
    "kind": "AdminNetworkPolicy",
    "metadata": {"name": "guardrail"},
    "spec": {
        "priority": 10,
        "subject": {"namespaces": {"matchLabels": {"tier": "app"}}},
        "ingress": [{"name": "deny-all", "action": "Deny", "from": [{"namespaces": {}}]}],
    },
}
KINDS = {"networkpolicies": "NetworkPolicy", "namespaces": "Namespace", "deployments": "Deployment"}


class Cluster:
    name = "fake"

    def __init__(
        self, objects: list[dict[str, Any]], behave: dict[Any, Any] | None = None, lists: dict[str, Any] | None = None
    ):
        self.objects, self.behave, self.lists = objects, behave or {}, lists or {}

    def get(self, resource: str, name: str | None = None, namespace: str | None = None, **_: Any) -> dict[str, Any]:
        for key in ((resource, name), (resource, namespace), resource):
            if key in self.behave:
                b = self.behave[key]
                if isinstance(b, str):
                    raise ClusterAccessError(b)
                return copy.deepcopy(b)  # type: ignore[no-any-return]
        if resource in self.lists and name is None:
            return {"kind": "List", "items": copy.deepcopy(self.lists[resource])}
        kind = KINDS.get(resource)
        if kind is None:
            raise ClusterAccessError(f'error: the server doesn\'t have a resource type "{resource}"')
        hits = [
            o
            for o in self.objects
            if o["kind"] == kind
            and (name is None or o["metadata"]["name"] == name)
            and (kind == "Namespace" or namespace is None or o["metadata"].get("namespace") == namespace)
        ]
        if name is not None:
            if not hits:
                q = "deployments.apps" if resource == "deployments" else resource
                raise ClusterAccessError(f'Error from server (NotFound): {q} "{name}" not found')
            return copy.deepcopy(hits[0])
        return {"kind": "List", "items": copy.deepcopy(hits)}


def _reach(cluster: Cluster, cni: str | None = None) -> dict[str, Any]:
    inv = inventory_from_cluster(cluster, "monitoring/prometheus", "shop/orders", cni)
    return check_reachability(inv, "monitoring/prometheus", "shop/orders", 8080)


# ------------------------------------------------------------------------------------------- D3: which CNI


def test_a_cluster_serving_ciliums_clusterwide_policy_is_read_as_cilium() -> None:
    """Cilium states no support for AdminNetworkPolicy. Read as "no Calico, so OVN-Kubernetes", the ANP denied."""
    out = _reach(
        Cluster([*NS, *WL, ALLOW_ALL], lists={"ciliumclusterwidenetworkpolicies": [], "adminnetworkpolicies": [ANP]})
    )
    assert out["verdict"] == "undetermined", out
    assert any("cilium" in n.lower() for n in out["notes"]), out["notes"]


def test_a_cluster_whose_cni_shows_no_sign_does_not_get_an_admin_tier_verdict() -> None:
    """kindnet, flannel, OpenShiftSDN: nothing names the CNI, so whether an AdminNetworkPolicy is enforced is not
    known -- an answer it decides is undetermined, never decided."""
    out = _reach(Cluster([*NS, *WL, ALLOW_ALL], lists={"adminnetworkpolicies": [ANP]}))
    assert out["verdict"] == "undetermined", out
    assert any("not identified" in n for n in out["notes"]), out["notes"]


def test_an_unidentified_cni_does_not_matter_where_no_admin_policy_exists() -> None:
    out = _reach(Cluster([*NS, *WL, ALLOW_ALL]))
    assert out["verdict"] == "allowed", out


def test_the_flag_still_decides_for_an_unidentified_cni() -> None:
    out = _reach(Cluster([*NS, *WL, ALLOW_ALL], lists={"adminnetworkpolicies": [ANP]}), cni="ovn-kubernetes")
    assert out["verdict"] == "denied", out


# ------------------------------------------------------------------------------------------- D4: in-cluster 404


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("404 page not found", "not-served"),
        ("404 page not found\n", "not-served"),
        ("<html><body><h1>404 Not Found</h1>nginx</body></html>", "not-read"),
        ("default backend - 404", "not-read"),
        ("", "not-read"),
        ('{"kind":"Status","reason":"NotFound","details":{"name":"x"', "not-read"),
        ("404 page not found, said the proxy", "not-read"),
    ],
)
def test_only_the_api_servers_own_404_is_an_api_that_is_not_served(body: str, expected: str) -> None:
    from kube_noob.debug.backends import InClusterReadError
    from kube_noob.debug.cluster import classify_read_failure

    exc = InClusterReadError("GET /apis/policy.networking.k8s.io/v1alpha1/adminnetworkpolicies", status=404, body=body)
    assert classify_read_failure("adminnetworkpolicies", exc) == expected


# ------------------------------------------------------------------------------------------- D5: direction fields


def test_a_direction_whose_networkpolicies_were_not_read_says_so_in_its_own_fields() -> None:
    out = _reach(
        Cluster(
            [*NS, *WL],
            {("networkpolicies", "shop"): 'Error from server (Forbidden): networkpolicies is forbidden: User "u"'},
        )
    )
    assert out["verdict"] == "undetermined"
    ingress = out["ingress"]
    assert ingress["evaluated"] is False and ingress["allowed"] is None and ingress.get("undetermined") is True
    assert "could not be read" in ingress["reason"]
    assert "No NetworkPolicy in shop selects" not in json.dumps(out)


def test_every_undetermined_direction_says_it_was_not_evaluated() -> None:
    """Neighbour: on every path where a direction is undetermined, its fields agree with the verdict."""
    for cluster in (
        Cluster([*NS, *WL], {("networkpolicies", "shop"): "kubectl timed out after 30.0s"}),
        Cluster([*NS, *WL], {("networkpolicies", "monitoring"): "kubectl timed out after 30.0s"}),
    ):
        out = _reach(cluster)
        for d in ("egress", "ingress"):
            r = out[d]
            if r.get("undetermined"):
                assert r["evaluated"] is False and r["allowed"] is not True, r


# ------------------------------------------------------------------------------------------- D6: escapes, servers


def test_an_escape_sequence_becomes_nothing_not_a_space() -> None:
    assert sanitize.visible_lines("\x1b[1mbold\x1b[0m text") == "bold text"


def test_the_long_running_servers_streams_are_not_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    from kube_noob import cli

    seen: dict[str, Any] = {}

    def fake_main(a: Any) -> int:
        seen["stdout"], seen["stderr"] = type(sys.stdout).__name__, type(sys.stderr).__name__
        return 0

    monkeypatch.setattr(cli, "_main", fake_main)
    for argv in (["serve"], ["mcp"], ["admission", "serve", "--tls-cert", "c", "--tls-key", "k"]):
        cli.main(argv)
        assert seen == {"stdout": type(sys.stdout).__name__, "stderr": type(sys.stderr).__name__}, argv
    cli.main(["rules"])
    assert seen["stdout"] == "_VisibleStream"


def test_help_is_printed_before_the_boundary(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from kube_noob import cli

    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert "usage:" in capsys.readouterr().out


# ------------------------------------------------------------------------------------------- D7: the rule


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("web" + ZWSP + "x", "web<U+200B>x"),  # inside a name: shown, so it cannot pass for "webx"
        ("shop/web" + "\u2060" + "-1", "shop/web<U+2060>-1"),
        ("say" + ZWSP + " hello", "say hello"),  # in prose: removed
        ("web\u3164x", "web<U+3164>x"),  # Hangul filler
        ("ab\u034fc", "ab<U+034F>c"),  # combining grapheme joiner
        ("x\ufe0fy", "x<U+FE0F>y"),  # a variation selector after ASCII
        ("x\U000e0100y", "x<U+E0100>y"),
        ("a\u2065b", "a<U+2065>b"),
        ("a\ufff0b", "a<U+FFF0>b"),
        ("a\U000e0080b", "a<U+E0080>b"),
        ("a\ufffeb", "a b"),  # noncharacter: replaced
        ("a\u2800b", "a b"),  # braille blank: prints as a space
        ("o" + "\u0336" * 40 + "k", "o" + "\u0336" * 4 + "k"),  # a combining flood is cut to four
    ],
)
def test_names_show_what_was_hidden_and_prose_drops_it(text: str, expected: str) -> None:
    assert sanitize.visible(text, mark=True) == expected


@pytest.mark.parametrize(
    "text",
    [
        "\u6f22\U000e0100",  # an ideographic variation sequence
        "1\ufe0f\u20e3",  # a keycap
        "\u2764\ufe0f" + ZWJ + "\U0001f525",
        "\u1820\u180b",  # Mongolian free variation selector after a Mongolian letter
        "a\u0301\u0302",  # two combining marks are not a flood
        "\uac00\u11a8",  # Hangul jamo, not fillers
    ],
)
def test_sequences_that_need_their_selectors_keep_them(text: str) -> None:
    assert sanitize.visible(text, mark=True) == text


@pytest.mark.parametrize(
    "text", [HOSTILE, "pay" + ZWSP + "pal", "a\r\nb\rc\td", "Iran" + ZWNJ + "ian", "\u0645\u06cc" + ZWNJ + "\u062e"]
)
def test_clean_and_visible_make_the_same_decision_about_every_character(text: str) -> None:
    """One implementation: an MCP result and a terminal line cannot disagree about a character."""
    assert sanitize.clean(text)[0] == sanitize.visible_lines(text)


def test_one_line_is_visible_with_white_space_collapsed() -> None:
    assert sanitize.one_line("  web" + ZWSP + "x \n\t  next\x1b[2J  ") == "web<U+200B>x next"


# ------------------------------------------------------------------------------------------- D8: MCP text


def test_mcp_text_content_carries_no_hidden_characters() -> None:
    from kube_noob import tool_runner
    from kube_noob.config import load_settings
    from kube_noob.toolkit import Toolkit

    specs = {s.name: s for s in Toolkit(load_settings()).specs()}
    manifest = (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
        f"  name: {json.dumps('web' + HOSTILE)}\n  namespace: shop\nspec:\n  template:\n    spec:\n"
        "      containers: [{name: c, image: 'nginx:latest'}]\n"
    )
    result = tool_runner.call(specs["audit_manifests"], {"manifests": manifest}, "")
    text = json.dumps(result, ensure_ascii=False)
    for ch in ("\x1b", "\x07", "\x85", "\u202e", "\u3164", "\ufff9", "\u2028", "\ue0b0", "\ufffe"):
        assert ch not in text, hex(ord(ch))


# ------------------------------------------------------------------------------------------- D9: list_items


@pytest.mark.parametrize(
    "data",
    [
        pytest.param({"kind": "Status", "items": []}, id="a-status-with-items"),
        pytest.param({"kind": "PodList", "items": []}, id="another-kinds-list"),
        pytest.param({"kind": "List", "items": [{"spec": {}}]}, id="an-item-without-metadata"),
        pytest.param({"kind": "List", "items": [{"metadata": {"namespace": "shop"}}]}, id="an-item-without-a-name"),
        pytest.param({"kind": "List", "items": [{"metadata": {"name": "x"}}]}, id="an-item-without-a-namespace"),
        pytest.param(
            {"kind": "List", "items": [{"metadata": {"name": "x", "namespace": "elsewhere"}}]}, id="another-namespace"
        ),
        pytest.param(
            {"kind": "List", "items": [{"kind": "Pod", "metadata": {"name": "x", "namespace": "shop"}}]},
            id="an-item-of-another-kind",
        ),
        pytest.param({"kind": "List", "metadata": {"continue": "abc"}, "items": []}, id="a-partial-page"),
    ],
)
def test_a_list_must_be_a_complete_list_of_the_kind_asked_for(data: dict[str, Any]) -> None:
    from kube_noob.debug.cluster import list_items

    with pytest.raises(ClusterAccessError):
        list_items(data, "networkpolicies", namespace="shop")


def test_a_list_of_the_kind_asked_for_is_read() -> None:
    from kube_noob.debug.cluster import list_items

    item = {"metadata": {"name": "x", "namespace": "shop"}}
    for kind in ("List", "NetworkPolicyList"):
        assert list_items({"kind": kind, "items": [item]}, "networkpolicies", namespace="shop") == [item]


def test_a_networkpolicy_list_that_is_not_one_leaves_the_answer_undetermined() -> None:
    bad = {
        "kind": "List",
        "items": [
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"name": "deny"},
                "spec": {"podSelector": {}, "policyTypes": ["Ingress"]},
            }
        ],
    }
    out = _reach(Cluster([*NS, *WL], {("networkpolicies", "shop"): bad}))
    assert out["verdict"] == "undetermined", out


# ------------------------------------------------------------------------------------------- D10: policyTypes


@pytest.mark.parametrize("types", ["Ingress", ["Ingres"], [None], {"Ingress": True}])
def test_a_policytypes_that_is_not_a_list_of_directions_is_not_read_as_one(types: Any, tmp_path: Path) -> None:
    from kube_noob.debug.netpol import Inventory

    pol = copy.deepcopy(DENY_ALL)
    pol["spec"]["policyTypes"] = types
    inv = Inventory([*NS, *WL, pol])
    out = check_reachability(inv, "monitoring/prometheus", "shop/orders", 8080)
    assert out["verdict"] == "undetermined", out


@pytest.mark.parametrize("peers", ["x", {"podSelector": {}}])
def test_a_peer_list_that_is_not_a_list_is_not_read_as_one(peers: Any) -> None:
    from kube_noob.debug.netpol import Inventory

    pol = copy.deepcopy(DENY_ALL)
    pol["spec"]["ingress"] = [{"from": peers}]
    out = check_reachability(Inventory([*NS, *WL, pol]), "monitoring/prometheus", "shop/orders", 8080)
    assert out["verdict"] == "undetermined", out


# ------------------------------------------------------------------------------------------- D12: cost


def test_text_with_nothing_to_change_costs_one_pass_and_no_per_character_work() -> None:
    ascii_blob = "line: Deployment shop/web rule KN-S001 high\n" * 20_000
    unicode_blob = "ligne: privil\u00e9gi\u00e9 \u6771\u4eac \U0001f4bb\n" * 20_000  # nothing to change
    before = sanitize.STATS["special"]
    assert sanitize.visible_lines(ascii_blob) is ascii_blob
    assert sanitize.visible_lines(unicode_blob) is unicode_blob
    assert sanitize.STATS["special"] == before  # no character was looked at one by one


def test_the_per_character_work_is_proportional_to_what_changes() -> None:
    text = ("plain words " * 1000 + ZWSP) * 10
    before = sanitize.STATS["special"]
    sanitize.visible_lines(text)
    assert sanitize.STATS["special"] - before == 10


# ------------------------------------------------------------------------------------------- minor: zstd


def test_the_zstd_child_does_not_write_to_the_terminal_itself(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    from kube_noob.sources import advisories

    calls: dict[str, Any] = {}
    real = subprocess.Popen

    def popen(*args: Any, **kwargs: Any) -> Any:
        calls.update(kwargs)
        return real(
            ["sh", "-c", "printf 'zstd: \\033[2J broken\\n' >&2; exit 1"],
            stdout=subprocess.PIPE,
            stderr=kwargs.get("stderr"),
        )

    monkeypatch.setattr(subprocess, "Popen", popen)
    archive = tmp_path / "x.tar.zst"
    archive.write_bytes(b"")
    with pytest.raises(advisories.AdvisoryError) as exc:
        list(advisories.from_archive(archive))
    assert calls.get("stderr") not in (None,)  # captured, not inherited
    assert "broken" in str(exc.value)
