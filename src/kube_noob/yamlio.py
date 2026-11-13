"""Safe multi-document YAML loading with source line tracking.

Defences: input size cap, document count cap, alias/anchor expansion budget (billion-laughs), nesting depth cap,
SafeLoader only. Duplicate mapping keys are recorded (PyYAML keeps the last one silently, the API server's strict
decoding rejects them) so the audit can report them instead of judging a different object than kubectl would.
Every parsed document keeps a map ``path tuple -> 1-based line`` so findings can point at exact lines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml

from kube_noob.errors import ManifestError

MAX_INPUT_BYTES = 5_000_000
MAX_DOCUMENTS = 1000
MAX_NODE_VISITS = 500_000
MAX_DEPTH = 100

PathT = tuple[str | int, ...]


@dataclass
class Document:
    index: int
    data: Any
    lines: dict[PathT, int] = field(default_factory=dict)
    start_line: int = 1
    duplicate_keys: list[tuple[PathT, int]] = field(default_factory=list)
    #: Per-list memo for `locator`: the keys a list's items share, computed once per list rather than once
    #: per finding (G252). Out of `repr` and `==` so a Document still prints and compares as its content.
    ambiguous_keys: dict[PathT, frozenset[str]] = field(default_factory=dict, repr=False, compare=False)

    def line_for(self, path: PathT) -> int:
        """Best line for a path: exact match, else nearest existing ancestor, else doc start."""
        p = tuple(path)
        while p:
            if p in self.lines:
                return self.lines[p]
            p = p[:-1]
        return self.start_line

    @property
    def kind(self) -> str:
        return str(self.data.get("kind", "")) if isinstance(self.data, dict) else ""

    @property
    def api_version(self) -> str:
        return str(self.data.get("apiVersion", "")) if isinstance(self.data, dict) else ""

    @property
    def name(self) -> str:
        if isinstance(self.data, dict) and isinstance(self.data.get("metadata"), dict):
            return str(self.data["metadata"].get("name", ""))
        return ""

    @property
    def namespace(self) -> str | None:
        if isinstance(self.data, dict) and isinstance(self.data.get("metadata"), dict):
            ns = self.data["metadata"].get("namespace")
            return str(ns) if ns is not None else None
        return None

    def ref(self) -> str:
        ns = f"{self.namespace}/" if self.namespace else ""
        return f"{self.kind}/{ns}{self.name or '<unnamed>'}"


def _walk(
    node: yaml.Node,
    path: PathT,
    out: dict[PathT, int],
    budget: list[int],
    line: int | None = None,
    dups: list[tuple[PathT, int]] | None = None,
) -> None:
    budget[0] -= 1
    if budget[0] < 0:
        raise ManifestError("YAML is too complex to process safely (node budget exceeded; possible alias/anchor bomb).")
    if len(path) > MAX_DEPTH:
        raise ManifestError(f"YAML nesting is too deep: more than {MAX_DEPTH} levels; refusing to process.")
    out.setdefault(path, line if line is not None else node.start_mark.line + 1)
    if isinstance(node, yaml.MappingNode):
        seen: set[str] = set()
        for key_node, value_node in node.value:
            key = key_node.value if isinstance(key_node, yaml.ScalarNode) else str(key_node.start_mark.line)
            if dups is not None and key != "<<":
                if key in seen:
                    dups.append(((*path, key), key_node.start_mark.line + 1))
                seen.add(key)
            _walk(value_node, (*path, key), out, budget, key_node.start_mark.line + 1, dups)
    elif isinstance(node, yaml.SequenceNode):
        for i, child in enumerate(node.value):
            _walk(child, (*path, i), out, budget, None, dups)


def load_documents(text: str) -> list[Document]:
    """Parse one or more YAML documents. Empty documents are skipped. ``List`` kinds are flattened."""
    if len(text.encode("utf-8", errors="replace")) > MAX_INPUT_BYTES:
        raise ManifestError(f"Input exceeds {MAX_INPUT_BYTES} bytes; split it into smaller files.")
    try:
        # Inside the try, because the Reader validates the whole string here: a control character (ESC, NUL)
        # raises ReaderError from the constructor, and with this line outside the handler that YAMLError escaped
        # as an unhandled exception -- which the MCP server turns into a 500 "internal error" for what is simply
        # input it cannot parse. A caller cannot act on a 500.
        loader = yaml.SafeLoader(text)
    except yaml.YAMLError as exc:
        raise ManifestError(f"Invalid YAML: {exc}") from exc
    docs: list[Document] = []
    budget = [MAX_NODE_VISITS]
    try:
        while loader.check_node():
            node = loader.get_node()
            if node is None:
                continue
            lines: dict[PathT, int] = {}
            dups: list[tuple[PathT, int]] = []
            _walk(node, (), lines, budget, None, dups)
            data = loader.construct_document(node)
            if data is None:
                continue
            if len(docs) >= MAX_DOCUMENTS:
                raise ManifestError(f"More than {MAX_DOCUMENTS} YAML documents; split the input.")
            docs.append(
                Document(
                    index=len(docs),
                    data=data,
                    lines=lines,
                    start_line=node.start_mark.line + 1,
                    duplicate_keys=dups,
                )
            )
    except yaml.YAMLError as exc:
        raise ManifestError(f"Invalid YAML: {exc}") from exc
    except RecursionError as exc:
        raise ManifestError(f"YAML nesting is too deep to process safely (limit {MAX_DEPTH} levels).") from exc
    finally:
        loader.dispose()
    return _flatten_lists(docs)


def _flatten_lists(docs: list[Document]) -> list[Document]:
    out: list[Document] = []
    for d in docs:
        if isinstance(d.data, dict) and d.data.get("kind") == "List" and isinstance(d.data.get("items"), list):
            for i, item in enumerate(d.data["items"]):
                prefix: PathT = ("items", i)
                sub = {k[len(prefix) :]: v for k, v in d.lines.items() if k[: len(prefix)] == prefix}
                sub_dups = [(k[len(prefix) :], ln) for k, ln in d.duplicate_keys if k[: len(prefix)] == prefix]
                out.append(
                    Document(
                        index=len(out), data=item, lines=sub, start_line=d.line_for(prefix), duplicate_keys=sub_dups
                    )
                )
        else:
            d.index = len(out)
            out.append(d)
    return out


class _Dumper(yaml.SafeDumper):
    pass


def _str_presenter(dumper: yaml.SafeDumper, data: str) -> yaml.ScalarNode:
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_Dumper.add_representer(str, _str_presenter)


def dump_documents(objs: list[Any]) -> str:
    """Deterministic YAML: insertion order preserved, block style, ``---`` separated."""
    parts = [
        yaml.dump(o, Dumper=_Dumper, sort_keys=False, default_flow_style=False, width=120, allow_unicode=True)
        for o in objs
    ]
    return "---\n" + "---\n".join(parts)


def get_path(data: Any, path: PathT) -> Any:
    cur = data
    for p in path:
        if isinstance(p, int):
            if not isinstance(cur, list) or p >= len(cur):
                return None
            cur = cur[p]
        else:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(p)
    return cur


def fmt_path(path: PathT) -> str:
    s = ""
    for p in path:
        s += f"[{p}]" if isinstance(p, int) else (f".{p}" if s else str(p))
    return s


def locator(data: Any, path: PathT, ambiguous: dict[PathT, frozenset[str]] | None = None) -> str:
    """``fmt_path`` with list indices replaced by the key that identifies the item.

    ``spec.template.spec.containers[0].securityContext`` becomes
    ``spec.template.spec.containers[name=api].securityContext``.

    An index is a position, and positions move: inserting a sidecar at the front renames every finding
    on every other container, so anything keyed on the raw path reports N fixed and N new findings for
    a change that fixed nothing. The container's name is the thing that did not move, and it lives only
    in the finding's message, which is the one field an identity must not use because messages carry
    counts and sorted lists that change on their own.

    Items with no natural key keep the index, and that is honest: a NetworkPolicy's ``ingress[1]`` and
    an RBAC ``rules[0]`` are identified by position in the API itself, so there is nothing better to use.

    A name two siblings SHARE is not a key either, so those items keep the index as well. The API server
    refuses most duplicates, but a rule that reports the duplicate is reading the object that still has it:
    two different defects on two entries called `gpu` would otherwise hash to one identity, and a baseline
    entry for either would suppress the other. Only the ambiguous entries fall back -- a unique sibling in
    the same list keeps its name.
    """
    out = ""
    for i, seg in enumerate(path):
        if not isinstance(seg, int):
            out += f".{seg}" if out else str(seg)
            continue
        key = _item_key(get_path(data, tuple(path[: i + 1])))
        if key and key in _ambiguous_keys(data, tuple(path[:i]), ambiguous):
            key = ""
        out += f"[{key or seg}]"
    return out


def _ambiguous_keys(data: Any, prefix: PathT, cache: dict[PathT, frozenset[str]] | None) -> frozenset[str]:
    """The keys two or more items of the list at ``prefix`` share, computed once per list when a cache is given.

    Without the cache this scanned every sibling for every finding, which is O(n^2) in the list's length: a
    Deployment with 2,000 containers took six seconds and one with 16,000 took six minutes, so an object
    padded with containers outran the admission webhook's three-second timeout and was admitted with no
    warning and no denial -- while the single process stayed busy and every other request timed out with it.
    One pass per list makes it linear (G252).
    """
    if cache is not None and prefix in cache:
        return cache[prefix]
    siblings = get_path(data, prefix)
    seen: dict[str, int] = {}
    if isinstance(siblings, list):
        for item in siblings:
            key = _item_key(item)
            if key:
                seen[key] = seen.get(key, 0) + 1
    out = frozenset(k for k, n in seen.items() if n > 1)
    if cache is not None:
        cache[prefix] = out
    return out


def _item_key(item: Any) -> str:
    """The field that identifies a list item, or ``""`` when nothing in it does."""
    if isinstance(item, dict):
        for field_name in ("name", "containerName"):
            value = item.get(field_name)
            if isinstance(value, str) and value:
                return f"{field_name}={value}"
        meta = item.get("metadata")
        if isinstance(meta, dict) and isinstance(meta.get("name"), str) and meta["name"]:
            return f"metadata.name={meta['name']}"
    elif isinstance(item, str) and item:
        return item  # a scalar list entry identifies itself: capabilities.add[ALL]
    return ""
