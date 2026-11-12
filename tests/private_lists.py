"""Find private control-character lists in Python source: what `tests/test_visible_everywhere.py` refuses outside
`sanitize.py` (G279). Kept in its own module so the reviewer's evasion corpus can be run against it directly.

It reads the syntax tree, not the text, and evaluates what a constant MEANS: escapes left in a raw string or a
regex (``\\x1b``, ``\\u202e``, ``\\N{ESCAPE}``, octal ``\\33``) are decoded before a character class is checked, and
an f-string's literal parts are joined. It flags:

* a character class (``[...]``, in a str or bytes constant or an f-string) whose members or ranges include a C0
  control other than white space, DEL, a C1 control, or a format, bidi, zero-width, BOM or tag character;
* ``\\p{C...}`` Unicode-property classes (the ``regex`` module);
* a ``.replace``/``.strip``/``.lstrip``/``.rstrip``/``.translate``/``str.maketrans`` whose literal argument names
  such a character;
* ``isprintable`` in any form (a call, ``str.isprintable`` passed to ``filter``, ``getattr(c, "isprintable")``);
* ``unicodedata.category`` -- under any alias -- compared with a ``C*`` or ``Z*`` category;
* ``ord(c)`` compared with the bounds of printable ASCII (31, 32, 126, 127, 159, 160);
* ``chr(...)`` of such a code point, or ``chr`` over a ``range`` that covers them (``map(chr, range(32))``);
* ``.encode("ascii", "ignore" | "replace")``, which drops everything that is not ASCII;
* ``string.printable`` (under any alias of the module), ``ord(c) in range(...)`` over such code points, a dict
  comprehension over such a range (a translate table), ``bytes([27]).decode()``, ``chr(int("1b", 16))`` and
  ``codecs.decode("\\x1b", "unicode_escape")`` (third review).

What it still cannot see: a pattern assembled at run time from innocent pieces (``"\\\\x" + "1b"``), a class
computed by a function, a table built in a loop, a codec's error handler registered by name, and a list of code
points compared one by one. Review has to look for those.
"""

from __future__ import annotations

import ast
import re
import unicodedata

_WHITE = {0x09, 0x0A, 0x0B, 0x0C, 0x0D}
_FORMAT = {
    0x00AD, 0x061C, 0x180E, 0xFEFF,
    *range(0x200B, 0x2010), *range(0x202A, 0x202F), *range(0x2060, 0x2070), *range(0xFFF9, 0xFFFC),
    *range(0xE0000, 0xE0080), *range(0xFE00, 0xFE10), 0x034F, 0x3164, 0x115F, 0x1160, 0xFFA0,
}  # fmt: skip


def bad(o: int) -> bool:
    return (o < 0x20 and o not in _WHITE) or 0x7F <= o <= 0x9F or o in _FORMAT


_ESCAPE = re.compile(r"\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|N\{[^}]{1,60}\}|[0-7]{1,3})")


def decode(text: str) -> str:
    """The characters a regex escape names, decoded; anything else left as it is."""

    def one(m: re.Match[str]) -> str:
        g = m.group(1)
        try:
            if g[0] in "xuU":
                return chr(int(g[1:], 16))
            if g[0] == "N":
                return unicodedata.lookup(g[2:-1])
            return chr(int(g, 8))
        except (ValueError, KeyError):
            return m.group(0)

    return _ESCAPE.sub(one, text)


def _classes(text: str) -> list[str]:
    out, i, n = [], 0, len(text)
    while i < n:
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == "[":
            j = i + 1
            if j < n and text[j] == "^":
                j += 1
            if j < n and text[j] == "]":
                j += 1
            while j < n and text[j] != "]":
                j += 2 if text[j] == "\\" else 1
            if j < n:
                out.append(text[i + 1 : j])
                i = j
        i += 1
    return out


def names_bad(text: str) -> bool:
    """Whether ``text`` (a pattern or a literal) holds a class naming a bad character, or a \\p{C} property."""
    if "\\p{C" in text or "\\P{C" in text:
        return True
    for found in _classes(decode(text)):
        chars = [c for c in found.lstrip("^") if c != "\\"]
        for k, c in enumerate(chars):
            if bad(ord(c)):
                return True
            if c == "-" and 0 < k < len(chars) - 1:
                lo, hi = sorted((ord(chars[k - 1]), ord(chars[k + 1])))
                if any(bad(o) for o in range(lo, min(hi, 0x10FFFF) + 1)):
                    return True
    return False


def _literal_text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
        return node.value.decode("latin-1")
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
    return None


def _has_bad_char(node: ast.AST) -> bool:
    text = _literal_text(node)
    if text is not None:
        return any(bad(ord(c)) for c in decode(text))
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return bad(node.value)
    if isinstance(node, ast.Dict):
        return any(k is not None and _has_bad_char(k) for k in node.keys)
    return False


def _range_covers_bad(node: ast.AST) -> bool:
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "range"):
        return False
    args = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, int)]
    if len(args) != len(node.args) or not args:
        return False
    lo, hi = (0, args[0]) if len(args) == 1 else (args[0], args[1])
    return any(bad(o) for o in range(max(lo, 0), min(hi, 0x110000)))


def _int_call_value(node: ast.AST) -> int | None:
    """The value of ``int("1b", 16)`` (literal arguments only), or None."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "int" and node.args):
        return None
    vals = [a.value for a in node.args if isinstance(a, ast.Constant)]
    if len(vals) != len(node.args) or not isinstance(vals[0], str):
        return None
    try:
        return int(vals[0], *(int(v) for v in vals[1:2]))
    except (TypeError, ValueError):
        return None


def _calls(node: ast.AST, name: str) -> bool:
    return any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == name for n in ast.walk(node))


_STRIPS = {"replace", "strip", "lstrip", "rstrip", "removeprefix", "removesuffix", "translate", "maketrans"}


def private_lists(src: str) -> list[tuple[int, str]]:
    """(line, source) of every place in ``src`` that keeps its own list of characters that do not print."""
    tree = ast.parse(src)
    docstrings = {
        id(n.body[0].value)
        for n in ast.walk(tree)
        if isinstance(n, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
        and n.body
        and isinstance(n.body[0], ast.Expr)
        and isinstance(n.body[0].value, ast.Constant)
    }
    category_names: set[str] = set()
    modules = {"unicodedata"}
    string_names = {"string"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "unicodedata":
            category_names |= {a.asname or a.name for a in node.names if a.name == "category"}
        if isinstance(node, ast.Import):
            modules |= {a.asname or a.name for a in node.names if a.name == "unicodedata"}
            string_names |= {a.asname or a.name for a in node.names if a.name == "string"}

    def is_category(call: ast.AST) -> bool:
        if not isinstance(call, ast.Call):
            return False
        f = call.func
        if isinstance(f, ast.Attribute) and f.attr == "category":
            return isinstance(f.value, ast.Name) and f.value.id in modules
        return isinstance(f, ast.Name) and f.id in category_names

    found: list[tuple[int, str]] = []

    def hit(node: ast.AST) -> None:
        found.append((getattr(node, "lineno", 0), (ast.get_source_segment(src, node) or "")[:120]))

    for node in ast.walk(tree):
        if id(node) in docstrings:
            continue
        text = _literal_text(node)
        if text is not None and names_bad(text):
            hit(node)
            continue
        if (isinstance(node, ast.Attribute) and node.attr == "isprintable") or (
            isinstance(node, ast.Constant) and node.value == "isprintable"
        ):
            hit(node)
        elif (
            isinstance(node, ast.Attribute)
            and node.attr == "printable"
            and isinstance(node.value, ast.Name)
            and node.value.id in string_names
        ):
            hit(node)  # `c in string.printable`: the printable-ASCII list under another name
        elif isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr in _STRIPS and any(_has_bad_char(a) for a in node.args):
                hit(node)
            elif (
                isinstance(f, ast.Attribute)
                and f.attr == "translate"
                and node.args
                and isinstance(node.args[0], ast.Call)
            ):
                inner = node.args[0]
                if (
                    isinstance(inner.func, ast.Attribute)
                    and inner.func.attr == "maketrans"
                    and any(_has_bad_char(a) for a in inner.args)
                ):
                    hit(node)
            elif isinstance(f, ast.Name) and f.id == "chr" and node.args and _has_bad_char(node.args[0]):
                hit(node)
            elif isinstance(f, ast.Name) and f.id == "chr" and node.args and bad(_int_call_value(node.args[0]) or 0x41):
                hit(node)  # chr(int("1b", 16))
            elif (
                isinstance(f, ast.Attribute)
                and f.attr == "decode"
                and isinstance(f.value, ast.Call)
                and isinstance(f.value.func, ast.Name)
                and f.value.func.id in {"bytes", "bytearray"}
                and f.value.args
                and isinstance(f.value.args[0], ast.List | ast.Tuple)
                and any(_has_bad_char(e) for e in f.value.args[0].elts)
            ):
                hit(node)  # bytes([27]).decode(): data bytes are fine, decoding them into text is a character
            elif (
                isinstance(f, ast.Attribute)
                and f.attr == "decode"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and str(node.args[1].value).lower() in {"unicode_escape", "unicode-escape", "raw_unicode_escape"}
                and (_literal_text(node.args[0]) is not None)
                and any(bad(ord(c)) for c in decode(_literal_text(node.args[0]) or ""))
            ):
                hit(node)  # codecs.decode("\\x1b", "unicode_escape")
            elif isinstance(f, ast.Name) and f.id == "map" and len(node.args) == 2:
                fn, it = node.args
                if isinstance(fn, ast.Name) and fn.id == "chr" and _range_covers_bad(it):
                    hit(node)
            elif isinstance(f, ast.Attribute) and f.attr == "encode" and node.args:
                codec = node.args[0]
                errors = (
                    node.args[1]
                    if len(node.args) > 1
                    else next((k.value for k in node.keywords if k.arg == "errors"), None)
                )
                if (
                    isinstance(codec, ast.Constant)
                    and str(codec.value).lower() in {"ascii", "us-ascii"}
                    and isinstance(errors, ast.Constant)
                    and errors.value in {"ignore", "replace"}
                ):
                    hit(node)
        elif isinstance(node, ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp):
            uses_chr = any(
                isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "chr" for n in ast.walk(node)
            )
            if (uses_chr or isinstance(node, ast.DictComp)) and any(_range_covers_bad(g.iter) for g in node.generators):
                hit(node)  # a table over range(32), with or without chr
        elif isinstance(node, ast.Compare):
            sides = [node.left, *node.comparators]
            if any(is_category(s) or (isinstance(s, ast.Subscript) and is_category(s.value)) for s in sides):
                for s in sides:
                    consts = [s] if isinstance(s, ast.Constant) else list(getattr(s, "elts", []))
                    if any(isinstance(c, ast.Constant) and str(c.value)[:1] in {"C", "Z"} for c in consts):
                        hit(node)
                        break
            elif any(
                isinstance(s, ast.Call) and isinstance(s.func, ast.Name) and s.func.id == "ord" for s in sides
            ) and any(isinstance(s, ast.Constant) and s.value in {31, 32, 126, 127, 159, 160} for s in sides):
                hit(node)
            elif (
                any(isinstance(op, ast.In | ast.NotIn) for op in node.ops)
                and _calls(node.left, "ord")
                and any(_range_covers_bad(c) for c in node.comparators)
            ):
                hit(node)  # ord(c) not in range(0x7f, 0xa0)
    return found
