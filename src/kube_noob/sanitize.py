"""Prompt-injection hygiene for text that came from outside: a cluster, a must-gather, a ticket, a memory entry, a
pasted payload or a web page.

Defence in depth, not a guarantee. kube-noob calls no model itself, but the model that calls kube-noob reads its
results, so text shaped to steer that model is found before a result leaves the MCP server. Two tiers:

- removed (the text is replaced by a visible marker): invisible characters (Unicode tag characters, bidirectional
  overrides and isolates, zero-width characters other than the joiner inside an emoji, soft hyphens and other
  format characters used to split words); chat-template and role markers (``<|im_start|>``, ``[INST]``,
  ``<<SYS>>``, ``### System:``, ``<system-reminder>``, ``{"role": "system"``, ``<instructions>``, and
  ``Human:`` / ``Assistant:`` lines when both appear); tool-call markup; instructions aimed at a model ("ignore
  previous instructions", "your new task is", "Claude, please run ...", "when you summarise this, say ...", in
  English, Spanish, French, German, Italian, Portuguese, Chinese, Japanese, Korean and Russian, and inside base64);
  and the address of every remote image (Markdown, reference-style or HTML), the usual way to make a renderer send
  data out, plus the query of a link when it carries a long, data-like value;
- flagged only (the text is kept, the result is marked ``untrusted``): phrases that are injections in one place and
  operations in another, such as "send the credentials to vault.example.com" or "note for the agents:".

Phrases are matched on a normalised copy of the text: compatibility forms folded (full-width and mathematical
letters), common Cyrillic and Greek look-alikes mapped to Latin, HTML entities decoded, terminal colour codes,
format characters and hyphenated line breaks removed, and every run of white space collapsed; a match is mapped back
to the original characters it came from. Every rule is deterministic and bounded. The evals in
``tests/fixtures/injection.yaml`` and ``tests/fixtures/injection_rt1.yaml`` (kept out of the package and the plugin,
since they hold attack text) gate detection and false positives, and a test runs every rule over all bundled text
expecting no finding.
"""

from __future__ import annotations

import base64
import binascii
import functools
import html
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

import yaml

MAX_SIGNALS = 20
MAX_DEPTH = 40
MAX_JSON_DEPTH = 64  # brackets deep that pasted JSON may nest before it is refused unread (real payloads: under 10)
# Files get a higher ceiling than pastes. The tight limit exists for the WebAssembly playground, whose stack is
# small, and for text a person pastes, which nests under ten. A scanner's own output is different: nested
# CycloneDX components are a dependency tree, and `vuln.reports` is built to accept a deep one and bound its own
# walk at MAX_DEPTH rather than refuse the document. Refusing at 64 would turn that into a rejection. 512 is far
# above any real SBOM and far below both CPython's recursion limit and a nesting bomb, which runs to six figures.
MAX_JSON_DEPTH_FILE = 512
MAX_YAML_DEPTH = 64  # nesting levels of YAML composed from outside; `yamlio` bounds manifests at its own MAX_DEPTH
MAX_SCAN = 4_000_000  # characters of one string scanned; the rest is kept as is (results are bounded upstream)
MAX_BASE64 = 20  # base64 runs decoded per string
MARKER = "[removed: {what}]"


class YamlTooDeep(ValueError):
    """Raised instead of composing YAML that nests past ``MAX_YAML_DEPTH``.

    A ``ValueError``, so an ``except ValueError`` catches it. ``yaml.YAMLError`` is *not* a ``ValueError``, so a
    caller that only catches ``yaml.YAMLError`` must be widened as well as pointed at the bounded loader.
    """


class JsonTooDeep(ValueError):
    """Raised instead of parsing JSON that nests past ``MAX_JSON_DEPTH``.

    A ``ValueError``, so the ``except ValueError`` every JSON reader here already has keeps catching it.
    """


# A complete JSON string literal, with the inner loop unrolled so the engine consumes long runs of ordinary
# characters in one step instead of one alternation per character. The trailing `"?` makes an unterminated string
# swallow the rest of the input, which is what counting character by character does.
_JSON_STRING = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"?')
_NOT_BRACKET = re.compile(r"[^{}\[\]]+")


def json_nesting_ok(text: str | bytes, limit: int = MAX_JSON_DEPTH) -> bool:
    """Whether JSON is shallow enough to hand to ``json.loads``, counted before parsing it.

    ``json.loads`` recurses, and from CPython 3.14 nothing portable stops it. Up to 3.13 it raises
    ``RecursionError`` at about ``sys.getrecursionlimit()`` levels, which every caller here catches. On 3.14 the
    limit no longer applies to it: measured on 3.14.6 with ``recursionlimit`` at its default 1000, a document
    10 000 brackets deep parses, and only 100 000 fails -- and whether even that fails depends on the C stack the
    process happens to have, so the same document is refused in a small container and accepted on a CI runner. In
    the WebAssembly runtime behind kube-noob.com's playground the overflow surfaces as a raw JavaScript
    ``RangeError`` that the runtime calls fatal, taking out ``diagnose`` and ``known_issues`` for a paste that
    merely starts with a bracket.

    So there is no depth a handler can be written against. Counting the brackets first refuses the same input at
    the same depth on every interpreter and every machine, before anything recurses.

    Two passes in C -- drop every string literal, then drop everything that is not a bracket -- so the loop below
    runs once per bracket rather than once per character. On a 50 MB document that is about 0.4 s instead of 3 s,
    and the two passes allocate less than the parse they guard.
    """
    s = text.decode("utf-8", errors="replace") if isinstance(text, bytes | bytearray) else text
    # Nothing can nest past the limit with fewer openers than that, and most documents stop here for free.
    if s.count("{") + s.count("[") <= limit:
        return True
    depth = 0
    for ch in _NOT_BRACKET.sub("", _JSON_STRING.sub("", s)):
        if ch in {"{", "["}:
            depth += 1
            if depth > limit:
                return False
        else:
            depth -= 1
    return True


_YAML_OPEN = (yaml.MappingStartEvent, yaml.SequenceStartEvent)
_YAML_CLOSE = (yaml.MappingEndEvent, yaml.SequenceEndEvent)


def yaml_nesting_ok(text: str, limit: int = MAX_YAML_DEPTH) -> bool:
    """Whether YAML is shallow enough to hand to a loader, counted from the event stream before composing it.

    The same problem as JSON, worse: ``yaml.SafeLoader``'s composer recurses in Python and ``yaml.CSafeLoader``'s
    recurses in C, where a deep document does not raise ``RecursionError`` but **segfaults the process** -- 50 000
    levels is enough on CPython 3.13, no 3.14 required. ``yaml.parse`` only emits events and recurses in neither
    implementation (40 007 events at 20 000 levels deep, measured), so the depth can be counted before anything
    builds a node.

    Malformed YAML returns ``True``: saying so is the loader's job, and its message is the better one.
    """
    depth = 0
    try:
        for event in yaml.parse(text):
            if isinstance(event, _YAML_OPEN):
                depth += 1
                if depth > limit:
                    return False
            elif isinstance(event, _YAML_CLOSE):
                depth -= 1
    except yaml.YAMLError:
        return True
    return True


def safe_load_bounded(text: str, limit: int = MAX_YAML_DEPTH) -> Any:
    """``yaml.safe_load`` with the nesting counted first. Raises ``YamlTooDeep`` (a ``ValueError``)."""
    if not yaml_nesting_ok(text, limit):
        raise YamlTooDeep(f"YAML nested too deeply (more than {limit} levels)")
    return yaml.safe_load(text)


def safe_load_all_bounded(text: str, limit: int = MAX_YAML_DEPTH) -> list[Any]:
    """``yaml.safe_load_all`` with the nesting counted first, returned as a list so the count cannot be skipped."""
    if not yaml_nesting_ok(text, limit):
        raise YamlTooDeep(f"YAML nested too deeply (more than {limit} levels)")
    return list(yaml.safe_load_all(text))


def loads_bounded(data: str | bytes, limit: int = MAX_JSON_DEPTH, object_pairs_hook: Any = None) -> Any:
    """``json.loads`` with the bracket depth counted first, so every reader refuses a nesting bomb identically.

    Raises ``JsonTooDeep`` (a ``ValueError``) rather than letting the interpreter decide, and otherwise behaves
    exactly like ``json.loads`` (``object_pairs_hook`` is passed through, for a reader that must see repeated keys).
    """
    if not json_nesting_ok(data, limit):
        raise JsonTooDeep(f"JSON nested too deeply (more than {limit} levels)")
    return json.loads(data, object_pairs_hook=object_pairs_hook)


# Terminal control sequences, removed whole (to nothing: a space would split what the sequence sat inside): CSI
# (ESC [ ... final), the string sequences OSC (ESC ], which carries OSC 8 hyperlinks and OSC 52 clipboard writes), DCS
# (ESC P), SOS (ESC X), PM (ESC ^) and APC (ESC _), each to BEL or ST, and the two-character escapes. A lone ESC that
# starts none of these is a control character like any other.
_TERMINAL_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|[\]PX^_][^\x07\x1b]{0,512}(?:\x07|\x1b\\)?|[ -/]*[0-~])")

#: A run of escape sequences; inside a name (`_IDENT` on both sides, the same set format characters use) it is
#: shown as `<ESC>`, so `api<ESC>.internal` is not `api.internal` (fourth review).
_ESCAPE_RUN = re.compile("(?:" + _TERMINAL_ESCAPE.pattern + ")+")


def _ranges(*spans: tuple[int, int]) -> str:
    return "".join(re.escape(chr(lo)) + ("-" + re.escape(chr(hi)) if hi != lo else "") for lo, hi in spans)


#: Format characters (Unicode general category Cf), FIXED here rather than read from ``unicodedata``: the
#: interpreter's Unicode table differs across the supported Pythons (3.11 has Unicode 14, 3.13 has 15.1), and output
#: must not. This is the Cf set of Unicode 15.1 plus the whole tag block; a test fails if this interpreter knows a Cf
#: character the list lacks.
_FORMAT_RANGES = (
    (0x00AD, 0x00AD),  # soft hyphen
    (0x0600, 0x0605),  # Arabic prepended concatenation marks
    (0x061C, 0x061C),  # Arabic letter mark
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x180E, 0x180E),  # Mongolian vowel separator
    (0x200B, 0x200F),  # zero width space, ZWNJ, ZWJ, LRM, RLM
    (0x202A, 0x202E),  # bidi embeddings and overrides
    (0x2060, 0x2064),  # word joiner, invisible operators
    (0x2066, 0x206F),  # bidi isolates, deprecated format characters
    (0xFEFF, 0xFEFF),  # byte order mark / zero width no-break space
    (0xFFF9, 0xFFFB),  # interlinear annotation marks
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),  # Egyptian hieroglyph format controls
    (0x1BCA0, 0x1BCA3),  # shorthand format controls
    (0x1D173, 0x1D17A),  # musical symbol beam and phrase controls
    (0xE0000, 0xE007F),  # the tag block
)
#: Default-ignorable characters that are not Cf but print nothing, and the unassigned default-ignorable ranges: the
#: Hangul fillers, the combining grapheme joiner, variation selectors, Mongolian free variation selectors, and
#: U+2065, U+FFF0-FFF8, U+E0080-E0FFF (reserved by Unicode as default-ignorable). Removed like format characters,
#: except where the text needs them (see :func:`_keep_in_context`).
_IGNORABLE_RANGES = (
    (0x034F, 0x034F),  # combining grapheme joiner
    (0x115F, 0x1160),  # Hangul choseong and jungseong fillers
    (0x17B4, 0x17B5),  # Khmer inherent vowels
    (0x180B, 0x180D),  # Mongolian free variation selectors
    (0x180F, 0x180F),
    (0x2065, 0x2065),
    (0x3164, 0x3164),  # Hangul filler
    (0xFE00, 0xFE0F),  # variation selectors
    (0xFFA0, 0xFFA0),  # halfwidth Hangul filler
    (0xFFF0, 0xFFF8),
    (0xE0080, 0xE0FFF),  # variation selectors supplement (E0100-E01EF) and the reserved rest
)
#: Replaced like controls: line and paragraph separators, surrogates, private use (what it shows is the reader's
#: font's business), noncharacters, and the braille blank, which prints as a space.
_REPLACED_RANGES = (
    (0x2028, 0x2029),
    (0x2800, 0x2800),
    (0xD800, 0xF8FF),  # surrogates, then the BMP private use area
    (0xFDD0, 0xFDEF),
    (0xFFFE, 0xFFFF),
    (0xF0000, 0x10FFFF),
)
#: Combining marks whose runs are capped: the blocks "Zalgo" text stacks. A run longer than this many is cut.
_COMBINING_RANGES = ((0x0300, 0x036F), (0x1AB0, 0x1AFF), (0x1DC0, 0x1DFF), (0x20D0, 0x20FF), (0xFE20, 0xFE2F))
MAX_COMBINING = 4

_FORMAT = frozenset(c for lo, hi in _FORMAT_RANGES for c in range(lo, hi + 1))
_IGNORABLE = frozenset(c for lo, hi in _IGNORABLE_RANGES for c in range(lo, hi + 1))
_JOINERS = frozenset({0x200C, 0x200D})  # ZWNJ and ZWJ: kept after a printing non-ASCII character
_BIDI_CODES = frozenset([*range(0x202A, 0x202F), *range(0x2066, 0x206A), 0x200E, 0x200F, 0x061C])
_TAG_CODES = frozenset(range(0xE0000, 0xE0080))
#: Every character the rule may change, as one class: a text without one is returned as it is, in one regex pass.
_NONASCII_SPECIAL = re.compile(
    "["
    + _ranges((0x80, 0x9F), *_FORMAT_RANGES, *_IGNORABLE_RANGES, *_REPLACED_RANGES)
    + "]|["
    + _ranges(*_COMBINING_RANGES)
    + "]{"
    + str(MAX_COMBINING + 1)
    + ",}"
)
_ASCII_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


@functools.lru_cache(maxsize=16)
def _controls(keep: str) -> re.Pattern[str]:
    """The ASCII control characters other than those in ``keep``, as one class."""
    chars = "".join(re.escape(chr(c)) for c in [*range(0x20), 0x7F] if chr(c) not in keep)
    return re.compile("[" + chars + "]")


#: An ASCII identifier character: a removed character with one of these on both sides sat inside a name, a path or
#: an id, and is shown as a marker so that "web<U+200B>x" cannot pass for "webx".
_IDENT = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/-")

#: The core's per-call statistics, for tests that count operations instead of timing them.
STATS = {"special": 0}


def _replaced(o: int) -> bool:
    return o < 0x20 or 0x7F <= o <= 0x9F or any(lo <= o <= hi for lo, hi in _REPLACED_RANGES)


def _printing_non_ascii(ch: str) -> bool:
    """A non-ASCII character that prints: what a joiner or a variation selector can belong to. Not white space
    (NBSP, U+2000-200A, U+3000): `one_line` strips it, and the selector it kept was then left on its own, so the
    output failed `has_invisible` (G279, fourth review)."""
    o = ord(ch)
    return o > 0x7F and not ch.isspace() and not _replaced(o) and o not in _FORMAT and o not in _IGNORABLE


def _keep_in_context(text: str, i: int, o: int) -> bool:
    """A format or ignorable character the text needs where it stands. ZWJ and ZWNJ after a printing non-ASCII
    character (emoji sequences; Devanagari, Sinhala, Kannada, Malayalam, Persian). VS15/VS16 after one, or between
    a keycap base and U+20E3. Other variation selectors after one (standardized and ideographic variation
    sequences). The Mongolian vowel separator and free variation selectors after a Mongolian letter."""
    prev = text[i - 1] if i > 0 else ""
    # a variation selector belongs to the glyph before it: "\u2764\ufe0f" + ZWJ + "\U0001f525" is one emoji
    j = i - 1
    while j > 0 and (0xFE00 <= ord(text[j]) <= 0xFE0F or 0xE0100 <= ord(text[j]) <= 0xE01EF):
        j -= 1
    base = text[j] if j >= 0 and i > 0 else ""
    after_non_ascii = bool(base) and _printing_non_ascii(base) and (base == prev or o in _JOINERS)
    if o in _JOINERS or 0xFE00 <= o <= 0xFE0F or 0xE0100 <= o <= 0xE01EF:
        if after_non_ascii:
            return True
        return o in (0xFE0E, 0xFE0F) and prev in "0123456789#*" and text[i + 1 : i + 2] == "\u20e3"
    if o in (0x180B, 0x180C, 0x180D, 0x180E, 0x180F):
        return bool(prev) and 0x1820 <= ord(prev) <= 0x18AF
    return False


def _core(text: str, replacement: str, keep: str, mark: bool, stats: dict[str, int] | None = None) -> str:
    """The one rule every output and every MCP result follows (``visible`` and ``clean`` both call it)."""
    # Inside a name (an identifier character on both sides) nothing is ever removed without a trace: removing
    # would join two halves into another name (`web<ESC>x` is not `webx`, `openshift<U+200B>-etcd` is not
    # `openshift-etcd`). With `mark` the trace is a marker; without, the replacement, or a space (G279, reviews 3-4).
    gap = replacement or " "
    if "\x1b" in text:
        source = text

        def esc(m: re.Match[str]) -> str:
            a, b = m.start(), m.end()
            if a > 0 and b < len(source) and source[a - 1] in _IDENT and source[b] in _IDENT:
                return "<ESC>" if mark else gap
            return ""

        text = _ESCAPE_RUN.sub(esc, text)
        if stats is not None:
            stats["escape"] = stats.get("escape", 0) + 1
    if "\r\n" in text:
        text = text.replace("\r\n", "\n" if "\n" in keep else replacement)
    controls = _controls(keep)
    if text.isascii():
        if not controls.search(text):
            return text
        if replacement:
            return controls.sub(replacement, text)
        source = text
        return controls.sub(lambda m: _dropped(source, m.start(), m.end(), mark, gap), text)
    has_controls = controls.search(text) is not None
    if not has_controls and not _NONASCII_SPECIAL.search(text):
        return text
    out: list[str] = []
    pos = 0
    last = ""  # the last character written, for the marker's left neighbour
    pattern = _NONASCII_SPECIAL if not has_controls else _ANY_SPECIAL
    for m in pattern.finditer(text):
        STATS["special"] += 1
        start, end = m.span()
        if start > pos:
            out.append(text[pos:start])
            last = text[start - 1]
        pos = end
        seg = m.group(0)
        if len(seg) > 1:  # a run of combining marks: the first MAX_COMBINING stay
            out.append(seg[:MAX_COMBINING])
            last = seg[MAX_COMBINING - 1]
            if stats is not None:
                stats["combining"] = stats.get("combining", 0) + len(seg) - MAX_COMBINING
            continue
        o = ord(seg)
        if seg in keep:
            out.append(seg)
            last = seg
        elif o < 0x20 or o == 0x7F or _replaced(o):
            put = replacement or _dropped(text, start, end, mark, gap)
            out.append(put)
            last = put[-1:] or last
            if stats is not None:
                stats["control"] = stats.get("control", 0) + 1
        elif _keep_in_context(text, start, o):
            out.append(seg)
            last = seg
        else:
            if stats is not None:
                kind = "tag" if o in _TAG_CODES else "bidi" if o in _BIDI_CODES else "format"
                stats[kind] = stats.get(kind, 0) + 1
            j = end
            while j < len(text) and (ord(text[j]) in _FORMAT or ord(text[j]) in _IGNORABLE):
                j += 1
            after = text[j : j + 1]
            if last and after and last in _IDENT and after in _IDENT:
                out.append(f"<U+{o:04X}>" if mark else gap)
                last = ">" if mark else gap[-1]
    out.append(text[pos:])
    return "".join(out)


_ANY_SPECIAL = re.compile(_NONASCII_SPECIAL.pattern + r"|[\x00-\x1f\x7f]")


def _dropped(text: str, start: int, end: int, mark: bool, gap: str) -> str:
    """What a character replaced by "" leaves: nothing, unless it sat inside a name (G279, fourth review)."""
    if start > 0 and end < len(text) and text[start - 1] in _IDENT and text[end] in _IDENT:
        return f"<U+{ord(text[start]):04X}>" if mark else gap
    return ""


def visible(text: str, *, replacement: str = " ", keep: str = "", mark: bool = True) -> str:
    """``text`` as it should reach a terminal or a file a person reads. The rule (G279), shared with ``clean``:

    * terminal control sequences (CSI, OSC -- hyperlinks and clipboard writes --, DCS, APC, PM, SOS) are removed;
    * C0 and C1 controls, DEL, the line and paragraph separators, lone surrogates, private use, noncharacters and
      the braille blank are replaced by ``replacement``. CR LF counts as one line break. ``keep`` names characters
      left alone (the newline and the tab for ``visible_lines``);
    * format and default-ignorable characters are removed: bidi overrides, embeddings, isolates and marks (LRM,
      RLM, ALM), the tag block, the soft hyphen, the BOM, zero-width spaces, interlinear annotation marks, the
      Hangul fillers, the combining grapheme joiner, variation selectors and the reserved default-ignorables. One
      that sat inside an ASCII name (an identifier character on both sides) is shown as ``<U+200B>`` instead, so
      ``web<U+200B>x`` cannot pass for ``webx``; an escape sequence there as ``<ESC>``. ``mark=False`` shows the
      replacement (or a space) there instead -- never nothing, which would splice the name. ``mark`` is the default
      (fourth review: eight callers that did not pass it spliced names);
    * kept where the text needs them: ZWJ and ZWNJ, variation selectors after a printing non-ASCII character (emoji
      sequences, Devanagari, Sinhala, Malayalam, Persian, ideographic variation sequences), VS16 in a keycap, and
      the Mongolian selectors after a Mongolian letter;
    * a run of more than four combining marks from the diacritical blocks is cut to four;
    * everything else is kept, including code points this interpreter does not know yet, so the result is the same
      on every supported Python.

    Callers collapse whitespace and cap the length themselves. Text with none of these characters is returned as
    it is, after one regular-expression pass.
    """
    return _core(text, replacement, keep, mark)


def replace_surrogates(text: str) -> str:
    """``text`` with every lone surrogate replaced by U+FFFD. A JSON or YAML escape such as ``\\ud800`` decodes to
    one, and it is not text: encoding it to UTF-8 raises, which made one such name fail a whole audit (G279)."""
    if text.isascii() or not any(0xD800 <= ord(ch) <= 0xDFFF for ch in text):
        return text
    return "".join("\ufffd" if 0xD800 <= ord(ch) <= 0xDFFF else ch for ch in text)


def visible_lines(text: str, *, mark: bool = True) -> str:
    """``visible`` for multi-line text -- a terminal line, a log, a whole Markdown document: the newline and the tab
    are kept (CR LF becomes a newline), everything else that does not print is handled as ``visible`` says."""
    return _core(text, " ", "\n\t", mark)


def visible_squeezed(text: str) -> str:
    """``visible`` for one line, where each RUN of replaced characters becomes a single space -- what a
    C0-range substitution did, so a scanner's CR LF still reads as one space. Ordinary spaces are untouched."""
    v = _core(text, "\x00", "", True)
    return re.sub("\x00+", " ", v) if "\x00" in v else v


def one_line(text: str) -> str:
    """``visible`` with every run of white space collapsed to one space: a name or a message on one line."""
    out = " ".join(_core(text, " ", "", True).split())
    # Idempotent (fourth review): removing a character can join two runs of combining marks into one longer than
    # the cap, or leave a selector without its base once white space is collapsed. A second pass only cuts.
    for _ in range(2):
        again = " ".join(_core(out, " ", "", True).split())
        if again == out:
            break
        out = again
    return out


#: The service-message prefixes CI systems read ANYWHERE in a line: GitHub's legacy ``##[`` (actions/runner
#: v2.321.0, src/Runner.Common/ActionCommand.cs, TryParse), Azure Pipelines' ``##vso[`` and TeamCity's
#: ``##teamcity[``. One rule covers all three: ``##``, letters, ``[``.
_SERVICE_MESSAGE = re.compile(r"(##[A-Za-z]*)\[")
#: The end of the text already written that a following ``[`` could complete into a service message.
_SERVICE_TAIL = re.compile(r"(?:##[A-Za-z]*|#)\Z")
#: How the broken characters are shown: the marker style ``visible`` uses, so nobody reads them as text.
BRACKET_MARK = "<U+005B>"
COLON_MARK = "<U+003A>"


def defuse_service_messages(text: str) -> str:
    """``text`` with every ``##[``, ``##vso[`` and ``##teamcity[`` broken by marking its bracket."""
    return _SERVICE_MESSAGE.sub(r"\1" + BRACKET_MARK, text) if "##" in text else text


class CommandGuard:
    """Keeps text from being read as a CI workflow command (G279, reviews CP3-Q3 and 3).

    A GitHub runner reads a command from every line a step writes: ``TryParseV2`` takes a line that, after leading
    white space, starts with ``::``; the legacy ``TryParse`` takes ``##[`` anywhere in a line. Azure Pipelines
    (``##vso[``) and TeamCity (``##teamcity[``) read theirs anywhere too. A ConfigMap key in an audit line
    (``p##[stop-commands]token``) could stop command processing, forge an annotation, set a step output or a
    variable, or mask text. This breaks each with a visible marker, in plain ASCII and unambiguously: the bracket
    of ``##...[`` becomes ``<U+005B>`` and the first colon of a line-leading ``::`` becomes ``<U+003A>``. Nothing
    else changes. Always on -- not only under GITHUB_ACTIONS, not only off a terminal: a log is replayed, and the
    same input gives the same bytes.

    Stateful, because a stream is written in pieces (``print`` writes the newline separately): it keeps the end
    of what was written that a ``[`` could complete, and holds back a colon that starts a line until the next
    character says whether it begins ``::``. :meth:`flush` writes a held colon."""

    def __init__(self) -> None:
        self._tail = ""
        self._lead: str | None = ""  # the current line so far, while it is only white space (or ends ":" written)
        self._held = False  # a line-leading ":" not yet written

    @property
    def at_line_start(self) -> bool:
        return self._lead == "" and not self._held

    def reset(self) -> None:
        """The next character starts a line (a command written on purpose has just ended one)."""
        self._tail, self._lead, self._held = "", "", False

    def flush(self) -> str:
        """What is held back, to be written now: a line-leading colon the next write may still mark."""
        if not self._held:
            return ""
        self._held = False
        self._lead = (self._lead or "") + ":"
        self._tail = ":"
        return ":"

    def feed(self, text: str) -> str:
        if "[" in text:
            prev = self._tail
            # The group re-emits what it matched, so the part that came from `prev` is unchanged and can be cut.
            text = _SERVICE_MESSAGE.sub(r"\1" + BRACKET_MARK, prev + text)[len(prev) :]
        lead, held = self._lead, self._held
        if lead is None and "\n" not in text:  # the common case: the middle of a line
            out = text
        else:
            parts: list[str] = []
            for i, seg in enumerate(text.split("\n")):
                if i:
                    if held:
                        parts.append(":")
                        held = False
                    parts.append("\n")
                    lead = ""
                j = 0
                while lead is not None and j < len(seg):
                    ch = seg[j]
                    if held:  # ws ":" so far, the colon not written
                        held = False
                        if ch == ":":
                            parts.append(COLON_MARK + ":")
                            j += 1
                        else:
                            parts.append(":")
                        lead = None
                    elif lead.endswith(":"):  # ws ":" so far, the colon written (a flush came between)
                        if ch == ":":
                            parts.append(COLON_MARK)
                            j += 1
                        lead = None
                    elif ch.isspace():  # Python's white space is a superset of what .NET's TrimStart() removes
                        parts.append(ch)
                        lead += ch
                        j += 1
                    elif ch == ":":
                        held = True
                        j += 1
                    else:
                        lead = None
                parts.append(seg[j:])
            out = "".join(parts)
        self._lead, self._held = lead, held
        if out:
            m = _SERVICE_TAIL.search((self._tail + out)[-64:])
            self._tail = m.group(0) if m else ""
        return out


def defuse_workflow_commands(text: str) -> str:
    """``text`` (whole lines) with no workflow command in it: see :class:`CommandGuard`."""
    g = CommandGuard()
    return g.feed(text) + g.flush()


def has_invisible(text: str, *, keep: str = "") -> bool:
    """Whether ``visible`` would change ``text`` (other than for the characters in ``keep``). For refusing a value
    outright -- a file name, a remembered command -- rather than cleaning it."""
    return _core(text, " ", keep, False) != text


def _chars(*points: int | tuple[int, int]) -> str:
    """A character class body from code points and ranges, so no invisible character sits in this source file."""
    out = []
    for p in points:
        if isinstance(p, tuple):
            out.append(re.escape(chr(p[0])) + "-" + re.escape(chr(p[1])))
        else:
            out.append(re.escape(chr(p)))
    return "".join(out)


ZWJ = chr(0x200D)
BOM = chr(0xFEFF)
_SPLITTERS = re.compile("[" + _chars(0x00AD, 0x034F) + "]")  # soft hyphen, combining grapheme joiner
_FILLERS = re.compile("[" + _chars(0x3164, 0xFFA0, 0x115F, 0x1160) + "]")  # Hangul fillers look like spaces
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_ENTITY = re.compile(r"&(?:#\d{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z]{2,10});")
_CONFUSABLE = str.maketrans(
    {
        0x0430: "a",
        0x0435: "e",
        0x043E: "o",
        0x0440: "p",
        0x0441: "c",
        0x0443: "y",
        0x0445: "x",
        0x0456: "i",
        0x0458: "j",
        0x0455: "s",
        0x0501: "d",
        0x0261: "g",
        0x03BF: "o",
        0x03B9: "i",
        0x03BD: "v",
        0x03B1: "a",
        0x0410: "A",
        0x0415: "E",
        0x041E: "O",
        0x0420: "P",
        0x0421: "C",
        0x0425: "X",
        0x0406: "I",
        0x039F: "O",
        0x0399: "I",
        0x0391: "A",
        0x0395: "E",
        0x041D: "H",
        0x041C: "M",
        0x0422: "T",
        0x041A: "K",
        0x0412: "B",
    }
)

_MODEL = (
    r"(?:AI|A\.I\.|assistant|LLM|large\s+language\s+model|language\s+model|chatbot|copilot|Claude|ChatGPT|GPT(?:-\d)?|"
    r"Gemini|Lightspeed|AI\s+agent|coding\s+agent)"
)
_HUMAN_ROLE = (
    r"(?:team|teams|platform|engineers?|developers?|researchers?|users?|admins?|operators?|workloads?|nodes?|"
    r"deployments?|services?|namespaces?|quotas?|clusters?|pods?|api|models?|serving|keys?|requires?|extension)"
)
_SENSITIVE = (
    r"(?:secrets?|credentials?|tokens?|api\s+keys?|passwords?|environment\s+variables|env\s+vars|kubeconfigs?|"
    r"ssh\s+keys?|private\s+keys?|service\s*account\s+tokens?|pull\s+secrets?)"
)
_ACT = (
    r"(?:say|state|report|claim|write|answer|reply|respond|conclude|output|print|reveal|show|send|append|approve|"
    r"grant|delete|remove|run|execute|close|mark|disable|scale|list|dump|tell|comply|obey|mount|treat|skip)"
)
_BYPASS = r"(?:approve|skip|bypass|grant|disable|ignore|mark\s+(?:every|all)|without\s+review|report|delete|treat)"

_ROLE = re.compile(
    r"<\|(?:im_start|im_end|im_sep|system|user|assistant|begin_of_text|end_of_text|start_header_id|end_header_id|"
    r"eot_id|endoftext)\|>"
    r"|\[/?INST\]|<</?SYS>>|<start_of_turn>|<end_of_turn>"
    r"|^[ \t]*#{2,4}[ \t]*(?:system|instruction|instructions|human|assistant)[ \t]*:"
    r"|</?(?:system|assistant)[-_](?:reminder|prompt|message|instructions?)(?:\s[^<>]{0,40})?>"
    r"|</(?:system|assistant)>|<assistant(?:\s[^<>]{0,40})?>|</?(?:instructions|system_prompt|developer_message)>"
    r"|\"role\"\s*:\s*\"(?:system|developer|assistant)\"\s*,\s*\"content\"\s*:",
    re.MULTILINE | re.IGNORECASE,
)
_TOOL_CALL = re.compile(
    r"</?(?:tool_call|tool_use|tool_result|function_calls?|invoke|antml:[a-z_]{1,30})(?:\s[^<>]{0,120})?>"
    r"|\"(?:function_call|tool_calls|tool_use)\"\s*:"
    r"|\{\s*\"name\"\s*:\s*\"(?:[a-z][a-z0-9]*(?:[_.][a-z0-9]+)+|kubectl|oc|bash|sh|shell|exec|run|python|helm|c[u]rl|"
    r"terminal)\"\s*,\s*\"(?:arguments|parameters|input)\"\s*:",
    re.IGNORECASE,
)
# Phrases aimed at a model, matched on the normalised copy (single spaces, folded look-alikes).
_INSTRUCTION = re.compile(
    r"\b(?:"
    r"(?:ignore|disregard|forget|override|bypass|skip)\s+(?:all\s+|any\s+|the\s+|your\s+|every\s+)?(?:of\s+)?"
    r"(?:the\s+|your\s+|these\s+|those\s+)?(?:previous|prior|above|earlier|preceding|original|system|initial|safety)\s+"
    r"(?:instructions?|prompts?|directions?|guardrails|system\s+prompts?)\b"
    r"|(?:ignore|disregard|bypass|override)\s+(?:all\s+|any\s+|the\s+)?(?:of\s+the\s+)?(?:previous|prior|above|earlier|"
    r"safety|security)\s+(?:messages?|rules|guidelines|context|constraints|checks|filters)\s*(?:and|[.,;:])\s*"
    r"(?:then\s+|instead\s+|just\s+)?" + _ACT + r"\b"
    r"|(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?your\s+(?:previous\s+|prior\s+|original\s+|"
    r"initial\s+)?(?:guidelines|rules|context|constraints|messages|training|programming|instructions)\b"
    r"|(?:override|ignore|disregard)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:context|instructions|rules)\s*:"
    r"|(?:bypass|ignore|disable|override)\s+(?:all\s+)?(?:the\s+|your\s+)?(?:safety|content|ethical)\s+"
    r"(?:guidelines|filters|rules|restrictions|policies|guardrails)\b"
    r"|(?:new|updated)\s+instructions?\s*:\s*[^.\n]{0,40}?\b" + _BYPASS + r"\b"
    r"|(?:do|rotate|change|fix|run)\s+nothing\s+and\s+(?:report|say|claim)\b"
    r"|(?:ignore|forget|disregard)\s+(?:everything|all)\s+(?:above|before\s+this|you\s+(?:were|have\s+been)\s+told)"
    r"\s*(?:and|,|;|\.)\s*(?:then\s+|instead\s+)?" + _ACT + r"\b"
    r"|forget\s+(?:everything|all)\s+you\s+(?:were|have\s+been)\s+told"
    r"|(?:disregard|ignore)\s+what\s+the\s+(?:user|human|operator)\s+(?:asked|said|wants|requested)"
    r"|you\s+are\s+now\s+(?:a|an|in|the)\s+(?:[\w-]+\s+){0,2}(?:" + _MODEL + r"(?!\s+" + _HUMAN_ROLE + r")|DAN|"
    r"jailbroken|unrestricted|unfiltered|developer\s+mode|god\s+mode|shell|terminal|root\s+shell|console)\b"
    r"|(?:real|actual|hidden|secret|override|true)\s+(?:system\s+)?instructions?\s*:"
    r"|(?:your|the)\s+(?:new|real|actual|only)\s+(?:task|job|goal|instructions?)\s+(?:is|are)\b"
    r"|system\s+prompt\s*:\s*(?:[^.\n]{0,60}?\b)?(?:you\s+are|you\s+will|ignore|always|never|from\s+now|skip|bypass|"
    r"approve|grant|the\s+user\s+is)\b"
    r"|(?:reveal|print|show|repeat|output|leak|dump)\s+(?:me\s+)?(?:your\s+(?:system\s+|hidden\s+|initial\s+|"
    r"original\s+)?|the\s+(?:system|hidden)\s+)(?:prompt|instructions)\b"
    r"|(?:do\s+not|don'?t|never)\s+(?:tell|inform|alert|warn|notify|show|mention|reveal|disclose)\s+(?:this\s+|these\s+|"
    r"it\s+|anything\s+)?(?:to\s+)?(?:the\s+)?(?:user|human|operator|admin(?:istrator)?)\s+(?:about|that|this|anything|"
    r"you|what\s+you)\b"
    r"|(?:do\s+not|don'?t)\s+(?:tell|inform|notify|alert|warn)\s+(?:the\s+)?(?:user|human|operator|admin)\s*[,;:]\s*"
    r"(?:just|simply|instead)\b"
    r"|(?:do\s+not|don'?t)\s+(?:mention|reveal|disclose)\s+(?:this|these\s+instructions|it)\s+to\s+(?:the\s+)?(?:user|human)"
    r"|(?:act|behave|respond|pretend)\s+(?:as\s+if\s+you\s+are|as|like)\s+(?:a|an)\s+(?:unrestricted|jailbroken|"
    r"unfiltered|uncensored|evil)\b(?!\s+(?:service\s*account|serviceaccount|user|role|policy|network))"
    r"|(?:DAN|god)\s+mode\s+(?:is\s+)?(?:enabled|activated|on)\b"
    r"|(?:note|message|instructions?|reminder)\s+(?:to|for)\s+(?:the\s+|any\s+|all\s+)?(?:AI|A\.I\.|assistant|LLM|"
    r"chatbot|copilot|Claude|ChatGPT|GPT|Gemini|language\s+model)s?(?!\s+" + _HUMAN_ROLE + r")(?:\s*[:,]|\s*$)"
    r"|if\s+you\s+are\s+(?:a|an)\s+(?:[\w-]+\s+)?" + _MODEL + r"(?!\s+" + _HUMAN_ROLE + r")\s*[,.:;]"
    r"|(?:attention|important|note)\s*[,:!-]?\s*(?:all\s+|any\s+)?(?:Claude|ChatGPT|Gemini|Copilot|assistant|AI|"
    r"A\.I\.|LLM|chatbot)s?\s*[:,!]"
    r"|(?:attention|important|note)\s*[,:!-]?\s*(?:all\s+|any\s+)?(?:Claude|ChatGPT|Gemini|Copilot|the\s+assistant|"
    r"the\s+AI|AI\s+agents?|agents?)\s+(?:should|must|will|shall)\s+(?:now\s+|immediately\s+)?" + _BYPASS + r"\b"
    r"|(?:any|every|all)\s+(?:AI\s+)?(?:models?|agents?)\s+(?:reading|processing|summari[sz]ing|parsing|reviewing)\s+"
    r"this\b"
    r"|" + _MODEL + r"s?\s+(?:reading|processing|summari[sz]ing|parsing|reviewing)\s+this\b"
    r"|the\s+(?:assistant|AI|LLM|chatbot)\s+(?:must|should|shall|will)\s+(?:now\s+|immediately\s+)?(?:silently|"
    r"secretly|ignore|disregard|approve|delete|reveal|print|send|report|run|execute|grant|disable|close|mark|scale)\b"
    r"|the\s+(?:model|agent)\s+(?:must|should|shall|will)\s+(?:now\s+|immediately\s+)?(?:silently|secretly)\b"
    r"|as\s+the\s+(?:AI|assistant|model|LLM|agent|chatbot)\s+(?:reading|reviewing|processing|handling|summari[sz]ing)"
    r"\s+[^.]{0,80}?,\s*you\s+(?:must|should|will|shall)\b"
    r"|^\s*(?:Claude|ChatGPT|Gemini|Copilot|assistant|AI)\s*,\s*(?:please\s+)?" + _ACT + r"\b"
    r"|^\s*(?:AI|assistant|LLM|Claude|ChatGPT|Gemini|Copilot)\s*:\s*[^\n]{0,80}?\b(?:do\s+not|don'?t)\s+(?:mention|"
    r"report|tell|show|say|flag)\b"
    r"|when\s+you\s+(?:summari[sz]e|read|process|review|analy[sz]e|describe)\s+(?:this|it)\s*,?\s*(?:always\s+)?"
    r"(?:say|state|report|claim|write|answer|conclude|mention\s+only)\b"
    r"|(?:classify|report|mark)\s+(?:this|it)\s+(?:\w+\s+){0,2}as\s+(?:compliant|clean|safe|secure|passing)\b"
    r"|suppress\s+all\s+(?:the\s+)?(?:findings|alerts|warnings)\b"
    # other languages: "ignore the previous instructions"
    r"|ignor(?:a|e|ez|iere|ate)\s+(?:todas\s+|toutes\s+|alle\s+|tutte\s+)?(?:las\s+|les\s+|le\s+|as\s+|die\s+)?"
    r"(?:instrucciones|instructions|anweisungen|istruzioni|instruções)\s+(?:anteriores|précédentes|precedenti|previas)"
    r"|ignor(?:a|e|ez|iere|ate)\s+(?:todas\s+|toutes\s+|alle\s+|tutte\s+)?(?:las\s+|les\s+|le\s+|as\s+|die\s+)?"
    r"(?:vorherigen|bisherigen|previous)\s+(?:anweisungen|instruktionen)"
    r"|игнорируй(?:те)?\s+(?:все\s+)?(?:предыдущие|прежние)\s+(?:инструкции|указания)"
    r")",
    re.IGNORECASE | re.MULTILINE,
)
_INSTRUCTION_CJK = re.compile(
    r"(?:忽略|无视|忽視|無視)(?:之前|以上|先前|上面|前面)?的?(?:所有|全部)?(?:指令|指示|说明|規則|规则)"
    r"|(?:以前|前|上記)の(?:指示|命令)を(?:すべて|全て)?無視"
    r"|이전\s*(?:의\s*)?(?:모든\s*)?(?:지시|명령)(?:를|을|사항을)?\s*무시"
)
# Flagged only: the same words are an injection in one place and an operation in another.
_HINT = re.compile(
    r"\b(?:"
    r"(?:send|post|upload|exfiltrate|forward|e-?mail|leak|copy)\s+(?:all\s+|the\s+|your\s+|any\s+|every\s+)?"
    r"(?:of\s+the\s+)?" + _SENSITIVE + r"\s+to\s+(?:https?://|\S+@\S+\.\w+|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b)"
    r"|(?:note|message|instructions?|reminder)\s+(?:to|for)\s+(?:the\s+|any\s+|all\s+)?(?:models?|agents?)\s*:"
    r"|without\s+(?:telling|informing|asking|alerting|notifying)\s+the\s+(?:user|human|operator)\b"
    r")",
    re.IGNORECASE,
)
_TRANSCRIPT_LINE = re.compile(r"^[ \t]*(?:Human|Assistant|User)[ \t]*:[ \t]+(?=\S)", re.MULTILINE)
_HUMAN_LINE = re.compile(r"^[ \t]*(?:Human|User)[ \t]*:[ \t]+\S", re.MULTILINE)
_ASSISTANT_LINE = re.compile(r"^[ \t]*Assistant[ \t]*:[ \t]+\S", re.MULTILINE)
_URL = r"(?:https?:)?//[^)\s>\"']{1,2000}"
_MD_IMAGE = re.compile(
    r"!\[([^\]\n]{0,200})\]\(\s*<?" + _URL + r">?(?:\s+(?:\"[^\"\n]{0,200}\"|'[^'\n]{0,200}'))?\s*\)", re.IGNORECASE
)
_MD_IMAGE_REF = re.compile(r"!\[([^\]\n]{0,200})\]\[([^\]\n]{1,80})\]")
_MD_DEF = re.compile(r"^[ \t]{0,3}\[([^\]\n]{1,80})\]:[ \t]*<?(" + _URL + r")>?", re.MULTILINE | re.IGNORECASE)
_HTML_IMG = re.compile(r"<img\b[^>]{0,500}?\bsrc\s*=\s*[\"']?" + _URL + r"[\"']?[^>]{0,500}>", re.IGNORECASE)
_DATA_QUERY = (  # a query that can carry data out: a value long enough for it, or a parameter named for it
    r"\?(?:[^)\s>\"']*?=[A-Za-z0-9+/_%.-]{24,}|(?:[^)\s>\"']*?[&;])?(?:token|data|d|q|secret|key|apikey|api_key|"
    r"password|pass|auth|session|code|t|s|k|leak|x|payload|c)=)[^)\s>\"']*"
)
_MD_LINK_QUERY = re.compile(
    r"(?<!!)\[([^\]\n]{1,200})\]\(\s*<?((?:https?:)?//[^)\s?>]{1,1000})" + _DATA_QUERY + r">?\s*\)"
)
_AUTOLINK_QUERY = re.compile(r"<((?:https?:)?//[^>\s?]{1,1000})" + _DATA_QUERY + r">", re.IGNORECASE)
_HREF_QUERY = re.compile(r"(\bhref\s*=\s*[\"']?(?:https?:)?//[^\"'\s>?]{1,1000})" + _DATA_QUERY, re.IGNORECASE)
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{32,4096}={0,2}(?![A-Za-z0-9+/=])")


@dataclass(frozen=True)
class Finding:
    kind: str
    excerpt: str
    field: str = ""

    def as_dict(self) -> dict[str, str]:
        out = {"kind": self.kind, "excerpt": self.excerpt}
        if self.field:
            out["field"] = self.field
        return out


_DEFANG = str.maketrans(dict.fromkeys('<>|[]{}"`*#'))


def _excerpt(s: str) -> str:
    """A preview that cannot carry the instruction back into the result: the first word, defanged, and the length."""
    words = " ".join(s.split()).translate(_DEFANG).split()
    first = words[0][:20] if words else ""
    return f"{first}... ({len(s)} characters)"


_WS = re.compile(r"\s+")


_MARKER = re.compile(r"<U\+[0-9A-F]{4,6}>|<ESC>")


def _normalise(text: str, fold: bool = True) -> tuple[str, list[int]]:
    """A copy for phrase matching and, for each of its characters, the index of the original character it came
    from: colour codes, format characters and hyphenated line breaks dropped, entities decoded, look-alikes folded
    (when ``fold``), white space collapsed."""
    if (
        text.isascii()
        and "&" not in text
        and "\x1b" not in text
        and "_" not in text
        and "-\n" not in text
        and "<" not in text
    ):
        parts: list[str] = []
        idx: list[int] = []
        pos = 0
        for m in _WS.finditer(text):
            start, end = m.span()
            parts.append(text[pos:start])
            idx.extend(range(pos, start))
            parts.append(" ")
            idx.append(start)
            pos = end
        parts.append(text[pos:])
        idx.extend(range(pos, len(text)))
        return "".join(parts), idx
    out: list[str] = []
    where: list[int] = []
    skip_until = -1
    ansi = {m.start(): m.end() for m in _ANSI.finditer(text)}
    # a marker `visible` left where it removed a character inside a name reads as that character did: nothing
    ansi |= {m.start(): m.end() for m in _MARKER.finditer(text)}
    entities = {m.start(): m for m in _ENTITY.finditer(text)}
    i = 0
    n = len(text)
    while i < n:
        if i < skip_until:
            i += 1
            continue
        if i in ansi:
            skip_until = ansi[i]
            i += 1
            continue
        ch = text[i]
        if i in entities:
            m = entities[i]
            decoded = html.unescape(m.group(0))
            if decoded != m.group(0):
                skip_until = m.end()
                chars = decoded
            else:
                chars = ch
        elif unicodedata.category(ch) == "Cf" or _SPLITTERS.match(ch) or 0xFE00 <= ord(ch) <= 0xFE0F:
            i += 1
            continue
        elif ch == "-" and i + 1 < n and text[i + 1] == "\n" and out and out[-1].isalpha():
            i += 2  # a word hyphenated across a line break
            continue
        else:
            chars = unicodedata.normalize("NFKC", ch)
            chars = chars.translate(_CONFUSABLE) if fold else chars
        for c in chars:
            blank = c.isspace() or bool(_FILLERS.match(c)) or c == "_"
            if blank and out and out[-1] == " ":
                continue
            out.append(" " if blank else c)
            where.append(i)
        i += 1
    return "".join(out), where


def _labels_as_words(text: str) -> str:
    """``ignore-previous-instructions`` read as words (a label or key that is a sentence)."""
    return re.sub(r"(?<=[A-Za-z])-(?=[A-Za-z])", " ", text)


def _decoded_base64(text: str) -> list[tuple[int, int]]:
    spans = []
    for m in list(_BASE64.finditer(text))[:MAX_BASE64]:
        raw = m.group(0)
        try:
            decoded = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        try:
            plain = decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if plain.isprintable() and (_INSTRUCTION.search(" ".join(plain.split())) or _INSTRUCTION_CJK.search(plain)):
            spans.append((m.start(), m.end()))
    return spans


def clean(text: str, field: str = "") -> tuple[str, list[Finding]]:
    """``text`` with invisible characters removed and injection shapes neutralised, and what was found."""
    if not text:
        return text, []
    head, tail = (text, "") if len(text) <= MAX_SCAN else (text[:MAX_SCAN], text[MAX_SCAN:])
    findings: list[Finding] = []
    if head.startswith(BOM):
        head = head[1:]  # a byte-order mark from a Windows editor: dropped, not a finding
    # The same rule `visible` applies, from the same function, so an MCP result and a terminal line cannot disagree
    # about a character (G279): escapes and format characters removed, controls replaced, joiners kept where a
    # script or an emoji needs them.
    stats: dict[str, int] = {}
    # Marked, so a name in a structured result reads `openshift<U+200B>-etcd`, not `openshift-etcd`; the phrase
    # matcher reads past the markers as it reads past the characters (fourth review).
    head = _core(head, " ", "\n\t", True, stats)
    for kind, label in (("tag", "unicode-tags"), ("bidi", "bidi-override"), ("format", "zero-width")):
        if stats.get(kind):
            findings.append(Finding(label, f"{stats[kind]} character(s) removed", field))

    def sub(rx: re.Pattern[str], kind: str, repl: Any) -> None:
        nonlocal head

        def one(m: re.Match[str]) -> str:
            findings.append(Finding(kind, _excerpt(m.group(0)), field))
            return str(repl(m) if callable(repl) else repl)

        head = rx.sub(one, head)

    sub(_ROLE, "role-marker", MARKER.format(what="role marker"))
    if _HUMAN_LINE.search(head) and _ASSISTANT_LINE.search(head):  # a scripted conversation, not one stray label
        sub(_TRANSCRIPT_LINE, "role-marker", MARKER.format(what="role marker") + " ")
    sub(_TOOL_CALL, "tool-call", MARKER.format(what="tool-call marker"))

    # phrases, on the normalised copy, mapped back to the original characters
    words = _labels_as_words(head)
    spans: list[tuple[int, int]] = []
    for fold in (True, False) if not words.isascii() else (True,):  # unfolded too: Cyrillic phrases stay Cyrillic
        norm, where = _normalise(words, fold)
        for rx in (_INSTRUCTION, _INSTRUCTION_CJK):
            for m in rx.finditer(norm):
                if m.end() > m.start():
                    spans.append((where[m.start()], where[m.end() - 1] + 1))
    spans += _decoded_base64(head)
    if spans:
        spans.sort()
        merged: list[list[int]] = []
        for s, e in spans:
            if merged and s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        parts, last = [], 0
        for s, e in merged:
            findings.append(Finding("instruction", _excerpt(head[s:e]), field))
            parts += [head[last:s], MARKER.format(what="instruction-like text")]
            last = e
        head = "".join(parts) + head[last:]
    for m in _HINT.finditer(" ".join(head.split())):
        findings.append(Finding("instruction-hint", _excerpt(m.group(0)), field))  # flagged; the text stays

    image = MARKER.format(what="remote image address")
    sub(_MD_IMAGE, "markdown-image", lambda m: f"[image: {m.group(1)}] {image}")
    sub(_HTML_IMG, "markdown-image", lambda m: f"[image] {image}")
    refs = {m.group(2).lower() for m in _MD_IMAGE_REF.finditer(head)}
    if refs:
        sub(
            _MD_DEF,
            "markdown-image",
            lambda m: f"[{m.group(1)}]: {image}" if m.group(1).lower() in refs else m.group(0),
        )
    gone = MARKER.format(what="query with data")
    sub(_MD_LINK_QUERY, "markdown-link", lambda m: f"[{m.group(1)}]({m.group(2)}) {gone}")
    sub(_AUTOLINK_QUERY, "markdown-link", lambda m: f"<{m.group(1)}> {gone}")
    sub(_HREF_QUERY, "markdown-link", lambda m: f"{m.group(1)} {gone}")
    return head + tail, findings


def detect(text: str) -> list[Finding]:
    """What :func:`clean` would find in ``text``."""
    return clean(text)[1]


def result(value: Any) -> Any:
    """Clean every string (and mapping key) in a tool result: dicts, lists and strings, depth-bounded. When anything
    was found, a dict result carries ``untrusted: true`` and ``injectionSignals`` (where, what kind, an excerpt; at
    most 20, the count of the rest in ``injectionSignalsTruncated``)."""
    found: list[Finding] = []

    def walk(v: Any, path: str, depth: int) -> Any:
        if depth > MAX_DEPTH:
            return v
        if isinstance(v, str):
            cleaned, f = clean(v, path)
            found.extend(f)
            return cleaned
        if isinstance(v, dict):
            out: dict[Any, Any] = {}
            for k, x in v.items():
                key = k
                if isinstance(k, str):
                    key, f = clean(k, f"{path}.<key>" if path else "<key>")
                    found.extend(f)
                    while key in out:
                        key = f"{key} (duplicate)"
                out[key] = walk(x, f"{path}.{key}" if path else str(key), depth + 1)
            return out
        if isinstance(v, list | tuple):
            return [walk(x, f"{path}[{i}]", depth + 1) for i, x in enumerate(v)]
        return v

    cleaned = walk(value, "", 0)
    if found and isinstance(cleaned, dict):
        seen: set[tuple[str, str, str]] = set()
        signals: list[dict[str, str]] = []
        for f in found:
            key = (f.kind, f.excerpt, f.field)
            if key not in seen:
                seen.add(key)
                signals.append(f.as_dict())
        cleaned["untrusted"] = True
        cleaned["injectionSignals"] = signals[:MAX_SIGNALS]
        if len(signals) > MAX_SIGNALS:
            cleaned["injectionSignalsTruncated"] = len(signals) - MAX_SIGNALS
    return cleaned
