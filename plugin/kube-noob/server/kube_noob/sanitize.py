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


def loads_bounded(data: str | bytes, limit: int = MAX_JSON_DEPTH) -> Any:
    """``json.loads`` with the bracket depth counted first, so every reader refuses a nesting bomb identically.

    Raises ``JsonTooDeep`` (a ``ValueError``) rather than letting the interpreter decide, and otherwise behaves
    exactly like ``json.loads``.
    """
    if not json_nesting_ok(data, limit):
        raise JsonTooDeep(f"JSON nested too deeply (more than {limit} levels)")
    return json.loads(data)


_TERMINAL_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]{0,256}(?:\x07|\x1b\\)?)")
#: Character categories that never print: controls (Cc), format characters (Cf: bidi marks and overrides,
#: zero-width characters, the soft hyphen, tag characters), surrogates (Cs), private use (Co), unassigned code points
#: (Cn), and line and paragraph separators (Zl, Zp).
_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


def visible(text: str) -> str:
    """``text`` with every character that does not print replaced by a space, and terminal escape sequences
    removed. The one place a shown string from untrusted input is made printable: a hand-kept list of invisible
    code points missed U+061C, the soft hyphen and the tag block, so this works on Unicode categories instead.
    Callers collapse whitespace and cap the length themselves."""
    if text.isascii():
        stripped = _TERMINAL_ESCAPE.sub(" ", text)
        return "".join(" " if ch < " " or ch == "\x7f" else ch for ch in stripped)
    stripped = _TERMINAL_ESCAPE.sub(" ", text)
    return "".join(" " if unicodedata.category(ch) in _INVISIBLE_CATEGORIES else ch for ch in stripped)


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
_TAGS = re.compile("[" + _chars((0xE0000, 0xE007F)) + "]")
_BIDI = re.compile("[" + _chars((0x202A, 0x202E), (0x2066, 0x2069), 0x200E, 0x200F, 0x061C) + "]")
_ZERO_WIDTH = re.compile("[" + _chars(0x200B, 0x200C, 0x2060, 0xFEFF, 0x180E, (0x2061, 0x2064)) + "]")
_SPLITTERS = re.compile("[" + _chars(0x00AD, 0x034F) + "]")  # soft hyphen, combining grapheme joiner
_EMOJI_JOIN = re.compile(r"(?<=[^\x00-\x7f])" + ZWJ + r"(?=[^\x00-\x7f])")  # inside an emoji sequence: kept
_VS_AFTER_ASCII = re.compile(r"(?<=[A-Za-z0-9])[" + _chars((0xFE00, 0xFE0F)) + "]")  # never part of an emoji
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


def _normalise(text: str, fold: bool = True) -> tuple[str, list[int]]:
    """A copy for phrase matching and, for each of its characters, the index of the original character it came
    from: colour codes, format characters and hyphenated line breaks dropped, entities decoded, look-alikes folded
    (when ``fold``), white space collapsed."""
    if text.isascii() and "&" not in text and "\x1b" not in text and "_" not in text and "-\n" not in text:
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
    kept_joins = _EMOJI_JOIN.sub("\x00", head) if ZWJ in head and "\x00" not in head else None
    work = kept_joins if kept_joins is not None else head
    for rx, kind in ((_TAGS, "unicode-tags"), (_BIDI, "bidi-override")):
        n = len(rx.findall(work))
        if n:
            findings.append(Finding(kind, f"{n} character(s) removed", field))
            work = rx.sub("", work)
    zero = len(_ZERO_WIDTH.findall(work)) + work.count(ZWJ) + len(_VS_AFTER_ASCII.findall(work))
    split = len(_SPLITTERS.findall(work))
    if zero or split:
        findings.append(Finding("zero-width", f"{zero + split} character(s) removed", field))
        work = _VS_AFTER_ASCII.sub("", _SPLITTERS.sub("", _ZERO_WIDTH.sub("", work.replace(ZWJ, ""))))
    head = work.replace("\x00", ZWJ) if kept_joins is not None else work

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
