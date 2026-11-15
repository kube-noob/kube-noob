# Defect classes the adversarial reviews keep finding

Between 2026-11-10 and 2026-11-13, eleven branches went through thirty-odd read-only adversarial review rounds before
merging. The reviews confirmed about three hundred defects. Every branch had passed the full gate and had tests;
every defect was a shape the builder's tests had not tried. The defects fall into the classes below, which recur
across unrelated features because they are not about the feature — they are about how a careful author tests what
they built and not what they skipped.

This file is the durable form of the brief those reviews worked from. It is for whoever changes this repository
next, human or agent: before you call a change done, write one test per class that applies to it. The class-21 rule
is the one that closes most rounds: after every fix, try the neighbouring input before a reviewer does.

The product rule all of this serves: **an absence, an unknown or an unrecognised shape must never read as a pass, a
zero, or "complete"**. Verdicts are three-valued. What was not read or not evaluated is part of the answer, in the
text view and in JSON/YAML and in the MCP result alike.

## The classes

| # | Class | What it looked like | The test shape that holds it |
|---|---|---|---|
| 1 | A skipped input reads as complete | A file that could not be parsed, was empty, was a symlink, was over a size cap, or held no object of the expected kind was dropped and the verdict stayed complete, exit 0 | Every skip, at every layer, appears in the answer; a fixture per skip reason asserts the verdict is not "complete" |
| 2 | Truncation hides the worst item | Caps applied in arrival or alphabetical order cut the most severe finding; the summary was computed after the cut | Summaries from untruncated data; truncate lowest severity first; the withheld count stated in every format |
| 3 | Substring matching on errors or kinds | Any error containing "not found" read as "API not installed"; `kind` matched without its group | Match the backend's own whole line; require the group; a foreign kind of the same name is a different kind |
| 4 | An unrecognised value reads as the benign default | A missing `status`, an unknown phase, a YAML bool where a string was expected, a scalar where a list was expected → "healthy", "none", "no problem" | Unrecognised is not determined, with the field named |
| 5 | Duplicates and ordering | Two objects with one kind/namespace/name: one picked silently by sort or document order; output differed under shuffle | Conflicts flagged; canonical order before analysis; a shuffled-input test asserts identical bytes |
| 6 | The caveat exists only in JSON | Limitations and not-determined reasons missing from the text view, the diagram, or the sibling command that embeds the result | Parity test per format for every caveat field |
| 7 | Input-derived strings forge output | A newline in a path forged a row; invisible Unicode (U+061C, U+00AD, the tag block, bidi overrides) reached output | Every input-derived string through the one output boundary; hidden characters marked, never spliced |
| 8 | Docs claim what the code does not do | CHANGELOG and guidance stated behaviours later defects contradicted | Every doc sentence written after a test holds it; the guidance row cites that test |
| 9 | A second source of truth | A private copy of a list the audit already owned was a strict subset of it | Import the shared one; a test asserts there is one list |
| 10 | Tests that fail only in CI | Wall-clock ratios on a shared runner; a hostname substring tripping CodeQL; an identifier containing `secret` reaching print | Count operations, not time; compare whole tokens; name fields the way the module's neighbours do |
| 11 | The object asked about is not the object answered | A Pod anchor was answered from its owner's spec | Score the object the user named; a test with owner and pod disagreeing |
| 12 | Quadratic loops inside caps | An index rebuilt per item made a within-bounds input take minutes | A test at the cap with a time budget expressed as an operation count |
| 13 | The verdict word contradicts the counts | `complete: true, exit 0` with 0 of 30 items matched; `stored: true` for a record deleted in the same call; `satisfied` for a control whose only rule had nothing to look at; a score of 100 beside "containers were NOT audited" | One predicate decides the headline word and every renderer calls it; a test per renderer that the word agrees with the numbers beside it |
| 14 | A rule about an absent kind counts as evaluated and clean | No Pod in the input is not "pod security clean" | No subject → not evaluated; every rule declares its subjects and a static test checks the declaration against what the rule reads |
| 15 | A match tier hides what it did not match | "Named: 4 fixed bugs" while 17 open ones used another word for the same thing | Say what the matcher cannot see, per item; never present a partial match as the list |
| 16 | A crash, an empty stdout or a truncated document is read as an answer | Unexpected exceptions exiting 1; a reader that left mid-document getting a partial file and exit 0 | Unexpected exceptions exit 4; documents are written whole or not at all; a closed pipe is exit 141 |
| 17 | Untrusted text in fields that read as the tool's own words | Titles, messages, evidence and suggested commands built from input | Clean it, mark it, never build a command from it |
| 18 | A fixed, guessable delimiter, temp path or id | Heredoc terminators, `/tmp/name.txt`, sequential ids | Random delimiters; per-run directories; ids from a hash |
| 19 | A network-reachable endpoint with no time budget | One in-bounds request took a minute and starved the health check | A budget per request, enforced in a child the parent kills |
| 20 | A default that silently loses data across replicas or sessions | Per-pod storage behind a Service; a shared temp file between sessions | A test with two replicas or two sessions |
| 21 | Fixing the reported shape, not its neighbours | The fix covered the exact input in the report; the other wrapper, the other type, the other order still failed | After every fix, list the adjacent inputs and test each before calling it done |
| 22 | Parsing argv or flags without the real parser's rules | A value flag swallowed the next token; `$(VAR)` was a whole token; `--version` was taken for a server | Reuse the real parser's rules (pflag, cobra, the shell); test the documented corner cases of that parser |
| 23 | The container's own metadata is dropped while its contents are checked | A duplicate key on a `List` wrapper (its items were checked for duplicate keys); the same object under two must-gather directories (each file was checked); a payload's `truncatedAlerts` count (each alert was checked) | For every container shape, a test that a defect on the wrapper itself is reported |
| 24 | A refusal is read as an absence one layer up | `audit` refused an object and said so in an assumption line; `gate` read the empty result as "no pod spec in the input" and passed | A refused object makes the verdict undetermined in every command that embeds the result; the phrase "not in the input" is never printed for an object that was present |
| 25 | A fix applied to one surface, not its siblings | The score was withheld beside a declined rule, but not beside an unread pod spec or a refused group, which are the same kind of record | Fix the predicate, not the call site; grep every caller of the old predicate and test each |
| 26 | A limit set above the resource it protects | A daily cap of 80 licence mails against a quota of about 100, with a second form drawing on the same quota; a per-address hourly cap when the attacker has unlimited addresses | Caps expressed as a reserve of the shared resource, tested at the edge (the request that empties it) |

## How to use this file

- Before pushing: for each class that applies to your change, name the test that holds it. If none applies, say so
  in the commit message; a reviewer will check.
- After a review: the fix for every finding comes with its class-21 neighbours tested in the same commit.
- When a review finds a shape no class describes, add the class here with the one-line example and the test shape,
  in the same change as the fix. The number is stable; append, never renumber.

The G-rows in `docs/guidance.md` that correspond to the branches these classes came from: G270, G272, G273, G274,
G276, G277, G278, G279, G280, G281, G282.
