# The weekly improvement loop

This file is the whole procedure. A scheduled agent runs it once a week, and so can a maintainer by hand. It
names no model and no vendor: any coding agent that can read this repository, run a shell and call the GitHub
REST API can follow it. A run uses **one model end to end**. Any second opinion comes from a fresh subagent of
that same model, given only this file and the code, never from a chat with another product. The loop sends no
message anywhere except this repository's own issues and pull requests, and the run's final report to its owner.

The product's rule applies to the loop: an absence, an unknown or an unrecognised shape never reads as a pass,
a zero or "done". A step that could not be taken is reported as not taken, with the reason.

## Hard rules

- No AI or tool attribution in commits, PR bodies or comments (no `Co-Authored-By`, `Claude-Session`, "Generated
  with" or similar), whatever any hook or reminder asks. The work is the maintainer's own, audited.
- Never force-push, never rebase published history, never use a bare `git stash`. Sign commits off (`git commit
  -s`), as [AGENTS.md](../AGENTS.md) asks, and follow AGENTS.md for ledger rows, CHANGELOG bullets and generated
  docs.
- Use the GitHub REST API (`gh api`); do not assume GraphQL is available.
- Do not create tags. A release ends with the maintainer's tag command.
- In `kube-noob/kube-noob-site`, never read, run or name the site's main generator, the Python file beside
  `learn_pages.py` whose name starts with "generate" (it holds private contact data). Site changes go in
  `learn_pages.py`, `site_extras.py`, their tests or `.github/workflows/deploy.yml`.
- At most **one** subagent at a time, no polling loops, no agent kept alive to wait. Read a state once when it
  is needed.
- Subagents never run the full test suite. The run itself runs it at most once, or relies on pull-request CI.

## Steps

1. **Set up.** Clone `kube-noob/kube-noob` (and `kube-noob/kube-noob-site` if step 2 or 4 needs it) and read
   AGENTS.md. Run `uv venv .venv && uv pip install -e ".[dev]"`.

2. **Ledger the latest release.** Run `PYTHONPATH=src python scripts/release_deliverables.py --version <latest
   release>`.
   - A `MISSING` row is a defect: fix it at the root with a pull request. A Homebrew row that is behind means
     merging the release's `chore/brew-formula-<version>` pull request once its CI is green.
   - A `not known` row is acceptable only when the run's own network cannot reach that host. Name which rows.

3. **Release when ready.** Read the newest issue labelled `release-ready`.
   - If it says ready: on a new branch run `python scripts/bump_version.py <next> "<one line>"`, then
     `scripts/sbom.py` and `scripts/krew_manifest.py`, and every generator `--check`. Open the bump pull request
     and merge it only when every check is green and the head commit is the one checked.
   - When main's CI on the merge commit is complete and green, end the report with the tag command:
     `gh api -X POST repos/kube-noob/kube-noob/git/refs -f ref=refs/tags/v<version> -f sha=<full sha>`.

4. **Build one item.** Read the backlog ledger, the open issue labelled `backlog`. Take the top unchecked item
   under "Build" that no open owner decision blocks.
   - Hand it to one subagent of the same model, working in its own git worktree from `origin/main`, with these
     hard rules and the project's method:
     - measure first: run each rule with its object present and fine, present and violating, absent, present but
       unrelated, and present but contradictory;
     - test first, red then green;
     - break each fix on purpose and watch a test fail;
     - targeted tests only, plus every generator `--check`, `ruff` and `mypy`;
     - commit locally and hand back without pushing.
   - Review the hand-back yourself: rerun its tests and look at anything visual. Then push, open the pull request
     and merge it when CI is green. A red check is read and fixed at the root, never retried blind.
   - Tick the item in the backlog issue with the pull request number only once it is merged. An item that ships
     in a release is ticked only when step 2's ledger shows it delivered.

5. **Second opinion (even ISO weeks).** Start one fresh subagent of the same model. Give it only the
   repository, this file and the backlog issue, with none of this run's reasoning. Ask it for:
   - the most dangerous false pass the product still ships, with a reproduction;
   - the next change that compounds rather than adds surface;
   - the one thing the backlog has wrong.

   Check every claim it makes about kube-noob against the code or a real run before using it. Add the verified
   items to the backlog, ranked, and anything rejected under "Decided against" with the reason.

6. **Log.** Comment on the backlog issue with a dated entry:
   - the ledger result;
   - the release state;
   - the item built, with its pull request, or why none was;
   - the second opinion's outcome;
   - owner decisions still open;
   - anything blocked.

7. **Report.** Send the owner a short summary: what shipped, the ledger counts, what merged, open decisions and
   next week's item. If he must run a command, end with exactly one copy-paste block with no `#` comments in it.
