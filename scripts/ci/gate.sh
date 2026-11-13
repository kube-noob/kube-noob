#!/bin/sh
# kube-noob gate, as the three CI wrappers run it: action.yml calls this file; the Tekton Task and the GitLab
# template carry a copy of its body (scripts/ci_wrappers.py writes it, --check holds it). POSIX sh: no arrays,
# no brace or command substitution -- the Tekton copy runs through Tekton's own substitution of such text.
#
# Inputs, through the environment (the wrappers never splice a user value into this text):
#   KN_PATHS KN_CHART KN_VALUES KN_NAMESPACE KN_CONTAINERFILES KN_SCANNER_REPORTS KN_VEX KN_KEV
#   KN_TRUST_REPORT_VEX KN_SARIF_REPORTS KN_PLATFORM KN_VERSION KN_EXCEPTIONS KN_FAIL_ON KN_ANNOTATIONS
# Files it writes: KN_SARIF KN_SUMMARY KN_REPORT (the JSON report) KN_CODEQUALITY (GitLab), scratch in KN_WORK.
# Status, to every sink that is set, the same words in each:
#   GITHUB_OUTPUT        result= exit-code= evidence= because=
#   GITHUB_STEP_SUMMARY  the headline, then the gate's own summary
#   KN_DOTENV            KUBE_NOOB_RESULT KUBE_NOOB_EXIT KUBE_NOOB_EVIDENCE KUBE_NOOB_BECAUSE (GitLab dotenv report)
#   KN_RESULT_PATH KN_EXIT_PATH KN_EVIDENCE_PATH KN_BECAUSE_PATH KN_COUNTS_PATH (Tekton results)
# result is the exit code's name and nothing else: 0 passed, 1 failed, 2 config-error, 3 clarification,
# 4 internal-error, 5 evidence-incomplete; any other code is internal-error with its number in exit-code.
# evidence is read from the report: complete, incomplete (with because) or not-run -- a report that is missing,
# is not JSON or has no notRun list is not-run, never complete. Merge status is not evidence status: a gate
# that exits 0 with checks not run says "merge: allowed · evidence: incomplete", never "passed" (G291).
set -e
if [ -z "$KN_PLATFORM" ]; then KN_PLATFORM=kubernetes; fi
if [ -z "$KN_FAIL_ON" ]; then KN_FAIL_ON=high; fi
if [ -z "$KN_WORK" ]; then KN_WORK=.; fi
if [ -z "$KN_SARIF" ]; then KN_SARIF=kube-noob.sarif; fi
if [ -z "$KN_SUMMARY" ]; then KN_SUMMARY=kube-noob-summary.md; fi
if [ -z "$KN_REPORT" ]; then KN_REPORT=kube-noob-gate.json; fi
set -- --platform "$KN_PLATFORM" --fail-on "$KN_FAIL_ON"
if [ -n "$KN_NAMESPACE" ]; then set -- "$@" --namespace "$KN_NAMESPACE"; fi
for p in $KN_PATHS; do set -- "$@" -f "$p"; done
if [ -n "$KN_CHART" ]; then set -- "$@" --chart "$KN_CHART"; fi
for v in $KN_VALUES; do set -- "$@" --values "$v"; done
for c in $KN_CONTAINERFILES; do set -- "$@" --containerfile "$c"; done
for r in $KN_SCANNER_REPORTS; do set -- "$@" --scanner-report "$r"; done
for x in $KN_VEX; do set -- "$@" --vex "$x"; done
if [ -n "$KN_KEV" ]; then set -- "$@" --kev "$KN_KEV"; fi
if [ "$KN_TRUST_REPORT_VEX" = "true" ]; then set -- "$@" --trust-report-vex; fi
for s in $KN_SARIF_REPORTS; do set -- "$@" --sarif-report "$s"; done
if [ -n "$KN_VERSION" ]; then set -- "$@" --version "$KN_VERSION"; fi
if [ -n "$KN_EXCEPTIONS" ]; then set -- "$@" --exceptions "$KN_EXCEPTIONS"; fi
if [ -n "$KN_ANNOTATIONS" ] && [ "$KN_ANNOTATIONS" != "false" ]; then set -- "$@" --github-annotations; fi
set -- "$@" --sarif "$KN_SARIF" --summary "$KN_SUMMARY"
if [ -n "$KN_CODEQUALITY" ]; then set -- "$@" --codequality "$KN_CODEQUALITY"; fi
raw="$KN_WORK/kube-noob-gate.out"
status="$KN_WORK/kube-noob-gate-status"
rm -rf "$status"
mkdir -p "$status"
# A gate that exits 2 or 4 writes none of these; what an earlier step in the same job left behind must not be
# read, summarised or uploaded as this run's.
rm -f "$raw" "$KN_REPORT" "$KN_SUMMARY" "$KN_SARIF"
if [ -n "$KN_CODEQUALITY" ]; then rm -f "$KN_CODEQUALITY"; fi
# From here nothing may abort before the status is written: a step that dies between the gate and its outputs
# is exactly the empty `result` this script exists to refuse.
set +e
rc=0
kube-noob gate "$@" --format json > "$raw" || rc=$?
# Workflow commands and the JSON report both come out on stdout, so the stream is captured once and split: the
# `::` lines are echoed to the log, where Actions turns them into annotations, and the rest is the report.
grep '^::' "$raw" 2>/dev/null
grep -v '^::' "$raw" > "$KN_REPORT" 2>/dev/null
case "$rc" in
  0) result=passed ;;
  1) result=failed ;;
  2) result=config-error ;;
  3) result=clarification ;;
  4) result=internal-error ;;
  5) result=evidence-incomplete ;;
  *) result=internal-error ;;
esac
evidence=not-run
because="the gate report could not be read"
counts="{}"
python3 -I -c '
import json, sys
report, out = sys.argv[1], sys.argv[2]

def clean(text):
    # One printable line: control characters and anything invisible (bidi marks, soft hyphens, tags) are
    # dropped, whitespace is squeezed, and "::" cannot start a workflow command on the Actions log.
    flat = " ".join("".join(c if c.isprintable() else " " for c in str(text)).split())
    return flat.replace("::", ": :")[:600]

try:
    text = open(report, encoding="utf-8", errors="replace").read()
except OSError:
    text = ""
if not text.strip():
    evidence, because, counts = "not-run", "the gate wrote no report", {}
else:
    try:
        rep = json.loads(text)
    except ValueError:
        rep = None
    if rep is None:
        evidence, because, counts = "not-run", "the report is not JSON", {}
    elif not isinstance(rep, dict):
        evidence, because, counts = "not-run", "the report is not an object", {}
    elif not isinstance(rep.get("notRun"), list):
        evidence, because, counts = "not-run", "the report has no notRun list", {}
    else:
        gaps = [clean(g) for g in rep["notRun"]]
        for u in rep.get("unreadable") or []:
            if isinstance(u, dict):
                gaps.append(clean(u.get("file")) + " could not be read")
        if rep.get("knownIssuesVerdict") == "not-determined":
            gaps.append("reported issues: not-determined")
        if rep.get("requiredEvaluated") is False:
            gaps.append("required checks: not all evaluated")
        evidence = "incomplete" if gaps else "complete"
        because = "; ".join(gaps)
        counts = rep.get("counts") if isinstance(rep.get("counts"), dict) else {}
for name, value in (("evidence", evidence), ("because", clean(because)), ("counts", json.dumps(counts, sort_keys=True))):
    with open(out + "/" + name, "w", encoding="utf-8") as f:
        f.write(value + "\n")
' "$KN_REPORT" "$status" 2>/dev/null \
  && read -r evidence < "$status/evidence" \
  && read -r because < "$status/because" \
  && read -r counts < "$status/counts" \
  || { evidence=not-run; because="the gate report could not be read"; counts="{}"; }
if [ "$rc" = 0 ]; then
  headline="## kube-noob gate: merge allowed · evidence: $evidence"
else
  headline="## kube-noob gate $result (exit $rc): merge blocked · evidence: $evidence"
fi
if [ -n "$because" ]; then headline="$headline ($because)"; fi
# The gate's own Markdown starts "## kube-noob gate passed|failed"; that heading is replaced by the headline
# above, so "passed" never stands beside incomplete evidence. The rest of its summary follows unchanged.
printf '%s\n' "$headline" > "$status/summary.md"
first=
if [ -f "$KN_SUMMARY" ]; then read -r first < "$KN_SUMMARY" || true; fi
case "$first" in
  "## kube-noob gate passed"|"## kube-noob gate failed") tail -n +2 "$KN_SUMMARY" >> "$status/summary.md" ;;
  "") printf '\n' >> "$status/summary.md" ;;
  *) printf '\n' >> "$status/summary.md"; cat "$KN_SUMMARY" >> "$status/summary.md" ;;
esac
cat "$status/summary.md"
if [ -n "$GITHUB_STEP_SUMMARY" ]; then cat "$status/summary.md" >> "$GITHUB_STEP_SUMMARY"; fi
if [ -n "$GITHUB_OUTPUT" ]; then
  printf 'result=%s\nexit-code=%s\nevidence=%s\nbecause=%s\n' "$result" "$rc" "$evidence" "$because" >> "$GITHUB_OUTPUT"
fi
if [ -n "$KN_DOTENV" ]; then
  printf 'KUBE_NOOB_RESULT=%s\nKUBE_NOOB_EXIT=%s\nKUBE_NOOB_EVIDENCE=%s\nKUBE_NOOB_BECAUSE=%s\n' \
    "$result" "$rc" "$evidence" "$because" > "$KN_DOTENV"
fi
if [ -n "$KN_RESULT_PATH" ]; then printf '%s' "$result" > "$KN_RESULT_PATH"; fi
if [ -n "$KN_EXIT_PATH" ]; then printf '%s' "$rc" > "$KN_EXIT_PATH"; fi
if [ -n "$KN_EVIDENCE_PATH" ]; then printf '%s' "$evidence" > "$KN_EVIDENCE_PATH"; fi
if [ -n "$KN_BECAUSE_PATH" ]; then printf '%s' "$because" > "$KN_BECAUSE_PATH"; fi
if [ -n "$KN_COUNTS_PATH" ]; then printf '%s' "$counts" > "$KN_COUNTS_PATH"; fi
exit "$rc"
