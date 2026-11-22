#!/usr/bin/env bash
# Run the gates CI runs on code, and NAME the ones this machine could not run.
#
# The header of this script used to say it ran "every gate CI runs on code". It did not: it ran eleven fewer,
# the coverage floor among them, and it passed four times in a row while CI failed -- on test (3.13), on
# helm-and-dogfood, and twice on main at a release commit. A gate that passes while the real gate fails is an
# absence reading as a pass, which is the defect this project exists to refuse, pointed at its own gate (G264).
#
# So: every step below is one CI runs. A step whose tool is missing here is not skipped quietly -- it is
# collected and printed at the end under NOT RUN, because "it did not run" is not "it passed". Exit status is
# 0 only if everything attempted passed; read it directly rather than through a pipe.
#
# Usage: scripts/check.sh           run the gates
#        scripts/check.sh --where   print which tree would be tested and stop; no gate is run
set -euo pipefail
case "${1:-}" in
  "" | --where) ;;
  *) echo "usage: scripts/check.sh [--where]" >&2; exit 2 ;;
esac

# ---- which tree is this? Decided from where this file IS, never from where it was called or what is installed.
# `pip install -e .` records ONE checkout, and every git worktree shares that site-packages. Until G346 nothing
# here set an import root, so from a worktree of this repository this script collected the worktree's tests and ran
# them against the main checkout's modules: 14 failed, 13 of them a branch's own new tests failing exactly as they
# fail without that branch's fix. That is G264 in a mirror -- a gate that FAILS while the code is right -- and it
# costs the same trust, because the first reading of it was "the fix is broken". The wrong tree was a working,
# slightly older copy of the same project, so nothing looked wrong except the answer.
#
# Followed through symlinks by hand: `readlink -f` is not on every macOS, and `dirname "$0"` on a symlink is the
# directory the LINK is in, which has no src/ beside it.
self="${BASH_SOURCE[0]}"
while [ -L "$self" ]; do
  link_dir="$(cd -P "$(dirname "$self")" && pwd)"
  self="$(readlink "$self")"
  case "$self" in /*) ;; *) self="$link_dir/$self" ;; esac
done
root="$(cd -P "$(dirname "$self")/.." && pwd)"
cd "$root"
py="${PYTHON:-python}"
[ -x .venv/bin/python ] && py=.venv/bin/python

# Absolute, and first. tests/conftest.py changes directory into tmp_path for every test, so a relative
# PYTHONPATH=src names nothing by the time a test spawns `python -m kube_noob`.
export PYTHONPATH="$root/src${PYTHONPATH:+:$PYTHONPATH}"

# imports_from PREFIX WHAT_DID_NOT_RUN PYTHON [ARG...]: stop unless that interpreter imports kube_noob from under
# PREFIX.
# Setting the variable is an intention; this is the measurement. An interpreter that does not honour it (a
# wrapper with its own PYTHONPATH, `-I`, a sitecustomize) would otherwise run every gate below on another tree
# and report the result as this one's.
imports_from() {
  local want="$1" unrun="$2" got
  shift 2
  got="$("$@" -c 'import os, kube_noob; print(os.path.realpath(kube_noob.__file__))' 2>&1)" \
    || got="nothing -- the import failed: $got"
  case "$got" in
    "$want"/*) printf '%s\n' "$got" ;;
    *)
      echo "check.sh: REFUSING TO RUN -- kube_noob would be imported from somewhere else." >&2
      echo "  expected under: $want" >&2
      echo "  imported from:  $got" >&2
      echo "  with:           $*" >&2
      echo "$unrun" >&2
      exit 1
      ;;
  esac
}
imported="$(imports_from "$root/src" \
  "No gate was run. A result from another tree is not a result for this one." "$py")"
echo "check.sh: testing $root (kube_noob from $imported)"
if [ "${1:-}" = "--where" ]; then
  echo "check.sh: --where only -- no gate was run, and this is not a pass."
  exit 0
fi

# installed CMD...: run something that drives a BUILT artifact (the wheel in its own venv, the plugin's locked
# environment, the air-gap install) without the import root above. With it, `"$w"/bin/kube-noob` would import
# src/ and the step that proves the wheel works would prove only that the source tree does.
installed() { env -u PYTHONPATH "$@"; }

notrun=()
need() { command -v "$1" >/dev/null 2>&1 || { notrun+=("$2 -- $1 is not installed"); return 1; }; }

# ---- ci/plugin: the generated copies and documents match the code they are generated from.
"$py" scripts/sync_plugin_server.py --check
"$py" scripts/ci_wrappers.py --check
"$py" scripts/permissions_doc.py --check
"$py" scripts/build_skill.py --check
"$py" scripts/safety_contract.py --check
"$py" scripts/compliance_doc.py --check
"$py" scripts/doc_numbers.py --check
"$py" scripts/fedramp_ksi.py --check
# Until 2026-11-15 these two ran in release.yml only, so a stale document blocked the release
# instead of the pull request that made it stale -- which is how the opentelemetry pin reached a
# pull request with an SBOM that did not list it (G298).
"$py" scripts/sbom.py --check
"$py" scripts/krew_manifest.py --check

# ---- ci/lint
"$py" -m ruff check src tests scripts skill
"$py" -m ruff format --check src tests scripts skill
"$py" -m mypy
if need pip-audit "ci/lint: pip-audit on requirements.lock"; then
  pip-audit -r requirements.lock --require-hashes --disable-pip --strict
fi

# ---- ci/test: the coverage floor is part of the gate, so run pytest the way CI runs it.
"$py" -m pytest --cov --cov-report=term-missing:skip-covered --cov-fail-under=80 -q
"$py" -m kube_noob selftest

# ---- ci/test: the wheel is built, installed clean, and driven -- none of which `pytest` touches.
rm -rf dist build
"$py" -m build >/dev/null
w="${TMPDIR:-/tmp}/kn-check-wheelenv"
rm -rf "$w" && "$py" -m venv "$w"
w="$(cd -P "$w" && pwd)"
installed "$w"/bin/pip install -q dist/*.whl
# The mirror of the check at the top: the wheel's interpreter must import the WHEEL, or the lines below test src/.
imports_from "$w" "The wheel was not driven, and nothing after this ran: it would have been src/ under its name." \
  installed "$w"/bin/python >/dev/null
installed "$w"/bin/kube-noob --version >/dev/null
installed "$w"/bin/kube-noob search "restricted-v2" --format json \
  | "$py" -c "import json,sys; assert json.load(sys.stdin)['results']"
# Written to a file and then grepped, exactly as CI does it. Piping into `grep -q` closes the pipe on the
# first match, `demo all` takes SIGPIPE, and `set -o pipefail` turns that into exit 141 -- a gate failing on
# its own plumbing rather than on the code. Do not make this clever.
d="${TMPDIR:-/tmp}/kn-check-demo.out"
( cd "${TMPDIR:-/tmp}" && installed "$w"/bin/kube-noob demo all > "$d" )
grep -q "kube-noob demo: Show and lock" "$d"
installed "$w"/bin/python -I scripts/e2e_mcp_offline.py "$w"/bin/kube-noob >/dev/null
# ---- ci/airgap: the same installed wheel, driven inside a network namespace with no interface (G294). CI installs
# it from a local wheel directory with --no-index first; here the venv above stands in for that install.
if unshare -rn true >/dev/null 2>&1; then
  installed scripts/airgap_check.sh checks "$w"/bin/kube-noob
else
  notrun+=("ci/airgap: scripts/airgap_check.sh checks -- unshare -rn is not permitted on this machine")
fi

# ---- ci/publishable
installed scripts/check_publishable.sh >/dev/null

# ---- ci/plugin: the plugin's lock, its own end-to-end run, and the formula against PyPI.
if need uv "ci/plugin: uv lock --check and the plugin dependency audit"; then
  uv lock --check --project plugin/kube-noob --default-index https://pypi.org/simple >/dev/null
  if need pip-audit "ci/plugin: pip-audit on the plugin's exported requirements"; then
    r="${TMPDIR:-/tmp}/kn-check-plugin-requirements.txt"
    uv export --project plugin/kube-noob --frozen --no-emit-project --format requirements-txt -o "$r" >/dev/null
    pip-audit -r "$r" --require-hashes --disable-pip --strict
    rm -f "$r"
  fi
fi
installed "$py" scripts/e2e_plugin.py >/dev/null
"$py" scripts/brew_formula.py --check >/dev/null

# ---- ci/plugin: OSCAL against the pinned NIST schema, and the guard that it ran rather than skipping.
if need npm "ci/plugin: OSCAL schema validation (ajv)"; then
  # The same pinned versions CI installs. Without this the validator is whatever ajv the tree happens to
  # carry, or none -- and `node scripts/json_schema_validate.mjs` would then fail on a missing module rather than
  # on the document, which is a gate failing for the wrong reason. node_modules/ is gitignored.
  npm install --no-save --no-audit --no-fund ajv@8.17.1 ajv-formats@3.0.1 ajv-draft-04@1.0.0 >/dev/null 2>&1
  o="${TMPDIR:-/tmp}/kn-check-oscal.json"
  "$py" -m kube_noob audit -f examples/insecure-deployment.yaml --platform openshift --version 4.22 \
    --oscal > "$o" || true
  node scripts/json_schema_validate.mjs tests/fixtures/oscal/oscal_assessment-results_schema.json "$o" >/dev/null
  # ci/plugin: the SARIF the gate hands to code scanning, against the OASIS schema rather than the URI it prints.
  g="${TMPDIR:-/tmp}/kn-check-gate.sarif.json"
  "$py" -m kube_noob gate -f examples/insecure-deployment.yaml --platform openshift --version 4.22 \
    --sarif "$g" --quiet >/dev/null 2>&1 || true
  node scripts/json_schema_validate.mjs tests/fixtures/sarif/sarif-schema-2.1.0.json "$g" >/dev/null
  out=$("$py" -m pytest tests/test_oscal.py tests/test_gate_sarif.py -q -rs 2>&1)
  if grep -q "ajv is not installed" <<<"$out"; then
    echo "a schema test SKIPPED" >&2
    exit 1
  fi
  grep -qE "[0-9]+ passed" <<<"$out"
fi

# ---- ci/helm-and-dogfood renders the chart and audits what it renders; there is no helm-free path to it.
need helm "ci/helm-and-dogfood: chart guards and the dogfood audit" || true

rm -rf "$w" dist build "$d"
echo "All checks passed!"
if [ ${#notrun[@]} -gt 0 ]; then
  echo
  echo "NOT RUN on this machine (${#notrun[@]}) -- this is not a pass, and CI still runs them:"
  printf '  - %s\n' "${notrun[@]}"
fi
