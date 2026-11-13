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
# Usage: scripts/check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
py="${PYTHON:-python}"
[ -x .venv/bin/python ] && py=.venv/bin/python

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

# ---- ci/lint
"$py" -m ruff check src tests scripts skill
"$py" -m ruff format --check src tests scripts skill
"$py" -m mypy src
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
"$w"/bin/pip install -q dist/*.whl
"$w"/bin/kube-noob --version >/dev/null
"$w"/bin/kube-noob search "restricted-v2" --format json \
  | "$py" -c "import json,sys; assert json.load(sys.stdin)['results']"
# Written to a file and then grepped, exactly as CI does it. Piping into `grep -q` closes the pipe on the
# first match, `demo all` takes SIGPIPE, and `set -o pipefail` turns that into exit 141 -- a gate failing on
# its own plumbing rather than on the code. Do not make this clever.
d="${TMPDIR:-/tmp}/kn-check-demo.out"
( cd "${TMPDIR:-/tmp}" && "$w"/bin/kube-noob demo all > "$d" )
grep -q "kube-noob demo: Show and lock" "$d"
"$w"/bin/python -I scripts/e2e_mcp_offline.py "$w"/bin/kube-noob >/dev/null

# ---- ci/publishable
scripts/check_publishable.sh >/dev/null

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
"$py" scripts/e2e_plugin.py >/dev/null
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
