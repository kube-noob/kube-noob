#!/bin/sh
# Air-gap verification as a transcript, not a claim (G294).
#
#   scripts/airgap_check.sh prepare <wheel-dir>        with network: download the dependency wheels requirements.lock
#                                                      pins (hashes checked) and copy dist/kube_noob-*.whl there
#   scripts/airgap_check.sh verify  <wheel-dir>        no network: inside `unshare -rn`, install from <wheel-dir> only
#                                                      (--no-index) into a fresh venv, then run the checks below
#   scripts/airgap_check.sh checks  <kube-noob>        no network: the checks alone, against an installed kube-noob
#
# The network proof first -- a DNS lookup and a TCP connect must both fail, or the run stops -- then four checks,
# each with the exit code it must return: `doctor` (0), `audit -f insecure-deployment.yaml` (1: findings at high),
# `must-gather analyze` on the bundled sample (0), and one MCP request (`tools/list`) over stdio (0). What
# this establishes: with the wheels already on local disk, the install and these four workflows need no network and
# attempt none that could succeed. What it does not: how the wheels got there (a mirrored index, a signed bundle, a
# verified `gh attestation verify` are the operator's steps), anything a check does not exercise, and -- without
# strace -- an attempt that was made, failed and was swallowed silently (the namespace makes every attempt fail;
# it cannot see one that was tolerated). Exit: 0 every check passed, 1 a check failed, 2 the run could not start.
set -eu

usage() {
  sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
}

say() { printf '%s\n' "$*"; }
die() { printf 'airgap_check: %s\n' "$*" >&2; exit 2; }

here="$(cd "$(dirname "$0")/.." && pwd)"
work=""
need_work() {
  # One scratch directory for the venv, the sample and the logs: KN_AIRGAP_WORK, or a fresh mktemp one (never a
  # fixed, guessable path). Exported so the re-exec inside the namespace writes to the same place.
  if [ -z "$work" ]; then
    work="${KN_AIRGAP_WORK:-}"
    if [ -z "$work" ]; then work="$(mktemp -d "${TMPDIR:-/tmp}/kn-airgap.XXXXXX")"; else mkdir -p "$work"; fi
    KN_AIRGAP_WORK="$work"
    export KN_AIRGAP_WORK
  fi
}

prepare() {
  dir="$1"
  mkdir -p "$dir"
  py="${PYTHON:-python3}"
  # Binary wheels only, hashes from the lock: what an operator mirrors is exactly this set.
  "$py" -m pip download --disable-pip-version-check --quiet --only-binary=:all: --require-hashes \
    -r "$here/requirements.lock" -d "$dir"
  set -- "$here"/dist/kube_noob-*.whl
  [ -f "$1" ] || die "no dist/kube_noob-*.whl to copy: build it first (python -m build)"
  cp "$@" "$dir/"
  say "prepared $dir: $(ls "$dir" | wc -l | tr -d ' ') wheels"
}

# -- the network proof and the checks run INSIDE the namespace -------------------------------------------------

probe_network() {
  py="$1"
  # Both must fail. A success means the namespace did not take, and nothing below would prove anything.
  if "$py" -I -c 'import socket; socket.getaddrinfo("pypi.org", 443)' >/dev/null 2>&1; then
    say "FAIL network: a DNS lookup succeeded; this is not a network-disabled environment"
    return 1
  fi
  if "$py" -I -c 'import socket; socket.create_connection(("127.0.0.1", 9), timeout=2)' >/dev/null 2>&1; then
    say "FAIL network: a TCP connect succeeded; this is not a network-disabled environment"
    return 1
  fi
  say "network: disabled (DNS lookup and a connect both failed inside unshare -rn)"
}

check() {
  # check <label> <expected exit> <command...>: runs it, keeps the output in the work dir, prints one line.
  label="$1"; want="$2"; shift 2
  log="$work/$(printf '%s' "$label" | tr -c 'A-Za-z0-9._-' '_').log"
  got=0
  "$@" >"$log" 2>&1 || got=$?
  if [ "$got" = "$want" ]; then
    say "ok    $label: exit $got"
    return 0
  fi
  say "FAIL  $label: expected exit $want, got $got (output in $log)"
  return 1
}

mcp_one_request() {
  # One JSON-RPC exchange over stdio with the installed server: initialize, initialized, tools/list. The reply must
  # name the audit tool. No MCP client library is needed, so this runs on the bare install.
  exe="$1"; py="$2"
  "$py" -I - "$exe" <<'PY'
import json, subprocess, sys, time
exe = sys.argv[1]
p = subprocess.Popen([exe, "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
deadline = time.monotonic() + 120


def send(msg):
    p.stdin.write(json.dumps(msg) + "\n")
    p.stdin.flush()


def wait_for(want_id):
    # Read replies until the one with this id: stdin stays open meanwhile, so the server is not shut down by EOF
    # while it is still answering (the first version closed stdin after writing and lost the reply on a slow box).
    while time.monotonic() < deadline:
        line = p.stdout.readline()
        if not line:
            return None
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if d.get("id") == want_id:
            return d
    return None


send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18",
      "capabilities": {}, "clientInfo": {"name": "airgap-check", "version": "0"}}})
init = wait_for(1)
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
reply = wait_for(2)
p.stdin.close()
try:
    p.wait(timeout=30)
except subprocess.TimeoutExpired:
    p.kill()
tools = [t["name"] for t in (reply or {}).get("result", {}).get("tools", [])]
if not init or not tools or not any(t == "audit" or t.endswith("_audit") for t in tools):
    print("no tools/list reply naming the audit tool; initialize:", bool(init), "stderr:", p.stderr.read()[-800:])
    sys.exit(1)
print(f"{len(tools)} tools listed over stdio, among them the audit tool")
PY
}

checks() {
  exe="$1"
  [ -x "$exe" ] || die "not an executable kube-noob: $exe"
  bindir="$(cd "$(dirname "$exe")" && pwd)"
  py="$bindir/python3"
  [ -x "$py" ] || py="$bindir/python"
  [ -x "$py" ] || die "no python next to $exe (a venv's bin directory is expected)"
  export HOME="$work/home" KUBE_NOOB_DATA_DIR="$work/data" XDG_CONFIG_HOME="$work/home"
  mkdir -p "$HOME" "$KUBE_NOOB_DATA_DIR"
  failed=0
  probe_network "$py" || failed=1
  if [ "$failed" = 1 ]; then
    say "FAIL: the network proof failed, so no check below would prove anything; nothing run"
    return 1
  fi
  example="$("$py" -I -c 'import kube_noob, pathlib; print(pathlib.Path(kube_noob.__file__).parent / "data" / "examples" / "insecure-deployment.yaml")')"
  [ -f "$example" ] || example="$here/examples/insecure-deployment.yaml"
  "$py" -I -c 'import sys, pathlib; from kube_noob.mustgather.sample import write; write(pathlib.Path(sys.argv[1]))' "$work/mg"
  check "doctor" 0 "$exe" doctor || failed=1
  check "audit insecure-deployment.yaml" 1 "$exe" audit -f "$example" || failed=1
  check "must-gather analyze" 0 "$exe" must-gather analyze "$work/mg/must-gather.tar.gz" || failed=1
  check "mcp tools/list" 0 mcp_one_request "$exe" "$py" || failed=1
  if [ "$failed" = 0 ]; then
    say "PASS: network proof + 4 checks; no network attempt could have succeeded (unshare -rn: no interface, no route)"
    return 0
  fi
  say "FAIL: see the lines above; logs in $work"
  return 1
}

install_and_check() {
  dir="$1"
  py="${PYTHON:-python3}"
  venv="$work/venv"
  rm -rf "$venv"
  "$py" -m venv "$venv"
  # --no-index: the directory is the only source; --require-hashes: the lock decides what may be installed.
  "$venv/bin/pip" install --disable-pip-version-check --quiet --no-index --find-links "$dir" --only-binary=:all: \
    --require-hashes -r "$here/requirements.lock" \
    || { say "FAIL  install dependencies from $dir (requirements.lock, --no-index)"; return 1; }
  one_wheel "$dir"
  set -- "$dir"/kube_noob-*.whl
  "$venv/bin/pip" install --disable-pip-version-check --quiet --no-index --no-deps "$1" \
    || { say "FAIL  install $1 (--no-index --no-deps)"; return 1; }
  say "ok    installed $(basename "$1") and $(ls "$dir" | wc -l | tr -d ' ') wheels from $dir with --no-index"
  checks "$venv/bin/kube-noob"
}

in_namespace() {
  # Re-run this script inside a user+network namespace with no interface but a down loopback. The namespace is
  # the proof: a command that reaches for the network fails there, loudly. The interpreter and the work directory
  # travel as absolute paths in the environment, so the copy inside the namespace (root's PATH under sudo included)
  # uses the same ones.
  self="$here/scripts/airgap_check.sh"
  PYTHON="$(command -v "${PYTHON:-python3}" || true)"
  [ -n "$PYTHON" ] || die "no python3 on PATH (set PYTHON)"
  export PYTHON
  # `unshare` itself first: without it the sudo path below died in `env: unshare: No such file` with exit 127
  # instead of this script's own refusal (review finding 11b).
  unshare="$(command -v unshare || true)"
  [ -n "$unshare" ] \
    || die "cannot create a network namespace here (no unshare on PATH): not run, which is not a pass"
  if "$unshare" -rn true >/dev/null 2>&1; then
    exec "$unshare" -rn "$self" "$@"
  fi
  if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    say "note: unshare -rn is not permitted for this user; running inside sudo unshare -n (as root)"
    exec sudo -n env "PYTHON=$PYTHON" "KN_AIRGAP_WORK=$work" "PATH=$PATH" "$unshare" -n "$self" "$@"
  fi
  die "cannot create a network namespace here (unshare -rn refused, no passwordless sudo): not run, which is not a pass"
}

one_wheel() {
  # Exactly one kube_noob wheel in the directory: two would install the first silently (review finding 11c).
  dir="$1"
  set -- "$dir"/kube_noob-*.whl
  [ -f "$1" ] || die "no kube_noob-*.whl in $dir (run: scripts/airgap_check.sh prepare $dir)"
  if [ $# -gt 1 ]; then
    names=""
    for w in "$@"; do names="$names $(basename "$w")"; done
    die "expected one kube_noob wheel in $dir, found $#:$names; keep the one to verify"
  fi
}

cmd="${1:-}"
case "$cmd" in
  -h|--help|help|"") usage; [ -n "$cmd" ] || exit 2; exit 0 ;;
  prepare|verify|checks|--inner-verify|--inner-checks) need_work ;;
  *) die "unknown command: $cmd (prepare, verify, checks)" ;;
esac
case "$cmd" in
  prepare) [ $# -ge 2 ] || die "usage: prepare <wheel-dir>"; prepare "$2" ;;
  verify)
    [ $# -ge 2 ] || die "usage: verify <wheel-dir>"
    dir="$2"
    [ -d "$dir" ] || die "no such directory: $dir"
    one_wheel "$dir"
    in_namespace --inner-verify "$dir"
    ;;
  --inner-verify) install_and_check "$2" ;;
  checks) [ $# -ge 2 ] || die "usage: checks <kube-noob>"; in_namespace --inner-checks "$2" ;;
  --inner-checks) checks "$2" ;;
esac
