#!/usr/bin/env bash
# Requirements R1.4 and R1.5 on a kind cluster: a sealed private seed image, opened with a key from a Secret, makes a
# new pod answer ticket questions with no Jira egress (config.offline); a wrong key imports nothing and says so while
# the pod keeps serving; jira.sync off says the copy changes only with a newer seed; jira.sync on with intervalHours
# 48 schedules its first run at a random offset and then every 48 h.
# Usage: scripts/e2e_jira_seed_kind.sh <kube-noob image name:tag loaded in kind> <kind cluster name>
set -euo pipefail
trap 'echo "::error title=jira seed in kind::line $LINENO: $BASH_COMMAND"; kubectl -n kn-seed get pods,events 2>/dev/null | tail -30' ERR
image="$1"
cluster="${2:-kn}"
here="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
cd "$here"

python3 - "$work" <<'PY'
import sys
from pathlib import Path

from kube_noob.sources.corpus import write_shard
from kube_noob.sources.jira_snapshot import export_snapshot

work = Path(sys.argv[1])
data = work / "data"
base = {"sourceId": "jira:OCPBUGS", "license": "public, not redistributable", "redistributable": False,
        "issueType": "Bug", "status": "Closed", "retrievedAt": "2026-10-28T00:00:00Z", "updated": "2026-10-27T00:00:00Z"}
recs = [{**base, "id": f"jira-OCPBUGS-{i}", "title": f"OCPBUGS-{i}: pod restarts {i}",
         "text": f"Pod restarts in namespace team{i}", "resolution": "Done", "fixVersions": ["4.20.0"]}
        for i in range(1, 40)]
recs.append({**base, "id": "jira-OCPBUGS-900", "title": "OCPBUGS-900: router cannot load its certificate",
             "text": "## Description\n\nhaproxy: unable to load default certificate file\n\n## Comments\n\n"
                     "Comment (2026-07-01): This is expected behavior: the secret was malformed.",
             "resolution": "Not a Bug"})
write_shard(data, "jira-ocpbugs", recs)
export_snapshot(data, work / "jira-snapshot.tgz")
PY
umask 077
openssl rand -base64 32 > "$work/seed.key"
openssl rand -base64 32 > "$work/wrong.key"
mkdir -p "$work/ctx/dist/seed"
kube-noob corpus seal "$work/jira-snapshot.tgz" -o "$work/ctx/dist/seed/jira-snapshot.tgz.enc" --key-file "$work/seed.key"
cp Containerfile.seed "$work/ctx/"
docker build -q -f "$work/ctx/Containerfile.seed" -t kn-seed:ci "$work/ctx"
kind load docker-image kn-seed:ci --name "$cluster"

ns=kn-seed
kubectl create namespace "$ns"
kubectl -n "$ns" create secret generic kn-token --from-literal=token=ci-token
kubectl -n "$ns" create secret generic kn-seed-key --from-file=key="$work/seed.key"
kubectl -n "$ns" create secret generic kn-wrong-key --from-file=key="$work/wrong.key"
repo="${image%:*}"
tag="${image##*:}"
common=(
  --set "image.repository=${repo}" --set "image.tag=${tag}" --set image.pullPolicy=Never
  --set auth.existingSecret=kn-token --set networkPolicy.allowRouter=false
  --set networkPolicy.egress.dnsNamespace=kube-system --set networkPolicy.egress.dnsPort=53
)
seed=(
  --set jira.seed.source=image --set jira.seed.image.repository=kn-seed --set jira.seed.image.tag=ci
  --set jira.seed.path=/seed/jira-snapshot.tgz.enc
)
logs() { kubectl -n "$ns" logs "deploy/$1-kube-noob" -c kube-noob; }
fail() {
  echo "::error title=jira seed in kind::$*"
  # Pods and events say a container is backing off; only its log says why. This script is the one that actually
  # fails in e2e-kind, and it printed neither -- so three branches and main carried an undiagnosable red job.
  bash scripts/ci_pod_failure.sh "$ns" "jira seed in kind"
  exit 1
}

# 1. the right key: the copy is imported on start and answers with no egress at all (offline lock)
helm install good deploy/helm/kube-noob -n "$ns" "${common[@]}" "${seed[@]}" --set config.offline=true \
  --set jira.seed.keySecret.name=kn-seed-key --wait --timeout 4m \
  || fail "helm install good did not become ready"
logs good | tee "$work/good.log"
grep -q "jira seed imported from /var/lib/kube-noob/seed/jira-snapshot.tgz.enc: jira-ocpbugs" "$work/good.log" \
  || fail "the sealed seed was not imported with the right key"
grep -q "jira sync: off (the copy changes only when a newer seed is imported)" "$work/good.log" || fail "sync off not stated"
kubectl -n "$ns" exec deploy/good-kube-noob -c kube-noob -- kube-noob ticket OCPBUGS-900 --format json > "$work/ticket.json"
python3 -c "
import json, sys
t = json.load(open(sys.argv[1]))
assert t['found'] and t['verdict'] == 'not-a-bug', t
print('ticket answered offline:', t.get('id'), t['verdict'])
" "$work/ticket.json"
kubectl -n "$ns" get networkpolicy good-kube-noob -o jsonpath='{.spec.egress}' | grep -qv "443" \
  || fail "the offline release must not open HTTPS egress"
kubectl -n "$ns" get deploy good-kube-noob -o yaml | grep -q "KUBE_NOOB_SEED_KEY_FILE" || fail "key file env missing"
if kubectl -n "$ns" get deploy good-kube-noob -o yaml | grep -q "$(cat "$work/seed.key")"; then
  fail "the key must never appear in the Deployment"
fi

# 2. the wrong key: nothing is imported, the reason is logged, the pod still serves
helm install bad deploy/helm/kube-noob -n "$ns" "${common[@]}" "${seed[@]}" --set config.offline=true \
  --set jira.seed.keySecret.name=kn-wrong-key --wait --timeout 4m \
  || fail "helm install bad did not become ready"
logs bad | tee "$work/bad.log"
grep -q "jira seed not imported: the key does not open jira-snapshot.tgz.enc (a wrong key or a damaged file); nothing was imported" \
  "$work/bad.log" || fail "a wrong key must fail closed with a clear message"
if kubectl -n "$ns" exec deploy/bad-kube-noob -c kube-noob -- kube-noob ticket OCPBUGS-900 --format json \
  | python3 -c "import json, sys; sys.exit(0 if json.load(sys.stdin).get('found') else 1)"; then
  fail "a wrong key must import nothing"
fi

# 3. sync on, every 48 h: the schedule is stated at start; uninstalled before its first run (30 s at the earliest)
helm install sync deploy/helm/kube-noob -n "$ns" "${common[@]}" --set jira.sync.enabled=true \
  --set jira.sync.intervalHours=48 --set jira.sync.projects=OCPBUGS --set jira.sync.maxRequests=10 \
  --set persistence.enabled=true --set replicaCount=1
kubectl -n "$ns" get configmap sync-kube-noob -o yaml | grep -q "syncEnabled: true" || fail "syncEnabled not rendered"
kubectl -n "$ns" get configmap sync-kube-noob -o yaml | grep -q "intervalHours: 48" || fail "intervalHours not rendered"
for _ in $(seq 90); do
  if logs sync 2>/dev/null | grep -q "jira sync: first run in"; then break; fi
  sleep 1
done
logs sync | tee "$work/sync.log"
helm uninstall sync -n "$ns" --wait
grep -Eq "jira sync: first run in [0-9]+ s, then every 48 h \+/- 10%" "$work/sync.log" || fail "sync schedule not stated"
first=$(grep -Eo "first run in [0-9]+" "$work/sync.log" | grep -Eo "[0-9]+")
[ "$first" -ge 30 ] && [ "$first" -le 600 ] || fail "first run must be jittered between 30 s and 10 min, got $first"
echo "jira seed and sync in kind: ok"
