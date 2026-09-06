#!/usr/bin/env bash
# Incident Lab injection harness: drives one real fault scenario against one
# kernel/topology matrix cell over SSH, fetches whatever cognitod captured,
# and stamps it with the ground truth only this script (not cognitod) knows.
#
# Transport is plain ssh/scp, not SSM: the point of this run is getting
# episode JSON files back to the laptop, and SSM would need an S3 hop or a
# port-forward tunnel to move files at all, for no benefit over the ssh
# access the module already provisions (key_name/admin_cidr_blocks).
#
# Usage:
#   ./inject.sh <cell-name> <host> <ssh-key-path> <scenario> <output-dir>
#
# scenario is one of: fork_storm | cpu_noisy_neighbor | short_job_churn
# (see injection.rs -- these are the only scenarios with a single-culprit
# shape xtask-lab's scorer can grade).
set -euo pipefail

CELL_NAME=$1
HOST=$2
KEY_PATH=$3
SCENARIO=$4
OUT_DIR=$5

INJECT_DURATION_SECONDS="${INJECT_DURATION_SECONDS:-120}"

case "$SCENARIO" in
    fork_storm) SCENARIO_FILE="fork-storm.yaml" ;;
    cpu_noisy_neighbor) SCENARIO_FILE="cpu-noisy-neighbor.yaml" ;;
    short_job_churn) SCENARIO_FILE="short-job-churn.yaml" ;;
    *)
        echo "unknown scenario: $SCENARIO (expected fork_storm, cpu_noisy_neighbor, or short_job_churn)" >&2
        exit 1
        ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH="ssh -i $KEY_PATH -o StrictHostKeyChecking=accept-new ubuntu@$HOST"
SCP="scp -i $KEY_PATH -o StrictHostKeyChecking=accept-new"
KUBECTL="sudo /usr/local/bin/k3s kubectl"

echo "=== [$CELL_NAME] ensuring victim namespace/pod ==="
$SSH "$KUBECTL apply -f -" < "$SCRIPT_DIR/scenarios/namespace.yaml"
$SSH "$KUBECTL wait --for=condition=Ready pod/payment-api -n prod --timeout=120s"

echo "=== [$CELL_NAME] snapshotting episode dir before injection ==="
BEFORE=$($SSH "sudo ls /var/lib/linnix/episodes 2>/dev/null || true")

echo "=== [$CELL_NAME] injecting $SCENARIO ==="
$SSH "$KUBECTL apply -f -" < "$SCRIPT_DIR/scenarios/$SCENARIO_FILE"

# From here on the offender is live on the cell. A Ctrl-C (or any failure)
# during the sleep below would otherwise exit under set -e and leave it
# running -- a later run of a different scenario only applies/deletes its
# own manifest, so the stray offender keeps faulting the victim underneath
# the new capture while every new episode gets stamped with the new
# scenario's ground truth, silently corrupting the corpus. The trap deletes
# the same manifest on any exit path; it's disarmed right after the normal
# delete below so that expected path doesn't run it twice.
CLEANUP_ARMED=1
cleanup_offender() {
    if [ "$CLEANUP_ARMED" = "1" ]; then
        echo "=== [$CELL_NAME] cleanup: deleting offender pods for $SCENARIO ===" >&2
        $SSH "$KUBECTL delete -f -" < "$SCRIPT_DIR/scenarios/$SCENARIO_FILE" || true
    fi
}
trap cleanup_offender EXIT INT TERM

echo "=== [$CELL_NAME] letting the fault run for ${INJECT_DURATION_SECONDS}s ==="
sleep "$INJECT_DURATION_SECONDS"

echo "=== [$CELL_NAME] tearing down the offender pods ==="
$SSH "$KUBECTL delete -f -" < "$SCRIPT_DIR/scenarios/$SCENARIO_FILE"
CLEANUP_ARMED=0

echo "=== [$CELL_NAME] diffing episode dir after injection ==="
AFTER=$($SSH "sudo ls /var/lib/linnix/episodes 2>/dev/null || true")
NEW_FILES=$(comm -13 <(echo "$BEFORE" | sort) <(echo "$AFTER" | sort))

if [ -z "$NEW_FILES" ]; then
    echo "!!! [$CELL_NAME] no new episode file after injecting $SCENARIO -- capture pipeline produced nothing" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"
while IFS= read -r fname; do
    [ -z "$fname" ] && continue
    LOCAL_PATH="$OUT_DIR/${CELL_NAME}-${SCENARIO}-${fname}"
    echo "=== [$CELL_NAME] fetching $fname -> $LOCAL_PATH ==="
    $SSH "sudo cat /var/lib/linnix/episodes/$fname" > "$LOCAL_PATH"
    echo "=== [$CELL_NAME] stamping ground truth ($SCENARIO) ==="
    cargo run -p xtask-lab -- stamp "$LOCAL_PATH" "$SCENARIO"
done <<< "$NEW_FILES"

echo "=== [$CELL_NAME] done: $SCENARIO ==="
