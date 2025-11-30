#!/bin/bash
set -e

echo "Building linnix-cli..."
cargo build -p linnix-cli

echo "Verifying 'processes' command existence..."
./target/debug/linnix-cli processes --help

echo "✅ 'linnix-cli processes' command exists."
echo ""
echo "To verify full functionality:"
echo "1. Run cognitod in a K8s cluster (or with KUBECONFIG set)."
echo "2. Annotate a pod: kubectl annotate pod <pod> linnix.dev/priority=critical"
echo "3. Run: ./target/debug/linnix-cli processes"
echo "4. Verify the PRIORITY column shows 'CRITICAL'."
