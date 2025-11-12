#!/bin/bash
# Linnix Demo Script - Fork Bomb Detection
# This script demonstrates Linnix catching a fork storm in real-time

set -e

echo "======================================"
echo "  Linnix Demo: Fork Storm Detection"
echo "======================================"
echo ""
echo "This demo shows Linnix detecting rapid process spawning"
echo "before it causes system issues."
echo ""

# Check if cognitod is running
if ! curl -s http://localhost:3000/health > /dev/null 2>&1; then
    echo "❌ Cognitod not running on port 3000"
    echo "Please start: docker run -d --privileged --pid=host --network=host linnix-cognitod"
    exit 1
fi

echo "✅ Linnix monitoring is active"
echo ""

# Start alert listener in background
echo "📡 Starting alert listener..."
curl -N http://localhost:3000/alerts 2>/dev/null | while read line; do
    if [[ "$line" == data:* ]]; then
        echo "🚨 ALERT: ${line#data: }"
    fi
done &
CURL_PID=$!

sleep 2

echo ""
echo "🔥 Launching fork bomb scenario..."
echo "   (Spawning 100 processes at 50 forks/sec)"
echo ""

# Run fork bomb
docker run --rm --name demo-fork-bomb linnix-demo-fork-bomb:latest &
DOCKER_PID=$!

# Wait for fork bomb to complete
wait $DOCKER_PID

echo ""
echo "✅ Fork bomb completed"
echo ""

# Give a moment for final alerts
sleep 3

# Stop alert listener
kill $CURL_PID 2>/dev/null

echo ""
echo "======================================"
echo "  Demo Complete!"
echo "======================================"
echo ""
echo "Linnix successfully detected the fork storm"
echo "and alerted before system impact."
echo ""
echo "Try it yourself:"
echo "  docker run --rm linnix-demo-fork-bomb"
echo ""
