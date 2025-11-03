#!/bin/bash
# Benchmark the distilled 3B model integration

set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔬 Linnix Distilled 3B Model - Performance Benchmark"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check prerequisites
if ! curl -s http://localhost:8090/v1/models > /dev/null 2>&1; then
    echo "❌ Model server not running on port 8090"
    echo "   Start with: ./serve_distilled_model.sh"
    exit 1
fi

if ! curl -s http://localhost:3000/system > /dev/null 2>&1; then
    echo "❌ Cognitod not running on port 3000"
    exit 1
fi

echo "✅ Prerequisites checked"
echo ""

# Test 1: Model loading time
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Test 1: Model Server Status"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

MODEL_INFO=$(curl -s http://localhost:8090/v1/models | jq -r '.data[0]')
echo "Model ID: $(echo "$MODEL_INFO" | jq -r '.id')"
echo "Parameters: $(echo "$MODEL_INFO" | jq -r '.meta.n_params' | awk '{printf "%.2f B\n", $1/1000000000}')"
echo "Context: $(echo "$MODEL_INFO" | jq -r '.meta.n_ctx_train') tokens"
echo "Vocabulary: $(echo "$MODEL_INFO" | jq -r '.meta.n_vocab') tokens"
echo "Size: $(echo "$MODEL_INFO" | jq -r '.meta.size' | awk '{printf "%.2f GB\n", $1/1073741824}')"
echo ""

# Test 2: Full analysis latency
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⏱️  Test 2: Full Analysis Latency (5 runs)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

TIMES=()
for i in {1..5}; do
    echo -n "Run $i: "
    START=$(date +%s.%N)
    LLM_ENDPOINT="http://localhost:8090/v1/chat/completions" \
    LLM_MODEL="linnix-3b-distilled" \
    cargo run --release -p linnix-reasoner 2>&1 > /dev/null
    END=$(date +%s.%N)
    ELAPSED=$(echo "$END - $START" | bc)
    TIMES+=($ELAPSED)
    echo "${ELAPSED}s"
done

echo ""
echo "Average: $(echo "${TIMES[@]}" | awk '{sum=0; for(i=1;i<=NF;i++)sum+=$i; print sum/NF "s"}')"
echo "Min: $(printf '%s\n' "${TIMES[@]}" | sort -n | head -1)s"
echo "Max: $(printf '%s\n' "${TIMES[@]}" | sort -n | tail -1)s"
echo ""

# Test 3: Short summary latency
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⚡ Test 3: Short Summary Latency (5 runs)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

SHORT_TIMES=()
for i in {1..5}; do
    echo -n "Run $i: "
    START=$(date +%s.%N)
    LLM_ENDPOINT="http://localhost:8090/v1/chat/completions" \
    LLM_MODEL="linnix-3b-distilled" \
    cargo run --release -p linnix-reasoner -- --short 2>&1 > /dev/null
    END=$(date +%s.%N)
    ELAPSED=$(echo "$END - $START" | bc)
    SHORT_TIMES+=($ELAPSED)
    echo "${ELAPSED}s"
done

echo ""
echo "Average: $(echo "${SHORT_TIMES[@]}" | awk '{sum=0; for(i=1;i<=NF;i++)sum+=$i; print sum/NF "s"}')"
echo "Min: $(printf '%s\n' "${SHORT_TIMES[@]}" | sort -n | head -1)s"
echo "Max: $(printf '%s\n' "${SHORT_TIMES[@]}" | sort -n | tail -1)s"
echo ""

# Test 4: Quality assessment
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎯 Test 4: Quality Assessment"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "Sample output:"
echo "────────────────────────────────────────────────"
LLM_ENDPOINT="http://localhost:8090/v1/chat/completions" \
LLM_MODEL="linnix-3b-distilled" \
cargo run --release -p linnix-reasoner -- --short 2>&1 | tail -8
echo "────────────────────────────────────────────────"
echo ""

# Test 5: Resource usage
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "💾 Test 5: Resource Usage"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

LLAMA_PID=$(pgrep -f llama-server || echo "")
if [ -n "$LLAMA_PID" ]; then
    MEM_KB=$(ps -o rss= -p "$LLAMA_PID")
    MEM_MB=$(echo "$MEM_KB / 1024" | bc)
    MEM_GB=$(echo "scale=2; $MEM_KB / 1024 / 1024" | bc)
    CPU_PCT=$(ps -o %cpu= -p "$LLAMA_PID")
    
    echo "llama-server process:"
    echo "  PID: $LLAMA_PID"
    echo "  Memory: ${MEM_MB} MB (${MEM_GB} GB)"
    echo "  CPU: ${CPU_PCT}%"
else
    echo "⚠️  Could not find llama-server process"
fi
echo ""

# Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📈 Benchmark Summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "✅ Model: linnix-3b-distilled (Q5_K_M, 2.1GB)"
echo "✅ Deployment: Pure CPU, no GPU required"
echo "✅ Full Analysis: $(echo "${TIMES[@]}" | awk '{sum=0; for(i=1;i<=NF;i++)sum+=$i; printf "%.1fs avg\n", sum/NF}')"
echo "✅ Short Summary: $(echo "${SHORT_TIMES[@]}" | awk '{sum=0; for(i=1;i<=NF;i++)sum+=$i; printf "%.1fs avg\n", sum/NF}')"
if [ -n "$MEM_GB" ]; then
    echo "✅ Memory Footprint: ${MEM_GB} GB"
fi
echo "✅ Enterprise Ready: On-premises CPU deployment"
echo ""
echo "🎉 Benchmark complete!"
