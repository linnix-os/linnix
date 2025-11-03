#!/bin/bash
# Serve the distilled 3B GGUF model with llama.cpp server

set -e

MODEL_PATH="linnix-3b-distilled-q5_k_m.gguf"
PORT="${LLAMA_PORT:-8090}"
CONTEXT_SIZE="${LLAMA_CTX:-4096}"
THREADS="${LLAMA_THREADS:-8}"

# Check if model exists
if [ ! -f "$MODEL_PATH" ]; then
    echo "❌ Model not found: $MODEL_PATH"
    echo "Please ensure the GGUF model is in the current directory."
    exit 1
fi

# Check if llama.cpp server exists
LLAMA_SERVER="$HOME/llama.cpp/build/bin/llama-server"
if [ ! -f "$LLAMA_SERVER" ]; then
    echo "❌ llama-server not found at: $LLAMA_SERVER"
    echo "Please build llama.cpp first:"
    echo "  cd ~/llama.cpp && cmake -B build && cmake --build build"
    exit 1
fi

echo "🚀 Starting Linnix Distilled 3B Model Server"
echo "   Model: $MODEL_PATH"
echo "   Port: $PORT"
echo "   Context: $CONTEXT_SIZE tokens"
echo "   Threads: $THREADS"
echo ""
echo "📡 API Endpoint: http://localhost:$PORT/v1/chat/completions"
echo "🛑 Press Ctrl+C to stop"
echo ""

# Start llama.cpp server with OpenAI-compatible API
exec "$LLAMA_SERVER" \
    --model "$MODEL_PATH" \
    --port "$PORT" \
    --ctx-size "$CONTEXT_SIZE" \
    --threads "$THREADS" \
    --n-gpu-layers 0 \
    --log-disable
