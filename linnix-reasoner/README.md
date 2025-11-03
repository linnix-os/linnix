# Linnix Reasoner

## What it does

**Linnix Reasoner** is a CLI tool that:
- Fetches a live Linux system snapshot from a running `cognitod` backend (`/system` endpoint)
- Sends the snapshot to an OpenAI LLM (Chat Completions API) for semantic analysis
- Prints the LLM's answer in a human-friendly or machine-friendly format

Use it to get instant, AI-powered insights about your system state!

---

## How to run it

1. **Build the tool:**
   ```sh
   cargo build -p linnix-reasoner
   ```

2. **Start the cognitod backend** (in another terminal):
   ```sh
   cargo run -p cognitod
   ```

3. **Run the reasoner:**
   ```sh
   # Basic usage (pretty output)
   cargo run -p linnix-reasoner

   # One-line summary from the LLM
   cargo run -p linnix-reasoner -- --short

   # Output raw LLM JSON for scripting/integration
   cargo run -p linnix-reasoner -- --json

   # Override model, endpoint, or API key
   cargo run -p linnix-reasoner -- --model gpt-4 --endpoint https://api.openai.com/v1/chat/completions --api-key sk-...
   ```

---

## Required environment variables

### Using OpenAI (Cloud)

- `OPENAI_API_KEY` (required unless using `--api-key`)
  - Your OpenAI API key for Chat Completions.
- `LLM_MODEL` (optional, default: `gpt-3.5-turbo`)
  - The LLM model to use (e.g., `gpt-3.5-turbo`, `gpt-4`).
- `LLM_ENDPOINT` (optional, default: `https://api.openai.com/v1/chat/completions`)
  - The OpenAI API endpoint.

**Example:**
```sh
export OPENAI_API_KEY=sk-...
cargo run -p linnix-reasoner -- --short
```

### Using Local Distilled Model (CPU-Only, On-Premises)

Linnix includes a **distilled 3B model** (2.1GB, Q5_K_M GGUF) optimized for CPU deployment:

1. **Start the model server:**
   ```sh
   ./serve_distilled_model.sh
   ```

2. **Configure environment:**
   ```sh
   source .env.distilled
   ```

3. **Run the reasoner:**
   ```sh
   cargo run -p linnix-reasoner
   ```

**Benefits:**
- ✅ **Pure CPU**: No GPU required
- ✅ **Fast**: 12+ tokens/second on modern CPUs
- ✅ **Private**: All data stays on-premises
- ✅ **Cost-effective**: Zero API costs
- ✅ **Small**: Only 2.1GB memory footprint

**Model Details:**
- **Architecture**: Qwen2.5-3B-Instruct (distilled from fine-tuned 7B)
- **Format**: GGUF Q5_K_M (64% compression)
- **Training**: H200 SXM with 12K telemetry examples
- **Context**: 4,096 tokens (32K max)

---

## Testing

Run the full integration test suite:
```sh
./test_reasoner_integration.sh
```

This will test:
- System snapshot analysis
- Short summaries
- Insights endpoint
- Model performance

You can also override these with CLI flags.