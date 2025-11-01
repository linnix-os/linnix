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

- `OPENAI_API_KEY` (required unless using `--api-key`)
  - Your OpenAI API key for Chat Completions.
- `LLM_MODEL` (optional, default: `gpt-3.5-turbo`)
  - The LLM model to use (e.g., `gpt-3.5-turbo`, `gpt-4`).
- `LLM_ENDPOINT` (optional, default: `https://api.openai.com/v1/chat/completions`)
  - The OpenAI API endpoint.

You can also override these with CLI flags.

---

**Example:**
```sh
export OPENAI_API_KEY=sk-...
cargo run -p linnix-reasoner -- --short
```