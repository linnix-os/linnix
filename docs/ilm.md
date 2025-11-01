# Linnix Local ILM Sidecar

Linnix bundles a CPU-only llama.cpp server (`linnix-llm`) to power lightweight incident reasoning on the same host as Cognitod. The service ships with a Q4 GGUF placeholder (`dist/models/model.gguf`) and runs with conservative resource fences (≤1.8 GB RAM, two threads, AVX2 CPU target). It exposes an OpenAI-compatible `/v1/chat/completions` endpoint on `127.0.0.1:8087`.

## Licensing

The bundled binary and default model are expected to be redistributable within the Linnix distribution. If you replace `model.gguf`, ensure the new weights are licensed for local inference and redistribution within your environment. Document the model source and license internally so operators know the provenance of the deployed artifact.

## Swapping the Model

1. Drop the desired `.gguf` file into `dist/models/model.gguf` before running `scripts/install.sh`.
2. Re-run the installer (or copy the new file to `/usr/local/share/linnix/models/model.gguf` on an existing node).
3. Restart the sidecar: `sudo systemctl restart linnix-llm`.
4. Verify health with `scripts/health_llm.sh`.

The Cognitod reasoner reads its endpoint from `reasoner.endpoint` in `/etc/linnix/linnix.toml`. Update that field if you move the model behind a different URL or port.
