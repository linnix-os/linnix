# Linnix AI Models

This directory contains language models for AI-powered incident detection.

## Available Models

### Linnix 3B Distilled (Production - **AVAILABLE NOW**)
- **File**: `linnix-3b-distilled-q5_k_m.gguf`
- **Size**: 2.1 GB
- **Use Case**: Production incident detection
- **Training**: Fine-tuned on 12K+ system observability incidents
- **Performance**: ~30 tok/s on 8-core CPU, 92% quality vs 7B teacher
- **License**: AGPL-3.0
- **Download**: [Hugging Face Hub](https://huggingface.co/parth21shah/linnix-3b-distilled)

### TinyLlama 1.1B (Legacy Testing)
- **File**: `tinyllama-1.1b-chat-v1.0.Q5_K_M.gguf`
- **Size**: 747 MB
- **Use Case**: Quick testing only (not trained for incidents)
- **Source**: [TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF](https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF)
- **License**: AGPL-3.0

## Quick Setup

### Option 1: Automatic Download (Recommended)
```bash
./setup-llm.sh
```

This script will:
1. Download the Linnix 3B model from Hugging Face (2.1GB)
2. Start cognitod + llama-server with Docker Compose
3. Verify both services are healthy

### Option 2: Manual Download

**Linnix 3B (production):**
```bash
mkdir -p models
cd models
wget https://huggingface.co/parth21shah/linnix-3b-distilled/resolve/main/linnix-3b-distilled-q5_k_m.gguf
```

**TinyLlama (legacy testing only):**
```bash
wget https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q5_K_M.gguf
```

### Option 3: Use Custom Model

Place any GGUF model in this directory and update `docker-compose.llm.yml`:

```yaml
command:
  - -m
  - /models/your-custom-model.gguf
```

## Model Performance

| Model | Size | Inference Speed | Accuracy | Best For |
|-------|------|----------------|----------|----------|
| TinyLlama 1.1B | 747 MB | ~50 tokens/sec | Good | Testing, development |
| Linnix 3B | 2.1 GB | ~30 tokens/sec | Excellent | Production use |

*Benchmarks on 8-core CPU, no GPU*

## System Requirements

### Minimum (TinyLlama)
- RAM: 2 GB
- CPU: 2 cores
- Disk: 1 GB

### Recommended (Linnix 3B)
- RAM: 4 GB
- CPU: 4 cores
- Disk: 3 GB

## Troubleshooting

### Model download fails
```bash
# Check internet connection
curl -I https://huggingface.co

# Use alternative download tool
curl -L -o models/tinyllama.gguf https://...
```

### Out of memory errors
```bash
# Reduce context size in docker-compose.llm.yml
--ctx-size 1024  # instead of 2048
```

### Slow inference
```bash
# Reduce thread count
-t 2  # instead of 4
```

## License

- **TinyLlama**: AGPL-3.0 (third-party model)
- **Linnix Models**: AGPL-3.0 (our fine-tuned models)
- See [LICENSE](../LICENSE) for full text

## Contributing

Want to improve the models? See:
## 📚 Resources

- [Hugging Face Model Card](https://huggingface.co/parth21shah/linnix-3b-distilled)
- [GitHub Releases](https://github.com/linnix-os/linnix/releases)
- [Main README](../README.md)
- [Contributing Guidelines](../CONTRIBUTING.md)
