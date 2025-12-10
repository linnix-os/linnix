# Dockerfile for llama.cpp server with Linnix 3B model
# Uses official pre-built ghcr.io/ggml-org/llama.cpp image for fast setup

FROM ghcr.io/ggml-org/llama.cpp:server AS llama-base

# Runtime stage - lightweight image with llama-server
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy llama-server binary from official image
COPY --from=llama-base /app/llama-server /usr/local/bin/llama-server
COPY --from=llama-base /app/*.so /usr/local/lib/

# Update library cache
RUN ldconfig

# Create model directory
RUN mkdir -p /models
WORKDIR /models

# Add download script
COPY download-model.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/download-model.sh

# Expose llama.cpp server port
EXPOSE 8090

# Health check
HEALTHCHECK --interval=15s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8090/health || exit 1

# Entry point: download model if needed, then start server
ENTRYPOINT ["/bin/bash", "-c", "/usr/local/bin/download-model.sh && exec llama-server \"$@\"", "--"]

# Default args (can be overridden in docker-compose)
CMD ["-m", "/models/linnix-3b-distilled-q5_k_m.gguf", \
     "--host", "0.0.0.0", \
     "--port", "8090", \
     "--ctx-size", "4096", \
     "-t", "8"]
