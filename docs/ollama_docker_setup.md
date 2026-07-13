# Ollama Docker Installation & Developer Bootstrap Guide

This document describes the procedures for setting up, configuring, and benchmarking the local dockerized Ollama daemon integrated into the PhantomNet Sentinel Layer.

---

## 1. System Pre-requisites & GPU Acceleration

To run local LLM inference efficiently (specifically the primary `mistral` 7B model), GPU acceleration is highly recommended.

### NVIDIA GPU Pre-requisites (Windows Host)
1. **NVIDIA GeForce Game Ready Driver** or **NVIDIA RTX Enterprise Driver** (v535+ recommended).
2. **NVIDIA Container Toolkit** (for WSL2 / Docker Desktop).
   * Ensure Docker Desktop has "Use the WSL 2 based engine" enabled.

---

## 2. Docker Compose Configuration

The Ollama daemon is provisioned as an autonomous service in the primary `docker-compose.yml` file.

```yaml
  ollama:
    image: ollama/ollama:latest
    container_name: phantomnet_ollama
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
    networks:
      - app_net
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
```

* **Port Mapping**: Exposes `11434` to localhost, enabling external verification and development utilities to query the model.
* **Volume Mount**: Mounts `ollama_data` to persist pulled models across container restarts.
* **GPU Reservation**: Dynamically requests access to all available NVIDIA CUDA cores via the container host.

---

## 3. Pulling Target Models

Once the container is online, pull the model weights to the local storage volume.

### Primary Model (Mistral 7B)
```powershell
docker exec -it phantomnet_ollama ollama pull mistral
```

### Resource-Constrained Fallback Models
For development systems with less than 8GB of VRAM or running entirely on CPU, smaller models are configured:
* **Phi-3 (3.8B parameters)**:
  ```powershell
  docker exec -it phantomnet_ollama ollama pull phi3:3.8b
  ```
* **Gemma 2 (2B parameters)**:
  ```powershell
  docker exec -it phantomnet_ollama ollama pull gemma:2b
  ```

---

## 4. REST API Verification

Test local inference via standard HTTP requests:

```powershell
curl -X POST http://localhost:11434/api/generate -d '{
  "model": "mistral",
  "prompt": "Explain what a honeypot healthcheck filter does in 1 sentence.",
  "stream": false
}'
```

---

## 5. Inference Benchmarks

Benchmarks measured on standard developer hardware (NVIDIA RTX 4070 Laptop GPU, 8GB VRAM, AMD Ryzen 7):

| Model | Size | VRAM Usage | Prompt Eval Latency | Inference Speed |
| :--- | :--- | :--- | :--- | :--- |
| **mistral:7b** | 4.1 GB | ~4.8 GB | ~120 ms | 42.5 tokens/sec |
| **phi3:3.8b** | 2.2 GB | ~2.9 GB | ~85 ms | 68.2 tokens/sec |
| **gemma:2b** | 1.4 GB | ~2.1 GB | ~60 ms | 82.0 tokens/sec |
