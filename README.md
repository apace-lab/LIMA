# LIMA

Docker-based proof-of-concept (PoC) environments for reproducing CVEs and GHSAs in LLM inference stacks: **LocalAI**, **Ollama**, **vLLM**, and **llama.cpp**.

Each CVE (or GHSA) lives in a product folder with a Docker setup and a run script. Use these only in isolated environments for security research and remediation validation.

## Repository structure

| Folder | Product | PoCs |
|--------|---------|------|
| [**LocalAI/**](LocalAI/) | [LocalAI](https://github.com/mudler/LocalAI) | 4 CVEs (CSRF, XSS, SSRF/LFI, RCE) |
| [**Ollama/**](Ollama/) | [Ollama](https://github.com/ollama/ollama) | 15 CVEs (DoS, info disclosure, RCE, path traversal, etc.) |
| [**vllm/**](vllm/) | [vLLM](https://github.com/vllm-project/vllm) | 23 items (CVEs + GHSA; RCE, DoS, ReDoS, etc.) |
| [**llama-cpp/**](llama-cpp/) | [llama.cpp](https://github.com/ggml-org/llama.cpp) / [llama-cpp-python](https://github.com/abetlen/llama-cpp-python) | 15 items (CVEs + GHSA; buffer overflows, RPC, SSTI, etc.) |

Each product folder has a **README.md** with the canonical CVE/GHSA list and short descriptions. Each CVE subfolder contains:

- `README.md` – summary, impact, and fix
- `Dockerfile` / `docker-compose.yml` – vulnerable environment
- Run script (e.g. `CVE-YYYY-NNNNN.sh`) – build and run steps

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (and Docker Compose)
- For some LocalAI PoCs: **x86_64** host (see [LocalAI/README.md](LocalAI/README.md); Apple Silicon may fail)

## Quick start

From the repo root:

```bash
# Example: run a vLLM PoC
./vllm/CVE-2024-11041/CVE-2024-11041.sh

# Example: run an Ollama PoC
./Ollama/CVE-2024-28224/CVE-2024-28224.sh

# Example: run a LocalAI PoC (x86_64 recommended)
./LocalAI/CVE-2024-6983/CVE-2024-6983.sh

# Example: run a llama.cpp PoC
./llama-cpp/CVE-2024-42479/CVE-2024-42479.sh
```

Or from inside a CVE folder:

```bash
cd Ollama/CVE-2024-28224
./CVE-2024-28224.sh
```

Cleanup is usually:

```bash
docker compose down
docker volume rm <volume_name> 2>/dev/null || true
```

Exact cleanup commands are in each CVE’s README.

## Product READMEs and CVE lists

- **[LocalAI/README.md](LocalAI/README.md)** – LocalAI CVE list and which PoCs are in this repo
- **[Ollama/README.md](Ollama/README.md)** – Ollama CVE list
- **[vllm/README.md](vllm/README.md)** – vLLM CVE/GHSA list
- **[llama-cpp/README.md](llama-cpp/README.md)** – llama.cpp / llama-cpp-python CVE/GHSA list
