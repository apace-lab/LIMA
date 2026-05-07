# LIMABench

Driver script for running all 58 LIMABench proof-of-concept scripts across four LLM inference frameworks: **LocalAI**, **Ollama**, **vLLM**, and **llama.cpp**.

The LIMA dataset covers **60 vulnerabilities** across four frameworks (llama.cpp 15, vLLM 25, Ollama 15, LocalAI 5). Two vLLM vulnerabilities could not be containerized and are documented in `vllm/README.md` but have no runnable PoC: **CVE-2025-46570** (requires multi-tenant timing measurements infeasible in isolation) and **CVE-2025-1953** (targets the `aibrix` plugin alongside core vLLM). The remaining **58 vulnerabilities** are fully runnable here.

## Prerequisites

- Docker ≥ 20.10 with Docker Compose
- Python ≥ 3.9
- `bash`, `curl`, standard Unix utilities
- x86_64 host recommended (some LocalAI PoCs do not build on Apple Silicon)
- **NVIDIA GPU required for 9 vLLM PoCs** — see [vLLM note](#vllm-gpu-requirement) below

## Quick start

```bash
cd LIMABench/
./run_all_pocs.sh
```

This runs all 58 PoCs sequentially with a 10-minute per-PoC timeout.

## Options

| Flag               | Default | Description                                                         |
| ------------------ | ------- | ------------------------------------------------------------------- |
| `--timeout SECS`   | `600`   | Per-PoC timeout in seconds                                          |
| `--framework NAME` | _(all)_ | Run only one framework: `LocalAI`, `Ollama`, `vllm`, or `llama-cpp` |
| `--dry-run`        | —       | List all PoCs without executing them                                |
| `--no-cleanup`     | —       | Skip the `docker compose down` run after each PoC                   |
| `--no-color`       | —       | Disable ANSI colour output                                          |

Examples:

```bash
# Run only llama-cpp PoCs
./run_all_pocs.sh --framework llama-cpp

# Run all PoCs with a 5-minute cap per test
./run_all_pocs.sh --timeout 300

# See all 58 PoCs without running anything
./run_all_pocs.sh --dry-run
```

## Runtime and why it may appear stuck

The full suite takes **1.5–2.5 hours on a cold machine** (no cached images). This is normal. The progress bar counter will sit at the same number for several minutes at a time but it is not frozen, it is waiting for a long-running PoC to finish.

The three main reasons a single test can take several minutes:

**1. Docker image pulls.** Each PoC targets a specific vulnerable version of a framework (e.g. `ollama/ollama:0.1.28`, `localai/localai:v2.14.0`). If that image is not already in your local Docker cache, it must be downloaded before the exploit can run. A single image can be several hundred MB to over 1 GB. This only happens the first time; subsequent runs reuse the cached image and are much faster.

**2. Building llama.cpp from source.** Several llama.cpp PoCs compile a specific vulnerable commit of llama.cpp inside Docker. A full C++ build from scratch takes 3–7 minutes per unique commit, even on a fast machine.

**3. Model downloads inside containers.** Some Ollama PoCs pull a base model (e.g. `llama2`, ~4 GB) as part of the demonstration. If the model is not already cached inside the Ollama container, the pull adds several minutes to that single test.

On a **warm machine** (all images cached from a prior run) the full suite completes in roughly **20–40 minutes**.

If a test exceeds the per-PoC timeout (default 600 s) the driver kills it and marks it `TIMEOUT`. Increase the timeout for slow-building PoCs:

```bash
./run_all_pocs.sh --timeout 1200
```

## Expected output

While running, the script displays a live progress bar:

```
[12/58] Ollama/CVE-2024-28224
[████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░]  20% | Done: 12  Passed: 10  Failed: 2  Remaining: 46
```

Each completed test prints a one-line result:

```
   12/58  Ollama/CVE-2024-28224        CONFIRMED    (38s)
```

The result label is one of:

| Label       | Meaning                                                                                            |
| ----------- | -------------------------------------------------------------------------------------------------- |
| `CONFIRMED` | Exit 0 and output contains an explicit vulnerability signal (crash, exploit, info-leak, etc.)      |
| `SETUP_OK`  | Exit 0 but no auto-detectable signal — environment was set up; manual trigger or inspection needed |
| `FAILED`    | Non-zero exit — typically a Docker build/pull error or missing dependency                          |
| `TIMEOUT`   | PoC exceeded the per-test timeout                                                                  |

On completion a summary is printed:

```
╔══════════════════════════════════════════════════════════════╗
║              LIMABench — Final Summary                       ║
╠══════════════════════════════════════════════════════════════╣
║  Total PoCs run          : 58                                ║
║  Total elapsed time      : 42m 10s                           ║
╠══════════════════════════════════════════════════════════════╣
║  Passed  (exit 0)        : 55   (94%)                        ║
║    ├─ Confirmed          : 50                                ║
║    └─ Setup only         :  5                                ║
║  Failed  (error/timeout) :  3                                ║
╚══════════════════════════════════════════════════════════════╝

Result: 58 issues in LIMABench, 55 successfully reproduced, 3 failed.
```

Per-PoC logs are saved to `LIMABench/results/<timestamp>/`.

## vLLM GPU requirement

9 of the 23 vLLM PoCs send exploit payloads to a live vLLM inference server and **cannot run without one**. A CUDA-capable NVIDIA GPU with at least 16 GB VRAM is required.

To start a compatible vLLM server before running those PoCs:

```bash
pip install 'vllm>=0.8.0,<0.9.0'
vllm serve meta-llama/Llama-3.2-3B-Instruct --port 8000
```

Then run the suite (the `VLLM_URL` variable is forwarded to each PoC script):

```bash
VLLM_URL=http://localhost:8000 ./run_all_pocs.sh --framework vllm
```

Without a running server these 9 PoCs will exit with `FAILED`. The remaining 14 vLLM PoCs are fully self-contained and do not require a GPU.

The affected CVEs are:
`CVE-2024-8768`, `CVE-2024-8939`, `CVE-2025-29770`, `CVE-2025-30202`,
`CVE-2025-32381`, `CVE-2025-48942`, `CVE-2025-48943`, `CVE-2025-48944`,
`CVE-2025-48956`.
