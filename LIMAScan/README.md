# LIMAScan

Taxonomy-driven dynamic testing tool for detecting LIMA vulnerabilities across LLM inference frameworks: **LocalAI**, **Ollama**, **vLLM**, and **llama.cpp**.

LIMAScan generates crafted payloads derived from observed vulnerability patterns across the LIMA dataset, then fires them at live LIF instances to detect crashes, Go panics, OOM kills, information leaks, and successful exploits. It re-discovers **13 known unpatched CVEs** and uncovers **7 previously unknown vulnerabilities** in the latest stable releases of the four LIFs.

## How it works

LIMAScan operates in three steps:

1. **Payload generation**: `generate_all_payloads.py` produces crafted GGUF files, malformed JSON schemas, grammar files, path-traversal strings, and ReDoS inputs covering all five root cause categories.
2. **Live testing**: each shell script starts the required Docker container (or connects to a running vLLM server), submits each payload, and checks the response for abnormal behavior.
3. **Result logging**: every test prints a one-line result and appends it to `payloads/results.txt`; Docker logs are saved under `payloads/logs/`.

## Root cause categories tested

| Category                    | Sub-patterns                                  | CVEs covered |
| --------------------------- | --------------------------------------------- | ------------ |
| Unsafe Model File Parsing   | Integer Overflow, Heap Overflow, Null Pointer | 19           |
| Untrusted Code Execution    | Unsafe Deserialization, Code Injection, SSTI  | 14           |
| Resource Exhaustion / DoS   | ReDoS, Recursion, Resource Exhaustion         | 22           |
| Insufficient Access Control | Path Traversal, SSRF, No Auth                 | 10           |
| Information Leakage         | Timing, hash side-channel                     | 3            |

See [`patterns.md`](patterns.md) for the full cross-framework pattern analysis and the results matrix from our evaluation.

## Prerequisites

- Docker ≥ 20.10 with Docker Compose
- Python ≥ 3.9
- `bash`, `curl`, `shasum` (standard Unix utilities)
- x86_64 host recommended (required for LocalAI containers)
- **NVIDIA GPU required for `run_vllm_tests.sh`** — see [vLLM note](#vllm-gpu-requirement) below

The three non-vLLM scripts (`run_full_cross_tests.sh` and `run_timed_tests.sh`) depend on specific versioned Docker environments from the LIMABench PoCs. They must be run from inside the repository root so the relative paths to `../LocalAI/localai-v3.12.1-retest`, `../Ollama/ollama-v0.17.0-retest`, and `../llama-cpp/llama-cpp-b8149-fuzz` resolve correctly.

## Scripts

| Script                    | What it does                                                                                   | Approx. runtime                     |
| ------------------------- | ---------------------------------------------------------------------------------------------- | ----------------------------------- |
| `run_full_cross_tests.sh` | Full cross-framework scan (LocalAI, llama.cpp, Ollama)                                         | ~4 min                              |
| `run_timed_tests.sh`      | Same scan with per-framework timing instrumentation                                            | ~2–3 min                            |
| `run_vllm_tests.sh`       | vLLM-specific tests: structured output crashes, ReDoS, resource exhaustion, recursion, no-auth | ~3–5 min (excludes model load time) |

## Quick start

```bash
cd LIMAScan/

# Full cross-framework scan (LocalAI, llama.cpp, Ollama)
./run_full_cross_tests.sh

# With per-framework timing measurements
./run_timed_tests.sh

# vLLM tests (requires a running vLLM server — see below)
./run_vllm_tests.sh
```

## Expected output

Each completed test prints a one-line result:

```
  [CRASHED] Heap Overflow/p2a_large_n_kv → LocalAI: OOMKilled=true exit=137 — GGUF triggered fatal OOM
  [PANIC_RECOVERED] Integer Overflow/p1a_negative_key_length → LocalAI: Go panic caught by recover()
  [NOT_VULNERABLE] Resource Exhaustion/p11b_huge_dims → LocalAI: Server survived
```

The result label is one of:

| Label             | Meaning                                                                           |
| ----------------- | --------------------------------------------------------------------------------- |
| `CRASHED`         | Server died (OOMKilled, non-zero exit, or health check failed)                    |
| `PANIC_RECOVERED` | Go runtime panic caught by `recover()` means server survives but parser is unsafe |
| `VULNERABLE`      | Explicit vulnerability signal confirmed (info leak, auth bypass, etc.)            |
| `ERROR_RETURNED`  | Server returned an HTTP error (5xx) on the crafted input                          |
| `NOT_VULNERABLE`  | Server handled the payload without abnormal behavior                              |
| `SKIPPED`         | Container failed to start or prerequisite environment was missing                 |

At the end of `run_full_cross_tests.sh` / `run_timed_tests.sh`, a summary is printed (23 total tests across LocalAI, llama.cpp, and Ollama):

```
Total tests: 23
  CRASHED:         2
  PANIC_RECOVERED: 3
  VULNERABLE:      1
  NOT_VULNERABLE:  17
  SKIPPED:         0
```

`run_vllm_tests.sh` produces its own summary (10 tests):

```
Total tests: 10
  CRASHED:         7
  VULNERABLE:      2
  ERROR_RETURNED:  0
  NOT_VULNERABLE:  1
```

Full results are saved to `payloads/results.txt` (non-vLLM) and `payloads/vllm_results.txt` (vLLM). Docker logs go to `payloads/logs/`.

When running `run_timed_tests.sh`, per-framework wall-clock times are also written to `payloads/timing.txt`:

```
PAYLOAD_GENERATION | 0s
LocalAI | 205s
llama-cpp | 18s
Ollama | 8s
```

## Payload files

The payload generator (`generate_all_payloads.py`) writes all files into the `payloads/` directory on first run. The scripts call it automatically on startup, so no manual pre-generation step is needed. The generated files include:

| File(s)                        | Pattern                                                                                                               |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| `p1a/b/c_*.gguf`               | Integer overflow / narrow casting (n_kv key/value lengths = 0x8000000000000000)                                       |
| `p2a/b/c/d_*.gguf`             | Heap buffer overflow (n_kv = 4B, n_tensors = 4B, small vocab, large key length)                                       |
| `p8a_nested_parens.gbnf`       | Recursion — 50 000-level GBNF grammar (LIMA-NEW-003 payload; generated but not submitted by current LIMAScan scripts) |
| `p8b_nested_schema.json`       | Recursion — 5 000-level JSON schema; submitted to vLLM by `run_vllm_tests.sh` (LIMA-NEW-004 pattern)                  |
| `p10a/b/c_*.gguf`              | Null pointer / truncated GGUF (magic-only, zero-length tensor name, abrupt EOF)                                       |
| `p11a/b/c_*.gguf`              | Resource exhaustion (alignment = 0, huge dims, block_count = 0)                                                       |
| `p11d_extreme_api_params.json` | Extreme API parameters (n_predict = 999 999 999, temperature = 99 999)                                                |
| `p5_traversal_payloads.txt`    | Path traversal strings                                                                                                |
| `p7_redos_payloads.json`       | ReDoS inputs (catastrophic backtracking patterns)                                                                     |

## vLLM GPU requirement

`run_vllm_tests.sh` sends exploit payloads to a live vLLM inference server and **requires a CUDA-capable NVIDIA GPU with at least 16 GB VRAM**.

If no server is already running, the script will attempt to start one automatically using `Qwen/Qwen2.5-0.5B-Instruct` (the smallest available chat model). First-time startup includes a model download and can take several minutes. Subsequent runs reuse the Hugging Face cache and load much faster.

To start a compatible server manually before running the script:

```bash
pip install 'vllm>=0.8.0,<0.9.0'
vllm serve Qwen/Qwen2.5-0.5B-Instruct --host 0.0.0.0 --port 8000
```

Then run the vLLM tests:

```bash
./run_vllm_tests.sh
```

The script checks `http://localhost:8000/v1/models` and connects to any already-running vLLM server automatically, so you can also point it at a server loaded with a different model by starting that server yourself first.

**Tests performed against vLLM:**

| Test                        | Pattern                           | CVE reference        |
| --------------------------- | --------------------------------- | -------------------- |
| `invalid_schema_type`       | Structured output crash           | CVE-2025-48942       |
| `invalid_regex`             | Invalid regex in guided decoding  | CVE-2025-48943       |
| `invalid_tool_schema`       | Invalid tool parameter schema     | CVE-2025-48944       |
| `tool_parser_backtrack`     | Tool call parser ReDoS            | CVE-2025-48887       |
| `json_extraction_backtrack` | JSON extraction ReDoS             | GHSA-j828-28rj-hfhp  |
| `extreme_max_tokens`        | Unbounded token generation        | Resource Exhaustion  |
| `extreme_best_of`           | Extreme `best_of` parameter       | CVE-2024-8939        |
| `large_http_header`         | 1 MB custom HTTP header           | CVE-2025-48956       |
| `nested_json_schema`        | 5 000-level JSON schema recursion | LIMA-NEW-004 pattern |
| `no_auth`                   | Unauthenticated API access check  | —                    |

## Key findings from our evaluation

Cross-framework testing revealed that the same crafted GGUF payload can crash multiple frameworks through entirely different parsers:

- **Heap overflow GGUFs → LocalAI v3.12.1: OOMKilled** (LIMA-NEW-007, documented in `patterns.md`). `gpustack/gguf-parser-go` does not validate `n_kv` or `vocab_size` before allocating; the `recover()` in `guesser.go` cannot catch a kernel-level SIGKILL. Both `p2a_large_n_kv.gguf` (n_kv = 0xFFFFFFFF, 4 billion) and `p2c_small_vocab.gguf` have been observed to trigger the OOM kill depending on container state.
- **`p11a_zero_alignment.gguf`** (alignment = 0) → divide-by-zero panic in **Ollama v0.17.0** (CVE-2025-0317 still unpatched as of testing); confirmed in `payloads/results.txt`.
- **`p8b_nested_schema.json`** (5 000-level JSON schema) → server crash in **vLLM 0.8.3** via xgrammar stack overflow (LIMA-NEW-004 pattern); confirmed in `payloads/vllm_results.txt`. Ollama is immune (Go's `encoding/json` enforces depth limits).

See `patterns.md` for the full results matrix across all five root cause categories and four frameworks.

## Notes

- The scripts use `set +e` so a single failing test does not abort the run. Skipped tests (e.g., when a container fails to start) are logged as `SKIPPED` in the results file.
- If a crash is detected, the script automatically restarts the affected container before continuing to the next test.
- Apple Silicon (arm64) hosts cannot build several of the LocalAI Docker images. On arm64, LocalAI tests will likely report `SKIPPED`.
- The `run_timed_tests.sh` script is functionally identical to `run_full_cross_tests.sh` but adds wall-clock timestamps around each framework section. Use it when you need the timing data for the paper's performance table.
