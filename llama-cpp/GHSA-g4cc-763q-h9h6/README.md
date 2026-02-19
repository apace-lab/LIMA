# GHSA-g4cc-763q-h9h6: llama.cpp Heap Over-Read in Vocab Loading

Docker-based Proof of Concept for reproducing [GHSA-g4cc-763q-h9h6](https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-g4cc-763q-h9h6).

## Vulnerability Summary

llama.cpp before commit c33fe8b8 has a CWE-125 (Out-of-bounds Read) vulnerability in the GGUF vocab loading code (`llama-vocab.cpp`). When loading a model whose vocabulary size is smaller than the hardcoded default ID for special tokens (e.g., BOS token id = 1), the code accesses `id_to_token[1]` when `id_to_token.size()` is only 1 (index 0). This causes a heap-based buffer over-read and a segmentation fault.

- **Advisory:** GHSA-g4cc-763q-h9h6 (no CVE assigned)
- **CWE:** CWE-125 (Out-of-bounds Read)
- **Severity:** Moderate
- **Impact:** Heap-based buffer over-read / Denial of Service (crash)
- **Attack vector:** Malicious GGUF model file with a tiny vocabulary
- **Affected file:** `llama-vocab.cpp` (`llama_vocab::impl::load`)
- **Fix:** Commit c33fe8b8

## Quick Start

```bash
# Run the full demo (creates malicious GGUF, builds vulnerable llama.cpp, triggers crash)
./GHSA-g4cc-763q-h9h6.sh
```

## How It Works

1. **Malicious GGUF**: The `create_malicious_gguf.py` script generates a structurally valid GGUF file with a vocabulary containing only 1 token (`<pad>` at index 0). Critically, the metadata sets `tokenizer.ggml.bos_token_id` to 1, which is beyond the vocabulary's bounds.
2. **Loading**: When llama.cpp loads this GGUF via `llama-cli`, the vocab loading code in `llama_vocab::impl::load` reads the BOS token ID (1) from the metadata and attempts to access `id_to_token[1]` to validate or configure the special token. Since the vocabulary only has 1 entry (index 0), this is an out-of-bounds heap read.
3. **Crash**: The out-of-bounds access reads past the end of the heap-allocated `id_to_token` vector, causing a segmentation fault (SIGSEGV). This results in a Denial of Service.

## Cleanup

```bash
docker compose down
docker rmi ghsa-g4cc-763q-h9h6-llamacpp 2>/dev/null || true
```
