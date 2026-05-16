# GHSA-j828-28rj-hfhp: vLLM Multiple ReDoS Vulnerabilities (CWE-1333)

Docker-based Proof of Concept for reproducing [GHSA-j828-28rj-hfhp](https://github.com/vllm-project/vllm/security/advisories/GHSA-j828-28rj-hfhp).

## Vulnerability Summary

vLLM < 0.9.0 contains several regular expressions that are susceptible to Regular Expression Denial of Service (ReDoS) attacks due to catastrophic backtracking. The vulnerable patterns are found in:

1. **`vllm/lora/utils.py`** (line 173): Pattern `r"\((.*?)\)\$?$"` for parsing PEFT-style LoRA module specifications.
2. **`vllm/entrypoints/openai/serving_chat.py`** (line 351): Pattern `r'.*"parameters":\s*(.*)'` for extracting JSON parameters from chat messages.
3. **`benchmarks/benchmark_serving_structured_output.py`**: Pattern `r'\{.*\}'` for extracting JSON objects from output strings.

- **Severity:** Moderate
- **Impact:** Denial of Service via CPU exhaustion
- **Attack:** Crafted text input to model/API
- **Affected:** vLLM >= 0.6.3, < 0.9.0
- **Fix:** vLLM 0.9.0+ replaces `re` with `regex` library (PR #18454)

## Expected results

The PoC tests all three patterns by applying each regex directly to crafted strings inside Docker. No running vLLM server or GPU is required. **2/3 patterns confirmed is the expected result.** Pattern 1 (`lora/utils.py`) will show "Not triggered" because the test payload (`"(" + ")" * N + "x"`) does not induce catastrophic backtracking for `r"\((.*?)\)\$?$"` : with a single opening parenthesis the engine runs in O(n) time, below the 3-second threshold. The other two patterns use greedy `.*` constructs that exhibit genuine O(n²) or worse behaviour and will be confirmed on any hardware.

## Quick Start

```bash
./GHSA-j828-28rj-hfhp.sh
```

## Files

| File | Description |
|------|-------------|
| `Dockerfile` | Python 3.10 image with vLLM v0.8.0 source cloned for reference |
| `docker-compose.yml` | Runs the ReDoS test script |
| `exploit.py` | Tests all vulnerable regex patterns with crafted payloads |
| `GHSA-j828-28rj-hfhp.sh` | Setup and run script |

## Cleanup

```bash
docker compose down
```
