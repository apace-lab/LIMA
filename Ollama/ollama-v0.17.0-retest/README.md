# Ollama v0.17.0 Vulnerability Retest

Retests 4 known-unfixed Ollama CVEs against the latest stable release (v0.17.0, 2026-02-21).

## CVEs Tested

| CVE | CWE | GGUF Payload | Expected Crash |
|-----|-----|-------------|----------------|
| CVE-2025-0317 | Divide by Zero | `general.alignment=0` | `ggufPadding()` panic |
| CVE-2025-0315 | Unbounded Alloc | Inflated dimensions (1M embedding, 16K blocks) | OOM / unresponsive |
| CVE-2025-0312 | Null Ptr Deref | Tensor with `dims=[0,256]` | nil pointer panic |
| CVE-2024-12055 | OOB Read | `general.alignment=0` | `readGGUFString` makeslice panic |

## Usage

```bash
./run_tests.sh
```

Requires: Docker, Python 3, curl.

## What This Tests

These 4 CVEs were confirmed unfixed as of Ollama v0.16.2 (our previous analysis).
This retest checks whether v0.17.0 has silently fixed any of them.

- If a CVE still crashes: the vulnerability persists in the latest release
- If a CVE no longer crashes: Ollama fixed it (check changelog/commits for the fix)
