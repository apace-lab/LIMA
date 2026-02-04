# CVE-2024-12055: Ollama Out-of-Bounds Read (gguf.go)

Docker-based Proof of Concept for reproducing [CVE-2024-12055](https://huntr.com/bounties/7b111d55-8215-4727-8807-c5ed4cf1bfbe).

## Vulnerability Summary

Ollama <= 0.3.14 has a CWE-125 (Out-of-Bounds Read) vulnerability in the GGUF parser (`gguf.go`). A malicious user can create a customized GGUF model file that, when uploaded to an Ollama server, causes the server to crash when processing the file—leading to Denial of Service (DoS).

- **CVSS:** 7.5 (HIGH)
- **Impact:** Server crash / Denial of Service
- **Attack:** No authentication required, network-accessible
- **Fix:** Upgrade to Ollama 0.3.15 or later

## Quick Start

```bash
# Run the full demo (creates malicious GGUF, starts Ollama, triggers crash, verifies)
./CVE-2024-12055.sh
```
The script automatically goes through everything and displays the crash to the user using the container
logs when it is successful.

## How It Works

1. **Malicious GGUF**: The `create_malicious_gguf.py` script generates a GGUF file with `general.alignment=0`. This causes the parser to miscalculate offsets when processing metadata.
2. **Modelfile**: References the malicious GGUF via `FROM /poc/malicious.gguf`.
3. **Model creation**: When `ollama create` parses the GGUF, `readGGUFString` in `gguf.go` attempts to allocate a slice with an invalid length, triggering `panic: runtime error: makeslice: len out of range` and crashing the server (DoS).

## Cleanup

```bash
docker compose down
docker volume rm cve-2024-12055_ollama_data 2>/dev/null || true
```
