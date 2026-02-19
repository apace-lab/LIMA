# GHSA-j828-28rj-hfhp: vLLM Multiple ReDoS Vulnerabilities
# Lightweight image - only needs Python and the vulnerable regex patterns

FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Clone vllm at vulnerable version to reference the actual source files
RUN git clone --depth 1 --branch v0.8.0 https://github.com/vllm-project/vllm.git /vllm-src

WORKDIR /workspace
COPY exploit.py /workspace/
