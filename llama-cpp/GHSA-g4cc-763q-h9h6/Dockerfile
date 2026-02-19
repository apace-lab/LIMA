FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y \
    git build-essential cmake

WORKDIR /build
RUN git clone https://github.com/ggml-org/llama.cpp.git && \
    cd llama.cpp && \
    git checkout c33fe8b8~1

WORKDIR /build/llama.cpp
RUN cmake -B build -DLLAMA_CURL=OFF -DBUILD_SHARED_LIBS=OFF && cmake --build build -j$(nproc)

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y libgomp1 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/llama.cpp/build/bin/llama-cli /usr/local/bin/llama-cli
WORKDIR /workspace
