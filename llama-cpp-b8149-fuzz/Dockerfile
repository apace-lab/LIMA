FROM ubuntu:22.04 AS builder
RUN apt-get update && apt-get install -y git build-essential cmake
WORKDIR /build
RUN git clone https://github.com/ggml-org/llama.cpp.git && \
    cd llama.cpp && git checkout b8149
WORKDIR /build/llama.cpp
RUN cmake -B build -DBUILD_SHARED_LIBS=OFF -DLLAMA_CURL=OFF && \
    cmake --build build -j$(nproc)

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y libgomp1 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/llama.cpp/build/bin/llama-cli /usr/local/bin/llama-cli
WORKDIR /workspace
