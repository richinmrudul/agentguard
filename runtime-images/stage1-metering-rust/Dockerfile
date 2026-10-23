# syntax=docker/dockerfile:1.7
FROM --platform=linux/amd64 docker.io/library/rust:1.95.0-alpine3.22@sha256:2805e96db5234c9cfaf7ecb50f488693dab84d28ad30b6290cc1b707a18bf775 AS builder

WORKDIR /build
COPY --chmod=0444 runtime-images/stage1-metering-rust/Cargo.toml runtime-images/stage1-metering-rust/Cargo.lock runtime-images/stage1-metering-rust/rust-toolchain.toml ./
COPY --chmod=0444 runtime-images/stage1-metering-rust/src/ ./src/
COPY --chmod=0444 agentguard/evaluation/stage1_pricing_v2.json /agentguard/evaluation/stage1_pricing_v2.json
RUN RUSTFLAGS='-C target-feature=+crt-static --remap-path-prefix=/build=.' \
    cargo build --release --locked --target x86_64-unknown-linux-musl

FROM scratch
LABEL org.opencontainers.image.title="AgentGuard Stage 1 compiled metering gateway candidate"
LABEL org.opencontainers.image.licenses="MIT"
COPY --from=builder --chmod=0555 /build/target/x86_64-unknown-linux-musl/release/agentguard-stage1-metering-gateway /stage1-metering-gateway
USER 65532:65532
WORKDIR /
EXPOSE 8080
ENTRYPOINT ["/stage1-metering-gateway"]
