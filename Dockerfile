FROM ghcr.io/rust-lang/rust:nightly-bookworm as builder

RUN apt-get update \
    && apt-get install -y \
    libssl-dev \
    llvm-14-dev \
    musl \
    musl-dev \
    musl-tools \
    pkg-config
RUN rustup component add rust-src
RUN rustup target add x86_64-unknown-linux-musl
RUN cargo install bpf-linker
COPY . /src/ioexporter
WORKDIR /src/ioexporter
RUN --mount=type=cache,target=/.root/cargo/registry \
    --mount=type=cache,target=/src/ioexporter/target \
    cargo xtask build-ebpf --release \
    && cargo build --release --target=x86_64-unknown-linux-musl \
    && ls -lR \
    && cp /src/ioexporter/target/x86_64-unknown-linux-musl/release/ioexporter /usr/sbin


FROM ghcr.io/rust-lang/rust:nightly-bookworm
COPY --from=builder /usr/sbin/ioexporter /usr/sbin/
ENTRYPOINT [ "/usr/sbin/ioexporter" ]
