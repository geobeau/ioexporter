# ioexporter

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```

## Codegen bindings

Dependencies:
```bash
apt install -y bpftool libclang-dev
bpftool -h # If you don't have it, install from source
cargo install bindgen-cli
```

Generate:
```
cargo xtask codegen
```

Find struct to add:
```
bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep <trace point>
```

