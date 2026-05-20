# build/

Release-build tooling for rs_srp.

- **`build.sh`** — builds release binaries for Linux, Windows, and macOS.
- **`Dockerfile`** — a containerised cross-compile toolchain, for CI or hosts
  where the native path is not wanted.

## build.sh (recommended)

```sh
./build/build.sh
```

Cross-compiles with [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild):
every target builds natively on the host, so there is no Docker image to
rebuild and no container filesystem overhead. `cargo-zigbuild` is installed
automatically if missing; the `zig` toolchain must already be present
(`brew install zig`, `apt install zig`, …).

The macOS binaries are produced only when `build.sh` runs on a Mac.

## Output

Binaries (`rs_srpd`, `rs_srpc`) land under `build/dist/`:

```
build/dist/linux-x86_64/      rs_srpd      rs_srpc
build/dist/windows-x86_64/    rs_srpd.exe  rs_srpc.exe
build/dist/macos-<arch>/      rs_srpd      rs_srpc       (Mac host only)
```

The Linux binary targets glibc 2.31, so it runs on any reasonably modern
distribution (Ubuntu 20.04+, Debian 11+, …).

## Dockerfile

`build/Dockerfile` bakes a Linux + Windows cross toolchain into an image, built
once and reused:

```sh
docker build -t rs_srp-builder build
docker run --rm -v "$PWD":/work -w /work rs_srp-builder \
    cargo build --release --target x86_64-unknown-linux-gnu
```

Use this on machines where a containerised build is preferred. To add targets
(e.g. `aarch64-unknown-linux-gnu`), extend the `--target` list in `build.sh`.
