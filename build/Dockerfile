# Cross-compilation toolchain for rs_srp.
#
# Baked once into an image so repeat builds skip the apt/rustup setup. It can
# produce the Linux (x86_64, glibc) and Windows (x86_64, GNU) binaries; macOS
# binaries can only be built on a macOS host, so build.sh does that natively.
#
# Debian bullseye gives glibc 2.31 — old enough that the Linux binary runs on
# any reasonably modern distro (Ubuntu 20.04+, etc.).
FROM rust:1-bullseye

# C cross-toolchains: an x86_64-linux linker (needed when the build host is
# arm64) and the mingw-w64 toolchain for Windows.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      gcc-x86-64-linux-gnu \
      gcc-mingw-w64-x86-64 \
 && rm -rf /var/lib/apt/lists/*

# Rust std for the cross targets.
RUN rustup target add x86_64-unknown-linux-gnu x86_64-pc-windows-gnu

# Point cargo and the `cc` crate (used by ring) at the cross compilers.
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc \
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
    CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc

WORKDIR /work
