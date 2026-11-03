FROM rust:bookworm

RUN apt-get update && apt-get install --yes --no-install-recommends \
    autoconf automake build-essential curl libltdl-dev libssl-dev libtool \
    libxml2-dev mold perl pkg-config time valgrind \
    && rm -rf /var/lib/apt/lists/*

# Link with mold. x86_64 first turns off the self-contained rust-lld it uses by
# default; elsewhere the system linker is replaced and the lld switch is unstable.
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C linker-features=-lld -C link-arg=-fuse-ld=mold" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C link-arg=-fuse-ld=mold"

WORKDIR /src
ENTRYPOINT ["cargo", "run", "--quiet", "-p", "xml-sec-tools", "--", "bench-compare"]
