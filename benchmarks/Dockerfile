FROM rust:bookworm

RUN apt-get update && apt-get install --yes --no-install-recommends \
    autoconf automake build-essential curl libltdl-dev libssl-dev libtool \
    libxml2-dev perl pkg-config time valgrind \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
ENTRYPOINT ["cargo", "run", "--quiet", "-p", "xml-sec-tools", "--", "bench-compare"]
