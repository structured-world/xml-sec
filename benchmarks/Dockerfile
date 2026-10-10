FROM rust:1.92-bookworm

RUN apt-get update && apt-get install --yes --no-install-recommends \
    autoconf automake build-essential curl jq libltdl-dev libssl-dev libtool \
    libxml2-dev nodejs perl pkg-config time valgrind \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
ENTRYPOINT ["bash", "scripts/benchmark-compare.sh"]
