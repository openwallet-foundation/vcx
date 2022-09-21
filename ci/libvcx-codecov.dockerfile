FROM ubuntu:18.04 as BASE

ARG UID=1000

ARG RUST_VER=nightly-2022-09-15

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
      apt-transport-https \
      build-essential \
      ca-certificates \
      cmake \
      curl \
      debhelper \
      devscripts \
      git \
      libssl-dev \
      libsqlite3-dev \
      libzmq3-dev \
      libzmq5 \
      pkg-config

# Install libsodium
RUN cd /tmp && \
   curl https://download.libsodium.org/libsodium/releases/libsodium-1.0.18.tar.gz | tar -xz && \
    cd /tmp/libsodium-1.0.18 && \
    ./configure && \
    make && \
    make install && \
    rm -rf /tmp/libsodium-1.0.18

RUN useradd -ms /bin/bash -u $UID indy

USER indy
WORKDIR /home/indy
COPY --chown=indy ./ aries-vcx/

# Install Rust toolchain
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain ${RUST_VER}
ENV PATH /home/indy/.cargo/bin:$PATH

# Build indy binaries and move to system library
USER indy
RUN cargo build --release --manifest-path=/home/indy/aries-vcx/Cargo.toml

USER root
RUN mv /usr/local/lib/libsodium.* \
    /usr/lib/x86_64-linux-gnu/libssl* \
    /usr/lib

USER indy

RUN cargo install grcov --version 0.8.9
