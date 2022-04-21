ARG ALPINE_CORE_IMAGE
FROM ${ALPINE_CORE_IMAGE} as builder
USER indy
WORKDIR /home/indy

COPY --chown=indy  ./ ./

USER indy
ENV X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_NO_VENDOR "true"
RUN cargo build --release --manifest-path=/home/indy/Cargo.toml
USER root
RUN mv /home/indy/target/release/libvcx.so .


FROM alpine:3.12
ARG UID=1000
ARG GID=1000
RUN addgroup -g $GID node && adduser -u $UID -D -G node node

COPY --from=builder /usr/lib/libindy.so /home/indy/lib*.so /usr/lib/

WORKDIR /home/node
RUN echo '@alpine38 http://dl-cdn.alpinelinux.org/alpine/v3.8/main' >> /etc/apk/repositories
RUN apk update && apk upgrade
RUN apk add --no-cache \
        bash \
        g++ \
        gcc \
        git \
        libsodium-dev \
        libzmq \
        nodejs \
        npm \
        make \
        openssl-dev \
        python2 \
        zeromq-dev
USER node