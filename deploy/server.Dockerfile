FROM rust:1.96-bookworm AS builder

WORKDIR /src
COPY . .
# The base image already pins its stable toolchain. Removing the floating
# `stable` toolchain file avoids a rustup channel sync (network) on every
# build; the host keeps using rust-toolchain.toml for local development.
RUN rm -f rust-toolchain.toml
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build -p mybox-server --release

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/mybox-server /usr/local/bin/mybox-server

EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/mybox-server"]
