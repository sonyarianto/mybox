FROM rust:1.96-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build -p mybox-server --release --bin browser_acceptance

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/browser_acceptance /usr/local/bin/mybox-browser-acceptance
COPY apps/web/dist /app/dist
ENV MYBOX_BROWSER_STATIC_DIR=/app/dist
EXPOSE 3301
ENTRYPOINT ["/usr/local/bin/mybox-browser-acceptance"]
