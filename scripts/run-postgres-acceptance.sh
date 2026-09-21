#!/usr/bin/env bash
set -euo pipefail

# PostgreSQL is intentionally internal-only in deploy/docker-compose.yml.
# Run the tests inside that network so this gate exercises the same DNS and
# connection path used by the API instead of depending on host routing to a
# container IP.
repo_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
compose_network="${MYBOX_COMPOSE_NETWORK:-deploy_default}"
database_host="${MYBOX_TEST_DATABASE_HOST:-postgres}"
database_port="${MYBOX_TEST_DATABASE_PORT:-5432}"
database_name="${MYBOX_TEST_DATABASE_NAME:-mybox}"
database_user="${MYBOX_TEST_DATABASE_USER:-mybox}"
database_password="${MYBOX_TEST_DATABASE_PASSWORD:-change-me-local-only}"
database_url="${MYBOX_TEST_DATABASE_URL:-postgres://${database_user}:${database_password}@${database_host}:${database_port}/${database_name}}"
rust_image="${MYBOX_RUST_TEST_IMAGE:-rust:1.96-bookworm}"
target_volume="${MYBOX_RUST_TARGET_VOLUME:-mybox-rust-target}"
cargo_volume="${MYBOX_RUST_CARGO_VOLUME:-mybox-rust-cargo}"
rustup_volume="${MYBOX_RUSTUP_VOLUME:-mybox-rustup}"

docker run --rm \
  --network "$compose_network" \
  --volume "$repo_dir:/src" \
  --volume "$target_volume:/src/target" \
  --volume "$cargo_volume:/cargo-cache" \
  --volume "$rustup_volume:/rustup-cache" \
  --workdir /src \
  --env CARGO_HOME=/cargo-cache \
  --env RUSTUP_HOME=/rustup-cache \
  --env RUSTUP_TOOLCHAIN=1.96.0 \
  --env MYBOX_TEST_DATABASE_URL="$database_url" \
  "$rust_image" \
  sh -ceu '
    cargo test -p mybox-server --test postgres_sync -- --ignored --nocapture
    cargo test -p mybox-server --test http_sync -- --ignored --nocapture
    cargo test -p mybox-server --lib postgres::tests::postgres_listener_forwards_committed_events_between_instances -- --ignored --nocapture
    cargo test -p mybox-server --lib postgres::tests::postgres_reconcile_transaction_faults_roll_back_all_stages -- --ignored --nocapture
  '

printf 'Database-backed sync acceptance passed on network %s\n' "$compose_network"
