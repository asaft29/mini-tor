#!/usr/bin/env bash
#
# demo_rotation.sh — 9 relays (3E/3M/3X) + tor-client with TUI.
# With 3 entries and 3 exits, each 15s circuit rebuild picks a different relay.
# Uses gRPC polling to verify readiness instead of fixed sleeps.
#
# Requires: grpcurl (go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest)
#
# Usage: bash scripts/demo_rotation.sh
#        Press 'q' or Ctrl+C to quit.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$ROOT_DIR/logs"
DISCOVERY_PORT=8080
DISCOVERY_URL="http://127.0.0.1:$DISCOVERY_PORT"
SOCKS_PORT=1080

mkdir -p "$LOG_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
RESET='\033[0m'

cleanup() {
    echo ""
    echo "Shutting down all services..."
    pkill -f "relay-node" 2>/dev/null || true
    pkill -f "tor-client" 2>/dev/null || true
    pkill -f "discovery" 2>/dev/null || true
    for port in 9001 9002 9003 9101 9102 9103 9201 9202 9203 8080 1080; do
        fuser -k ${port}/tcp 2>/dev/null || true
    done
    echo "Done."
}
trap cleanup EXIT INT TERM

# ── Aggressive pre-cleanup ──

echo "Cleaning up stale processes..."
for port in 9001 9002 9003 9101 9102 9103 9201 9202 9203 8080 1080; do
    fuser -k ${port}/tcp 2>/dev/null || true
done
sleep 1

# ── Check for grpcurl ──

HAVE_GRPCURL=false
if command -v grpcurl &>/dev/null; then
    HAVE_GRPCURL=true
else
    echo "  (grpcurl not found — using sleep-based waits instead)"
    echo "  Install for faster startup: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest"
fi

# ── Wait helpers ──

wait_for_discovery() {
    if [ "$HAVE_GRPCURL" = true ]; then
        echo -n "  Waiting for discovery gRPC..."
        for i in $(seq 1 20); do
            if grpcurl -plaintext "127.0.0.1:$DISCOVERY_PORT" list 2>/dev/null | grep -qi Discovery; then
                echo -e " ${GREEN}ready${RESET}"
                return 0
            fi
            sleep 0.5
        done
        echo -e " ${RED}failed${RESET}"
        return 1
    else
        sleep 3
    fi
}

wait_for_relays() {
    local expected=$1
    if [ "$HAVE_GRPCURL" = true ]; then
        echo -n "  Waiting for ${expected} relays to register..."
        for i in $(seq 1 30); do
            local count
            count=$(grpcurl -plaintext "127.0.0.1:$DISCOVERY_PORT" \
                discovery.services.Discovery/GetStats 2>/dev/null | \
                python3 -c 'import json,sys; print(json.load(sys.stdin)["totalNodes"])' 2>/dev/null || echo 0)
            if [ "${count:-0}" -ge "$expected" ]; then
                echo -e " ${GREEN}${count} relays${RESET}"
                return 0
            fi
            sleep 1
        done
        echo -e " ${RED}timeout${RESET}"
        return 1
    else
        sleep 10
    fi
}

# ── Build (only if needed) ──

cd "$ROOT_DIR"
if [ ! -f target/release/discovery ] || [ ! -f target/release/relay-node ] || [ ! -f target/release/tor-client ]; then
    echo "Building release binaries..."
    cargo build --release
fi

# ── Start services ──

echo ""
echo -e "${BOLD}Starting Discovery Service...${RESET}"
cargo run --release -p discovery --quiet -- --port "$DISCOVERY_PORT" --allow-same-ip > "$LOG_DIR/discovery.log" 2>&1 &
wait_for_discovery

echo ""
echo -e "${BOLD}Starting 9 relay nodes (3E/3M/3X)...${RESET}"

cargo run --release -p relay-node --quiet -- --node-type entry  --port 9001 --directory-url "$DISCOVERY_URL" > "$LOG_DIR/relay-entry-9001.log" 2>&1 &
cargo run --release -p relay-node --quiet -- --node-type entry  --port 9002 --directory-url "$DISCOVERY_URL" > "$LOG_DIR/relay-entry-9002.log" 2>&1 &
cargo run --release -p relay-node --quiet -- --node-type entry  --port 9003 --directory-url "$DISCOVERY_URL" > "$LOG_DIR/relay-entry-9003.log" 2>&1 &

cargo run --release -p relay-node --quiet -- --node-type middle --port 9101 --directory-url "$DISCOVERY_URL" > "$LOG_DIR/relay-middle-9101.log" 2>&1 &
cargo run --release -p relay-node --quiet -- --node-type middle --port 9102 --directory-url "$DISCOVERY_URL" > "$LOG_DIR/relay-middle-9102.log" 2>&1 &
cargo run --release -p relay-node --quiet -- --node-type middle --port 9103 --directory-url "$DISCOVERY_URL" > "$LOG_DIR/relay-middle-9103.log" 2>&1 &

cargo run --release -p relay-node --quiet -- --node-type exit   --port 9201 --directory-url "$DISCOVERY_URL" > "$LOG_DIR/relay-exit-9201.log" 2>&1 &
cargo run --release -p relay-node --quiet -- --node-type exit   --port 9202 --directory-url "$DISCOVERY_URL" > "$LOG_DIR/relay-exit-9202.log" 2>&1 &
cargo run --release -p relay-node --quiet -- --node-type exit   --port 9203 --directory-url "$DISCOVERY_URL" > "$LOG_DIR/relay-exit-9203.log" 2>&1 &

wait_for_relays 9

echo ""
echo -e "${BOLD}Starting Tor Client with TUI${RESET} (--hops 3, pool-size 1)"
echo "  Watch the circuit path change every 15 seconds!"
echo "  Press 'q' to quit."
echo ""

cargo run --release -p tor-client --quiet -- --tui --hops 3 --pool-size 1 --directory-url "$DISCOVERY_URL" --socks-addr "127.0.0.1:$SOCKS_PORT"
