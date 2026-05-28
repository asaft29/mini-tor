#!/usr/bin/env bash
#
# demo.sh — Launch the full Tor-like onion routing system on localhost.
#
# Starts:  discovery (port 8080)
#          entry relay (port 9001)
#          middle relay (port 9002)
#          exit relay (port 9003)
#          tor-client SOCKS5 proxy (port 1080)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# --- Configuration (override via env vars) --------
DISCOVERY_PORT="${DISCOVERY_PORT:-8080}"
ENTRY_PORT="${ENTRY_PORT:-9001}"
MIDDLE_PORT="${MIDDLE_PORT:-9002}"
EXIT_PORT="${EXIT_PORT:-9003}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
POOL_SIZE="${POOL_SIZE:-3}"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/logs}"
RUST_LOG="${RUST_LOG:-info}"
# ---------------------------------------------------

SKIP_BUILD=false
NO_TUI=false
for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=true ;;
        --no-tui) NO_TUI=true ;;
        --help|-h)
            echo "Usage: $0 [--skip-build] [--no-tui]"
            echo ""
            echo "Launches the full onion routing demo on localhost."
            echo "By default the tor-client runs with a TUI dashboard."
            echo ""
            echo "Options:"
            echo "  --skip-build   Skip cargo build, use existing binaries"
            echo "  --no-tui       Run tor-client in the background (log to file)"
            echo ""
            echo "Environment variables:"
            echo "  DISCOVERY_PORT  Discovery service port  (default: 8080)"
            echo "  ENTRY_PORT      Entry relay port        (default: 9001)"
            echo "  MIDDLE_PORT     Middle relay port       (default: 9002)"
            echo "  EXIT_PORT       Exit relay port         (default: 9003)"
            echo "  SOCKS_PORT      SOCKS5 proxy port       (default: 1080)"
            echo "  POOL_SIZE       Circuit pool size        (default: 3)"
            echo "  LOG_DIR         Log output directory     (default: ./logs)"
            echo "  RUST_LOG        Log level filter         (default: info)"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg (try --help)"
            exit 1
            ;;
    esac
done

# Collect background PIDs so we can clean up on exit
PIDS=()

cleanup() {
    echo ""
    echo "==> Shutting down all services..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    # Give processes a moment to unregister from discovery
    sleep 1
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
    echo "==> All services stopped."
}

trap cleanup EXIT INT TERM

# ---- Helpers ----

wait_for_http() {
    local url="$1"
    local name="$2"
    local max_attempts="${3:-30}"
    local attempt=0

    while [ "$attempt" -lt "$max_attempts" ]; do
        if curl -sf "$url" >/dev/null 2>&1; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 0.5
    done
    echo "ERROR: $name did not become ready at $url after $max_attempts attempts"
    return 1
}

wait_for_tcp() {
    local host="$1"
    local port="$2"
    local name="$3"
    local max_attempts="${4:-30}"
    local attempt=0

    while [ "$attempt" -lt "$max_attempts" ]; do
        if bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 0.5
    done
    echo "ERROR: $name did not start listening on $host:$port after $max_attempts attempts"
    return 1
}

section() {
    echo ""
    echo "========================================"
    echo "  $1"
    echo "========================================"
}

# ---- Build ----

if [ "$SKIP_BUILD" = false ]; then
    section "Building all services (release)"
    cargo build --release --manifest-path "$ROOT_DIR/Cargo.toml"
    echo "Build successful."
else
    echo "(Skipping build — using existing binaries)"
fi

DISCOVERY_BIN="$ROOT_DIR/target/release/discovery"
RELAY_BIN="$ROOT_DIR/target/release/relay-node"
CLIENT_BIN="$ROOT_DIR/target/release/tor-client"

for bin in "$DISCOVERY_BIN" "$RELAY_BIN" "$CLIENT_BIN"; do
    if [ ! -x "$bin" ]; then
        echo "ERROR: Binary not found: $bin"
        echo "Run without --skip-build to compile first."
        exit 1
    fi
done

# ---- Prepare log directory ----

mkdir -p "$LOG_DIR"
echo "Logs will be written to: $LOG_DIR"

# ---- Check for port conflicts ----

check_port() {
    local port="$1"
    local name="$2"
    if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
        echo "ERROR: Port $port is already in use (needed for $name)"
        echo "Kill the process using it or set ${name}_PORT env var."
        exit 1
    fi
}

check_port "$DISCOVERY_PORT" "DISCOVERY"
check_port "$ENTRY_PORT" "ENTRY"
check_port "$MIDDLE_PORT" "MIDDLE"
check_port "$EXIT_PORT" "EXIT"
check_port "$SOCKS_PORT" "SOCKS"

# ---- Launch Discovery Service ----

section "Starting Discovery Service (port $DISCOVERY_PORT)"

RUST_LOG="$RUST_LOG" \
    "$DISCOVERY_BIN" \
    > "$LOG_DIR/discovery.log" 2>&1 &
PIDS+=($!)
echo "  PID: ${PIDS[-1]}"

wait_for_tcp 127.0.0.1 "$DISCOVERY_PORT" "Discovery gRPC"
echo "  Discovery gRPC service is listening."
echo "  Web UI at http://127.0.0.1:${DISCOVERY_WEB_PORT:-8081}"

# ---- Launch Relay Nodes ----

start_relay() {
    local node_type="$1"
    local port="$2"

    section "Starting $node_type relay (port $port)"

    RUST_LOG="$RUST_LOG" \
        "$RELAY_BIN" \
        --node-type "$node_type" \
        --port "$port" \
        --host 127.0.0.1 \
        --directory-url "http://127.0.0.1:$DISCOVERY_PORT" \
        > "$LOG_DIR/relay-${node_type}.log" 2>&1 &
    PIDS+=($!)
    echo "  PID: ${PIDS[-1]}"

    wait_for_tcp 127.0.0.1 "$port" "$node_type relay"
    echo "  $node_type relay is listening."
}

start_relay entry "$ENTRY_PORT"
start_relay middle "$MIDDLE_PORT"
start_relay exit "$EXIT_PORT"

# Wait for discovery to be ready (give relays time to register)
echo ""
echo "Waiting for relays to register with discovery..."
sleep 5
echo "Discovery should now be ready with 3 relay nodes."

# Print registered nodes via gRPC
echo ""
echo "Registered nodes (use grpcurl to list):"
echo "  grpcurl -plaintext 127.0.0.1:$DISCOVERY_PORT discovery.Discovery/GetAllNodes"

# ---- Launch Tor Client ----

section "Starting Tor Client (SOCKS5 on port $SOCKS_PORT)"

if [ "$NO_TUI" = true ]; then
    # Background mode — log to file, no TUI
    RUST_LOG="$RUST_LOG" \
        "$CLIENT_BIN" \
        --socks-addr "127.0.0.1:$SOCKS_PORT" \
        --directory-url "http://127.0.0.1:$DISCOVERY_PORT" \
        --pool-size "$POOL_SIZE" \
        > "$LOG_DIR/tor-client.log" 2>&1 &
    PIDS+=($!)
    echo "  PID: ${PIDS[-1]}"

    # Give the client time to build its circuit pool
    echo "  Waiting for tor-client to build circuits..."
    wait_for_tcp 127.0.0.1 "$SOCKS_PORT" "tor-client SOCKS5" 60
    echo "  Tor client SOCKS5 proxy is ready."

    # ---- Summary ----

    section "All services running!"

    echo ""
    echo "  Discovery gRPC:  127.0.0.1:$DISCOVERY_PORT  (gRPC reflection enabled)"
    echo "  Web UI:          http://127.0.0.1:${DISCOVERY_WEB_PORT:-8081}"
    echo "  Entry relay:  127.0.0.1:$ENTRY_PORT"
    echo "  Middle relay: 127.0.0.1:$MIDDLE_PORT"
    echo "  Exit relay:   127.0.0.1:$EXIT_PORT"
    echo "  SOCKS5 proxy: 127.0.0.1:$SOCKS_PORT"
    echo ""
    echo "  Log directory: $LOG_DIR/"
    echo ""
    echo "Test with:"
    echo "  curl --socks5 127.0.0.1:$SOCKS_PORT http://example.com"
    echo "  curl --socks5 127.0.0.1:$SOCKS_PORT http://httpbin.org/ip"
    echo ""
    echo "Monitor logs:"
    echo "  tail -f $LOG_DIR/discovery.log"
    echo "  tail -f $LOG_DIR/relay-entry.log"
    echo "  tail -f $LOG_DIR/tor-client.log"
    echo ""
    echo "Press Ctrl+C to stop all services."
    echo ""

    # ---- Keep alive until Ctrl+C ----

    while true; do
        for i in "${!PIDS[@]}"; do
            pid="${PIDS[$i]}"
            if ! kill -0 "$pid" 2>/dev/null; then
                wait "$pid" 2>/dev/null
                exit_code=$?
                if [ "$exit_code" -ne 0 ]; then
                    echo "WARNING: Process $pid exited with code $exit_code"
                    echo "Check logs in $LOG_DIR/ for details."
                fi
                unset 'PIDS[$i]'
            fi
        done

        if [ "${#PIDS[@]}" -eq 0 ]; then
            echo "All services have stopped."
            exit 1
        fi

        sleep 2
    done
else
    # TUI mode (default) — tor-client runs in foreground with --tui
    echo "  Launching tor-client with TUI dashboard..."
    echo "  (Press 'q' in the TUI or Ctrl+C to stop everything)"
    echo ""
    echo "  Discovery gRPC:  127.0.0.1:$DISCOVERY_PORT  (gRPC reflection enabled)"
    echo "  Web UI:          http://127.0.0.1:${DISCOVERY_WEB_PORT:-8081}"
    echo "  Entry relay:  127.0.0.1:$ENTRY_PORT"
    echo "  Middle relay: 127.0.0.1:$MIDDLE_PORT"
    echo "  Exit relay:   127.0.0.1:$EXIT_PORT"
    echo "  SOCKS5 proxy: 127.0.0.1:$SOCKS_PORT"
    echo ""
    echo "Test from another terminal:"
    echo "  curl --socks5 127.0.0.1:$SOCKS_PORT http://example.com"
    echo ""

    # Run tor-client in the foreground — the TUI takes over the terminal.
    # When the user quits (q / Ctrl+C), this process exits and the
    # cleanup trap fires, stopping all background services.
    RUST_LOG="$RUST_LOG" \
        "$CLIENT_BIN" \
        --socks-addr "127.0.0.1:$SOCKS_PORT" \
        --directory-url "http://127.0.0.1:$DISCOVERY_PORT" \
        --pool-size "$POOL_SIZE" \
        --tui
    # When tor-client exits, the EXIT trap cleans up background services.
fi
