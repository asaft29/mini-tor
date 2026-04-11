#!/usr/bin/env bash
#
# demo_circuit.sh — Launch a demo with a configurable number of relay hops.
#
# Usage: ./scripts/demo_circuit.sh <num_hops> [options]
#
# <num_hops>  Number of relay nodes in the circuit (3–10).
#             Layout: 1 entry + (N-2) middle relays + 1 exit.
#
# Options:
#   --no-tui       Run tor-client in background (logs to file, no dashboard)
#   --skip-build   Skip cargo build, use existing release binaries
#   --yes          Skip the 10-hop confirmation prompt
#   --help, -h     Show this help

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# ---- Terminal colours (disabled when not a TTY) ----

if [ -t 2 ] && tput colors &>/dev/null && [ "$(tput colors)" -ge 8 ]; then
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    BOLD='\033[1m'
    RESET='\033[0m'
    TICK='✔'
    CROSS='✘'
    WARN='⚠'
else
    RED='' YELLOW='' BOLD='' RESET=''
    TICK='[ok]' CROSS='[error]' WARN='[warn]'
fi

# Print a styled error to stderr and exit.
die() {
    printf "${RED}${BOLD}  %s  error${RESET}${RED} · %s${RESET}\n" "$CROSS" "$*" >&2
    exit 1
}

# Print a styled warning to stderr (no exit).
warn() {
    printf "${YELLOW}${BOLD}  %s  warning${RESET}${YELLOW} · %s${RESET}\n" "$WARN" "$*" >&2
}

# ---- Parse arguments ----

NUM_HOPS=""
SKIP_BUILD=false
NO_TUI=false
AUTO_YES=false

for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=true ;;
        --no-tui)     NO_TUI=true ;;
        --yes|-y)     AUTO_YES=true ;;
        --help|-h)
            echo "Usage: $0 <num_hops> [--skip-build] [--no-tui] [--yes]"
            echo ""
            echo "Launch a demo with <num_hops> relay nodes on localhost."
            echo "  <num_hops>  Circuit size: 3–10 hops"
            echo "              Layout: 1 entry + (N-2) middles + 1 exit"
            echo ""
            echo "Options:"
            echo "  --skip-build   Use existing release binaries (skip cargo build)"
            echo "  --no-tui       Run tor-client in background with log output"
            echo "  --yes, -y      Skip the 10-hop confirmation prompt"
            echo ""
            echo "Environment variables:"
            echo "  DISCOVERY_PORT  Discovery service port (default: 8080)"
            echo "  SOCKS_PORT      SOCKS5 proxy port      (default: 1080)"
            echo "  POOL_SIZE       Circuit pool size       (default: 1)"
            echo "  BASE_PORT       Starting port for relays (default: random)"
            echo "  LOG_DIR         Log output directory    (default: ./logs)"
            echo "  RUST_LOG        Log level filter        (default: info)"
            echo ""
            echo "Examples:"
            echo "  $0 3           # Minimal: entry → middle → exit"
            echo "  $0 5 --no-tui  # 5-hop circuit, background mode"
            echo "  $0 10 --yes    # Maximum circuit, skip confirmation"
            exit 0
            ;;
        [0-9]*)
            NUM_HOPS="$arg"
            ;;
        *)
            die "Unknown option: $arg  (run '$0 --help' for usage)"
            ;;
    esac
done

# ---- Validate num_hops ----

if [ -z "$NUM_HOPS" ]; then
    die "<num_hops> is required — run '$0 --help' for usage"
fi

if ! [[ "$NUM_HOPS" =~ ^[0-9]+$ ]]; then
    die "<num_hops> must be a positive integer, got: $NUM_HOPS"
fi

if [ "$NUM_HOPS" -lt 3 ]; then
    die "minimum circuit size is 3 hops (1 entry + 1 middle + 1 exit), got $NUM_HOPS"
fi

if [ "$NUM_HOPS" -gt 10 ]; then
    die "maximum circuit size is 10 hops, got $NUM_HOPS — try a value between 3 and 10"
fi

NUM_MIDDLES=$((NUM_HOPS - 2))

# ---- 10-hop confirmation ----

if [ "$NUM_HOPS" -eq 10 ] && [ "$AUTO_YES" = false ]; then
    echo ""
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    echo "  ║  ⚠  Maximum circuit size requested: 10 hops                 ║"
    echo "  ║                                                              ║"
    echo "  ║  This will launch 10 relay processes:                        ║"
    echo "  ║    1 entry  +  8 middle relays  +  1 exit                    ║"
    echo "  ║                                                              ║"
    echo "  ║  10 is the maximum allowed value. Expect higher latency      ║"
    echo "  ║  and more resource usage than a standard 3-hop circuit.      ║"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
    echo ""
    read -r -p "  Do you understand and want to build a 10-hop circuit? [yes/N] " answer
    if [ "$answer" != "yes" ] && [ "$answer" != "YES" ]; then
        echo "Aborted. Use a smaller value (3–9) or pass --yes to skip this prompt."
        exit 0
    fi
    echo ""
fi

# ---- Config from env ----

DISCOVERY_PORT="${DISCOVERY_PORT:-8080}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
POOL_SIZE="${POOL_SIZE:-1}"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/logs}"
RUST_LOG="${RUST_LOG:-info}"

# ---- Port allocation ----
#
# Pick NUM_HOPS free ports randomly from the ephemeral range 20000–55000,
# avoiding DISCOVERY_PORT and SOCKS_PORT.

RESERVED_PORTS=("$DISCOVERY_PORT" "$SOCKS_PORT")
RELAY_PORTS=()

find_free_port() {
    local attempt
    for attempt in $(seq 1 200); do
        local candidate
        candidate=$(shuf -i 20000-55000 -n 1)

        # Skip reserved ports
        local skip=false
        for rp in "${RESERVED_PORTS[@]}"; do
            if [ "$candidate" -eq "$rp" ]; then
                skip=true
                break
            fi
        done
        [ "$skip" = true ] && continue

        # Skip already-allocated relay ports
        for ap in "${RELAY_PORTS[@]}"; do
            if [ "$candidate" -eq "$ap" ]; then
                skip=true
                break
            fi
        done
        [ "$skip" = true ] && continue

        # Check the port is free on the system
        if ! ss -tlnp 2>/dev/null | grep -q ":${candidate} "; then
            echo "$candidate"
            return
        fi
    done
    die "could not find a free port after 200 attempts"
}

for _ in $(seq 1 "$NUM_HOPS"); do
    port=$(find_free_port)
    RELAY_PORTS+=("$port")
    RESERVED_PORTS+=("$port")
done

# ---- Assign roles ----
# RELAY_PORTS[0]           → entry
# RELAY_PORTS[1..N-2]      → middle (NUM_MIDDLES nodes)
# RELAY_PORTS[N-1]         → exit

ENTRY_PORT="${RELAY_PORTS[0]}"
EXIT_PORT="${RELAY_PORTS[$((NUM_HOPS - 1))]}"
MIDDLE_PORTS=("${RELAY_PORTS[@]:1:$NUM_MIDDLES}")

# ---- Helpers ----

PIDS=()

cleanup() {
    echo ""
    echo "==> Shutting down all services..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    sleep 0.8
    for pid in "${PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    echo "==> Done."
}

trap cleanup EXIT INT TERM

wait_for_http() {
    local url="$1" name="$2" max="${3:-40}" attempt=0
    while [ "$attempt" -lt "$max" ]; do
        if curl -sf "$url" >/dev/null 2>&1; then return 0; fi
        attempt=$((attempt + 1))
        sleep 0.5
    done
    printf "${RED}${BOLD}  %s  error${RESET}${RED} · %s did not become ready at %s${RESET}\n" \
        "$CROSS" "$name" "$url" >&2
    return 1
}

wait_for_tcp() {
    local host="$1" port="$2" name="$3" max="${4:-40}" attempt=0
    while [ "$attempt" -lt "$max" ]; do
        if bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then return 0; fi
        attempt=$((attempt + 1))
        sleep 0.5
    done
    printf "${RED}${BOLD}  %s  error${RESET}${RED} · %s not listening on %s:%s${RESET}\n" \
        "$CROSS" "$name" "$host" "$port" >&2
    return 1
}

section() {
    echo ""
    echo "──────────────────────────────────────────"
    echo "  $1"
    echo "──────────────────────────────────────────"
}

check_port() {
    local port="$1" name="$2"
    if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
        die "port $port is already in use (needed for $name)"
    fi
}

# ---- Pre-flight checks ----

check_port "$DISCOVERY_PORT" "discovery"
check_port "$SOCKS_PORT" "SOCKS5 proxy"

# ---- Build ----

DISCOVERY_BIN="$ROOT_DIR/target/release/discovery"
RELAY_BIN="$ROOT_DIR/target/release/relay-node"
CLIENT_BIN="$ROOT_DIR/target/release/tor-client"

if [ "$SKIP_BUILD" = false ]; then
    section "Building all services (release)"
    cargo build --release --manifest-path "$ROOT_DIR/Cargo.toml"
    echo "Build complete."
else
    echo "(Skipping build — using existing binaries)"
fi

for bin in "$DISCOVERY_BIN" "$RELAY_BIN" "$CLIENT_BIN"; do
    if [ ! -x "$bin" ]; then
        die "binary not found: $bin — run without --skip-build to compile first"
    fi
done

# ---- Summary ----

mkdir -p "$LOG_DIR"

echo ""
echo "  Circuit layout for $NUM_HOPS hops:"
echo "    Entry:  127.0.0.1:$ENTRY_PORT"
for mp in "${MIDDLE_PORTS[@]}"; do
    echo "    Middle: 127.0.0.1:$mp"
done
echo "    Exit:   127.0.0.1:$EXIT_PORT"
echo "  Discovery: 127.0.0.1:$DISCOVERY_PORT"
echo "  SOCKS5:    127.0.0.1:$SOCKS_PORT"
echo "  Logs:      $LOG_DIR/"
echo ""

# ---- Launch Discovery ----

section "Starting Discovery Service (port $DISCOVERY_PORT)"

CONSENSUS_PATH="$ROOT_DIR/services/discovery/data/consensus.json" \
    RUST_LOG="$RUST_LOG" \
    "$DISCOVERY_BIN" \
    > "$LOG_DIR/discovery.log" 2>&1 &
PIDS+=($!)

wait_for_http "http://127.0.0.1:$DISCOVERY_PORT/health" "Discovery" 40
echo "  Discovery is healthy."

# ---- Launch Relay Nodes ----

start_relay() {
    local node_type="$1"
    local port="$2"
    local label="${3:-$node_type}"

    RUST_LOG="$RUST_LOG" \
        "$RELAY_BIN" \
        --node-type "$node_type" \
        --port "$port" \
        --host 127.0.0.1 \
        --directory-url "http://127.0.0.1:$DISCOVERY_PORT" \
        --heartbeat-interval 30 \
        > "$LOG_DIR/relay-${label}.log" 2>&1 &
    PIDS+=($!)

    wait_for_tcp 127.0.0.1 "$port" "$label relay"
    echo "  $label relay (port $port) is listening."
}

section "Starting $NUM_HOPS relay nodes"

start_relay entry "$ENTRY_PORT" "entry"

for i in "${!MIDDLE_PORTS[@]}"; do
    start_relay middle "${MIDDLE_PORTS[$i]}" "middle-$((i + 1))"
done

start_relay exit "$EXIT_PORT" "exit"

# Wait for discovery to see all relay types registered (readiness check)
echo ""
echo "  Waiting for discovery to see all relay types registered..."
wait_for_http "http://127.0.0.1:$DISCOVERY_PORT/ready" "Discovery readiness" 40
echo "  Discovery reports READY."

# Show registered nodes
echo ""
echo "  Registered nodes:"
if command -v jq >/dev/null 2>&1; then
    curl -sf "http://127.0.0.1:$DISCOVERY_PORT/api/nodes" \
        | jq -r '.nodes[] | "    [\(.node_type)] \(.address)"' 2>/dev/null \
        || curl -sf "http://127.0.0.1:$DISCOVERY_PORT/api/nodes"
else
    curl -sf "http://127.0.0.1:$DISCOVERY_PORT/api/nodes"
fi

# ---- Launch Tor Client ----

section "Starting Tor Client (SOCKS5 port $SOCKS_PORT, --hops $NUM_HOPS)"

CLIENT_EXTRA_ARGS=""
if [ "$NUM_HOPS" -eq 10 ]; then
    # Pass --yes to bypass the interactive confirmation in the binary
    # (the user already confirmed in this script)
    CLIENT_EXTRA_ARGS="--yes"
fi

if [ "$NO_TUI" = true ]; then
    RUST_LOG="$RUST_LOG" \
        "$CLIENT_BIN" \
        --socks-addr "127.0.0.1:$SOCKS_PORT" \
        --directory-url "http://127.0.0.1:$DISCOVERY_PORT" \
        --pool-size "$POOL_SIZE" \
        --hops "$NUM_HOPS" \
        > "$LOG_DIR/tor-client.log" 2>&1 &
    PIDS+=($!)

    echo "  Waiting for tor-client to build circuits..."
    wait_for_tcp 127.0.0.1 "$SOCKS_PORT" "tor-client SOCKS5" 120
    echo "  Tor client SOCKS5 proxy is ready."

    section "All services running!"
    echo ""
    echo "  Discovery:    http://127.0.0.1:$DISCOVERY_PORT  (Swagger: /swagger-ui)"
    echo "  SOCKS5 proxy: 127.0.0.1:$SOCKS_PORT  (--hops $NUM_HOPS)"
    echo ""
    echo "  Test with:"
    echo "    curl --socks5 127.0.0.1:$SOCKS_PORT http://example.com"
    echo "    curl --socks5 127.0.0.1:$SOCKS_PORT http://httpbin.org/ip"
    echo ""
    echo "  Monitor logs:"
    echo "    tail -f $LOG_DIR/tor-client.log"
    echo "    tail -f $LOG_DIR/discovery.log"
    echo ""
    echo "  Press Ctrl+C to stop all services."
    echo ""

    while true; do
        all_dead=true
        for pid in "${PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                all_dead=false
                break
            fi
        done
        if [ "$all_dead" = true ]; then
            echo "All services have stopped."
            exit 1
        fi
        sleep 2
    done
else
    # TUI mode — tor-client runs in the foreground.
    # For the 10-hop case the binary will print its own dialoguer prompt;
    # we already confirmed above so this path only runs if --yes was set
    # (which means the binary's prompt is bypassed via stdin redirection).
    echo "  Launching tor-client with TUI dashboard..."
    echo "  (Press 'q' or Ctrl+C to stop everything)"
    echo ""
    echo "  Test from another terminal:"
    echo "    curl --socks5 127.0.0.1:$SOCKS_PORT http://example.com"
    echo ""

    if [ "$NUM_HOPS" -eq 10 ]; then
        # Feed 'yes' to stdin so the binary's dialoguer confirmation auto-accepts.
        echo "yes" | RUST_LOG="$RUST_LOG" \
            "$CLIENT_BIN" \
            --socks-addr "127.0.0.1:$SOCKS_PORT" \
            --directory-url "http://127.0.0.1:$DISCOVERY_PORT" \
            --pool-size "$POOL_SIZE" \
            --hops "$NUM_HOPS" \
            --tui
    else
        RUST_LOG="$RUST_LOG" \
            "$CLIENT_BIN" \
            --socks-addr "127.0.0.1:$SOCKS_PORT" \
            --directory-url "http://127.0.0.1:$DISCOVERY_PORT" \
            --pool-size "$POOL_SIZE" \
            --hops "$NUM_HOPS" \
            --tui
    fi
fi
