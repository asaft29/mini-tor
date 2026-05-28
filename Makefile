
# ── Tor Onion Routing Project — Makefile ──
# Usage:
#   make build                     Compile all services (release)
#   make test                      Run the full test suite
#   make lint                      Format check + clippy (CI parity)
#   make fix                       Auto-fix formatting
#
#   make discovery-tui             Discovery service with TUI dashboard
#   make relay-entry-tui           Entry relay with TUI on port 9001
#   make relay-middle-tui          Middle relay with TUI on port 9101
#   make relay-exit-tui            Exit relay with TUI on port 9201
#   make relay-wizard              Relay interactive config wizard
#   make client-tui                Tor client with TUI (3 hops, pool of 3)
#   make client-wizard             Tor client interactive config wizard
#
#   make demo                      Generic demo (3 hops by default)
#   make demo-rotation             9-relay rotation demo with TUI
#
# All values are overridable:  make relay-entry-tui PORT=9005

# ── Default ports ────────────────────────────────────────────────────────────

DISCOVERY_PORT ?= 8081
DISCOVERY_URL  ?= http://localhost:8081

ENTRY_PORT     ?= 9001
MIDDLE_PORT    ?= 9101
EXIT_PORT      ?= 9201

HOPS           ?= 3
POOL           ?= 3
SOCKS_ADDR     ?= 127.0.0.1:1080

N              ?= 3

ALLOW_SAME_IP  ?= --allow-same-ip

# ── Build / Test / Lint ──────────────────────────────────────────────────────

.PHONY: build test lint fix clean

build:
	cargo build --release

test:
	cargo test --workspace --exclude web-ui --all-features

lint:
	cargo fmt --all -- --check
	cargo clippy --workspace --exclude web-ui --all-targets --all-features -- -D warnings

fix:
	cargo fmt --all

clean:
	cargo clean

# ── Discovery ────────────────────────────────────────────────────────────────

.PHONY: discovery-tui

discovery-tui:
	cargo run -p discovery -- --tui --port $(DISCOVERY_PORT) $(ALLOW_SAME_IP)

# ── Relay — TUI mode (type given, wizard skipped) ────────────────────────────

.PHONY: relay-entry-tui relay-middle-tui relay-exit-tui

relay-entry-tui:
	cargo run -p relay-node -- --tui --node-type entry \
		--port $(ENTRY_PORT) --directory-url $(DISCOVERY_URL)

relay-middle-tui:
	cargo run -p relay-node -- --tui --node-type middle \
		--port $(MIDDLE_PORT) --directory-url $(DISCOVERY_URL)

relay-exit-tui:
	cargo run -p relay-node -- --tui --node-type exit \
		--port $(EXIT_PORT) --directory-url $(DISCOVERY_URL)

# ── Relay — Wizard mode (no type, interactive config) ────────────────────────

.PHONY: relay-wizard

relay-wizard:
	cargo run -p relay-node -- --tui \
		--port $(ENTRY_PORT) --directory-url $(DISCOVERY_URL)

# ── Tor Client — TUI mode (hops given, wizard skipped) ───────────────────────

.PHONY: client-tui

client-tui:
	cargo run -p tor-client -- --tui --hops $(HOPS) --pool-size $(POOL) \
		--directory-url $(DISCOVERY_URL) --socks-addr $(SOCKS_ADDR)

# ── Tor Client — Wizard mode (no hops, interactive config) ───────────────────

.PHONY: client-wizard

client-wizard:
	cargo run -p tor-client -- --tui \
		--directory-url $(DISCOVERY_URL) --socks-addr $(SOCKS_ADDR)

# ── Demos ────────────────────────────────────────────────────────────────────

.PHONY: demo demo-rotation

demo:
	bash scripts/demo_generic.sh $(N)

demo-rotation:
	bash scripts/demo_rotation.sh
