.PHONY: workflow fmt fmt-check web-ui

workflow: fmt-check
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	cargo test --workspace --all-features
	cargo build --release

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

web-ui:
	cd services/web-ui && trunk build --release
