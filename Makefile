.PHONY: test

test:
	RUSTFLAGS="-D warnings" cargo nextest run --workspace --profile default
	RUSTFLAGS="-D warnings" cargo nextest run --workspace --profile e2e --config-file nextest.toml
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features -- -D warnings
	cargo deny check
