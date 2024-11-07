.PHONY: test, clippy

clippy:
	cargo clippy --all-targets --all-features

test:
	cargo test
