.PHONY: build test test-priv lint bench
build:
	cargo build --release -j 2
# Unit tests + privileged tests (which print SKIPPED unless enabled).
test:
	cargo test -j 2
# Full suite including namespaces/cgroups/mounts; needs root.
test-priv:
	HULL_PRIVILEGED_TESTS=1 cargo test -j 2 -- --test-threads=4
lint:
	cargo fmt --check
	cargo clippy --all-targets -j 2 -- -D warnings
bench:
	scripts/bench.sh 50
