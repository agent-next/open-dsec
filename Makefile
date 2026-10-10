.PHONY: setup check host-check

# Toolchain components and dependencies needed by make check
# (prerequisites from README: rust stable, uv, Python >= 3.10).
setup:
	rustup component add rustfmt clippy
	cargo fetch --locked
	cd sdk/python && uv sync --group dev

# Everything here runs unprivileged, without docker/KVM (AGENTS.md).
# dsec-vmm is M3 work in progress; check what M1 ships.
check:
	cargo fmt --all --check
	cargo clippy --workspace --exclude dsec-vmm --all-targets -- -D warnings
	cargo test --workspace --exclude dsec-vmm
	cd sdk/python && uv run --group dev pytest -q

# Tests that need real privileges/services: docker for the container
# backend, and the dev-up control plane for the SDK e2e.
host-check:
	cargo build
	cargo test -p dsec-edge -- --ignored
	$(CURDIR)/scripts/dev-up.sh
	cd sdk/python && DSEC_ENDPOINT=127.0.0.1:9100 uv run --group dev pytest -q -m host; rc=$$?; \
	  leftover=$$(docker ps -a --filter label=open-dsec -q | wc -l); \
	  $(CURDIR)/scripts/dev-down.sh; \
	  test $$rc -eq 0 && test $$leftover -eq 0 || { echo "host-check failed (pytest rc=$$rc, leftover containers=$$leftover)"; exit 1; }
