# AegisOS — thin make targets over boot.sh / cargo (the real build logic
# lives in boot.sh; this file is the conventional entry point).
#
# make test-qemu-pr14 — full QEMU boot; PASSES only if every acceptance
# marker (M1 + PR-1.1/1.2/1.3, plus PR-1.4's success *or* its honest
# environment-blocked verdict) is present. See docs/arch/syscall-entry.md
# for what "blocked" means and how to retry on another environment.

.PHONY: build boot test test-qemu test-qemu-pr14 clean

build:
	./boot.sh --build-only

boot:
	./boot.sh --verify

test:
	cargo test --workspace

test-qemu: test-qemu-pr14

test-qemu-pr14:
	./boot.sh --verify

clean:
	cargo clean
	rm -f target/aegis-boot.elf target/kernel.bin
