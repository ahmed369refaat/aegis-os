# AegisOS — thin make targets over boot.sh / cargo (the real build logic
# lives in boot.sh; this file is the conventional entry point).
#
# make test-qemu — full QEMU boot; PASSES only if every acceptance
# marker (M1 + exception/mm selftests + the full seven-run ring-3
# sequence of ADR-0010) is present. The old "environment-blocked"
# verdict is RETIRED: boot.sh fails on it (it was four local bugs,
# all fixed).

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
