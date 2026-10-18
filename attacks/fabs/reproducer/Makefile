PYTHON ?= python3
CARGO ?= cargo
ACTUAL_TARGET ?= /tmp/fabs-public-actual-bn254-target

.PHONY: reproduce full actual actual-offline check

reproduce:
	cd .. && PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m reproducer.runner --reference

full:
	cd .. && PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m reproducer.runner --full --reference

actual:
	CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=$(ACTUAL_TARGET) $(CARGO) run \
		--release --locked --manifest-path actual-bn254/Cargo.toml

actual-offline:
	CARGO_BUILD_JOBS=1 CARGO_NET_OFFLINE=true CARGO_TARGET_DIR=$(ACTUAL_TARGET) \
		$(CARGO) run --release --offline --locked \
		--manifest-path actual-bn254/Cargo.toml

check:
	PYTHONPYCACHEPREFIX=/tmp/fabs-public-pycache $(PYTHON) -m py_compile \
		fabs_reference.py report.py runner.py
	cd .. && PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m reproducer.runner --full --reference >/dev/null

