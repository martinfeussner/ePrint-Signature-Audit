CARGO ?= cargo

.PHONY: smoke full check-pins clean

smoke:
	CARGO="$(CARGO)" ./reproduce.sh --smoke

full:
	CARGO="$(CARGO)" ./reproduce.sh --full

check-pins:
	./scripts/check-pins.sh

clean:
	rm -rf build output

