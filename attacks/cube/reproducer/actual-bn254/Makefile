CARGO ?= cargo
TARGET_DIR ?= target

.PHONY: reproduce reproduce-offline clean

reproduce:
	CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=$(TARGET_DIR) $(CARGO) run --release --locked

reproduce-offline:
	CARGO_BUILD_JOBS=1 CARGO_NET_OFFLINE=true CARGO_TARGET_DIR=$(TARGET_DIR) \
		$(CARGO) run --release --offline --locked

clean:
	rm -rf $(TARGET_DIR)
