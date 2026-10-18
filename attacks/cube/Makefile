PYTHON ?= python3

.PHONY: all reproduce actual-bn254 paper clean

all: reproduce

reproduce:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -B reproduce.py --reference > /tmp/cube-public-reference.json
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -B reproduce-all-rows.py --reference > /tmp/cube-public-all-rows.json
	cmp /tmp/cube-public-reference.json reference-output.json
	cmp /tmp/cube-public-all-rows.json all-rows-reference-output.json

actual-bn254:
	$(MAKE) -C reproducer/actual-bn254 reproduce-offline

paper:
	$(MAKE) -C paper all

clean:
	$(MAKE) -C paper clean
	rm -rf __pycache__ reproducer/actual-bn254/target
