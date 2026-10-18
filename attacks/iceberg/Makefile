PYTHON ?= python3

.PHONY: all reproduce source-exact paper clean

all: reproduce

reproduce:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -B reproduce.py > /tmp/iceberg-public-reference.json
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -B reproduce-all-rows.py > /tmp/iceberg-public-all-rows.json
	cmp /tmp/iceberg-public-reference.json reference-output.json
	cmp /tmp/iceberg-public-all-rows.json all-rows-reference-output.json

source-exact:
	./reproducer/source-exact/reproduce-source-exact.sh

paper:
	$(MAKE) -C paper all

clean:
	$(MAKE) -C paper clean
	rm -rf __pycache__ reproducer/__pycache__
