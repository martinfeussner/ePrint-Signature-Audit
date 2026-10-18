PYTHON ?= python3

.PHONY: all reproduce actual-bn254 paper clean

all: reproduce

reproduce:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce.py --reference > /tmp/fabs-public-quick.json
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce-all-rows.py --reference > /tmp/fabs-public-all.json
	cmp /tmp/fabs-public-quick.json reference-output.json
	cmp /tmp/fabs-public-all.json all-rows-reference-output.json

actual-bn254:
	$(MAKE) -C reproducer actual-offline

paper:
	$(MAKE) -C paper all

clean:
	$(MAKE) -C paper clean
	rm -rf __pycache__ reproducer/__pycache__
