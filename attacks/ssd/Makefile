PYTHON ?= python3
PYCACHE_ROOT ?= /tmp/ssd-public-pycache

.PHONY: all reproduce paper check clean

all: check paper

reproduce:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce.py --reference > /tmp/ssd-public-quick.json
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce-all-rows.py --reference > /tmp/ssd-public-all-rows.json
	cmp /tmp/ssd-public-quick.json reference-output.json
	cmp /tmp/ssd-public-all-rows.json all-rows-reference-output.json

paper:
	$(MAKE) -C paper all

check: reproduce
	PYTHONPYCACHEPREFIX=$(PYCACHE_ROOT) $(PYTHON) -m py_compile \
		reproduce.py reproduce-all-rows.py validate-package.py \
		reproducer/__init__.py reproducer/ssd_reference.py reproducer/report.py
	$(PYTHON) -m json.tool metadata.json >/dev/null
	$(PYTHON) -m json.tool affected-rows.json >/dev/null
	$(PYTHON) validate-package.py
	! rg -n '\\operatorname' --glob '*.md' .
	sha256sum -c SHA256SUMS

clean:
	$(MAKE) -C paper clean
	rm -rf __pycache__ reproducer/__pycache__

