PYTHON ?= python3
PYCACHE_ROOT ?= /tmp/hppk-ds-public-pycache

.PHONY: all reproduce paper draft-check final-check sha256-preview finalize-hashes clean

all: final-check

reproduce:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce.py --reference > /tmp/hppk-ds-public-quick.json
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce-all-rows.py --reference > /tmp/hppk-ds-public-full.json
	cmp /tmp/hppk-ds-public-quick.json reference-output.json
	cmp /tmp/hppk-ds-public-full.json all-rows-reference-output.json

paper:
	$(MAKE) -C paper all
	rm -f paper/attack.aux paper/attack.log paper/attack.out paper/attack.toc

draft-check: reproduce
	PYTHONPYCACHEPREFIX=$(PYCACHE_ROOT) $(PYTHON) -m py_compile \
		reproduce.py reproduce-all-rows.py validate-package.py \
		reproducer/__init__.py reproducer/hppk_reference.py reproducer/report.py
	$(PYTHON) -m json.tool metadata.json >/dev/null
	$(PYTHON) -m json.tool affected-rows.json >/dev/null
	$(PYTHON) -m json.tool reference-output.json >/dev/null
	$(PYTHON) -m json.tool all-rows-reference-output.json >/dev/null
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) validate-package.py
	! rg -n '\\operatorname' --glob '*.md' .

final-check: reproduce paper
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) validate-package.py --final
	sha256sum -c SHA256SUMS

sha256-preview:
	find . -type f ! -name SHA256SUMS ! -name '*.aux' ! -name '*.log' ! -name '*.out' ! -name '*.toc' -print0 | LC_ALL=C sort -z | xargs -0 sha256sum

# Do not invoke until every sealed later-gate handoff has been reconciled.
finalize-hashes: reproduce paper
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) validate-package.py --final --allow-missing-manifest
	find . -type f ! -name SHA256SUMS ! -name '*.aux' ! -name '*.log' ! -name '*.out' ! -name '*.toc' -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) validate-package.py --final
	sha256sum -c SHA256SUMS

clean:
	$(MAKE) -C paper clean
	rm -rf __pycache__ reproducer/__pycache__
