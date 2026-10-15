PYTHON ?= python3
PYCACHE_ROOT ?= /tmp/jevil-public-pycache

.PHONY: all references smoke full paper draft-check final-check finalize-hashes clean

all: draft-check

references:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce.py --reference > /tmp/jevil-public-quick.json
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce-all-rows.py --reference > /tmp/jevil-public-full.json
	cmp /tmp/jevil-public-quick.json reference-output.json
	cmp /tmp/jevil-public-full.json all-rows-reference-output.json

smoke:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce.py

full:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce-all-rows.py

paper:
	$(MAKE) -C paper clean all
	rm -f paper/attack.aux paper/attack.log paper/attack.out paper/attack.toc

draft-check: references
	PYTHONPYCACHEPREFIX=$(PYCACHE_ROOT) $(PYTHON) -m py_compile \
		reproduce.py reproduce-all-rows.py validate-package.py
	$(PYTHON) -m json.tool metadata.json >/dev/null
	$(PYTHON) -m json.tool affected-rows.json >/dev/null
	$(PYTHON) -m json.tool reference-output.json >/dev/null
	$(PYTHON) -m json.tool all-rows-reference-output.json >/dev/null
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) validate-package.py
	! rg -n '\\operatorname' --glob '*.md' .

final-check: references paper
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) validate-package.py --final
	sha256sum -c SHA256SUMS

finalize-hashes: references paper
	rm -f SHA256SUMS
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) validate-package.py --final --allow-missing-manifest
	find . -type f ! -path './SHA256SUMS' ! -path './reproducer/build/*' ! -path './reproducer/output/*' ! -name '*.aux' ! -name '*.log' ! -name '*.out' ! -name '*.toc' -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) validate-package.py --final
	sha256sum -c SHA256SUMS

clean:
	$(MAKE) -C paper clean
	rm -rf __pycache__ reproducer/build reproducer/output
