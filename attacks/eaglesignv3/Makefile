PYTHON ?= python3
PYCACHE_ROOT ?= /tmp/eaglesignv3-public-pycache

.PHONY: all references smoke full paper build final-check finalize-hashes clean

all: final-check

references:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce.py --reference > /tmp/eaglesignv3-public-quick.json
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce-all-rows.py --reference > /tmp/eaglesignv3-public-full.json
	cmp /tmp/eaglesignv3-public-quick.json reference-output.json
	cmp /tmp/eaglesignv3-public-full.json all-rows-reference-output.json

smoke:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce.py

full:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce-all-rows.py

paper:
	$(MAKE) -C paper clean all
	rm -f paper/attack.aux paper/attack.log paper/attack.out paper/attack.toc

build:
	$(MAKE) -C reproducer build

final-check: references
	PYTHONPYCACHEPREFIX=$(PYCACHE_ROOT) $(PYTHON) -m py_compile \
		reproduce.py reproduce-all-rows.py validate-package.py \
		reproducer/report.py reproducer/solve_milp.py
	$(PYTHON) -m json.tool metadata.json >/dev/null
	$(PYTHON) -m json.tool affected-rows.json >/dev/null
	$(PYTHON) -m json.tool reference-output.json >/dev/null
	$(PYTHON) -m json.tool all-rows-reference-output.json >/dev/null
	$(PYTHON) -m json.tool reproducer/validation/independent-replay-20261015.json >/dev/null
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) validate-package.py
	! rg -n '\\operatorname' --glob '*.md' .
	! rg -ni '\bCBC\b|six-hour' README.md paper reproducer metadata.json
	! rg -ni 'pending publication review|private uncounted|publication candidate|CANDIDATE_PENDING|PRIVATE_UNCOUNTED' README.md paper reproducer metadata.json
	( cd reproducer && sha256sum -c SHA256SUMS )
	sha256sum -c SHA256SUMS

finalize-hashes: references paper
	rm -f SHA256SUMS reproducer/SHA256SUMS
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) validate-package.py --allow-missing-manifest
	( cd reproducer && find . -type f ! -path './SHA256SUMS' \
		! -path './build/*' ! -path './output/*' \
		! -name '*.aux' ! -name '*.log' ! -name '*.out' ! -name '*.toc' \
		-print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS )
	find . -type f ! -path './SHA256SUMS' \
		! -path './reproducer/build/*' ! -path './reproducer/output/*' \
		! -name '*.aux' ! -name '*.log' ! -name '*.out' ! -name '*.toc' \
		-print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) validate-package.py
	( cd reproducer && sha256sum -c SHA256SUMS )
	sha256sum -c SHA256SUMS

clean:
	$(MAKE) -C paper clean
	$(MAKE) -C reproducer clean
	rm -rf __pycache__ reproducer/__pycache__
