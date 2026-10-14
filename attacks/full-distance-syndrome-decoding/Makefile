PYTHON ?= python3
PYCACHE_ROOT ?= /tmp/fdsd-public-pycache

.PHONY: all reproduce paper check clean

all: check paper

reproduce:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce.py > /tmp/fdsd-public-quick.json
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce-all-rows.py > /tmp/fdsd-public-all-rows.json
	cmp /tmp/fdsd-public-quick.json reference-output.json
	cmp /tmp/fdsd-public-all-rows.json all-rows-reference-output.json

paper:
	$(MAKE) -C paper all

check: reproduce
	PYTHONPYCACHEPREFIX=$(PYCACHE_ROOT) $(PYTHON) -m py_compile \
		reproduce.py reproduce-all-rows.py \
		reproducer/__init__.py reproducer/fdsd_reference.py \
		reproducer/generate_case.py reproducer/public_attack.py \
		reproducer/report.py reproducer/verify_forgery.py
	$(MAKE) -C reproducer verify-pins
	sha256sum -c SHA256SUMS
	! rg -n -i 'prepublication|staged|outstanding|must not be promoted|not yet classified|awaiting' \
		README.md metadata.json paper/attack.tex
	! rg -n '\\operatorname' --glob '*.md' .

clean:
	$(MAKE) -C paper clean
	rm -rf __pycache__ reproducer/__pycache__ reproducer/output output
