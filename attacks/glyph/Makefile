PYTHON ?= python3

.PHONY: all reproduce paper check clean

all: check paper

reproduce:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce.py > /tmp/glyph-quick.json
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce-all-rows.py > /tmp/glyph-full.json
	cmp /tmp/glyph-quick.json reference-output.json
	cmp /tmp/glyph-full.json all-rows-reference-output.json

paper:
	$(MAKE) -C paper all

check: reproduce
	$(PYTHON) -m py_compile reproduce.py reproduce-all-rows.py reproducer/report.py
	$(MAKE) -C reproducer verify-pins
	! rg -n 'PENDING|STAGED_PENDING|candidate for `VERIFIED_ATTACK`|\\operatorname' README.md metadata.json paper/attack.tex

clean:
	$(MAKE) -C paper clean
	$(MAKE) -C reproducer clean
	rm -rf __pycache__ reproducer/__pycache__ reproducer/output
