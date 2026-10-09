PYTHON ?= python3

.PHONY: all reproduce paper check clean

all: check paper

reproduce:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce.py > /tmp/random-split-stgen-primary.json
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce-all-rows.py > /tmp/random-split-stgen-independent.json
	cmp /tmp/random-split-stgen-primary.json reference-output.json
	cmp /tmp/random-split-stgen-independent.json all-rows-reference-output.json

paper:
	$(MAKE) -C paper all

check: reproduce
	$(PYTHON) -m py_compile reproduce.py reproduce-all-rows.py reproducer/primary.py reproducer/independent.py
	! rg -n 'VERIFIED_ATTACK.*passed|arbitrary.document.*forg' README.md paper/attack.tex

clean:
	$(MAKE) -C paper clean
	rm -rf __pycache__ reproducer/__pycache__
