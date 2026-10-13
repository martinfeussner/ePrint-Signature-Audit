PYTHON ?= python3

.PHONY: all reproduce paper check clean

all: check paper

reproduce:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce.py > /tmp/tot-primary.json
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) reproduce-all-rows.py > /tmp/tot-independent.json
	cmp /tmp/tot-primary.json reference-output.json
	cmp /tmp/tot-independent.json all-rows-reference-output.json

paper:
	$(MAKE) -C paper all

check: reproduce
	$(PYTHON) -m py_compile reproduce.py reproduce-all-rows.py
	! rg -n 'PENDING|STAGED_PENDING|candidate for `VERIFIED_ATTACK`|\\operatorname' README.md metadata.json paper/attack.tex

clean:
	$(MAKE) -C paper clean
	rm -rf __pycache__ reproducer/primary/__pycache__ reproducer/independent/__pycache__
