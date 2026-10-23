PYTHON ?= python3

.PHONY: quick full paper check

quick:
	$(PYTHON) -B reproduce.py --reference

full:
	$(PYTHON) -B reproduce-all-rows.py

paper:
	$(MAKE) -C paper

check:
	$(PYTHON) -B reproduce.py --reference
	$(PYTHON) -B reproduce-all-rows.py --reference
