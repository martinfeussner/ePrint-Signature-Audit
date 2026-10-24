PYTHON ?= python3
FULL_OUTPUT ?= fresh-evidence.json

.PHONY: quick full paper check

quick:
	$(PYTHON) -B reproduce.py --reference

full:
	@test ! -e "$(FULL_OUTPUT)" || { echo "refusing to overwrite $(FULL_OUTPUT)" >&2; exit 2; }
	$(PYTHON) -B reproduce-all-rows.py --trials 1 --output "$(FULL_OUTPUT)"
	$(PYTHON) -B reproducer/validate_evidence.py --evidence "$(FULL_OUTPUT)" --implementation reproduce-all-rows.py

paper:
	$(MAKE) -C paper

check:
	$(PYTHON) -B reproduce.py --reference
