PYTHON ?= python3
PYCACHE_ROOT ?= /tmp/dss-ms-public-pycache
ONE_WORKER_ENV = OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 NUMEXPR_NUM_THREADS=1 PYTHONHASHSEED=0

.PHONY: all quick reproduce exact all-rows paper check clean

all: check paper

quick:
	$(ONE_WORKER_ENV) PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -B reproduce.py --mode quick >/dev/null
	@echo PASS_QUICK_REPRODUCTION

exact:
	$(ONE_WORKER_ENV) PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -B reproduce.py --mode exact --reference > /tmp/dss-ms-primary-reference.json
	cmp /tmp/dss-ms-primary-reference.json reference-output.json
	@echo PASS_EXACT_REPRODUCTION

all-rows:
	$(ONE_WORKER_ENV) PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -B reproduce-all-rows.py --reference > /tmp/dss-ms-all-rows-reference.json
	cmp /tmp/dss-ms-all-rows-reference.json all-rows-reference-output.json
	@echo PASS_ALL_ROWS_REPRODUCTION

reproduce: exact all-rows

paper:
	$(MAKE) -C paper all

check: reproduce
	PYTHONPYCACHEPREFIX=$(PYCACHE_ROOT) $(PYTHON) -m py_compile reproduce.py reproduce-all-rows.py
	$(PYTHON) -m json.tool metadata.json >/dev/null
	$(PYTHON) -m json.tool reference-output.json >/dev/null
	$(PYTHON) -m json.tool all-rows-reference-output.json >/dev/null
	$(PYTHON) -c 'import json; p=json.load(open("reference-output.json")); assert p["result"].startswith("PASS_") and p["checks"] and all(p["checks"].values()) and p["digests"]; a=json.load(open("all-rows-reference-output.json")); assert a["all_rows_pass"] is True and a["results"] and all(r["all_expected_checks_pass"] for r in a["results"])'

clean:
	$(MAKE) -C paper clean
	rm -rf __pycache__
