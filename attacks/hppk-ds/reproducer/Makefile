PYTHON ?= python3

.PHONY: quick all-rows reference check clean

quick:
	./reproduce.sh --quick

all-rows:
	./reproduce.sh --all-rows

reference:
	./reproduce.sh --reference-quick
	./reproduce.sh --reference-all-rows

check:
	PYTHONPYCACHEPREFIX=/tmp/hppk-ds-public-pycache $(PYTHON) -m py_compile \
		__init__.py hppk_reference.py report.py

clean:
	rm -rf __pycache__
