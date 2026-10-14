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
	PYTHONPYCACHEPREFIX=/tmp/ssd-public-pycache $(PYTHON) -m py_compile \
		__init__.py ssd_reference.py report.py

clean:
	rm -rf __pycache__

