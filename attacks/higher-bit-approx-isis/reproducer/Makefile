PYTHON ?= python3

.PHONY: quick full reference check clean

quick:
	./reproduce.sh --quick

full:
	./reproduce.sh --full

reference:
	./reproduce.sh --reference-quick
	./reproduce.sh --reference-full

check:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m py_compile \
		__init__.py hbaisis_reference.py report.py

clean:
	rm -rf __pycache__

