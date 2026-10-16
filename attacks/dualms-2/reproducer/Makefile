.PHONY: reproduce reference check

reproduce:
	./reproduce.sh

reference:
	./reproduce.sh --reference

check:
	python3 -m py_compile dualms2_reference.py runner.py
	./reproduce.sh --reference
