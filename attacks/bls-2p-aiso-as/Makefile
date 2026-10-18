.PHONY: reproduce source-exact validate paper clean

reproduce:
	python3 -B reproduce.py --reference >/dev/null
	python3 -B reproduce-all-rows.py --reference >/dev/null

source-exact:
	./reproducer/source-exact/reproduce-source-exact.sh

validate: reproduce
	python3 -m py_compile reproduce.py reproduce-all-rows.py
	python3 -m json.tool metadata.json >/dev/null
	sha256sum -c SHA256SUMS

paper:
	$(MAKE) -C paper

clean:
	$(MAKE) -C paper clean
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
