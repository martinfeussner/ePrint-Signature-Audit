.PHONY: reference all-rows validate paper clean

reference:
	python3 reproduce.py --reference

all-rows:
	python3 reproduce-all-rows.py --reference

validate:
	python3 validate-package.py

paper:
	$(MAKE) -C paper

clean:
	$(MAKE) -C paper clean
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
