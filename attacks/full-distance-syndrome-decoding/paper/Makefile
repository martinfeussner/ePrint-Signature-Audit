SOURCE_DATE_EPOCH ?= 1791936000
LATEX_ENV = env SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) FORCE_SOURCE_DATE=1 TZ=UTC

.PHONY: all clean

all: attack.pdf

attack.pdf: attack.tex
	$(LATEX_ENV) pdflatex -interaction=nonstopmode -halt-on-error attack.tex
	$(LATEX_ENV) pdflatex -interaction=nonstopmode -halt-on-error attack.tex

clean:
	rm -f attack.aux attack.log attack.out attack.pdf
