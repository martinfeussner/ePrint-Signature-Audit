PDFLATEX ?= pdflatex
SOURCE_DATE_EPOCH ?= 1791504000
export SOURCE_DATE_EPOCH

.PHONY: all clean

all: attack.pdf

attack.pdf: attack.tex
	$(PDFLATEX) -interaction=nonstopmode -halt-on-error attack.tex
	$(PDFLATEX) -interaction=nonstopmode -halt-on-error attack.tex

clean:
	rm -f attack.aux attack.log attack.out attack.toc
