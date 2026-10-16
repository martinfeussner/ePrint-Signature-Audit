.PHONY: all clean

all: attack.pdf

attack.pdf: attack.tex
	pdflatex -interaction=nonstopmode -halt-on-error attack.tex
	pdflatex -interaction=nonstopmode -halt-on-error attack.tex

clean:
	rm -f attack.aux attack.log attack.out attack.pdf
