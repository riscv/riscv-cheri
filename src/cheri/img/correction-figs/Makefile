.PHONY: all
all: out/capformat-correction-illustration.png out/capformat-correction-cases.png

out:
	mkdir $@

out/%.pdf: %.tex capformat.tex out
	tectonic --outdir out $<

out/%.png: out/%.pdf
	convert -density 150 -quality 100 -flatten $< $@

.PHONY: clean
clean:
	rm -rf out
