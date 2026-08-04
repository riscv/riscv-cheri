FIGURES := capformat-correction-illustration capformat-correction-cases cap-bounds-map

.PHONY: all
all: $(addprefix out/,$(addsuffix .png,$(FIGURES))) $(addprefix out/,$(addsuffix .pdf,$(FIGURES)))

out:
	mkdir $@

# ../%.pdf and ../%.png are only refreshed when the content
# actually changes so unrelated rebuilds don't touch their mtime.
out/%.pdf: %.tex capformat.tex | out
	SOURCE_DATE_EPOCH=0 tectonic --outdir out $<
	# cmp -s $@ ../$*.pdf || cp $@ ../$*.pdf

out/%.png: out/%.pdf
	convert -density 150 -quality 100 -flatten -strip $< $@
	cmp -s $@ ../$*.png || cp $@ ../$*.png

.PHONY: clean
clean:
	rm -rf out
