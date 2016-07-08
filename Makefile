# Makefile

FN=draft-wood-icnrg-ccnxkeyexchange-00

all: ${FN}.txt ${FN}.html

${FN}.txt: ${FN}.xml
	xml2rfc $<

${FN}.html: ${FN}.xml
	xml2rfc --html $<

${FN}.xml: ${FN}.mkd
	kramdown-rfc2629 $< >$@

clean:
	rm -f ${FN}.xml *~
