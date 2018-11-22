VERSION=00
BASENAME=draft-madden-generalised-siv-$(VERSION)

# Use 'pip install xml2rfc'

all: generalised-siv.xml
	xml2rfc generalised-siv.xml --text --html --basename $(BASENAME)

.PHONY: all

