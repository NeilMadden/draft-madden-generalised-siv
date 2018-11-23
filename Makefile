VERSION=01
BASENAME=draft-madden-generalised-siv-$(VERSION)

# Use 'pip install xml2rfc'

all: generalised-siv.xml 
	cp generalised-siv.xml $(BASENAME).xml
	xml2rfc generalised-siv.xml --text --html --basename $(BASENAME)

xchacha20siv.o: xchacha20siv.c xchacha20siv.h
	gcc -c -std=c99 xchacha20siv.c

demo: main.c xchacha20siv.o
	gcc -o demo -std=c99 main.c xchacha20siv.o -lsodium

clean:
	rm -f *.o demo

.PHONY: all clean

