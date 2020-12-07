LIBS = $(shell pkgconf --libs openssl)
LIBS += $(shell pkgconf --libs gnutls)
LIBS += -lm

obj = crypto.o utils.o minecraft.o

.PHONY: all

all: a.out

run: a.out
	-./a.out

a.out: main.c pkt.o $(obj)
	gcc -g main.c pkt.o $(obj) $(LIBS)

pkt.o: net/pkt.c net/pkt.h
	gcc -g -c $< -o $@ $(LIBS)

%.o: %.c %.h
	gcc -g -c $< -o $@ $(LIBS)


