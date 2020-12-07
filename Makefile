LIBS = $(shell pkgconf --libs openssl)
LIBS += $(shell pkgconf --libs gnutls)
LIBS += -lm -pthread -lz

obj = crypto.o utils.o minecraft.o compress.o pkt.o

.PHONY: all

all: a.out

run: a.out
	-./a.out

a.out: main.c $(obj)
	gcc -g main.c $(obj) $(LIBS)

pkt.o: net/pkt.c net/pkt.h
	gcc -g -c $< -o $@ $(LIBS)

%.o: %.c %.h
	gcc -g -c $< -o $@ $(LIBS)


