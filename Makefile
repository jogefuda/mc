.PHONY: all

all: a.out

run: a.out
	-./a.out

a.out: main.c pkt.o
	gcc -g main.c pkt.o

pkt.o: net/pkt.c net/pkt.h
	gcc -g -c $< -o $@
