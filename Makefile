
a.out: main.c pkt.o
	gcc main.c pkt.o


pkt.o: net/pkt.c net/pkt.h
	gcc -c $< -o $@
