LIBS = -lm -pthread -lz -lgnutls -lssl -lcrypto -lcurl -lgmp
OBJ = crypto.o utils.o minecraft.o compress.o hash.o net/pkt.o net/auth.o 

.PHONY: all clean run

all: a.out

run: a.out
	-./a.out

a.out: main.c $(OBJ)
	$(CC) -g $< $(OBJ) $(LIBS)

%.o: %.c %.h
	$(CC) -g -c $< -o $@ $(LIBS)

clean:
	@$(RM) ./*.o ./*.txt a.out
