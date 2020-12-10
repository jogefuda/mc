LIBS = -lm -lpthread -lz -lgnutls -lssl -lcrypto -lcurl -lgmp
NET_OBJ = $(patsubst %.c,%.o,$(wildcard net/*.c))
OBJ = $(patsubst %.c,%.o,$(wildcard *.c))
OBJ += $(NET_OBJ)
OBJ := $(filter-out main.o,$(OBJ))

.PHONY: all clean run

all: a.out

run: a.out
	-./a.out

a.out: main.o $(OBJ)
	$(CC) -g $< $(OBJ) $(LIBS)

%.o: %.c %.h
	$(CC) -g -c $< -o $@ $(LIBS)

clean:
	@$(RM) ./*.o ./*.txt a.out
