CC = gcc
CFLAGS = -lpcap
DEPS = arraylist.h
OBJ = main.o arraylist.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

main: $(OBJ)
	gcc -o $@ $^ $(CFLAGS)

clean:
	rm -f $(OBJ) main