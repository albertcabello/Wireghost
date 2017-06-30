CC = gcc
CFLAGS = -lpcap
DEPS = arraylist.h
OBJ = main.o arraylist.o

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

main: $(OBJ)
	gcc $(CFLAGS) -o $@ $^

clean:
	rm -f $(OBJ) main