
NETMAP_INC_DIR = ../../../../netmap/sys

.PHONY: clean

all: pslib.a

pslib.a: pslib.c
	gcc -O3 -c -g -Wall -fPIC -I$(NETMAP_INC_DIR) -o pslib.o pslib.c
	ar rcs libps.a pslib.o

clean:
	rm -f *.o *.a
