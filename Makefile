CC=gcc
CFLAGS=-lpcap -lpthread -lrt -O3

all: net_analyze.o
	$(CC) -o net_analyze net_analyze.o $(CFLAGS)

clean:
	rm net_analyze net_analyze.o