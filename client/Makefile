CC=g++
CFLAGS=-g -Wall
LD=-lssl -lcrypto

all: ffbackup-client

ffbackup-client: client.o
	$(CC) $(CFLAGS) client.cpp -o ffbackup-client $(LD)
clean:
	rm -f ffbackup-client *.o
