CC=g++
CFLAGS=-g -Wall
LD=-lssl -lcrypto

all: ffbackup-server
ffbackup-server: server.o
	$(CC) $(CFLAGS) server.cpp -o ffbackup-server $(LD)
clean:
	rm -f ffbackup-server *.o
