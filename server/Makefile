CC=g++
CFLAGS=-g -Wall
LD=-lssl -lcrypto

all: ffbackup-server
ffbackup-server: server.cpp
	$(CC) $(CFLAGS) server.cpp -o ffbackup-server $(LD)
clean:
	rm -f ffbackup-server
