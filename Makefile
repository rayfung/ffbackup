CC=g++
CFLAGS=-g -Wall
LD=-lssl -lcrypto

all: pbclient pbserver

pbclient: pbclient.cpp
	$(CC) $(CFLAGS) pbclient.cpp -o pbclient $(LD)

pbserver: pbserver.cpp
	$(CC) $(CFLAGS) pbserver.cpp -o pbserver $(LD)

clean:
	rm -f pbclient pbserver
