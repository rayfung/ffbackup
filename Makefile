CC=gcc
CFLAGS=-g -Wall
LD=-lssl -lcrypto

all: pbclient pbserver

pbclient: pbclient.c
	$(CC) $(CFLAGS) pbclient.c -o pbclient $(LD)

pbserver: pbserver.c
	$(CC) $(CFLAGS) pbserver.c -o pbserver $(LD)

clean:
	rm -f pbclient pbserver
