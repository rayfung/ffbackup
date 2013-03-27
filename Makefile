CC=gcc
CFLAGS=-g -Wall
LD=-lssl -lcrypto

all: client server

client: ossl_client.c
	$(CC) $(CFLAGS) ossl_client.c -o client $(LD)

server: ossl_server.c
	$(CC) $(CFLAGS) ossl_server.c -o server $(LD)

clean:
	rm -f client server
