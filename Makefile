CC=gcc
CFLAGS=-g -Wall
LD=-lssl -lcrypto

all:  ossl_client ossl_server

ossl_client: ossl_client.o 
	$(CC) $(CFLAGS) ossl_client.o -o ossl_client $(LD)

ossl_server: ossl_server.o 
	$(CC) $(CFLAGS) ossl_server.o -o ossl_server $(LD)

clean:
	rm -f *.o ossl_client ossl_server
