CC=g++
CFLAGS=-g -Wall
LD=-lssl -lcrypto

all: ffbackup-server

ffbackup-server: server.o task.o ffbuffer.o client_request.o client_response.o
	$(CC) $(CFLAGS) server.o task.o ffbuffer.o client_request.o client_response.o -o ffbackup-server $(LD)

server.o: server.cpp server.h task.h ffbuffer.h
	$(CC) $(CFLAGS) -c server.cpp -o server.o $(LD)

task.o: task.cpp server.h task.h ffbuffer.h
	$(CC) $(CFLAGS) -c task.cpp -o task.o $(LD)

ffbuffer.o: ffbuffer.cpp ffbuffer.h
	$(CC) $(CFLAGS) -c ffbuffer.cpp -o ffbuffer.o $(LD)

client_request.o: client_request.cpp client_request.h ffbuffer.h
	$(CC) $(CFLAGS) -c client_request.cpp -o client_request.o $(LD)

client_response.o: client_response.cpp client_response.h ffbuffer.h
	$(CC) $(CFLAGS) -c client_response.cpp -o client_response.o $(LD)

clean:
	rm -f ffbackup-server *.o
