CC=g++
CFLAGS=-g -Wall
LD=-lssl -lcrypto

all: ffbackup-server

ffbackup-server: server.o task.o ffbuffer.o ffprotocol.o
	$(CC) $(CFLAGS) server.o task.o ffbuffer.o ffprotocol.o -o ffbackup-server $(LD)

server.o: server.cpp server.h task.h ffbuffer.h
	$(CC) $(CFLAGS) -c server.cpp -o server.o $(LD)

task.o: task.cpp server.h task.h ffbuffer.h
	$(CC) $(CFLAGS) -c task.cpp -o task.o $(LD)

ffbuffer.o: ffbuffer.cpp ffbuffer.h
	$(CC) $(CFLAGS) -c ffbuffer.cpp -o ffbuffer.o $(LD)

ffprotocol.o: ffprotocol.cpp ffprotocol.h ffbuffer.h data_types.h
	$(CC) $(CFLAGS) -c ffprotocol.cpp -o ffprotocol.o $(LD)

clean:
	rm -f ffbackup-server *.o
