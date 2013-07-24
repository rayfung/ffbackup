CC=g++
CFLAGS=-g -Wall
LD=-lssl -lcrypto

all: ffbackup-server
ffbackup-server: server.o task.o ffbuffer.o
	$(CC) $(CFLAGS) server.o task.o ffbuffer.o -o ffbackup-server $(LD)
server.o: server.cpp
	$(CC) $(CFLAGS) -c server.cpp -o server.o $(LD)
task.o: task.cpp
	$(CC) $(CFLAGS) -c task.cpp -o task.o $(LD)
ffbuffer.o: ffbuffer.cpp
	$(CC) $(CFLAGS) -c ffbuffer.cpp -o ffbuffer.o $(LD)
clean:
	rm -f ffbackup-server *.o
