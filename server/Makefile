CC=g++
CFLAGS=-g -Wall
LD=-lssl -lcrypto

all: ffbackup-server
ffbackup-server: server.o task.o
	$(CC) $(CFLAGS) server.o task.o -o ffbackup-server $(LD)
server.o: server.cpp
	$(CC) $(CFLAGS) -c server.cpp -o server.o $(LD)
task.o: task.cpp
	$(CC) $(CFLAGS) -c task.cpp -o task.o $(LD)
clean:
	rm -f ffbackup-server *.o
