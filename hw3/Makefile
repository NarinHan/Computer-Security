# Compiler and Flags
CC = gcc
CFLAGS = -Wall -O2 -pthread
LDFLAGS = -lssl -lcrypto -pthread

# Targets
all: tls_chat_clnt tls_chat_serv

tls_chat_clnt: tls_chat_clnt.o
	$(CC) $(CFLAGS) -o tls_chat_clnt tls_chat_clnt.o $(LDFLAGS)

tls_chat_serv: tls_chat_serv.o
	$(CC) $(CFLAGS) -o tls_chat_serv tls_chat_serv.o $(LDFLAGS)

# Compile object files
tls_chat_clnt.o: tls_chat_clnt.c
	$(CC) $(CFLAGS) -c tls_chat_clnt.c

tls_chat_serv.o: tls_chat_serv.c
	$(CC) $(CFLAGS) -c tls_chat_serv.c

# Clean up build artifacts
clean:
	rm -f *.o tls_chat_clnt tls_chat_serv

