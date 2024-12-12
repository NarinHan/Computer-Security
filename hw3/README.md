# TLS Chat Program

This project implements a simple TLS-encrypted chat application with both a server and a client component, using OpenSSL for TLS support. The server can handle multiple clients and broadcast messages and files between them securely. The client connects to the server, sends/receives messages, and can also transfer files over the encrypted channel.

## Features

- **TLS Encryption:**  
  Uses OpenSSL for TLS (Transport Layer Security) to secure the connection and data transmission.

- **Multi-Client Support (Server):**  
  The server can accept multiple clients simultaneously. Each message or file from one client is broadcast to all other clients.

- **File Transfer:**  
  Clients can send files to the server, which in turn broadcasts the file to all connected clients. Files are split into chunks and sent securely.

- **Distinct Commands:**
  - Normal chat messages are simply typed and sent.
  - To send a file, the client uses the command `file_share: <filename>`.

- **No Self-Message Display (Client):**  
  The client does not display its own messages that are echoed back from the server.

- **Graceful Shutdown:**  
  Typing 'q' on the client side requests a graceful termination.

## Requirements

- **Operating System:**  
  Linux or a Unix-like environment is recommended.

- **Dependencies:**  
  - GCC or Clang (any C compiler supporting C99 or newer)
  - pthread library (POSIX threads)
  - OpenSSL (libssl, libcrypto)

### OpenSSL Version

This code has been tested with:  
- **OpenSSL version:** 1.1.1 or later

Check your installed version with: `openssl version`
Any recent stable OpenSSL (1.1.1 or 3.x) should work.

## Generating Certificates

Before running the server, you need a server certificate and private key. You can generate a self-signed certificate for testing:

`
openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 365
`

Follow the prompts to create a certificate. The resulting server.crt and server.key files will be used by the server.
The client will use server.crt as a trusted CA to verify the server’s certificate.

## Compilation

Compile the server and client using the following commands:
- Compile the server
`gcc -o tls_chat_serv tls_chat_serv.c -lpthread -lssl -lcrypto`
- Compile the client
`gcc -o tls_chat_clnt tls_chat_clnt.c -lpthread -lssl -lcrypto`

Or you can simple use `make` for both programs to be compiled.

**Notes:**
Ensure the -lssl -lcrypto flags come after the source files.
If OpenSSL is installed in a non-standard location, you may need to add -I and -L flags to indicate include and library paths. For example: 
` 
gcc -I/usr/local/ssl/include -L/usr/local/ssl/lib -o tls_chat_serv tls_chat_serv.c -lpthread -lssl -lcrypto
`
Adjust paths as necessary.

## Running the Server
1. Place `server.crt` and `server.key` in the same directory as `tls_chat_serv`.
2. Run the server: `./tls_chat_serv <port>`
   For example: `./tls_chat_serv 9999`

## Running the Client
1. Place `server.crt` in the same directory as `tls_chat_clnt` so the client can verify the server’s certificate.
2. Run the client: `./tls_chat_clnt <server_ip> <port> <name>`
   For example: `./tls_chat_clnt 127.0.0.1 9999 alice`

## Usage
**Chatting:**
- Simply type your message and press Enter. All other connected clients will receive it.

**Quitting:**
- Type 'q' or 'Q' and press Enter to gracefully disconnect.

**File Sharing:**
- To send a file to all other clients: `file_share: <filename>`
- For example: `file_share: newton.png`

The client will read the file image.png from the current directory, send it to the server, and the server will broadcast it to all other clients. The receiving clients will save the file in their current directory.
