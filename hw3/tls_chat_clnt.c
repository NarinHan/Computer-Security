#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h> 
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "proto.h"

#define NAME_SIZE 20

void *send_msg(void * arg);
void *recv_msg(void * arg);
void error_handling(char * msg);

char name[NAME_SIZE] = "[DEFAULT]";
SSL_CTX *ctx;
SSL *ssl;
int sock;
int done = 0; // Flag to indicate user requested quit

pthread_t snd_thread, rcv_thread;

int send_file_to_server(SSL *ssl, const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("file open error");
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Prepend client name to filename to make it unique
    char unique_filename[BUF_SIZE];
    snprintf(unique_filename, sizeof(unique_filename), "%s_%s", name, filename);

    // Send file meta first with unique filename
    if (send_file_meta(ssl, unique_filename, (uint64_t)fsize) < 0) {
        fclose(fp);
        return -1;
    }

    uint8_t fbuf[BUF_SIZE];
    size_t nread;
    uint64_t total_sent = 0;
    int chunk_count = 0;
    while (1) {
        // Read a chunk of the file
        nread = fread(fbuf, 1, sizeof(fbuf), fp);
        
        if (nread == 0) {
            // Check if we've reached end of file or an error occurred
            if (feof(fp)) {
                break;  // Successfully reached end of file
            }
            
            if (ferror(fp)) {
                perror("File read error");
                fclose(fp);
                return -1;
            }
        }
        printf("nread : %zu\n", nread);
        
        if (send_file_data(ssl, fbuf, (uint32_t)nread) < 0) {
            fclose(fp);
            fprintf(stderr, "Failed to send file data chunk.\n");
            return -1;
        }
        total_sent += nread;
        chunk_count++;

        // Debug: print confirmation of chunk sent
        printf("Sent chunk #%d of size %zu, total sent: %llu bytes\n",
               chunk_count, nread, (unsigned long long)total_sent);

        // If we haven't read as much as we expected, check if there's an error
        if (nread < sizeof(fbuf) && ferror(fp)) {
            perror("fread error after partial read");
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);
    // Confirm if we sent exactly fsize bytes
    if ((uint64_t)fsize != total_sent) {
        fprintf(stderr, "Warning: file size mismatch. Expected %ld, sent %llu bytes.\n", fsize, (unsigned long long)total_sent);
    } else {
        printf("File [%s] sent successfully! Total bytes: %llu, Chunks: %d\n",
               filename, (unsigned long long)total_sent, chunk_count);
    }
    return 0;
}

int main(int argc, char *argv[])
{
    // Initialize OpenSSL
    SSL_library_init(); // Initialize SSL library
    OpenSSL_add_all_algorithms(); // Load all crypto algorithms
    SSL_load_error_strings(); // Load human-readable SSL error strings
    const SSL_METHOD *method = TLS_client_method(); // Use TLS client method
    ctx = SSL_CTX_new(method); // Create new SSL context
    if (!ctx) {
        error_handling("SSL_CTX_new() error");
    }

    // Load the server's certificate as trusted CA
    if (!SSL_CTX_load_verify_locations(ctx, "server.crt", NULL)) {
        fprintf(stderr, "Error loading server certificate as CA.\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); // Enable certificate verification

    if (argc != 4) {
        printf("Usage : %s <IP> <port> <name>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    snprintf(name, sizeof(name), "[%s]", argv[3]);
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        error_handling("socket() error");
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family=AF_INET;
    serv_addr.sin_addr.s_addr=inet_addr(argv[1]);
    serv_addr.sin_port=htons(atoi(argv[2]));

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
        error_handling("connect() error");

    ssl = SSL_new(ctx); // Create new SSL structure
    SSL_set_fd(ssl, sock); // Associate SSL with the socket
    // Initiate TLS handshake as client
    if (SSL_connect(ssl) <= 0) { // SSL_connect() performs TLS/SSL handshake
        ERR_print_errors_fp(stderr);
        error_handling("SSL_connect() error");
    }

    printf("TLS handshake successful!\n");
    printf("Cipher: %s\n", SSL_get_cipher(ssl)); // SSL_get_cipher() retrieves the currently used cipher
    printf("TLS Version: %s\n", SSL_get_version(ssl)); // SSL_get_version() gets the TLS/SSL protocol version

    pthread_create(&snd_thread, NULL, send_msg, NULL);
    pthread_create(&rcv_thread, NULL, recv_msg, NULL);
    pthread_join(snd_thread, NULL);
    pthread_join(rcv_thread, NULL);

    // After threads exit, perform a clean shutdown
    // SSL_shutdown() sends a "close_notify" alert to properly close the TLS connection
    SSL_shutdown(ssl); 
    SSL_free(ssl);  // Free the SSL structure
    SSL_CTX_free(ctx); // Free the SSL context
    close(sock);
    return 0;
}


void *send_msg(void *arg)
{
    char msg[BUF_SIZE];

    while (!done) {
        printf("%s ", name);
        fflush(stdout);

        if (!fgets(msg, BUF_SIZE, stdin)) {
            // End of input (EOF)
            done = 1;
            break;
        }

        if (!strcmp(msg, "q\n") || !strcmp(msg, "Q\n")) {
            // User wants to quit
            done = 1;
            break;
        }

        // Trim newline
        size_t len = strlen(msg);
        if (len > 0 && msg[len-1] == '\n') {
            msg[len-1] = '\0';
        }

        if (strncmp(msg, "file_share:", 11) == 0) {
            char filename[BUF_SIZE];
            if (sscanf(msg + 11, "%s", filename) != 1) {
                printf("Usage: file_share: <filename>\n");
                continue;
            }
            printf("Sending file: %s\n", filename);
            if (send_file_to_server(ssl, filename) < 0) {
                fprintf(stderr, "Failed to send file.\n");
            }
        } else {
            // Normal text message
            char name_msg[NAME_SIZE+BUF_SIZE];
            snprintf(name_msg, sizeof(name_msg), "%s %s", name, msg);
            if (send_text_message(ssl, name_msg) < 0) {
                fprintf(stderr, "Failed to send text message.\n");
            } else {
                printf("Sent TEXT: \"%s\"\n", name_msg);
            }
        }
    }

    return NULL;
}


void *recv_msg(void *arg)
{
    uint8_t *payload = NULL;
    uint8_t type;
    uint32_t length;

    char current_filename[BUF_SIZE];
    FILE *fp = NULL;
    uint64_t file_bytes_remaining = 0;
    int receiving_file = 0;
    uint64_t total_received = 0;
    int chunk_count = 0;
    int is_own_file = 0;  // Flag to track if the file is sent by this client

    while (1) {
        if (done) {
            // If done=1 and no pending data, break immediately
            if (SSL_pending(ssl) == 0) { // SSL_pending() checks if data is ready to be read
                break;
            }
        }

        int ret = recv_one_message(ssl, &payload, &type, &length);
        if (ret <= 0) {
            // Server closed connection or error occurred
            break;
        }

        if (type == MSG_TYPE_TEXT) {
            char *text = (char*)malloc(length+1);
            memcpy(text, payload, length);
            text[length] = '\0';
            free(payload); 
            payload = NULL;

            // Check if this message is from us (skip if yes)
            if (strncmp(text, name, strlen(name)) != 0) {
                printf("Received TEXT: \"%s\"\n", text);
            }
            free(text);

        } else if (type == MSG_TYPE_FILE_META) {
            if (length < 12) { free(payload); break; }

            uint32_t fname_len_net;
            memcpy(&fname_len_net, payload, 4);
            uint32_t fname_len = ntohl(fname_len_net);
            if (length < 4+fname_len+8) { 
                free(payload); 
                break; 
            }

            memcpy(current_filename, payload+4, fname_len);
            current_filename[fname_len] = '\0';

            uint64_t fsize_net;
            memcpy(&fsize_net, payload+4+fname_len, 8);
            uint64_t fsize = ntohll(fsize_net);

            free(payload); 
            payload = NULL;

            // Check if this file is from this client
            is_own_file = strstr(current_filename, name) != NULL;
            if (is_own_file) {
                printf("Skipping own file transfer: %s\n", current_filename);
                continue;
            }

            fp = fopen(current_filename, "wb");
            if (!fp) {
                fprintf(stderr, "Could not open file %s for writing. Discarding data.\n", current_filename);
                file_bytes_remaining = fsize;
            } else {
                file_bytes_remaining = fsize;
            }
            receiving_file = 1;
            total_received = 0;
            chunk_count = 0;
            printf("Receiving file: %s (%llu bytes)\n", current_filename, (unsigned long long)fsize);

        } else if (type == MSG_TYPE_FILE_DATA) {
            // Skip processing if this is the client's own file
            if (is_own_file) {
                free(payload);
                payload = NULL;
                continue;
            }

            if (receiving_file) {
                size_t to_write = (length > file_bytes_remaining) ? (size_t)file_bytes_remaining : length;
                if (fp) {
                    fwrite(payload, 1, to_write, fp);
                    fflush(fp); // Ensure data is written to disk
                }
                file_bytes_remaining -= to_write;
                total_received += to_write;
                chunk_count++;

                if (file_bytes_remaining == 0) {
                    if (fp) {
                        fclose(fp);
                        fp = NULL;
                    }
                    receiving_file = 0;
                    printf("File [%s] received successfully! %llu bytes total in %d chunks.\n",
                           current_filename, (unsigned long long)total_received, chunk_count);
                }
            }
            free(payload); 
            payload = NULL;
        } else {
            printf("Received unknown message type: %d\n", type);
            free(payload); 
            payload = NULL;
        }
    }

    if (fp) {
        fclose(fp);
        fp = NULL;
    }

    return NULL;
}


void error_handling(char *msg)
{
    fputs(msg, stderr);
    fputc('\n', stderr);
    exit(1);
}
