#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "proto.h"

int clnt_cnt = 0;
int clnt_socks[MAX_CLNT];
SSL *ssl_list[MAX_CLNT]; 
pthread_mutex_t mutx;

SSL_CTX *ctx;

void *handle_clnt(void * arg);
void error_handling(char * msg);

void broadcast_text_message(const char *text) {
    SSL *local_ssl_list[MAX_CLNT];
    int local_count;

    // Acquire the lock only to copy the list of clients
    pthread_mutex_lock(&mutx);
    local_count = clnt_cnt;
    for (int i = 0; i < local_count; i++) {
        local_ssl_list[i] = ssl_list[i];
    }
    pthread_mutex_unlock(&mutx);

    // Now send to all clients without holding the mutex
    for (int i = 0; i < local_count; i++) {
        // SSL_write inside send_text_message can block, but no mutex is held
        send_text_message(local_ssl_list[i], text);
    }
}

void broadcast_file_meta(const char *filename, uint64_t fsize) {
    SSL *local_ssl_list[MAX_CLNT];
    int local_count;

    pthread_mutex_lock(&mutx);
    local_count = clnt_cnt;
    for (int i = 0; i < local_count; i++) {
        local_ssl_list[i] = ssl_list[i];
    }
    pthread_mutex_unlock(&mutx);

    for (int i = 0; i < local_count; i++) {
        send_file_meta(local_ssl_list[i], filename, fsize);
    }
}

void broadcast_file_data(const uint8_t *data, uint32_t length) {
    SSL *local_ssl_list[MAX_CLNT];
    int local_count;

    pthread_mutex_lock(&mutx);
    local_count = clnt_cnt;
    for (int i = 0; i < local_count; i++) {
        local_ssl_list[i] = ssl_list[i];
    }
    pthread_mutex_unlock(&mutx);

    for (int i = 0; i < local_count; i++) {
        send_file_data(local_ssl_list[i], data, length);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage : %s <port>\n", argv[0]);
        exit(1);
    }

    // Initialize OpenSSL
    SSL_library_init(); // Initialize SSL library
    OpenSSL_add_all_algorithms(); // Load crypto algorithms
    SSL_load_error_strings(); // Load error strings for debugging
    const SSL_METHOD *method = TLS_server_method(); // Use TLS server method
    ctx = SSL_CTX_new(method); // Create SSL context
    if (!ctx) {
        error_handling("SSL_CTX_new() error");
    }

    // Load server certificate
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        error_handling("Certificate error");
    }
    // Load server private key
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        error_handling("PrivateKey error");
    }
    // Check that private key and certificate match
    if (!SSL_CTX_check_private_key(ctx)) {
        error_handling("Private key does not match the certificate public key");
    }

    pthread_mutex_init(&mutx, NULL);
    int serv_sock = socket(PF_INET, SOCK_STREAM, 0);

    struct sockaddr_in serv_adr;
    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family = AF_INET; 
    serv_adr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_adr.sin_port = htons(atoi(argv[1]));

    if (bind(serv_sock, (struct sockaddr*) &serv_adr, sizeof(serv_adr)) == -1)
        error_handling("bind() error");
    if (listen(serv_sock, 5) == -1)
        error_handling("listen() error");

    printf("Server running on port %s...\n", argv[1]);

    while (1)
    {
        struct sockaddr_in clnt_adr;
        socklen_t clnt_adr_sz = sizeof(clnt_adr);
        int clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_adr, &clnt_adr_sz);
        if (clnt_sock == -1) continue;

        SSL *ssl = SSL_new(ctx); // Create new SSL object
        SSL_set_fd(ssl, clnt_sock); // Associate SSL with the socket
        // Perform TLS handshake
        if (SSL_accept(ssl) <= 0) { // SSL_accept() establishes SSL/TLS session as server
            ERR_print_errors_fp(stderr);
            close(clnt_sock);
            SSL_free(ssl);
            continue;
        }
        printf("TLS handshake successful with client %s\n", inet_ntoa(clnt_adr.sin_addr));

        pthread_mutex_lock(&mutx);
        clnt_socks[clnt_cnt] = clnt_sock;
        ssl_list[clnt_cnt] = ssl;
        clnt_cnt++;
        pthread_mutex_unlock(&mutx);

        pthread_t t_id;
        pthread_create(&t_id, NULL, handle_clnt, (void*)&clnt_sock);
        pthread_detach(t_id);
        printf("Connected client IP: %s \n", inet_ntoa(clnt_adr.sin_addr));
    }

    close(serv_sock);
    SSL_CTX_free(ctx);
    return 0;
}

void *handle_clnt(void * arg)
{
    int clnt_sock = *((int*)arg);
    SSL *ssl = NULL;

    pthread_mutex_lock(&mutx);
    for (int i = 0; i < clnt_cnt; i++) {
        if (clnt_socks[i] == clnt_sock) {
            ssl = ssl_list[i];
            break;
        }
    }
    pthread_mutex_unlock(&mutx);

    uint8_t *payload = NULL;
    uint8_t type;
    uint32_t length;

    while (1) {
        int ret = recv_one_message(ssl, &payload, &type, &length);
        if (ret <= 0) {
            // Client disconnected
            break;
        }

        if (type == MSG_TYPE_TEXT) {
            char *text = (char*)malloc(length+1);
            memcpy(text, payload, length);
            text[length] = '\0';
            free(payload); 
            payload = NULL;

            printf("Server received TEXT: \"%s\"\n", text);
            broadcast_text_message(text);
            free(text);

        } else if (type == MSG_TYPE_FILE_META) {
            if (length < 12) { 
                free(payload); 
                break; 
            }

            uint32_t fname_len_net;
            memcpy(&fname_len_net, payload, 4);
            uint32_t fname_len = ntohl(fname_len_net);
            if (length < 4 + fname_len + 8) { free(payload); break; }

            char *filename = (char*)malloc(fname_len+1);
            memcpy(filename, payload+4, fname_len);
            filename[fname_len] = '\0';

            uint64_t fsize_net;
            memcpy(&fsize_net, payload+4+fname_len, 8);
            uint64_t fsize = ntohll(fsize_net);

            printf("Server received FILE META: filename=%s, size=%llu\n", filename, (unsigned long long)fsize);

            free(payload); 
            payload = NULL;

            broadcast_file_meta(filename, fsize);
            free(filename);

        } else if (type == MSG_TYPE_FILE_DATA) {
            // Broadcast the received data chunk to all
            printf("Server received FILE DATA chunk (%u bytes)\n", length);
            broadcast_file_data(payload, length);
            free(payload); 
            payload = NULL;
        } else {
            // Unknown message type
            free(payload); 
            payload = NULL;
        }
    }

    // Remove client
    pthread_mutex_lock(&mutx);
    for (int i = 0; i < clnt_cnt; i++) {
        if (clnt_socks[i] == clnt_sock) {
            SSL_free(ssl_list[i]); // Free SSL object
            for (int j = i; j < clnt_cnt - 1; j++) {
                clnt_socks[j] = clnt_socks[j+1];
                ssl_list[j] = ssl_list[j+1];
            }
            clnt_cnt--;
            printf("Number of current connected clients: %d\n", clnt_cnt);
            break;
        }
    }
    pthread_mutex_unlock(&mutx);
    close(clnt_sock);
    return NULL;
}

void error_handling(char * msg)
{
    fputs(msg, stderr);
    fputc('\n', stderr);
    exit(EXIT_FAILURE);
}
