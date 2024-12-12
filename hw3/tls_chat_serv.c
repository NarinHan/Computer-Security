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

#define BUF_SIZE 1024
#define MAX_CLNT 256

#define htonll(x)   ((((uint64_t)htonl(x)) << 32) + htonl(x >> 32))
#define ntohll(x)   ((((uint64_t)ntohl(x)) << 32) + ntohl(x >> 32))

void *handle_clnt(void * arg);
void send_msg(char * msg, int len);
void broadcast_file(void *data, int len);
void error_handling(char * msg);

int clnt_cnt = 0;
int clnt_socks[MAX_CLNT];
SSL *ssl_list[MAX_CLNT]; // store SSL pointers for each client
pthread_mutex_t mutx;

SSL_CTX *ctx;

int main(int argc, char *argv[])
{
	int serv_sock, clnt_sock;
	struct sockaddr_in serv_adr, clnt_adr;
	int clnt_adr_sz;
	pthread_t t_id;

	if (argc != 2) {
		printf("Usage : %s <port>\n", argv[0]);
		exit(1);
	}
    
    // initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        error_handling("SSL_CTX_new() error");
    }

    // load server certificate and key
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        error_handling("Certificate error");
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        error_handling("PrivateKey error");
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        error_handling("Private key does not match the certificate public key");
    }
  
	pthread_mutex_init(&mutx, NULL);
	serv_sock = socket(PF_INET, SOCK_STREAM, 0);

	memset(&serv_adr, 0, sizeof(serv_adr));
	serv_adr.sin_family = AF_INET; 
	serv_adr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_adr.sin_port = htons(atoi(argv[1]));
	
	if (bind(serv_sock, (struct sockaddr*) &serv_adr, sizeof(serv_adr)) == -1)
		error_handling("bind() error");
	if (listen(serv_sock, 5) == -1)
		error_handling("listen() error");
	
	while (1)
	{
		clnt_adr_sz = sizeof(clnt_adr);
		clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_adr, &clnt_adr_sz);
        if (clnt_sock == -1) continue;

        // create SSL object and accept
        SSL *ssl = SSL_new(ctx); // create a new SSL object
        SSL_set_fd(ssl, clnt_sock); // associate SSL with the socket
                                
        // perform TLS handshake with the client
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(clnt_sock);
            SSL_free(ssl);
            continue;
        }
        printf("TLS handshake successful!\n");
	    printf("Cipher: %s\n", SSL_get_cipher(ssl));
        printf("TLS Version: %s\n", SSL_get_version(ssl));

		pthread_mutex_lock(&mutx);
		clnt_socks[clnt_cnt++] = clnt_sock;
        ssl_list[clnt_cnt] = ssl;
        clnt_cnt++;
		pthread_mutex_unlock(&mutx);
	
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
	int str_len = 0, i;
	char msg[BUF_SIZE];
    SSL *ssl = NULL;

    // find the corresponding SSL for this client socket
    pthread_mutex_lock(&mutx);
    for (i = 0; i < clnt_cnt; i++) {
        if (clnt_socks[i] == clnt_sock) {
            ssl = ssl_list[i];
            break;
        }
    }
    pthread_mutex_unlock(&mutx);
    
    int ret = SSL_read(ssl, msg, sizeof(msg));
    if (ret <= 0) {
        int err = SSL_get_error(ssl, ret);
        switch (err) {
            case SSL_ERROR_ZERO_RETURN:
                // The TLS/SSL peer has closed the connection
                fprintf(stderr, "SSL_read: Connection closed by peer.\n");
                break;
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                // Non-blocking operation: SSL_read needs to be called again later
                fprintf(stderr, "SSL_read: Non-blocking retry needed.\n");
                break;
            case SSL_ERROR_SYSCALL:
                // Check errno or additional error info
                perror("SSL_read: I/O error");
                break;
            case SSL_ERROR_SSL:
                // A failure in the SSL library occurred, print details
                fprintf(stderr, "SSL_read: SSL protocol error.\n");
                ERR_print_errors_fp(stderr);
                break;
            default:
                fprintf(stderr, "SSL_read: Unexpected error code %d.\n", err);
                ERR_print_errors_fp(stderr);
                break;
        }
        // Depending on err, you may need to clean up and close the connection
    }    

    while ((str_len = SSL_read(ssl, msg, sizeof(msg))) > 0)
    {
        msg[str_len] = 0;
        printf("Received: %s\n", msg);

        // check if command is file_share
        if (strstr(msg, "file_share:") != NULL) {
            // read file size
            uint64_t fsize_net;
            if (SSL_read(ssl, &fsize_net, sizeof(uint64_t)) <= 0)
                break;
            uint64_t fsize = ntohll(fsize_net);

            // Read file data
            char *file_data = (char*)malloc(fsize);
            if (!file_data) {
                // If memory alloc fails, just discard data
                char dummy[BUF_SIZE];
                uint64_t remaining = fsize;
                while (remaining>0) {
                    int toread = (remaining > sizeof(dummy)) ? sizeof(dummy) : remaining;
                    int n = SSL_read(ssl,dummy,toread);
                    if (n <= 0) break;
                    remaining -= n;
                }
                continue;
            }

            uint64_t remaining = fsize;
            char fbuf[BUF_SIZE];
            char *ptr = file_data;
            while (remaining > 0) {
                int toread = (remaining > sizeof(fbuf)) ? sizeof(fbuf) : remaining;
                int n = SSL_read(ssl, fbuf, toread);
                if (n <= 0) { 
                    free(file_data); 
                    goto cleanup;
                }
                memcpy(ptr, fbuf, n);
                ptr += n;
                remaining -= n;
            }

            // broadcast the initial line (with file_share:)
            send_msg(msg, str_len);
            // broadcast the file size
            broadcast_file((char*)&fsize_net, sizeof(uint64_t));
            // Broadcast the file data
            broadcast_file(file_data, fsize);
            free(file_data);
        } else {
            send_msg(msg, str_len);
        }
    }

cleanup:
	pthread_mutex_lock(&mutx);
	for (i = 0; i < clnt_cnt; i++)   // remove disconnected client
	{
		if (clnt_sock == clnt_socks[i])
		{
            SSL_free(ssl_list[i]);
            // shift remaining clients
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

void send_msg(char * msg, int len)   // send to all
{
	pthread_mutex_lock(&mutx);
	for (int i = 0; i < clnt_cnt; i++)
		SSL_write(ssl_list[i], msg, len);
	pthread_mutex_unlock(&mutx);
}

void broadcast_file(void *data, int len) 
{
    pthread_mutex_lock(&mutx);
    for (int i = 0; i < clnt_cnt; i++) {
        SSL_write(ssl_list[i], data, len);
    }
    pthread_mutex_unlock(&mutx);
}

void error_handling(char * msg)
{
	fputs(msg, stderr);
	fputc('\n', stderr);
	exit(EXIT_FAILURE);
}
