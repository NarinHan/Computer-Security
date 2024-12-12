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
	
#define BUF_SIZE 1024
#define NAME_SIZE 20
	
#define htonll(x)   ((((uint64_t)htonl(x)) << 32) + htonl(x >> 32))
#define ntohll(x)   ((((uint64_t)ntohl(x)) << 32) + ntohl(x >> 32))

void *send_msg(void * arg);
void *recv_msg(void * arg);
void error_handling(char * msg);
	
char name[NAME_SIZE] = "[DEFAULT]";
char msg[BUF_SIZE];

SSL_CTX *ctx;
SSL *ssl;
	
int main(int argc, char *argv[])
{
	int sock;
	struct sockaddr_in serv_addr;
	pthread_t snd_thread, rcv_thread;
	void * thread_return;
	if (argc != 4) {
		printf("Usage : %s <IP> <port> <name>\n", argv[0]);
		exit(EXIT_FAILURE);
	 }
	
	sprintf(name, "[%s]", argv[3]);
	sock = socket(PF_INET, SOCK_STREAM, 0);
	
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port = htons(atoi(argv[2]));
	  
	if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
		error_handling("connect() error");

    // initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms(); // load all crypto algorithms
    SSL_load_error_strings(); // load all error messages
    const SSL_METHOD *method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        error_handling("SLS_CTX_new() error");
    }

    // load server's (self-signed) certificate as trusted CA
    if (!SSL_CTX_load_verify_locations(ctx, "server.crt", NULL)) {
        fprintf(stderr, "Error loading server certificate as trusted CA.\n");
        ERR_print_errors_fp(stderr); 
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        error_handling("SSL_connect() error");
    }
    printf("TLS handshake successful!\n");
    printf("Cipher: %s\n", SSL_get_cipher(ssl));
    printf("TLS Version: %s\n", SSL_get_version(ssl));

	pthread_create(&snd_thread, NULL, send_msg, (void*)&sock);
	pthread_create(&rcv_thread, NULL, recv_msg, (void*)&sock);
	pthread_join(snd_thread, &thread_return);
	pthread_join(rcv_thread, &thread_return);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
	close(sock);  
	return 0;
}
	
void *send_msg(void * arg)   // send thread main
{
	int sock = *((int*)arg);
	char name_msg[NAME_SIZE+BUF_SIZE];

	while (1) 
	{
        printf("%s ", name);
        fflush(stdout);

		if (!fgets(msg, BUF_SIZE, stdin)) 
            break;

		if (!strcmp(msg, "q\n") || !strcmp(msg, "Q\n")) 
		{
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
			close(sock);
			exit(EXIT_SUCCESS);
		}

        if (strncmp(msg, "file_share:", 11) == 0) {
            // extract file name
            char filename[BUF_SIZE];
            if (sscanf(msg + 11, "%s", filename) != 1) {
                printf("Usage: file_share: <filename>\n");
                continue;
            }

            // send the command line first to inform
            sprintf(name_msg, "%s %s", name, msg);
            SSL_write(ssl, name_msg, strlen(name_msg));

            // open the file and send the contents
            FILE *fp = fopen(filename, "rb");
            if (!fp) {
                perror("file open error");
                continue;
            }

            // get file size
            fseek(fp, 0, SEEK_END);
            long fsize = ftell(fp);
            fseek(fp, 0, SEEK_SET);

            // send file size
            long fsize_net = htonll((uint64_t)fsize);
            SSL_write(ssl, (char *)&fsize_net, sizeof(uint64_t));

            // send file data
            char fbuf[BUF_SIZE];
            size_t nread;
            while ((nread = fread(fbuf, 1, sizeof(fbuf), fp)) > 0) {
                SSL_write(ssl, fbuf, nread);
            }
            fclose(fp);
            printf("File [%s] sent successfully!\n", filename);
        } else {    
		    sprintf(name_msg, "%s %s", name, msg);
            SSL_write(ssl, name_msg, strlen(name_msg));
        }
	}
	
    return NULL;
}
	
void *recv_msg(void * arg)   // read thread main
{
	int sock = *((int*)arg);
	char name_msg[NAME_SIZE+BUF_SIZE];
	int str_len;

	while (1)
	{
        // receive data over TLS
		str_len = SSL_read(ssl, name_msg, NAME_SIZE+BUF_SIZE-1);
		if (str_len <= 0) 
			return (void*)-1;
		name_msg[str_len] = 0;

        if (strstr(name_msg, "file_share:") != NULL) {
            char *p = strstr(name_msg, "file_share:");
            char filename[BUF_SIZE];
            if (sscanf((p+11), "%s", filename) != 1) {
                fputs("Error parsing filename.\n", stderr);
                continue;
            }

            // read file size
            uint64_t fsize_net;
            if (SSL_read(ssl, &fsize_net, sizeof(uint64_t)) <= 0) {
                fputs("Error reading file size.\n", stderr);
                continue;
            }
            uint64_t fsize = ntohll(fsize_net);

            // receive the file data
            FILE *fp = fopen(filename, "wb");
            if (!fp) {
                fputs("File open error.\n", stdout);
                // still must read the data to clear the SSL buffer
                char dummy[BUF_SIZE];
                uint64_t remaining = fsize;
                while (remaining > 0) {
                    int toread = (remaining > sizeof(dummy)) ? sizeof(dummy) : remaining;
                    int n = SSL_read(ssl, dummy, toread);
                    if (n <= 0) break;
                    remaining -= n;
                }
                continue;
            }

            uint64_t remaining = fsize;
            while (remaining > 0) {
                char fbuf[BUF_SIZE];
                int toread = (remaining > sizeof(fbuf)) ? sizeof(fbuf) : remaining;
                int n = SSL_read(ssl, fbuf, toread);
                if (n <= 0) break;
                fwrite(fbuf, 1, n, fp);
                remaining -= n;
            }
            
            fclose(fp);
            printf("File [%s] received succesfully!\n", filename);
        } else {
            fputs(name_msg, stdout);
        }
    }
	return NULL;
}
	
void error_handling(char *msg)
{
	fputs(msg, stderr);
	fputc('\n', stderr);
	exit(1);
}
