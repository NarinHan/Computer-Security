#ifndef PROTO_H
#define PROTO_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUF_SIZE 4096 
#define MAX_CLNT 256

#define MSG_TYPE_TEXT       0x01
#define MSG_TYPE_FILE_META  0x02
#define MSG_TYPE_FILE_DATA  0x03

#define htonll(x)   ((((uint64_t)htonl((uint32_t)((x)>>32))) << 32) + htonl((uint32_t)(x)))
#define ntohll(x)   ((((uint64_t)ntohl((uint32_t)((x)>>32))) << 32) + ntohl((uint32_t)(x)))

struct message_header {
    uint8_t type;
    uint32_t length;
};

static int ssl_write_full(SSL *ssl, const void *buf, int len) {
    int total_written = 0;
    const uint8_t *p = (const uint8_t*)buf;
    while (total_written < len) {
        int n = SSL_write(ssl, p + total_written, len - total_written);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            switch (err) {
                case SSL_ERROR_WANT_WRITE:
                    // Retry if write would block
                    usleep(10000);  // Small delay to prevent tight loop
                    continue;
                case SSL_ERROR_WANT_READ:
                    // Retry if read is needed
                    usleep(10000);
                    continue;
                default:
                    // Actual error occurred
                    fprintf(stderr, "SSL write error: %d\n", err);
                    return -1;
            }
        }
        total_written += n;
    }
    return total_written;
}

static int ssl_read_full(SSL *ssl, void *buf, int len) {
    int total_read = 0;
    uint8_t *p = (uint8_t*)buf;
    while (total_read < len) {
        int n = SSL_read(ssl, p + total_read, len - total_read);
        if (n <= 0) return n;
        total_read += n;
    }
    return total_read;
}

static int send_text_message(SSL *ssl, const char *text) {
    struct message_header hdr;
    hdr.type = MSG_TYPE_TEXT;
    uint32_t payload_len = (uint32_t)strlen(text);
    hdr.length = htonl(payload_len);

    if (ssl_write_full(ssl, &hdr, sizeof(hdr)) <= 0) return -1;
    if (payload_len > 0 && ssl_write_full(ssl, text, payload_len) <= 0) return -1;
    return 0;
}

static int send_file_meta(SSL *ssl, const char *filename, uint64_t file_size) {
    struct message_header hdr;
    hdr.type = MSG_TYPE_FILE_META;

    uint32_t fname_len = (uint32_t)strlen(filename);
    uint32_t meta_len = sizeof(uint32_t) + fname_len + sizeof(uint64_t);
    hdr.length = htonl(meta_len);

    uint8_t *payload = (uint8_t*)malloc(meta_len);
    if (!payload) return -1;

    uint32_t fname_len_net = htonl(fname_len);
    memcpy(payload, &fname_len_net, sizeof(fname_len_net));
    memcpy(payload + sizeof(fname_len_net), filename, fname_len);
    uint64_t fsize_net = htonll(file_size);
    memcpy(payload + sizeof(fname_len_net) + fname_len, &fsize_net, sizeof(fsize_net));

    int ret = 0;
    if (ssl_write_full(ssl, &hdr, sizeof(hdr)) <= 0) ret = -1;
    if (!ret && ssl_write_full(ssl, payload, meta_len) <= 0) ret = -1;
    free(payload);
    return ret;
}

static int send_file_data(SSL *ssl, const uint8_t *data, uint32_t length) {
    struct message_header hdr;
    hdr.type = MSG_TYPE_FILE_DATA;
    hdr.length = htonl(length);

    if (ssl_write_full(ssl, &hdr, sizeof(hdr)) <= 0) return -1;
    if (length > 0 && ssl_write_full(ssl, data, length) <= 0) return -1;
    return 0;
}

static int recv_one_message(SSL *ssl, uint8_t **out_payload, uint8_t *out_type, uint32_t *out_length) {
    struct message_header hdr;
    int n = ssl_read_full(ssl, &hdr, sizeof(hdr));
    if (n <= 0) return n;

    uint8_t type = hdr.type;
    uint32_t length = ntohl(hdr.length);

    uint8_t *payload = NULL;
    if (length > 0) {
        payload = (uint8_t*)malloc(length);
        if (!payload) return -1;
        n = ssl_read_full(ssl, payload, length);
        if (n <= 0) {
            free(payload);
            return n;
        }
    }

    *out_type = type;
    *out_length = length;
    *out_payload = payload;
    return 1;
}

#endif // PROTO_H
