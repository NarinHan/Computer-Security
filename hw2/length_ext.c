#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

void calculate_padding(int original_length, unsigned char *padding, int *padding_length) {
    int block_size = 64; // SHA-256 block size in bytes
    int length_field_size = 8; // Length field is 8 bytes

    // Calculate the number of padding bytes needed
    int padding_bytes_needed = block_size - ((original_length % block_size) + length_field_size);
    if (padding_bytes_needed <= 0) {
        padding_bytes_needed += block_size;
    }

    *padding_length = padding_bytes_needed + length_field_size;

    // Construct the padding
    memset(padding, 0, *padding_length); // Initialize all bytes to zero
    padding[0] = 0x80; // Start with \x80

    // Add the length field (original message length in bits, big-endian format)
    long long bit_length = (long long)original_length * 8;
    for (int i = 0; i < 8; i++) {
        padding[*padding_length - 8 + i] = (bit_length >> (56 - i * 8)) & 0xff;
    }
}

char *url_encode_padding(const unsigned char *padding, int padding_length) {
    int encoded_length = (padding_length * 3) + 1; // Each byte becomes %xx, plus null terminator
    char *encoded_padding = (char *)malloc(encoded_length);
    if (encoded_padding == NULL) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }

    encoded_padding[0] = '\0'; // Initialize encoded string
    char temp[4]; // Temporary buffer for %xx encoding
    for (int i = 0; i < padding_length; i++) {
        sprintf(temp, "%%%02x", padding[i]);
        strcat(encoded_padding, temp);
    }

    return encoded_padding; // Return dynamically allocated string
}

int main(int argc, const char *argv[]) {
    int i;
    unsigned char buffer[SHA256_DIGEST_LENGTH];
    SHA256_CTX c;

    // Initialize SHA-256 context with the original MAC state
    SHA256_Init(&c);
    for (i = 0; i < 64; i++)
        SHA256_Update(&c, "*", 1);

    // Original MAC of the message is computed in Task 1
    unsigned int original_mac[] = {
        0xa83e3e00, 0x45483304, 0xe79069af, 0x2241b5ff,
        0xb19c9087, 0x54cf2dba, 0xcf6c9ecf, 0x305116ec
    };
    c.h[0] = htole32(original_mac[0]);
    c.h[1] = htole32(original_mac[1]);
    c.h[2] = htole32(original_mac[2]);
    c.h[3] = htole32(original_mac[3]);
    c.h[4] = htole32(original_mac[4]);
    c.h[5] = htole32(original_mac[5]);
    c.h[6] = htole32(original_mac[6]);
    c.h[7] = htole32(original_mac[7]);

    // Construct padding for the original message
    const char *public_message = "myname=Narin&uid=1005&lstcmd=1";
    const char *original_message = "xciujk:myname=Narin&uid=1005&lstcmd=1";
    int original_length = strlen(original_message);
    unsigned char padding[64];
    int padding_length = 0;
    calculate_padding(original_length, padding, &padding_length);
    printf("padding length: %d\n", padding_length);

    // URL-encode the padding
    char *encoded_padding = url_encode_padding(padding, padding_length);

    // Append the new message
    const char *new_message = "&download=secret.txt";
    int new_message_length = strlen(new_message);

    // Process the new message using SHA-256
    SHA256_Update(&c, new_message, new_message_length);
    SHA256_Final(buffer, &c);

    char forged_mac[65];
    for (i = 0; i < 32; i++) {
        sprintf(&forged_mac[i * 2], "%02x", buffer[i]);
    }

    // Construct the malicious URL
    char malicious_url[1024];
    snprintf(malicious_url, sizeof(malicious_url),
             "http://www.seedlab-hashlen.com/?%s%s%s&mac=%s",
             public_message, encoded_padding, new_message, forged_mac);

    // Print the results
    printf("Public message: %s\n", public_message);
    printf("Encoded Padding: %s\n", encoded_padding);
    printf("New message: %s\n", new_message);
    printf("Forged MAC: %s\n", forged_mac);
    printf("Malicious URL: %s\n", malicious_url);

    free(encoded_padding);

    return 0;
}
