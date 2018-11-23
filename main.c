/*
 * main.c --
 *
 *      Main driver for testing xchacha20siv.c. Uses libsodium to
 *      implement the HMAC-SHA256 and XChaCha20 functions.
 *
 * Copyright (c) 2018 Neil Madden.
 * Copyright (c) 2018 ForgeRock AS.
 */
#include "xchacha20siv.h"
#include <sodium/crypto_stream_xchacha20.h>
#include <sodium/crypto_auth_hmacsha256.h>
#include <string.h>
#include <stdio.h>

static const unsigned char KEY[64] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf
};

static const unsigned char PLAINTEXT[] =
    "Ladies and Gentlemen of the class of '99: If I could offer you "
    "only one tip for the future, sunscreen would be it.";
static const size_t PT_LEN = 114;

static const unsigned char ASSOC_DATA[12] = {
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 
    0xc4, 0xc5, 0xc6, 0xc7
};

static const unsigned char IV[8] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
};

int main(void)
{
    FILE *out;
    unsigned char buf[TAG_LEN + PT_LEN];
    memcpy(buf + TAG_LEN, PLAINTEXT, PT_LEN);
    int ret;

    const assoc_data_t ad[2] = {
        { .data = ASSOC_DATA, .len = 12 },
        { .data = IV, .len = 8 }
    };

    xchacha20siv_encrypt(KEY, buf, PT_LEN, ad, 2);

    out = fopen("/tmp/ciphertext.bin", "wb");
    fwrite(buf, sizeof(buf), 1, out);
    fclose(out);

    return 0;
}

void hmac_sha256(const void *key, const void *data, size_t len, void *tag)
{
    if (crypto_auth_hmacsha256(tag, data, len, key) != 0) {
        fprintf(stderr, "crypto_auth_hmacsha256 returned non-zero error\n");
        exit(1);
    }
}

void xchacha20(const void *key, const void *iv, void *data, size_t len)
{
    if (crypto_stream_xchacha20_xor(data, data, len, iv, key) != 0) {
        fprintf(stderr, "crypto_stream_xchacha20_xor returned non-zero error\n");
        exit(1);
    }
}
