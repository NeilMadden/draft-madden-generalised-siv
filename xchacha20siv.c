/*
 * xchacha20siv.c --
 *
 *      Reference implementation of XChaCha20-HMAC-SHA256-SIV.
 *
 * Copyright (c) 2018 Neil Madden.
 * Copyright (c) 2018 ForgeRock AS.
 */

#include "xchacha20siv.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>

static const unsigned char ZERO[TAG_LEN] = { 0 };
static const unsigned char ONE[TAG_LEN]  = { 0, [TAG_LEN-1] = 1 };

static const unsigned char PRIM_POLY[2] = { 0x04, 0x25 };

void hexdump(const unsigned char *data, size_t len)
{
    size_t i;

    for (i = 0; i < len; ++i) {
        if (i % 16 == 0) { printf("\n   "); }
        if (i % 4 == 0) { printf(" "); }

        printf("%02x", data[i]);
    }
    printf("\n");
}

static void xor(unsigned char *x, const unsigned char *y, size_t len)
{
    size_t i;

    for (i = 0; i < len; ++i) {
        x[i] ^= y[i];
    }

    printf("xor:");
    hexdump(x, len);
}

static void xorend(unsigned char *x, size_t x_len, const unsigned char *y, size_t y_len)
{
    size_t i;
    size_t diff = x_len - y_len;

    for (i = 0; i < y_len; ++i) {
        x[diff + i] ^= y[i];
    }
}

static void dbl(unsigned char d[TAG_LEN])
{
    unsigned char carry = 0;
    unsigned char tmp;
    unsigned char mask;
    size_t i;

    // Left-shift
    for (i = TAG_LEN; i-- > 0;) {
        tmp = (d[i] << 1) | carry;
        carry = (d[i] >> 7) & 0x01;
        d[i] = tmp;
    }

    // Bit-sliced constant time conditional xor
    mask = -carry;
    d[TAG_LEN - 2] ^= PRIM_POLY[0] & mask;
    d[TAG_LEN - 1] ^= PRIM_POLY[1] & mask;

    printf("dbl():");
    hexdump(d, TAG_LEN);
}

static void s2v(const void *key, void *plaintext, size_t pt_len, const assoc_data_t *ad, size_t ad_len, void *tag)
{
    unsigned char d[TAG_LEN];
    unsigned char t[TAG_LEN];
    unsigned char pad[TAG_LEN];
    size_t i;

    memset(pad, 0, TAG_LEN);

    if (ad_len == 0 && plaintext == NULL) {
        hmac_sha256(key, ONE, TAG_LEN, tag);
        printf("HMAC-SHA256(<one>):\n");
        hexdump(tag, TAG_LEN);
        return;
    }

    hmac_sha256(key, ZERO, TAG_LEN, d);
    printf("HMAC-SHA256(<zero>):");
    hexdump(d, TAG_LEN);
    for (i = 0; i < ad_len; ++i) {
        dbl(d);
        hmac_sha256(key, ad[i].data, ad[i].len, t);
        printf("HMAC-SHA256(AD%zu):", (i + 1));
        hexdump(t, TAG_LEN);
        xor(d, t, TAG_LEN);
    }

    if (pt_len >= TAG_LEN) {
        xorend(plaintext, pt_len, d, TAG_LEN);
        printf("xorend:");
        hexdump(plaintext, pt_len);
        hmac_sha256(key, plaintext, pt_len, t);
        /* Undo the XOR to leave plaintext as it was. */
        xorend(plaintext, pt_len, d, TAG_LEN);
    } else {
        dbl(d);
        memcpy(pad, plaintext, pt_len);
        xor(d, pad, TAG_LEN);
        hmac_sha256(key, d, TAG_LEN, t);
    }

    printf("HMAC-SHA256(final):");
    hexdump(t, TAG_LEN);

    memcpy(tag, t, TAG_LEN);
}

void xchacha20siv_encrypt(
        const void *key, void *plaintext, size_t pt_len, const assoc_data_t *ad, size_t ad_len)
{

    const void *macKey = key;
    const void *encKey = key + PRF_KEY_LEN;
    unsigned char tag[TAG_LEN];
    unsigned char siv[IV_LEN];

    s2v(macKey, plaintext + TAG_LEN, pt_len, ad, ad_len, tag);
    memcpy(siv, tag, IV_LEN);

    printf("SIV:");
    hexdump(siv, IV_LEN);

    xchacha20(encKey, siv, plaintext + TAG_LEN, pt_len);
    memcpy(plaintext, tag, TAG_LEN);

    printf("Ciphertext:");
    hexdump(plaintext, TAG_LEN + pt_len);
}

static int ct_cmp(const unsigned char *x, const unsigned char *y, size_t len)
{
    size_t i;
    unsigned char c = 0;

    for (i = 0; i < len; ++i) {
        c |= x[i] ^ y[i];
    }

    return c;
}

int xchacha20siv_decrypt(
        const void *key, void *ciphertext, size_t ct_len, const assoc_data_t *ad, size_t ad_len)
{
    const void *macKey = key;
    const void *encKey = key + PRF_KEY_LEN;
    unsigned char computed_tag[TAG_LEN];
    unsigned char siv[IV_LEN];
    const void *tag = ciphertext;

    memcpy(siv, tag, IV_LEN);
    xchacha20(encKey, siv, ciphertext + TAG_LEN, ct_len);

    s2v(macKey, ciphertext + TAG_LEN, ct_len, ad, ad_len, computed_tag);

    if (ct_cmp(computed_tag, tag, TAG_LEN) != 0) {
        memset(ciphertext, 0, ct_len + TAG_LEN);
        memset(computed_tag, 0, TAG_LEN);
        return -1;
    }

    return 0;
}
