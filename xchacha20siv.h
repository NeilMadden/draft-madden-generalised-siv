/*
 * xchacha20siv.h --
 *
 *      Reference implementation of XChaCha20-HMAC-SHA256-SIV.
 *
 * Copyright (c) 2018 Neil Madden.
 */

#ifndef _XCHACHA20SIV_H
#define _XCHACHA20SIV_H

#include <unistd.h>

static const size_t PRF_KEY_LEN     = 32;
static const size_t CIPHER_KEY_LEN  = 32;
static const size_t IV_LEN          = 24;
static const size_t TAG_LEN         = 32;

typedef struct {
    const unsigned char *data;
    size_t len;
} assoc_data_t;

/* 
 * Required hmac_sha256 function, takes 32-byte key and arbitrary length data
 * and writes 32-byte tag into *tag.
 */
void hmac_sha256(const void *key, const void *data, size_t len, void *tag);

/*
 * XChaCha20 encrypt/decrypt in-place. Block counter is set to 0.
 */
void xchacha20(const void *key, const void* iv, void *data, size_t len);

/*
 * xchacha20siv_encrypt --
 *
 *      Encrypts and authenticates the given plaintext in-place. The plaintext buffer must
 *      be pt_len + TAG_LEN bytes in size with the actual plaintext starting at TAG_LEN offset.
 *      The HMAC-SHA256 tag will be prepended to the encrypted ciphertext.
 */
void xchacha20siv_encrypt(
        const void *key, void *plaintext, size_t pt_len, const assoc_data_t *ad, size_t ad_len);
int xchacha20siv_decrypt(
        const void *key, void *ciphertext, size_t ct_len, const assoc_data_t *ad, size_t ad_len);


#endif /* _XCHACHA20SIV_H */
