#include "crypto.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

const uint8_t APM3_SEED[96] = {
    0xC7, 0x3C, 0xDD, 0xBF, 0x7A, 0xFB, 0x0E, 0xBC, 0xE6, 0xDE, 0xD4, 0xD9, 0xB3, 0xDF, 0x3B, 0x03,
    0x3F, 0xE1, 0x40, 0xE4, 0xF4, 0xFF, 0x96, 0xC5, 0x79, 0x90, 0x8B, 0x5B, 0x69, 0x6A, 0xBE, 0xEE,
    0x32, 0x6C, 0x5E, 0xEA, 0x47, 0xC0, 0xA3, 0x40, 0x51, 0xDC, 0x55, 0xBF, 0x8C, 0x2A, 0x80, 0x7B,
    0xE4, 0xC6, 0xE3, 0xEF, 0x2F, 0x15, 0x30, 0x84, 0x69, 0x3C, 0xE2, 0xD2, 0x1E, 0xF1, 0xBB, 0x13,
    0xDC, 0xC9, 0x6D, 0x31, 0x7C, 0x3F, 0xCC, 0x7A, 0xB9, 0x44, 0x63, 0x6D, 0x65, 0xC2, 0x8B, 0xB8,
    0xE2, 0xF7, 0x74, 0x8D, 0xC6, 0x42, 0x08, 0xA8, 0x73, 0x41, 0x4B, 0x78, 0x7E, 0x3F, 0x18, 0x66
};
const uint8_t APM3_KEY[16] = {
    0x87, 0x3d, 0xf6, 0x32, 0xb9, 0x88, 0xae, 0x14,
    0xaa, 0x9f, 0x73, 0x6b, 0x03, 0xa5, 0x1c, 0x4f
};
const uint8_t APM3_IV[16] = {
    0x35, 0x7d, 0xc1, 0x90, 0x30, 0xd8, 0xe8, 0xd4,
    0x94, 0x1a, 0x7e, 0x6a, 0xce, 0xb9, 0x4e, 0x4c
};

const EVP_CIPHER *select_aes_cbc(size_t key_len)
{
    switch (key_len) {
        case 16: return EVP_aes_128_cbc();
        case 24: return EVP_aes_192_cbc();
        case 32: return EVP_aes_256_cbc();
        default: return NULL;
    }
}

int aes_cbc_encrypt(const uint8_t *key, size_t key_len,
                    const uint8_t *iv,
                    const uint8_t *in, size_t len,
                    uint8_t *out)
{
    const EVP_CIPHER *cipher = select_aes_cbc(key_len);
    if (!cipher)
        return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    int ret = -1;

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1)
        goto _end;

    /* Input is always block-aligned; disable automatic PKCS#7 padding. */
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int n1 = 0, n2 = 0;

    if (EVP_EncryptUpdate(ctx, out, &n1, in, (int)len) != 1)
        goto _end;

    if (EVP_EncryptFinal_ex(ctx, out + n1, &n2) != 1)
        goto _end;

    ret = 0;

_end:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int aes_cbc_decrypt(const uint8_t *key, size_t key_len,
                    const uint8_t *iv,
                    const uint8_t *in, size_t len,
                    uint8_t *out)
{
    const EVP_CIPHER *cipher = select_aes_cbc(key_len);
    if (!cipher)
        return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    int ret = -1;

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1)
        goto _end;

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int n1 = 0, n2 = 0;

    if (EVP_DecryptUpdate(ctx, out, &n1, in, (int)len) != 1)
        goto _end;

    if (EVP_DecryptFinal_ex(ctx, out + n1, &n2) != 1)
        goto _end;

    ret = 0;

_end:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int hmac_sha1(const uint8_t *key, size_t key_len,
              const uint8_t *data, size_t data_len,
              uint8_t out[20])
{
    unsigned int out_len = 0;
    unsigned char *result = HMAC(EVP_sha1(),
                                 key,  (int)key_len,
                                 data, data_len,
                                 out, &out_len);
    if (!result || out_len != 20)
        return -1;
    return 0;
}

#ifdef __SSE2__
// https://github.com/proeren2002/unsegaREBORN
// SPDX-License-Identifier: UNLICENSE
void derive_page_iv(const uint8_t base_iv[16], uint64_t offset,
                    uint8_t out_iv[16])
{
    __asm__ volatile (
        "movq %[off], %%xmm0\n\t"
        "punpcklqdq %%xmm0, %%xmm0\n\t"
        "movdqu (%[base]), %%xmm1\n\t"
        "pxor %%xmm0, %%xmm1\n\t"
        "movdqu %%xmm1, (%[out])\n\t"
        :
        : [off] "r" (offset), [base] "r" (base_iv), [out] "r" (out_iv)
        : "xmm0", "xmm1", "memory"
    );
}
#else
void derive_page_iv(const uint8_t base_iv[16], uint64_t offset,
                    uint8_t out_iv[16])
{
    for (int i = 0; i < 16; i++)
        out_iv[i] = base_iv[i] ^ (uint8_t)(offset >> (8 * (i % 8)));
}
#endif

bool apm3_derive_key(const char id[4], uint8_t key[16], uint8_t iv[16]) {
    uint8_t data[sizeof(APM3_SEED)];

    if (aes_cbc_decrypt(APM3_KEY, sizeof(APM3_KEY), APM3_IV, APM3_SEED, sizeof(APM3_SEED), data) != 0) {
        return false;
    }

    uint8_t intermediate[32];

    if (aes_cbc_encrypt(data, 16, data + 16, data + 64, sizeof(intermediate), intermediate) != 0) {
        return false;
    }

    memcpy(key, intermediate, 16);
    memcpy(iv, intermediate + 16, 16);

    for (int i = 0; i < 16; i++) {
        key[i] ^= (uint8_t)id[i % 4];
        iv[i] ^= (uint8_t)id[i % 4];
    }

    return true;
}
