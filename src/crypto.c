#include "crypto.h"

#include <string.h>

#include <openssl/hmac.h>

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
