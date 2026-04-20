#pragma once

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>

struct GameKeyEntry {
    char id[4];
    uint8_t key[16];
    uint8_t iv[16];
};

extern const struct GameKeyEntry EMBEDDED_GAME_KEYS[];
extern const size_t EMBEDDED_GAME_KEYS_COUNT;

const EVP_CIPHER *select_aes_cbc(size_t key_len);

/*
 * AES-CBC encrypt/decrypt - no padding (data must be a multiple of 16 bytes).
 * This initializes a new OpenSSL context and performs AES key expansion every time.
 * If performance is a concern, consider managing your own OpenSSL context.
 *
 * key_len : 16 (AES-128), 24 (AES-192), or 32 (AES-256)
 * iv      : exactly 16 bytes
 * len     : must be a multiple of 16
 * out     : at least `len` bytes; may alias `in` only if out == in
 *
 * Returns 0 on success, -1 on failure.
 */
int aes_cbc_encrypt(const uint8_t *key, size_t key_len,
                    const uint8_t *iv,
                    const uint8_t *in, size_t len,
                    uint8_t *out);

int aes_cbc_decrypt(const uint8_t *key, size_t key_len,
                    const uint8_t *iv,
                    const uint8_t *in, size_t len,
                    uint8_t *out);

/*
 * HMAC-SHA1.
 *
 * out : exactly 20 bytes written on success.
 * Returns 0 on success, -1 on failure.
 */
int hmac_sha1(const uint8_t *key, size_t key_len,
              const uint8_t *data, size_t data_len,
              uint8_t out[20]);

/*
 * Derive the per-page IV.
 *
 * base_iv : 16-byte base IV supplied by the user
 * offset  : byte offset of the page within the *decrypted* image
 *           (page 0 → 0, page 1 → 4096, …)
 * out_iv  : 16 bytes written
 *
 * Algorithm (mirrors the reference Python):
 *   out_iv[i] = base_iv[i] ^ ((offset >> (8 * (i % 8))) & 0xFF)
 */
void derive_page_iv(const uint8_t base_iv[16], uint64_t offset,
                    uint8_t out_iv[16]);

bool find_game_keys(const char id[4], const struct GameKeyEntry **out);
bool apm3_derive_key(const char id[4], uint8_t key[16], uint8_t iv[16]);
