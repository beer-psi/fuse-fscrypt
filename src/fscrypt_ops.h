#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <pthread.h>

#include <openssl/evp.h>

#include "cache.h"
#include "fscrypt.h"

/** Size of the encrypted BootID area at the start of the container. */
#define FSCRYPT_BOOT_SIZE       10240U

/**
 * File offset of the 20-byte HMAC-SHA1 signature.
 * Covers bytes [FSCRYPT_CRC32_OFFSET, header_block_count * block_size).
 * Calculated after the CRC32 array is fully populated.
 */
#define FSCRYPT_HMAC_OFFSET     10240U
#define FSCRYPT_HMAC_SIZE       20U

/**
 * File offset where the CRC32 array begins.
 *
 * Layout of the CRC32 array:
 *   CRC32[0]  @ 10752  – special: CRC32(block0[0:10240] + block0[10756:block_size])
 *   CRC32[n]  @ 10752 + n*4  – CRC32 of the full contents of block n  (n >= 1)
 *
 * CRC32[0] covers everything in block 0 except the region
 * [FSCRYPT_HMAC_OFFSET, FSCRYPT_CRC32_OFFSET + 4) = [10240, 10756),
 * i.e. the HMAC, the inter-field padding, and CRC32[0] itself.
 */
#define FSCRYPT_CRC32_OFFSET    10752U

/**
 * When calculating the CRC32 of the first block, skip the HMAC signature and
 * the CRC32 entry of the first block.
 */
#define FSCRYPT_CRC32_SKIP      516U

extern const uint8_t FSCRYPT_BOOT_KEY[16];
extern const uint8_t FSCRYPT_BOOT_IV[16];

extern const uint8_t FSCRYPT_HMAC_KEY[];
extern const size_t  FSCRYPT_HMAC_KEY_LEN;

/*  Runtime state  */

struct fscrypt_state {
    /** Open file descriptor for the container (O_RDWR). */
    FILE* fp;

    /** Decrypted and parsed BootID read from the container on mount. */
    struct BootID bootid;

    /** The image's timestamp, calculated from the boot ID. */
    time_t image_timestamp;

    /** Pointer to a null-terminated string of the image's filename. */
    char* image_filename;

    /**
     * Live block count - may differ from boot_id.block_count when the image
     * has been extended by writes.  Flushed back into boot_id on fsync/close.
     */
    uint64_t current_block_count;

    /**
     * True when block 0's CRC32 entry or the HMAC signature are stale and
     * must be recomputed before the next unmount / fsync.
     */
    bool headers_dirty;

    /** AES key used for page encryption (16, 24, or 32 bytes). */
    uint8_t file_key[32];
    size_t  file_key_len;

    /** Base IV from which per-page IVs are derived. Always 16 bytes. */
    uint8_t file_iv[16];

    /** Cipher context for encryption operations. */
    EVP_CIPHER_CTX* encrypt_ctx;

    /** Cipher context for decryption operations. */
    EVP_CIPHER_CTX* decrypt_ctx;

    /** LRU cache for recently decrypted pages. */
    struct PageCache* page_cache;

    /** Protects all mutable fields for multi-threaded FUSE access. */
    pthread_mutex_t lock;
};

/*  Public API  */

/**
 * fscrypt_open_container - open an existing fscrypt container file.
 *
 * @path     : path to the container file (opened O_RDWR)
 * @key      : AES key for page encryption
 * @key_len  : 16, 24, or 32
 * @iv       : base IV for per-page IV derivation (exactly 16 bytes)
 * @iv_len   : must be 16
 * @no_cache : do not cache recently accessed pages
 * @out      : on success, set to a heap-allocated fscrypt_state
 *
 * Returns 0 on success, negative errno on failure.
 *
 * The BootID CRC32 is verified; a mismatch produces a warning on stderr but
 * does not prevent mounting (the caller supplied the key and presumably knows
 * what they are doing).
 */
int fscrypt_open_container(const char   *path,
                           const uint8_t *key, size_t key_len,
                           const uint8_t *iv,  size_t iv_len,
                           int no_cache,
                           struct fscrypt_state **out);

/**
 * fscrypt_close_container - flush pending headers, then close and free state.
 *
 * Safe to call with NULL.
 */
void fscrypt_close_container(struct fscrypt_state *state);

/**
 * fscrypt_image_size - logical byte size of the exposed disk image.
 *
 * = (current_block_count - header_block_count) * block_size
 */
uint64_t fscrypt_image_size(struct fscrypt_state *state);

/**
 * fscrypt_read - decrypt and return up to @size bytes from image offset @offset.
 *
 * Reads are satisfied page-by-page (4096 B).  Bytes beyond the current image
 * size return 0 (EOF).
 *
 * Returns the number of bytes placed in @buf, or a negative errno.
 */
ssize_t fscrypt_read(struct fscrypt_state *state,
                     void *buf, size_t size, off_t offset);

/**
 * fscrypt_write - encrypt and persist @size bytes to image offset @offset.
 *
 * Partial-page writes perform a read-decrypt-modify-encrypt-write cycle.
 * The image is extended automatically when writing past the current end.
 * The CRC32 entry for every touched data block is updated immediately before
 * this function returns (block 0's CRC32 and the HMAC are deferred to flush).
 *
 * Returns the number of bytes consumed from @buf, or a negative errno.
 */
ssize_t fscrypt_write(struct fscrypt_state *state,
                      const void *buf, size_t size, off_t offset);

/**
 * fscrypt_truncate - resize the image to exactly @new_size bytes.
 *
 * @new_size is rounded up to the next block boundary to determine the new
 * block_count.  The underlying file is ftruncate'd accordingly.
 *
 * Returns 0 on success, negative errno on failure.
 */
int fscrypt_truncate(struct fscrypt_state *state, uint64_t new_size);

/**
 * fscrypt_flush_headers - recompute and write the deferred header fields.
 *
 * Performs the following steps (in order, so each step sees the results of
 * the previous one):
 *   1. Re-encrypt the BootID area with the updated block_count.
 *   2. Compute and write CRC32[m] for every header block m in [1, header_block_count).
 *   3. Compute and write CRC32[0]  =  CRC32(block0[0:10240] + block0[10756:block_size]).
 *   4. Compute and write the HMAC-SHA1 over bytes [10752, header_block_count * block_size).
 *
 * Is a no-op when headers_dirty is false.
 * Returns 0 on success, negative errno on failure.
 */
int fscrypt_flush_headers(struct fscrypt_state *state);
