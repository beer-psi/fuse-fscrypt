#include "fscrypt_ops.h"
#include "crypto.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <zlib.h>

const uint8_t FSCRYPT_BOOT_KEY[16] = {
    0x09, 0xca, 0x5e, 0xfd, 0x30, 0xc9, 0xaa, 0xef,
    0x38, 0x04, 0xd0, 0xa7, 0xe3, 0xfa, 0x71, 0x20
};

const uint8_t FSCRYPT_BOOT_IV[16] = {
    0xb1, 0x55, 0xc2, 0x2c, 0x2e, 0x7f, 0x04, 0x91,
    0xfa, 0x7f, 0x0f, 0xdc, 0x21, 0x7a, 0xff, 0x90
};

const uint8_t FSCRYPT_HMAC_KEY[] = {
    0xe1, 0xbd, 0xcb, 0x2d, 0x5e, 0x9e, 0xd3, 0xb5, 0xde, 0x23,
    0x43, 0x64, 0xdf, 0xa4, 0xd1, 0x26, 0x84, 0x9e, 0xdf, 0xf7,
    0x69, 0xfc, 0x6c, 0x28, 0xfb, 0xa5, 0xf4, 0x3b, 0xc4, 0x82,
    0xbd, 0x74, 0x79, 0xd6, 0x76, 0xaf, 0xce, 0x81, 0x88, 0xe1,
    0xd3, 0xa6, 0x85, 0x2f, 0x4e, 0xbc, 0xe4, 0x5c, 0xde, 0x46,
    0xbd, 0x15, 0xe8, 0xee, 0x5f, 0xe8, 0x4d, 0x19, 0x7f, 0x94,
    0x5a, 0x54, 0x51, 0x8f
};

const size_t FSCRYPT_HMAC_KEY_LEN = sizeof FSCRYPT_HMAC_KEY;

const uint8_t OPTION_KEY[] = {
    0x5c, 0x84, 0xa9, 0xe7, 0x26, 0xea, 0xa5, 0xdd,
    0x35, 0x1f, 0x2b, 0x07, 0x50, 0xc2, 0x36, 0x97
};
const uint8_t OPTION_IV[] = {
    0xc0, 0x63, 0xbf, 0x6f, 0x56, 0x2d, 0x08, 0x4d,
    0x79, 0x63, 0xc9, 0x87, 0xf5, 0x28, 0x17, 0x61
};

const uint8_t EXFAT_HEADER[] = {
    0xeb, 0x76, 0x90, 0x45, 0x58, 0x46, 0x41, 0x54,
    0x20, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00
};
const uint8_t NTFS_HEADER[] = {
    0xeb, 0x52, 0x90, 0x4e, 0x54, 0x46, 0x53, 0x20,
    0x20, 0x20, 0x20, 0x00, 0x10, 0x01, 0x00, 0x00
};

/** Absolute container-file offset of the first byte of block @n. */
static inline off_t block_start(const struct fscrypt_state *s, uint64_t n)
{
    return (off_t)(n * s->bootid.block_size);
}

/** Block index (0-based) that contains the given container-file offset. */
static inline uint64_t offset_to_block(const struct fscrypt_state *s, off_t off)
{
    return (uint64_t)off / s->bootid.block_size;
}

/**
 * Container-file offset corresponding to @img_off bytes into the
 * decrypted image (i.e. after the header blocks).
 */
static inline off_t img_to_cont(const struct fscrypt_state *s, off_t img_off)
{
    return (off_t)(s->bootid.header_block_count * s->bootid.block_size)
           + img_off;
}

/**
 * Read exactly @len bytes from the container at offset @off into @buf.
 * Any bytes not returned by pread (e.g. at/past EOF) are zero-filled so
 * callers always receive a fully populated buffer.
 * Returns 0 on success, negative errno on I/O error.
 */
static int read_exact(int fd, void *buf, size_t len, off_t off)
{
    ssize_t n = pread(fd, buf, len, off);
    if (n < 0)
        return -errno;
    if ((size_t)n < len)
        memset((char *)buf + n, 0, len - (size_t)n);
    return 0;
}

/**
 * Compute and persist the CRC32 entry for block @block_num.
 *
 * Reads the entire block (block_size bytes) from the container, computes
 * crc32 over all bytes, then writes the 4-byte little-endian result to:
 *
 *   FSCRYPT_CRC32_OFFSET + block_num * 4
 *
 * This helper MUST NOT be called for block 0; that entry uses a special
 * formula and is handled exclusively by fscrypt_flush_headers().
 *
 * Must be called with state->lock held.
 */
static int update_block_crc32(struct fscrypt_state *s, uint64_t block_num)
{
    uint64_t block_size = s->bootid.block_size;

    uint8_t *buf = malloc(block_size);
    if (!buf)
        return -ENOMEM;

    int ret = read_exact(s->fd, buf, block_size, block_start(s, block_num));
    if (ret != 0) {
        free(buf);
        return ret;
    }

    uint32_t crc = crc32_z(0L, buf, block_size);
    free(buf);

    off_t   crc_off = (off_t)FSCRYPT_CRC32_OFFSET + (off_t)(block_num * 4u);
    ssize_t n = pwrite(s->fd, &crc, sizeof crc, crc_off);
    if (n != (ssize_t)sizeof crc)
        return (n < 0) ? -errno : -EIO;

    return 0;
}

/*  fscrypt_open_container  */

int fscrypt_open_container(const char    *path,
                           const uint8_t *key, size_t key_len,
                           const uint8_t *iv,  size_t iv_len,
                           struct fscrypt_state **out)
{
    if (key_len != 0 && key_len != 16 && key_len != 24 && key_len != 32)
        return -EINVAL;
    if (iv_len != 0 && iv_len != 16)
        return -EINVAL;

    struct fscrypt_state *s = calloc(1, sizeof *s);
    if (!s)
        return -ENOMEM;

    int ret = 0;

    s->fd = open(path, O_RDWR);
    if (s->fd < 0) {
        ret = -errno;
        goto err_free;
    }

    /*  Read and decrypt the BootID area  */
    uint8_t enc_boot[FSCRYPT_BOOT_SIZE];
    ret = read_exact(s->fd, enc_boot, FSCRYPT_BOOT_SIZE, 0);
    if (ret != 0)
        goto err_close;

    uint8_t dec_boot[FSCRYPT_BOOT_SIZE];
    if (aes_cbc_decrypt(FSCRYPT_BOOT_KEY, sizeof FSCRYPT_BOOT_KEY,
                        FSCRYPT_BOOT_IV,
                        enc_boot, FSCRYPT_BOOT_SIZE,
                        dec_boot) != 0) {
        fprintf(stderr, "fscrypt: BootID AES-CBC decryption failed\n");
        ret = -EIO;
        goto err_close;
    }

    /*  Verify the internal CRC32  */
    /*
     * dec_boot layout:
     *   [0 :  4)  CRC32 of dec_boot[4:10240]
     *   [4 : 10240)  BootID struct (10236 bytes)
     */
    uint32_t stored_crc, computed_crc;
    memcpy(&stored_crc, dec_boot, sizeof stored_crc);
    computed_crc = crc32_z(0, dec_boot + 4, FSCRYPT_BOOT_SIZE - 4);
    if (stored_crc != computed_crc) {
        fprintf(stderr,
                "fscrypt: BootID CRC32 mismatch "
                "(stored=0x%08x computed=0x%08x) - proceeding\n",
                stored_crc, computed_crc);
    }

    /*  Verify magic bytes  */
    /*
     * BootID.magic is the second field, right after the uint32_t length field,
     * so it lives at dec_boot + 4 (CRC32 prefix) + 4 (length field) = +8.
     */
    static const uint8_t BTID_MAGIC[4] = {'B', 'T', 'I', 'D'};
    if (memcmp(dec_boot + 4 + sizeof(uint32_t), BTID_MAGIC, 4) != 0)
        fprintf(stderr,
                "fscrypt: BootID magic mismatch - container may be invalid\n");

    /*  Copy the BootID struct and validate critical fields  */
    memcpy(&s->bootid, dec_boot + 4, sizeof s->bootid);

    if (s->bootid.block_size == 0) {
        fprintf(stderr, "fscrypt: block_size is zero\n");
        ret = -EINVAL;
        goto err_close;
    }
    if (s->bootid.header_block_count == 0) {
        fprintf(stderr, "fscrypt: header_block_count is zero\n");
        ret = -EINVAL;
        goto err_close;
    }
    if (s->bootid.block_count < s->bootid.header_block_count) {
        fprintf(stderr,
                "fscrypt: block_count (%" PRIu64
                ") < header_block_count (%" PRIu64 ")\n",
                s->bootid.block_count, s->bootid.header_block_count);
        ret = -EINVAL;
        goto err_close;
    }

    /* Determine the filename of the image file. */
    switch (s->bootid.type) {
        case APP_TYPE_SYSTEM:
            /* fallthrough */
        case APP_TYPE_APP:
            s->image_filename = "image.ntfs";
            break;
        case APP_TYPE_OPTION:
            s->image_filename = "image.exfat";
            break;
        default:
            fprintf(stderr, "fscrypt: unknown app type %d", s->bootid.type);
            ret = -EINVAL;
            goto err_close;
    }

    // If key or IV is not provided, perform a lookup from the EMBEDDED_GAME_KEYS
    // table and fill in anything still missing
    if (key_len == 0 || iv_len == 0) {
        const uint8_t* known_key = nullptr;
        size_t known_key_len = 0;
        const uint8_t* known_iv = nullptr;

        // TODO: special breed of apps known as the APM3 option. These are NTFS images.
        // APM3 keys are derived by
        // - decrypting a fixed seed with a fixed key/iv
        // - take the first 16 bytes of the decrypted seed as the key, then the next
        // 16 bytes of the decrypted seed as the IV, use that to encrypt 32 bytes of
        // the decrypted seed starting from offset 64
        // - take the first 16 bytes of this encryption result as the key, take the
        // next 16 bytes of this encryption result as the IV, apply XOR on both of
        // them with the game ID, use that as the actual key/iv
        if (s->bootid.type == APP_TYPE_OPTION) {
            known_key = OPTION_KEY;
            known_key_len = sizeof(OPTION_KEY);
            known_iv = OPTION_IV;
        } else {
            const struct GameKeyEntry* keys = nullptr;

            // It is not super disastrous if we don't know the IV, since we can usually brute force
            // it using the trick below. Missing a key is a huge issue though.
            if (!find_game_keys(s->bootid.id, &keys) && key_len == 0) {
                fprintf(
                    stderr, "fscrypt: key was not provided and %.*s is not a known ID.\n",
                    (int)sizeof(s->bootid.id), s->bootid.id
                );
                ret = -EINVAL;
                goto err_close;
            }

            if (keys != nullptr) {
                known_key = keys->key;
                known_key_len = sizeof(keys->key);
                known_iv = keys->iv;
            }
        }

        if (key_len == 0) {
            // guaranteed that we have a game key since game key lookup fails
            // if key_len == 0
            key = known_key;
            key_len = known_key_len;
        }

        if (iv_len == 0 && known_iv != nullptr) {
            iv = known_iv;
            iv_len = 16;
        }
    }

    memcpy(s->page_key, key, key_len);
    s->page_key_len = key_len;

    if (iv_len == 0 || s->bootid.derive_iv) {
        // If IV is not given or the image uses a "derived" IV, try to guess the IV
        // This is basically done by decrypting the first 16 bytes of the image with
        // the exFAT/NTFS header and see if it makes sense.
        const uint8_t* expected_header = nullptr;
        uint8_t encrypted_header[16];
        uint8_t decrypted_header[16];
        uint8_t calculated_iv[16];

        if (s->bootid.type == APP_TYPE_OPTION) {
            expected_header = EXFAT_HEADER;
        } else {
            expected_header = NTFS_HEADER;
        }

        ret = read_exact(s->fd, encrypted_header, sizeof(encrypted_header), s->bootid.header_block_count * s->bootid.block_size);

        if (ret != 0) {
            goto err_close;
        }

        if (aes_cbc_decrypt(s->page_key, s->page_key_len, expected_header, encrypted_header, 16, calculated_iv) != 0) {
            fprintf(stderr, "fscrypt: failed to derive IV (could not decrypt data with filesystem header as IV)\n");
            ret = -EIO;
            goto err_close;
        }

        if (aes_cbc_decrypt(s->page_key, s->page_key_len, calculated_iv, encrypted_header, 16, decrypted_header) != 0) {
            fprintf(stderr, "fscrypt: failed to derive IV (could not decrypt data with derived IV)\n");
            ret = -EIO;
            goto err_close;
        }

        if (memcmp(decrypted_header, expected_header, 16) != 0) {
            fprintf(stderr, "fscrypt: failed to derive IV (header decrypted with calculated IV does not match filesystem header)\n");
            ret = -EIO;
            goto err_close;
        }

        memcpy(s->page_iv, calculated_iv, 16);
    } else {
        // iv_len is either 0 or 16, since we already validated input
        // params, and our embedded keys only either set an IV or not
        memcpy(s->page_iv, iv, iv_len);
    }

    const EVP_CIPHER* cipher = select_aes_cbc(s->page_key_len);

    if (cipher == nullptr) {
        fprintf(stderr, "fscrypt: unsupported AES key length %zu\n", s->page_key_len);
        ret = -EINVAL;
        goto err_close;
    }

    // Initialize OpenSSL contexts once so that key expansion does not have to be performed
    // every page read.
    s->encrypt_ctx = EVP_CIPHER_CTX_new();

    if (EVP_EncryptInit_ex(s->encrypt_ctx, cipher, nullptr, s->page_key, s->page_iv) != 1) {
        fprintf(stderr, "fscrypt: failed to initialize encryption context\n");
        ret = -EIO;
        goto err_close;
    }

    EVP_CIPHER_CTX_set_padding(s->encrypt_ctx, 0);

    s->decrypt_ctx = EVP_CIPHER_CTX_new();

    if (EVP_DecryptInit_ex(s->decrypt_ctx, cipher, nullptr, s->page_key, s->page_iv) != 1) {
        fprintf(stderr, "fscrypt: failed to initialize decryption context\n");
        ret = -EIO;
        goto err_close;
    }

    EVP_CIPHER_CTX_set_padding(s->decrypt_ctx, 0);

    s->current_block_count = s->bootid.block_count;
    s->headers_dirty       = false;

    struct tm bootid_tm = {
        .tm_sec = s->bootid.timestamp.second,
        .tm_min = s->bootid.timestamp.minute,
        .tm_hour = s->bootid.timestamp.hour,
        .tm_mday = s->bootid.timestamp.day,
        .tm_mon = s->bootid.timestamp.month - 1,
        .tm_year = s->bootid.timestamp.year - 1900,
        .tm_gmtoff = 9 * 3600,
        .tm_zone = "Asia/Tokyo",
    };
    s->image_timestamp = mktime(&bootid_tm);

    pthread_mutex_init(&s->lock, NULL);

    *out = s;
    return 0;

err_close:
    close(s->fd);
err_free:
    free(s);
    return ret;
}

void fscrypt_close_container(struct fscrypt_state *s)
{
    if (!s)
        return;
    fscrypt_flush_headers(s);
    pthread_mutex_destroy(&s->lock);
    close(s->fd);
    EVP_CIPHER_CTX_free(s->encrypt_ctx);
    EVP_CIPHER_CTX_free(s->decrypt_ctx);
    free(s);
}

uint64_t fscrypt_image_size(struct fscrypt_state *s)
{
    pthread_mutex_lock(&s->lock);
    uint64_t sz = 0;
    if (s->current_block_count > s->bootid.header_block_count)
        sz = (s->current_block_count - s->bootid.header_block_count)
             * s->bootid.block_size;
    pthread_mutex_unlock(&s->lock);
    return sz;
}

ssize_t fscrypt_read(struct fscrypt_state *s,
                     void *buf, size_t size, off_t offset)
{
    pthread_mutex_lock(&s->lock);

    /* Derive image size under the lock. */
    uint64_t img_size = 0;
    if (s->current_block_count > s->bootid.header_block_count)
        img_size = (s->current_block_count - s->bootid.header_block_count)
                   * s->bootid.block_size;

    if (offset < 0 || (uint64_t)offset >= img_size) {
        pthread_mutex_unlock(&s->lock);
        return 0;
    }
    if ((uint64_t)offset + size > img_size)
        size = (size_t)(img_size - (uint64_t)offset);

    uint8_t *out_ptr = (uint8_t *)buf;
    size_t   done    = 0;
    int      ret     = 0;

    uint8_t page_iv[16], enc[FSCRYPT_PAGE_SIZE], dec[FSCRYPT_PAGE_SIZE];

    while (done < size) {
        uint64_t img_cur       = (uint64_t)offset + done;
        uint64_t page_num      = img_cur / FSCRYPT_PAGE_SIZE;
        uint64_t page_off      = img_cur % FSCRYPT_PAGE_SIZE;
        /* Image offset of the start of this page (used for IV derivation). */
        uint64_t page_img_base = page_num * FSCRYPT_PAGE_SIZE;

        off_t cont_off = img_to_cont(s, (off_t)page_img_base);

        /* Read one encrypted page; zero-pad if the file is shorter. */
        ret = read_exact(s->fd, enc, FSCRYPT_PAGE_SIZE, cont_off);

        if (ret != 0)
            break;

        /* Derive per-page IV and decrypt. */
        derive_page_iv(s->page_iv, page_img_base, page_iv);

        if (EVP_DecryptInit_ex(s->decrypt_ctx, nullptr, nullptr, nullptr, page_iv) != 1) {
            ret = -EIO;
            break;
        }

        int n1 = 0, n2 = 0;

        if (EVP_DecryptUpdate(s->decrypt_ctx, dec, &n1, enc, (int)FSCRYPT_PAGE_SIZE) != 1) {
            ret = -EIO;
            break;
        }

        if (EVP_DecryptFinal_ex(s->decrypt_ctx, dec + n1, &n2) != 1) {
            ret = -EIO;
            break;
        }

        size_t copy = FSCRYPT_PAGE_SIZE - (size_t)page_off;
        if (copy > size - done)
            copy = size - done;
        memcpy(out_ptr + done, dec + page_off, copy);
        done += copy;
    }

    pthread_mutex_unlock(&s->lock);
    return ret ? (ssize_t)ret : (ssize_t)done;
}

ssize_t fscrypt_write(struct fscrypt_state *s,
                      const void *buf, size_t size, off_t offset)
{
    if (size == 0)
        return 0;

    pthread_mutex_lock(&s->lock);

    const uint8_t *in_ptr = (const uint8_t *)buf;
    size_t   done         = 0;
    int      ret          = 0;

    /*
     * Track the range of data blocks touched across all page writes so that
     * CRC32 entries are computed once, after all pages in a block have been
     * written - not after each individual page (which would produce a stale
     * intermediate CRC32 for multi-page writes to the same block).
     */
    uint64_t first_dirty = UINT64_MAX;
    uint64_t last_dirty  = 0;

    uint8_t dec[FSCRYPT_PAGE_SIZE], enc_new[FSCRYPT_PAGE_SIZE], page_iv[16];

    /*  Phase 1: write every page  */
    while (done < size) {
        uint64_t img_cur       = (uint64_t)offset + done;
        uint64_t page_num      = img_cur / FSCRYPT_PAGE_SIZE;
        uint64_t page_off      = img_cur % FSCRYPT_PAGE_SIZE;
        uint64_t page_img_base = page_num * FSCRYPT_PAGE_SIZE;

        off_t  cont_off = img_to_cont(s, (off_t)page_img_base);

        /* Number of bytes from `buf` that go into this page. */
        size_t copy = FSCRYPT_PAGE_SIZE - (size_t)page_off;
        if (copy > size - done)
            copy = size - done;

        /*
         * For a partial-page write we must first read and decrypt the
         * existing page content so that only the targeted bytes change.
         * For a full-page write we start from zeroes.
         *
         * read_exact zero-pads if the page lies past the current end-of-file
         * (e.g. first write to a newly extended region), so partial-page
         * handling on brand-new pages is safe.
         */
        if (page_off != 0 || copy < FSCRYPT_PAGE_SIZE) {
            uint8_t enc_old[FSCRYPT_PAGE_SIZE];
            int rd = read_exact(s->fd, enc_old, FSCRYPT_PAGE_SIZE, cont_off);
            if (rd != 0) { ret = rd; break; }

            derive_page_iv(s->page_iv, page_img_base, page_iv);

            int n1 = 0, n2 = 0;

            if (EVP_DecryptInit_ex(s->decrypt_ctx, nullptr, nullptr, nullptr, page_iv) != 1
                || EVP_DecryptUpdate(s->decrypt_ctx, enc_old, &n1, dec, (int)FSCRYPT_PAGE_SIZE) != 1
                || EVP_DecryptFinal_ex(s->decrypt_ctx, enc_old + n1, &n2) != 1) {
                /*
                 * A decryption failure on an unwritten (all-zero) page is
                 * benign.  Treat the page as all zeroes and continue.
                 */
                memset(dec, 0, FSCRYPT_PAGE_SIZE);
            }
        } else {
            memset(dec, 0, FSCRYPT_PAGE_SIZE);
        }

        /* Patch the new data into the decrypted buffer. */
        memcpy(dec + page_off, in_ptr + done, copy);

        /* Encrypt the modified page. */
        derive_page_iv(s->page_iv, page_img_base, page_iv);

        if (EVP_EncryptInit_ex(s->encrypt_ctx, nullptr, nullptr, nullptr, page_iv) != 1) {
            ret = -EIO;
            break;
        }

        int n1 = 0, n2 = 0;

        if (EVP_EncryptUpdate(s->encrypt_ctx, enc_new, &n1, dec, (int)FSCRYPT_PAGE_SIZE) != 1) {
            ret = -EIO;
            break;
        }

        if (EVP_EncryptFinal_ex(s->encrypt_ctx, enc_new + n1, &n2) != 1) {
            ret = -EIO;
            break;
        }

        ssize_t n = pwrite(s->fd, enc_new, FSCRYPT_PAGE_SIZE, cont_off);
        if (n != (ssize_t)FSCRYPT_PAGE_SIZE) {
            ret = (n < 0) ? -errno : -EIO;
            break;
        }

        done += copy;

        /* Update dirty block range. */
        uint64_t block_num = offset_to_block(s, cont_off);
        if (block_num < first_dirty) first_dirty = block_num;
        if (block_num > last_dirty)  last_dirty  = block_num;

        /* Extend block count if this write grew the container. */
        off_t    new_end = cont_off + (off_t)FSCRYPT_PAGE_SIZE;
        uint64_t new_bc  =
            (uint64_t)((new_end + (off_t)s->bootid.block_size - 1)
                        / (off_t)s->bootid.block_size);
        if (new_bc > s->current_block_count)
            s->current_block_count = new_bc;
    }

    /*  Phase 2: immediately update CRC32 for every touched data block  */
    /*
     * Block 0's CRC32[0] uses a special formula that depends on the complete
     * CRC32 array; it is deferred to fscrypt_flush_headers().
     * All data blocks (block_num >= header_block_count) are updated now.
     */
    if (done > 0 && first_dirty <= last_dirty) {
        for (uint64_t bn = first_dirty; bn <= last_dirty; bn++) {
            int crc_ret = update_block_crc32(s, bn);
            if (crc_ret != 0)
                fprintf(stderr,
                        "fscrypt: CRC32 update failed for block %" PRIu64
                        ": %s\n",
                        bn, strerror(-crc_ret));
        }
        s->headers_dirty = true;
    }

    pthread_mutex_unlock(&s->lock);
    return ret ? (ssize_t)ret : (ssize_t)done;
}

int fscrypt_truncate(struct fscrypt_state *s, uint64_t new_size)
{
    pthread_mutex_lock(&s->lock);

    uint64_t block_size    = s->bootid.block_size;
    uint64_t header_blocks = s->bootid.header_block_count;

    /* Round the requested image size up to a whole number of blocks. */
    uint64_t data_blocks = (new_size + block_size - 1) / block_size;
    uint64_t new_bc      = data_blocks + header_blocks;

    if (ftruncate(s->fd, (off_t)(new_bc * block_size)) != 0) {
        int ret = -errno;
        pthread_mutex_unlock(&s->lock);
        return ret;
    }

    s->current_block_count = new_bc;
    s->headers_dirty       = true;

    pthread_mutex_unlock(&s->lock);
    return 0;
}

int fscrypt_flush_headers(struct fscrypt_state *s)
{
    pthread_mutex_lock(&s->lock);

    if (!s->headers_dirty) {
        pthread_mutex_unlock(&s->lock);
        return 0;
    }

    int      ret           = 0;
    uint64_t block_size    = s->bootid.block_size;
    uint64_t header_blocks = s->bootid.header_block_count;

    /*
     * Step 1 - Re-encrypt the BootID area with the live block_count.
     *
     * dec_boot layout (10240 bytes):
     *   [0 :  4)   CRC32 of dec_boot[4:10240]
     *   [4 : 10240) BootID struct
     *  */
    s->bootid.block_count = s->current_block_count;

    uint8_t dec_boot[FSCRYPT_BOOT_SIZE];
    uint32_t boot_crc = crc32_z(0, (const uint8_t*)&s->bootid, sizeof s->bootid);
    memcpy(dec_boot,     &boot_crc,   sizeof boot_crc);
    memcpy(dec_boot + 4, &s->bootid, sizeof s->bootid);

    uint8_t enc_boot[FSCRYPT_BOOT_SIZE];
    if (aes_cbc_encrypt(FSCRYPT_BOOT_KEY, sizeof FSCRYPT_BOOT_KEY,
                        FSCRYPT_BOOT_IV,
                        dec_boot, FSCRYPT_BOOT_SIZE,
                        enc_boot) != 0) {
        ret = -EIO;
        goto done;
    }
    if (pwrite(s->fd, enc_boot, FSCRYPT_BOOT_SIZE, 0)
            != (ssize_t)FSCRYPT_BOOT_SIZE) {
        ret = -errno;
        goto done;
    }

    /*
     * Step 2 - CRC32[m] for each header block m in [1, header_blocks).
     *
     * Header blocks m ≥ 1 may contain a continuation of the CRC32 array
     * (for very large images) plus random fill.  We read each block's current
     * content (including any CRC32 entries that fscrypt_write already wrote),
     * compute the block CRC32, and write the entry at
     *   FSCRYPT_CRC32_OFFSET + m * 4
     * in block 0 (for typical image sizes).  Step 3 therefore sees the
     * updated values when it reads block 0.
     *  */
    for (uint64_t m = 1; m < header_blocks; m++) {
        uint8_t *blk = malloc(block_size);
        if (!blk) { ret = -ENOMEM; goto done; }

        ret = read_exact(s->fd, blk, block_size, block_start(s, m));
        if (ret != 0) { free(blk); goto done; }

        uint32_t crc = crc32_z(0, blk, block_size);
        free(blk);

        off_t crc_off = (off_t)FSCRYPT_CRC32_OFFSET + (off_t)(m * 4u);
        if (pwrite(s->fd, &crc, sizeof crc, crc_off) != (ssize_t)sizeof crc) {
            ret = -errno;
            goto done;
        }
    }

    /*
     * Step 3 - Compute and write CRC32[0].
     *
     * CRC32[0] = CRC32( block0[0 : FSCRYPT_BOOT_SIZE]
     *                 + block0[FSCRYPT_BOOT_SIZE + FSCRYPT_CRC32_SKIP
     *                          : block_size] )
     *
     * i.e. the encrypted BootID concatenated with everything in block 0
     * after the skipped region [10240, 10756).  The skipped bytes are:
     *   [10240, 10260)  HMAC-SHA1 (not yet written - but excluded anyway)
     *   [10260, 10752)  inter-field padding
     *   [10752, 10756)  CRC32[0] itself
     *
     * We read block 0 now so we pick up the new BootID from step 1 and the
     * updated CRC32[1..] entries from step 2.
     *  */
    {
        uint8_t *blk0 = malloc(block_size);
        if (!blk0) { ret = -ENOMEM; goto done; }

        ret = read_exact(s->fd, blk0, block_size, 0);
        if (ret != 0) { free(blk0); goto done; }

        uint32_t crc0 = crc32_z(0, blk0, FSCRYPT_BOOT_SIZE);
        crc0 = crc32_z(crc0,
                          blk0 + FSCRYPT_BOOT_SIZE + FSCRYPT_CRC32_SKIP,
                          block_size - FSCRYPT_BOOT_SIZE - FSCRYPT_CRC32_SKIP);
        free(blk0);

        if (pwrite(s->fd, &crc0, sizeof crc0, (off_t)FSCRYPT_CRC32_OFFSET)
                != (ssize_t)sizeof crc0) {
            ret = -errno;
            goto done;
        }
    }

    /*
     * Step 4 - Compute and write the HMAC-SHA1.
     *
     * The HMAC covers bytes [FSCRYPT_CRC32_OFFSET, header_blocks * block_size)
     * which includes CRC32[0] (just written in step 3) and all subsequent
     * CRC32 entries plus any random fill in the header blocks.
     *  */
    {
        size_t hmac_data_len =
            (size_t)(header_blocks * block_size) - FSCRYPT_CRC32_OFFSET;

        uint8_t *hmac_data = malloc(hmac_data_len);
        if (!hmac_data) { ret = -ENOMEM; goto done; }

        ret = read_exact(s->fd, hmac_data, hmac_data_len,
                         (off_t)FSCRYPT_CRC32_OFFSET);
        if (ret != 0) { free(hmac_data); goto done; }

        uint8_t hmac[FSCRYPT_HMAC_SIZE];
        int hr = hmac_sha1(FSCRYPT_HMAC_KEY, FSCRYPT_HMAC_KEY_LEN,
                           hmac_data, hmac_data_len, hmac);
        free(hmac_data);
        if (hr != 0) { ret = -EIO; goto done; }

        if (pwrite(s->fd, hmac, FSCRYPT_HMAC_SIZE, (off_t)FSCRYPT_HMAC_OFFSET)
                != (ssize_t)FSCRYPT_HMAC_SIZE) {
            ret = -errno;
            goto done;
        }
    }

    s->headers_dirty = false;

done:
    pthread_mutex_unlock(&s->lock);
    return ret;
}
