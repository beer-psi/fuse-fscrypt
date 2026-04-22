#if FUSE_USE_VERSION >= 30
#include <fuse3/fuse.h>
#else
#include <fuse.h>
#endif

#include <errno.h> // IWYU pragma: keep
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <time.h>

#include "fscrypt_ops.h"

#ifdef FUSE_WINFSP_FUSE_H_INCLUDED
#   undef stat
#   define stat fuse_stat
#endif

#ifdef __MINGW32__
#   define blkcnt_t long int
#endif

#define IMAGE_FILE_HANDLE 1

struct cli_options {
    const char *container;
    const char *key_hex;
    const char *iv_hex;
    int         show_help;
    int         no_cache;
};

static struct cli_options cli_opts = { 0 };

#define OPTION(templ, field) \
    { templ, offsetof(struct cli_options, field), 1 }

static const struct fuse_opt option_spec[] = {
    OPTION("--container=%s", container),
    OPTION("-c %s",          container),
    OPTION("--key=%s",       key_hex),
    OPTION("-k %s",          key_hex),
    OPTION("--iv=%s",        iv_hex),
    OPTION("-i %s",          iv_hex),
    OPTION("-h",             show_help),
    OPTION("--help",         show_help),
    OPTION("--no-cache",     no_cache),
    FUSE_OPT_END
};

/*
 * Parse a hex string (e.g. "deadbeef") into raw bytes.
 * Returns 0 on success; -1 if the string is malformed.
 * *out_len is set to the number of bytes written to out[].
 * out[] must have room for at least strlen(hex)/2 bytes.
 */
static int parse_hex(const char *hex, uint8_t *out, size_t *out_len)
{
    size_t hlen = strlen(hex);
    if (hlen == 0 || hlen % 2 != 0)
        return -1;

    *out_len = hlen / 2;
    for (size_t i = 0; i < *out_len; i++) {
        char pair[3] = { hex[2 * i], hex[2 * i + 1], '\0' };
        char *endp;
        unsigned long v = strtoul(pair, &endp, 16);
        if (*endp != '\0')
            return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static inline struct fscrypt_state *get_state(void)
{
    return (struct fscrypt_state *)fuse_get_context()->private_data;
}

static int fscrypt_fuse_getattr(const char *path,
#if FUSE_USE_VERSION >= 30
                                struct stat *st,
                                struct fuse_file_info *fi)
{
#else
                                struct stat *st)
{
    const struct fuse_file_info* fi = nullptr;
#endif
    memset(st, 0, sizeof *st);

    if (strcmp(path, "/") == 0) {
        st->st_mode  = S_IFDIR | 0755;
        st->st_nlink = 2;
        return 0;
    }

    if ((fi != nullptr && fi->fh == IMAGE_FILE_HANDLE) || (path[0] == '/' && strcmp(path + 1, get_state()->image_filename) == 0)) {
        struct fscrypt_state *s = get_state();
        uint64_t img_sz = fscrypt_image_size(s);

        st->st_mode    = S_IFREG | 0644;
        st->st_nlink   = 1;
        st->st_size    = (off_t)img_sz;
        st->st_blksize = FSCRYPT_PAGE_SIZE;
        st->st_blocks  = (blkcnt_t)((img_sz + 511u) / 512u);

        time_t now = time(NULL);
        st->st_atim.tv_sec = now;
        st->st_mtim.tv_sec = s->image_timestamp;
        st->st_ctim.tv_sec = s->image_timestamp;
        return 0;
    }

    return -ENOENT;
}

static int fscrypt_fuse_readdir(const char *path, void *buf,
                                fuse_fill_dir_t filler, off_t offset,
#if FUSE_USE_VERSION >= 30
                                struct fuse_file_info *fi,
                                enum fuse_readdir_flags flags)
#else
                                struct fuse_file_info* fi)
#endif
{
    (void)offset;
    (void)fi;
#if FUSE_USE_VERSION >= 30
    (void)flags;
#endif

    if (strcmp(path, "/") != 0)
        return -ENOENT;

#if FUSE_USE_VERSION >= 30
    filler(buf, ".",           NULL, 0, 0);
    filler(buf, "..",          NULL, 0, 0);
    filler(buf, get_state()->image_filename, NULL, 0, 0);
#else
    filler(buf, ".",           NULL, 0);
    filler(buf, "..",          NULL, 0);
    filler(buf, get_state()->image_filename, NULL, 0);
#endif

    return 0;
}

static int fscrypt_fuse_open(const char *path, struct fuse_file_info *fi)
{
    if (path[0] != '/' || strcmp(path + 1, get_state()->image_filename) != 0)
        return -ENOENT;

    fi->fh = IMAGE_FILE_HANDLE;

    return 0;
}

static int fscrypt_fuse_read(const char *path, char *buf, size_t size,
                              off_t offset, struct fuse_file_info *fi)
{
    if (fi->fh != IMAGE_FILE_HANDLE)
        return -ENOENT;

    ssize_t ret = fscrypt_read(get_state(), buf, size, offset);

    /* FUSE read() must return a non-negative value or -errno. */
    return (int)ret;
}

static int fscrypt_fuse_write(const char *path, const char *buf, size_t size,
                               off_t offset, struct fuse_file_info *fi)
{
    if (fi->fh != IMAGE_FILE_HANDLE)
        return -ENOENT;

    ssize_t ret = fscrypt_write(get_state(), buf, size, offset);
    return (int)ret;
}

static int fscrypt_fuse_truncate(const char *path,
#if FUSE_USE_VERSION >= 30
                                  off_t size,
                                  struct fuse_file_info *fi)
{
#else
                                  off_t size)
{
    const struct fuse_file_info* fi = nullptr;
#endif
    if (size < 0)
        return -EINVAL;
    if ((fi != nullptr && fi->fh == IMAGE_FILE_HANDLE) || (path[0] == '/' && strcmp(path + 1, get_state()->image_filename) == 0))
        return fscrypt_truncate(get_state(), (uint64_t)size);

    return -ENOENT;
}

static int fscrypt_fuse_flush(const char *path, struct fuse_file_info *fi)
{
    if (fi->fh != IMAGE_FILE_HANDLE)
        return 0;

    return fscrypt_flush_headers(get_state());
}

static int fscrypt_fuse_fsync(const char *path, int datasync,
                               struct fuse_file_info *fi)
{
    (void)datasync;

    if (fi->fh != IMAGE_FILE_HANDLE)
        return 0;

    return fscrypt_flush_headers(get_state());
}

static void fscrypt_fuse_destroy(void *private_data)
{
    fscrypt_close_container((struct fscrypt_state *)private_data);
}

static const struct fuse_operations fscrypt_ops = {
    .getattr  = fscrypt_fuse_getattr,
    .readdir  = fscrypt_fuse_readdir,
    .open     = fscrypt_fuse_open,
    .read     = fscrypt_fuse_read,
    .write    = fscrypt_fuse_write,
    .truncate = fscrypt_fuse_truncate,
    .flush    = fscrypt_fuse_flush,
    .fsync    = fscrypt_fuse_fsync,
    .destroy  = fscrypt_fuse_destroy,
};

static void print_usage(const char *progname)
{
    fprintf(stderr,
        "Usage: %s [options] <mountpoint>\n"
        "\n"
        "fscrypt FUSE filesystem options:\n"
        "  -c PATH, --container=PATH   path to the fscrypt container file\n"
        "  -k HEX,  --key=HEX          container's AES key\n"
        "  -i HEX,  --iv=HEX           container'S AES initialization vector\n"
        "  --no-cache                  do not cache recently accessed pages\n"
        "  -h, --help                  show this help message\n"
        "\n",
        progname);
}

int main(int argc, char **argv)
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    if (fuse_opt_parse(&args, &cli_opts, option_spec, NULL) == -1) {
        fuse_opt_free_args(&args);
        return 1;
    }

    if (cli_opts.show_help) {
        print_usage(argv[0]);
        /* Pass --help to libfuse so it prints its own option list too. */
        fuse_opt_add_arg(&args, "--help");
        fuse_main(args.argc, args.argv, &fscrypt_ops, NULL);
        fuse_opt_free_args(&args);
        return 0;
    }

    bool missing = false;
    if (!cli_opts.container) {
        fprintf(stderr, "error: --container / -c is required\n");
        missing = true;
    }
    if (missing) {
        fprintf(stderr, "Try '%s --help' for usage information.\n", argv[0]);
        fuse_opt_free_args(&args);
        return 1;
    }

    uint8_t key[32];
    size_t  key_len = 0;
    if (cli_opts.key_hex != nullptr && parse_hex(cli_opts.key_hex, key, &key_len) != 0) {
        fprintf(stderr, "error: --key is not a valid hex string\n");
        fuse_opt_free_args(&args);
        return 1;
    }
    if (key_len != 0 && key_len != 16 && key_len != 24 && key_len != 32) {
        fprintf(stderr,
                "error: --key must be 32, 48, or 64 hex characters "
                "(got %zu hex chars = %zu bytes)\n",
                key_len * 2, key_len);
        fuse_opt_free_args(&args);
        return 1;
    }

    uint8_t iv[16];
    size_t  iv_len = 0;
    if (cli_opts.iv_hex != nullptr && (parse_hex(cli_opts.iv_hex, iv, &iv_len) != 0 || iv_len != 16)) {
        fprintf(stderr,
                "error: --iv must be exactly 32 hex characters (16 bytes)\n");
        fuse_opt_free_args(&args);
        return 1;
    }

    struct fscrypt_state *state = NULL;
    int ret = fscrypt_open_container(cli_opts.container,
                                     key, key_len,
                                     iv,  iv_len,
                                     cli_opts.no_cache,
                                     &state);
    if (ret != 0) {
        fprintf(stderr, "error: cannot open container '%s': %s\n",
                cli_opts.container, strerror(-ret));
        fuse_opt_free_args(&args);
        return 1;
    }

    fprintf(stderr,
            "fscrypt: mounted '%s' on '%s'\n"
            "  block_size=%" PRIu64 "  header_blocks=%" PRIu64
            "  total_blocks=%" PRIu64 "  image_size=%" PRIu64 " bytes\n",
            cli_opts.container, args.argv[args.argc - 1],
            state->bootid.block_size,
            state->bootid.header_block_count,
            state->current_block_count,
            fscrypt_image_size(state));

    ret = fuse_main(args.argc, args.argv, &fscrypt_ops, state);

    fuse_opt_free_args(&args);
    return ret;
}
