# fuse-fscrypt

FUSE driver for SEGA's fscrypt filesystem container format. This makes it possible to
inspect and modify the contents of the filesystem without having to extract its contents
to disk. If you wish to extract to disk, [fsdecrypt] or [unsegaREBORN] are better choices.

[fsdecrypt]: https://gitea.tendokyu.moe/beerpsi/fsdecrypt
[unsegaREBORN]: https://github.com/proeren2002/unsegaREBORN

## TODO

- [ ] Support APM3 options

## Usage

Key and IV can be omitted for [known games](src/keys.c).

```
fuse-fscrypt [options] <mountpoint>

fscrypt FUSE filesystem options:
  -c PATH, --container=PATH   path to the fscrypt container file
  -k HEX,  --key=HEX          container's AES key
  -i HEX,  --iv=HEX           container'S AES initialization vector

FUSE options:
    -h   --help            print help
    -V   --version         print version
    -d   -o debug          enable debug output (implies -f)
    -f                     foreground operation
    -s                     disable multi-threaded operation
    -o clone_fd            use separate fuse device fd for each thread
                           (may improve performance)
    -o max_idle_threads    the maximum number of idle worker threads
                           allowed (default: -1)
    -o max_threads         the maximum number of worker threads
                           allowed (default: 10)
    -o kernel_cache        cache files in kernel
    -o [no]auto_cache      enable caching based on modification times (off)
    -o no_rofd_flush       disable flushing of read-only fd on close (off)
    -o umask=M             set file permissions (octal)
    -o fmask=M             set file permissions (octal)
    -o dmask=M             set dir  permissions (octal)
    -o uid=N               set file owner
    -o gid=N               set file group
    -o entry_timeout=T     cache timeout for names (1.0s)
    -o negative_timeout=T  cache timeout for deleted names (0.0s)
    -o attr_timeout=T      cache timeout for attributes (1.0s)
    -o ac_attr_timeout=T   auto cache timeout for attributes (attr_timeout)
    -o noforget            never forget cached inodes
    -o remember=T          remember cached inodes for T seconds (0s)
    -o modules=M1[:M2...]  names of modules to push onto filesystem stack
    -o allow_other         allow access by all users
    -o allow_root          allow access by root
    -o auto_unmount        auto unmount on process termination
    -o io_uring            enable io-uring
    -o io_uring_q_depth=<n> io-uring queue depth

Options for subdir module:
    -o subdir=DIR	    prepend this directory to all paths (mandatory)
    -o [no]rellinks	    transform absolute symlinks to relative

Options for iconv module:
    -o from_code=CHARSET   original encoding of file names (default: UTF-8)
    -o to_code=CHARSET     new encoding of the file names (default: UTF-8)
```

## Utilities

Higher-level utilities to make mounting a bunch of apps and options less miserable.

The mount scripts are only tested on Linux (and probably only works on Linux, due
to reliance on `/proc`). They also need `user_allow_other` enabled in `/etc/fuse.conf`.

### mount-app

Mount base and update `.app`/`.pack` containers into a specified mount directory.
Requires `fuse-fscrypt`, [`ntfs-3g`] and [`libvhdi`] installed in PATH.

[`ntfs-3g`]: https://github.com/tuxera/ntfs-3g
[`libvhdi`]: https://github.com/libyal/libvhdi

```
mount-app BASE DELTA1 DELTA2 /mnt
```

> [!WARNING]
> Patch/delta images will be directly modified to refer to the correct parent VHD. Make a backup!

This creates `/mnt/BASE` containing the contents of the base image, `/mnt/DELTA1`
containing the contents of BASE + DELTA1, and `/mnt/DELTA2` containing the contents
of BASE + DELTA1 + DELTA2

Mounts are read-only by default. Pass `--rw` to make the BASE mount read-write (this
requires `guestmount` from [`libguestfs`] in PATH). DELTA mounts cannot be read-write
due to [lack of] [support] by `libvhdi`.

[`libguestfs`]: https://libguestfs.org
[lack of]: https://github.com/libyal/libvhdi/issues/18
[support]: https://github.com/libyal/libvhdi/issues/20

### mount-option

Mount option `.opt` containers into a specified mount directory.
Requires `fuse-fscrypt` and [`exfatprogs`] installed in PATH.

[`exfatprogs`]: https://github.com/exfatprogs/exfatprogs

```
mount-option OPTION1 OPTION2 /mnt
```

This mounts `OPTION1` and `OPTION2` into `/mnt/OPTION1` and `/mnt/OPTION2` respectively.

Mounts are read-only by default. Pass `--rw` to make them read-write.

### make-fscrypt.py

Requires [`construct`] and [`PyCryptodome`].

[`construct`]: https://pypi.org/project/construct
[`PyCryptodome`]: https://pypi.org/project/pycryptodome

Creates a new fscrypt container from the raw disk image file and a provided boot ID.
See the configuration section of the script for more information.

To create an NTFS disk image on a file (`mkfs.ntfs` from [`ntfs-3g`]):

[`ntfs-3g`]: https://github.com/tuxera/ntfs-3g

```sh
dd if=/dev/zero of=image.ntfs bs=262144 count=16
mkfs.ntfs -F -c 4096 -s 4096 -p 29 -H 16 -S 32 image.ntfs
# parameters chosen to match official images as closely as possible
```

To create an exFAT disk image on a file (`mkfs.exfat` from [`exfatprogs`]):

[`exfatprogs`]: https://github.com/exfatprogs/exfatprogs

```sh
dd if=/dev/zero of=image.ntfs bs=262144 count=16
mkfs.exfat -s 4096 -c 4096 -b 128K -f -C image.exfat
# parameters chosen to match official images as closely as possible
```
