project('fuse-fscrypt', 'c', default_options: ['c_std=c23'])

fuse3_dep = dependency('fuse3')
openssl_dep = dependency('openssl')
zlib_dep = dependency('zlib')

executable(
    'fuse-fscrypt',
    sources: [
        'src/main.c',
        'src/crypto.c',
        'src/keys.c',
        'src/fscrypt_ops.c',
    ],
    dependencies: [fuse3_dep, openssl_dep, zlib_dep],
    c_args: ['-D_GNU_SOURCE'],
)
