project('fuse-fscrypt', 'c', default_options: ['c_std=c23'])

exe_deps = [dependency('openssl'), dependency('zlib')]

if host_machine.system() == 'windows'
    exe_deps += declare_dependency(
        include_directories: include_directories('C:/Program Files (x86)/WinFsp/inc/fuse'),
    )
    exe_deps += meson.get_compiler('c').find_library('winfsp-x64', dirs: 'C:/Program Files (x86)/WinFsp/lib', static: true)
else
    fuse3_dep = dependency('fuse3')

    if fuse3_dep.found()
        exe_deps += fuse3_dep
        add_project_arguments('-DFUSE_USE_VERSION=31', language: ['c'])
    else
        exe_deps += dependency('fuse', required: true)
        add_project_arguments('-DFUSE_USE_VERSION=26', language: ['c'])
    endif
endif

exe_ldargs = []

if host_machine.system() == 'windows'
    exe_ldargs += ['-static', '-static-libgcc']
endif

executable(
    'fuse-fscrypt',
    sources: [
        'src/main.c',
        'src/crypto.c',
        'src/keys.c',
        'src/cache.c',
        'src/fscrypt_ops.c',
    ],
    dependencies: exe_deps,
    link_args: exe_ldargs,
    c_args: ['-D_GNU_SOURCE'],
)
