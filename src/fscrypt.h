#include <stdint.h>

enum AppType : uint8_t {
    APP_TYPE_SYSTEM,
    APP_TYPE_APP,
    APP_TYPE_OPTION,
};

struct __attribute__((packed)) Timestamp {
    uint16_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    uint8_t millisecond;
};

struct __attribute__((packed)) Version {
    uint8_t release;
    uint8_t minor;
    uint16_t major;
};

struct __attribute__((packed)) BootID {
    // Always 0x2800 (10240 bytes).
    uint32_t length;
    // Always { 'B', 'T', 'I', 'D' }.
    uint8_t magic[4];
    // Unknown field, usually 1 but can also be 0.
    uint8_t unk1;
    // The application type of this image.
    enum AppType type;
    // The sequence number of this image, in case of patches.
    uint8_t sequence_number;
    // Whether the IV for this image must be derived (unknown method) instead of
    // being a fixed known value.
    bool derive_iv;
    // The application's ID.
    char id[4];
    // The application's timestamp (when this image was built).
    struct Timestamp timestamp;
    // The application's version. This is either:
    // - a name for APP_TYPE_OPTION
    // - <major>.<minor>.<release> for everything else.
    union {
        struct Version version;
        char name[4];
    } version;
    // Total number of blocks in the container file, including the inner encrypted
    // image and any header blocks:
    //     block_count = ceil(filesize / block_size) + header_block_count
    uint64_t block_count;
    // Size in bytes of each block. Typically 0x40000 (262144 bytes).
    uint64_t block_size;
    // Number of blocks in the header (including the BootID). This is typically 8.
    // After the header is the encrypted disk image e.g. if header_block_count is
    // 8 then the header is blocks 0-7 and the image starts from block 8 (offset block_size * 8).
    uint64_t header_block_count;
    // Unknown field, usually set to 0.
    uint64_t unk2;
    // The hardware family this image is for.
    char hw_family[3];
    // The hardware family's generation.
    uint8_t hw_generation;
    struct Timestamp orig_timestamp;
    struct Version orig_version;
    struct Version os_version;
    char strings[0x27AC];
};

#define SYSTEM_FILENAME_PRINT_ARGS(bootid) "%.*s_%04u.%02u.%02u_%04u%02u%02u%02u%02u%02u_%u.ntfs", \
    (int)sizeof((bootid)->hw_family), (bootid)->hw_family, \
    (bootid)->os_version.major, (bootid)->os_version.minor, (bootid)->os_version.release, \
    (bootid)->timestamp.year, (bootid)->timestamp.month, (bootid)->timestamp.day, \
    (bootid)->timestamp.hour, (bootid)->timestamp.minute, (bootid)->timestamp.second, \
    (bootid)->sequence_number

#define APP_FILENAME_PRINT_ARGS(bootid) "%.*s_%u.%02u.%02u_%04u%02u%02u%02u%02u%02u_%u.ntfs", \
    (int)sizeof((bootid)->id), (bootid)->id, \
    (bootid)->version.version.major, (bootid)->version.version.minor, (bootid)->version.version.release, \
    (bootid)->timestamp.year, (bootid)->timestamp.month, (bootid)->timestamp.day, \
    (bootid)->timestamp.hour, (bootid)->timestamp.minute, (bootid)->timestamp.second, \
    (bootid)->sequence_number

#define OPTION_FILENAME_PRINT_ARGS(bootid) "%.*s_%.*s_%04u%02u%02u%02u%02u%02u_%u.exfat", \
    (int)sizeof((bootid)->id), (bootid)->id, \
    (int)sizeof((bootid)->version.name), (bootid)->version.name, \
    (bootid)->timestamp.year, (bootid)->timestamp.month, (bootid)->timestamp.day, \
    (bootid)->timestamp.hour, (bootid)->timestamp.minute, (bootid)->timestamp.second, \
    (bootid)->sequence_number

#define PATCH_FILENAME_PRINT_ARGS(bootid) "%.*s_%u.%02u.%02u_%04u%02u%02u%02u%02u%02u_%u_%u.%02u.%02u.ntfs", \
    (int)sizeof((bootid)->id), (bootid)->id, \
    (bootid)->version.version.major, (bootid)->version.version.minor, (bootid)->version.version.release, \
    (bootid)->timestamp.year, (bootid)->timestamp.month, (bootid)->timestamp.day, \
    (bootid)->timestamp.hour, (bootid)->timestamp.minute, (bootid)->timestamp.second, \
    (bootid)->sequence_number, \
    (bootid)->orig_version.major, (bootid)->orig_version.minor, (bootid)->orig_version.release
