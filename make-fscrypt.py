# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "construct",
#     "pycryptodome",
# ]
# ///
# pyright: reportMissingTypeStubs=false, reportOperatorIssue=false, reportUnknownArgumentType=false, reportUnknownMemberType=false
from math import ceil
import os
import secrets
import struct
import time
import zlib

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA1
from Crypto.PublicKey import RSA
from construct import (
    Bytes,
    Const,
    IfThenElse,
    Int16ul,
    Int32ul,
    Int64ul,
    Int8ul,
    Struct,
)

# ---- Configuration
ENCRYPTION_KEY = bytes.fromhex("5c84a9e726eaa5dd351f2b0750c23697")
ENCRYPTION_IV = bytes.fromhex("c063bf6f562d084d7963c987f5281761")
INPUT_FILE = "image.exfat"  # Should not be encrypted.
OUTPUT_FILE = "option.opt"
BOOTID = {
    "unk1": 0x01,  # Ocassionally you'll see this be 0.
    "type": 0x02,  # 0: OS, 1: App, 2: Option
    "sequence_number": 0,  # Only applies to app patches.

    # If this is enabled, the container should be decrypted with a derived IV. The derivation algorithm is unknown.
    "derive_iv": 0,
    
    "game_id": b"SDGS",
    "game_timestamp": {
        "year": 2023,
        "month": 12,
        "day": 28,
        "hour": 16,
        "minute": 34,
        "second": 43,
        "milli": 0,
    },
    "game_version": b"A041",
    "block_size": 0x40000,
    "header_block_count": 8,
    "unk2": 0,
    "hw_family": b"ACA",
    "hw_generation": 0,

    # Fill in orig_timestamp/orig_version if you're making an app patch.
    "orig_timestamp": {
        "year": 0,
        "month": 0,
        "day": 0,
        "hour": 0,
        "minute": 0,
        "second": 0,
        "milli": 0,
    },
    "orig_version": {
        "release": 0,
        "minor": 0,
        "major": 0,
    },
    
    "os_version": {
        "release": 1,
        "minor": 54,
        "major": 80,
    },
    
    # Depending on the app/opt/pack, this might have some text in it.
    "strings": b"\x00" * 0x27AC,
}
# ----

# ---- Keys
# The BootID (app/opt/pack header) encryption key and IV.
BTKEY = bytes.fromhex("09ca5efd30c9aaef3804d0a7e3fa7120")
BTIV = bytes.fromhex("b155c22c2e7f0491fa7f0fdc217aff90")

# The HMAC key used to "verify" the array of block CRCs.
SIGKEY = bytes.fromhex(
    "e1bdcb2d5e9ed3b5de234364dfa4d126849edff769fc6c28fba5f43bc482bd7479d676afce8188e1d3a6852f4ebce45cde46bd15e8ee5fe84d197f945a54518f"
)

# The header metadata contains the timestamp when the container is
# created, and the path to the original file, then just a bunch of random
# bytes. The private key used to decrypt the header metadata is unknown.
HEADER_META_PUBKEY = RSA.import_key("""-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA8f+6o4yvruBLMM2S7eDb
zj/qyJXzAS0y2EYsuG1as/iypwfPnE2gf8H1s6WQmyACt1AKHUx/wQ8BFiq3iPTf
8a5A7JL0j8GvM1wnxK5uvh9DjI87zvT//lG87w85g6FjiIF8L1VnsTWayR7RCPA6
PCEj8xojPFt8aRSJCtFj5lHHCVnGwvke7GvKqurK4ChzkMOtT51TPHh6TxJn2bWM
e6tRxZak5hpQVfJjbI4WJHTAf6zW6JgapuoBeIRSexOfhoJqIwCpTuakFHNR/8S1
cmXgLGsxis1GKkNIWHsLHNbbj5nOUplNKjEh5+r4LP8befsp2M2pd76hmEJPp76T
F89SKPiGH94DpRuiabk9s9YGPxXTeqLcFJbRm+FboHfDZPKiCi/7eJzvhMI0p3V+
XZ2IH0PLZ3U4n0mXSGb775X7570SogziOTRWHmv6NnlIi+157THLCpHVsb2+3ro6
TQ6ngalXgGKxfjAJJlauXBjACTPyI97/owqqHLHSq7St6BFSEKonbkbvWNMsX6Oz
lvn7AFIAkcdKVV83Y+xWIvbw5NPT6iyeoXxv+/w+oqcstU4DiiAZp1gJuMABxWki
o9b87jSZx0qORHqXjdNZsM1yZO+/A2VT2xeBTpW/UOAfIDC0aOhAD6rtAix45d4+
ehEDoy8d0wPMyN3VrZ8J2l0CAwEAAQ==
-----END PUBLIC KEY-----
""")
# ----

# ---- Constants. Don't edit.
EXFAT_HEADER = bytes.fromhex("EB769045584641542020200000000000")
OPTION_IV = bytes.fromhex("C063BF6F562D084D7963C987F5281761")
# ----

# ---- Script
Timestamp = Struct(
    "year" / Int16ul,
    "month" / Int8ul,
    "day" / Int8ul,
    "hour" / Int8ul,
    "minute" / Int8ul,
    "second" / Int8ul,
    "milli" / Int8ul,
)

Version = Struct(
    "release" / Int8ul,
    "minor" / Int8ul,
    "major" / Int16ul,
)

BootID = Struct(
    "length" / Const(0x2800, Int32ul),
    "magic" / Const(b"BTID", Bytes(4)),
    "unk1" / Int8ul,
    "type" / Int8ul,
    "sequence_number" / Int8ul,
    "derive_iv" / Int8ul,
    "game_id" / Bytes(4),
    "game_timestamp" / Timestamp,
    "game_version" / IfThenElse(lambda ctx: ctx.type == 0x02, Bytes(4), Version),
    "block_count" / Int64ul,
    "block_size" / Int64ul,
    "header_block_count" / Int64ul,
    "unk2" / Int64ul,
    "hw_family" / Bytes(3),
    "hw_generation" / Int8ul,
    "orig_timestamp" / Timestamp,
    "orig_version" / Version,
    "os_version" / Version,
    "strings" / Bytes(0x27AC),
)


def get_page_iv(iv: bytes, offset: int):
    return bytes(x ^ (offset >> (8 * (i % 8))) & 0xFF for (i, x) in enumerate(iv))


filesize = os.stat(INPUT_FILE).st_size
BOOTID["block_count"] = ceil(filesize / BOOTID["block_size"]) + 8

header_key = secrets.token_bytes(16)
header_iv = secrets.token_bytes(16)
encrypted_keypair = PKCS1_OAEP.new(HEADER_META_PUBKEY).encrypt(header_key + header_iv)
header_meta = struct.pack("<Q", int(time.time())) + os.path.abspath(INPUT_FILE).encode(
    "utf-8"
) + b"\x00"
header_meta += secrets.token_bytes(
    BOOTID["block_size"] - len(header_meta) - len(encrypted_keypair)
)
header_meta = encrypted_keypair + AES.new(header_key, AES.MODE_CBC, header_iv).encrypt(header_meta)
header_meta_crc32 = zlib.crc32(header_meta)
block_crc32s = [
    0,
    header_meta_crc32,
    header_meta_crc32,
    header_meta_crc32,
    header_meta_crc32,
    header_meta_crc32,
    header_meta_crc32,
    header_meta_crc32,
]

with open(INPUT_FILE, "rb") as fin, open(OUTPUT_FILE, "w+b") as fout:
    # Write the bootID.
    cipher = AES.new(BTKEY, AES.MODE_CBC, BTIV)
    bootid = BootID.build(BOOTID)
    bootid_crc32 = zlib.crc32(bootid)
    bootid_bytes = cipher.encrypt(struct.pack("<I", bootid_crc32) + bootid)

    _ = fout.write(bootid_bytes)

    # Ignore the CRC32s and the signature for now, we'll come back later.
    # We'll generate random bytes for them though.
    _ = fout.write(secrets.token_bytes(BOOTID["block_size"] - 0x2800))

    for i in range(BOOTID["header_block_count"] - 1):
        _ = fout.write(header_meta)

    # Encrypt the contents of the file.
    total_written = 0
    to_read = filesize
    block_crc32 = 0

    while to_read > 0:
        page_iv = get_page_iv(ENCRYPTION_IV, total_written)
        contents = fin.read(4096)
        contents_len = len(contents)

        to_read -= contents_len

        if contents_len < 4096:
            contents += b"\x00" * (4096 - contents_len)

        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, page_iv)
        encrypted = cipher.encrypt(contents)
        total_written += fout.write(encrypted)
        block_crc32 = zlib.crc32(encrypted, block_crc32)

        if (total_written % BOOTID["block_size"]) == 0:
            block_crc32s.append(block_crc32)
            block_crc32 = 0

    # Pad with null bytes if we have an unfinished block.
    if (total_written % BOOTID["block_size"]) != 0:
        null_byte_count = BOOTID["block_size"] - (total_written % BOOTID["block_size"])

        while null_byte_count > 0:
            page_iv = get_page_iv(ENCRYPTION_IV, total_written)
            cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, page_iv)
            encrypted = cipher.encrypt(b"\x00" * 4096)
            total_written += fout.write(encrypted)
            block_crc32 = zlib.crc32(encrypted, block_crc32)

            null_byte_count -= 4096

        block_crc32s.append(block_crc32)
        block_crc32 = 0

    # We can finally revisit the CRC32s.
    _ = fout.seek(0x2A04)

    for crc32 in block_crc32s[1:]:
        _ = fout.write(struct.pack("<I", crc32))

    _ = fout.seek(0)
    block_0_crc32 = zlib.crc32(fout.read(0x2800))

    # Skip the HMAC signature and the first CRC32, which we're trying to calculate.
    _ = fout.seek(0x204, os.SEEK_CUR)
    block_0_crc32 = zlib.crc32(
        fout.read(BOOTID["block_size"] - 0x2800 - 0x204), block_0_crc32
    )

    _ = fout.seek(0x2A00)
    _ = fout.write(struct.pack("<I", block_0_crc32))

    # Calculate the HMAC signature.
    _ = fout.seek(0x2A00)
    hmac = HMAC.new(SIGKEY, digestmod=SHA1)
    to_read = BOOTID["block_size"] * 8 - 0x2A00

    while to_read > 0:
        block = fout.read(min(0x1000, to_read))
        if len(block) == 0:
            raise Exception("Ran out of data making the signature.")

        _ = hmac.update(block)
        to_read -= len(block)

    _ = fout.seek(0x2800)
    _ = fout.write(hmac.digest())
