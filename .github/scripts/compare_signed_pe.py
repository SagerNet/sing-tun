#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path


class PEFormatError(ValueError):
    pass


def read_u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "little")


def read_u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little")


def canonicalize_signed_pe(path: Path) -> bytes:
    data = bytearray(path.read_bytes())
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEFormatError(f"{path}: missing DOS header")

    pe_offset = read_u32(data, 0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise PEFormatError(f"{path}: missing PE header")

    optional_offset = pe_offset + 24
    magic = read_u16(data, optional_offset)
    if magic == 0x10B:
        data_directory_offset = optional_offset + 96
    elif magic == 0x20B:
        data_directory_offset = optional_offset + 112
    else:
        raise PEFormatError(f"{path}: unsupported optional header magic 0x{magic:04x}")

    checksum_offset = optional_offset + 64
    if checksum_offset + 4 > len(data):
        raise PEFormatError(f"{path}: truncated optional header")
    data[checksum_offset:checksum_offset + 4] = b"\x00" * 4

    security_directory_offset = data_directory_offset + 8 * 4
    if security_directory_offset + 8 > len(data):
        raise PEFormatError(f"{path}: truncated data directories")

    certificate_offset = read_u32(data, security_directory_offset)
    certificate_size = read_u32(data, security_directory_offset + 4)
    data[security_directory_offset:security_directory_offset + 8] = b"\x00" * 8

    if certificate_offset == 0 or certificate_size == 0:
        return bytes(data)

    certificate_end = certificate_offset + certificate_size
    if certificate_end > len(data):
        raise PEFormatError(f"{path}: certificate table exceeds file size")

    return bytes(data[:certificate_offset] + data[certificate_end:])


def canonical_sha256(path: Path) -> str:
    return hashlib.sha256(canonicalize_signed_pe(path)).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare two PE files after stripping Authenticode-only differences.",
    )
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    args = parser.parse_args()

    try:
        left_hash = canonical_sha256(args.left)
        right_hash = canonical_sha256(args.right)
    except (OSError, PEFormatError) as exc:
        print(exc, file=sys.stderr)
        return 2

    print(f"{args.left}: {left_hash}")
    print(f"{args.right}: {right_hash}")
    return 0 if left_hash == right_hash else 1


if __name__ == "__main__":
    raise SystemExit(main())
