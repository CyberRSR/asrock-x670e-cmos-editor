"""Carve compressed payloads out of an AMI Aptio V SPI image.

The ASRock image wraps every module in a GUID-defined LZMA section behind a proprietary 8-byte
record header, so instead of trusting the container the carver anchors on the LZMA section
signature itself and, as a fallback, on raw LZMA_Alone property bytes.
"""
from __future__ import annotations

import re
import struct
import uuid
from dataclasses import dataclass

from uefi.decompress import LZMA_GUID, lzma_alone_decompress

LZMA_GUID_LE = LZMA_GUID.bytes_le


@dataclass
class Payload:
    offset: int          # offset of the section/record inside the image
    data: bytes
    source: str
    uncompressed_size: int

    @property
    def pe_machine(self) -> str | None:
        idx = self.data.find(b"PE\x00\x00")
        if 0 < idx <= 0x1000:
            machine = struct.unpack_from("<H", self.data, idx + 4)[0]
            return {0x8664: "x64", 0x14c: "x86", 0xaa64: "arm64"}.get(machine, hex(machine))
        return None


def find_guid_defined_sections(image: bytes) -> list[tuple[int, int, int]]:
    """(section_start, payload_offset, uncompressed_size) for each LZMA GUID-defined section."""
    found = []
    for m in re.finditer(re.escape(LZMA_GUID_LE), image):
        guid_off = m.start()
        section_start = guid_off - 4
        if section_start < 0:
            continue
        sec_size = int.from_bytes(image[section_start:section_start + 3], "little")
        sec_type = image[section_start + 3]
        data_off = struct.unpack_from("<H", image, guid_off + 16)[0] or 20
        payload_off = guid_off + 16 + (data_off - 4) if data_off >= 4 else guid_off + 20
        found.append((section_start, sec_size, sec_type, payload_off))  # type: ignore[misc]
    return found


def find_raw_lzma_streams(image: bytes, min_dict: int = 1 << 16) -> list[int]:
    """Offsets where an LZMA_Alone header with plausible parameters starts."""
    out = []
    for m in re.finditer(rb"\x5d\x00\x00\x00[\x01\x10]", image):
        out.append(m.start())
    return out


def carve(image: bytes, log=print) -> list[Payload]:
    payloads: list[Payload] = []
    seen: set[bytes] = set()

    def keep(offset: int, data: bytes, source: str) -> None:
        if len(data) < 0x40:
            return
        key = data[:64]
        if key in seen:
            return
        seen.add(key)
        payloads.append(Payload(offset, data, source, len(data)))
        log(f"  {source:12s} @{offset:#09x} -> {len(data):#x} bytes")

    for section_start, sec_size, sec_type, payload_off in _sections(image):
        if sec_type != 0x02:
            continue
        try:
            data = lzma_alone_decompress(image[payload_off:])
        except Exception as exc:
            log(f"  LZMA section @{payload_off:#09x} failed: {type(exc).__name__}: {exc}")
            continue
        keep(payload_off, data, "guid-section")

    covered = {p.offset for p in payloads}
    for off in find_raw_lzma_streams(image):
        if any(abs(off - c) < 0x20 for c in covered):
            continue
        try:
            data = lzma_alone_decompress(image[off:], max_out=1 << 22)
        except Exception:
            continue
        keep(off, data, "raw-lzma")
    return payloads


def _sections(image: bytes):
    for m in re.finditer(re.escape(LZMA_GUID_LE), image):
        guid_off = m.start()
        section_start = guid_off - 4
        sec_size = int.from_bytes(image[section_start:section_start + 3], "little")
        sec_type = image[section_start + 3]
        data_off = struct.unpack_from("<H", image, guid_off + 16)[0] or 0x18
        payload_off = section_start + data_off
        yield section_start, sec_size, sec_type, payload_off
