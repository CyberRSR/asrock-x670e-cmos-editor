"""Firmware volume / FFS walking for AMI Aptio V SPI images.

Only the pieces the settings editor needs are implemented: locate firmware volumes by their
``_FVH`` signature, walk FFS file nodes, split sections and transparently decompress
GUID-defined payloads so the setup modules behind them become searchable.
"""
from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field

from .decompress import guid_defined_decompress

SECTION_NAMES = {
    0x01: "COMPRESSION",
    0x02: "GUID_DEFINED",
    0x03: "DISPOSABLE",
    0x04: "PE32",
    0x05: "PIC",
    0x06: "TE",
    0x07: "DXE_DEPEX",
    0x08: "VERSION",
    0x09: "USER_INTERFACE",
    0x0A: "COMPATIBILITY16",
    0x0B: "FIRMWARE_VOLUME_IMAGE",
    0x0C: "FREEFORM_SUBTYPE_GUID",
    0x0D: "ROM_CLASS",
}
FILE_TYPES = {
    0x00: "RAW", 0x01: "FFS", 0x02: "DRIVER", 0x03: "EXECUTABLE", 0x04: "SECURITY_CORE",
    0x05: "PEI_CORE", 0x06: "DXE_CORE", 0x07: "PEIM_DRIVER", 0x08: "SMM_DRIVER",
    0x09: "SMM_CORE", 0x0A: "OEM", 0x0B: "ABSOLUTE", 0x0D: "ASIC_DATA",
    0x0E: "FIRMWARE_VOLUME_IMAGE", 0x0F: "SMM_CORE_STANDALONE", 0xF0: "PAD",
}
FVFS_GUID = uuid.UUID("8C8CE578-8A3D-4F1C-9935-896185C32DD3")
FVFS3_GUID = uuid.UUID("5473C07A-3DCB-4DCA-BD6F-1E9689E7349A")
COMPRESS_NORMAL = 0x00


@dataclass
class Section:
    offset: int
    length: int
    kind: str
    sec_type: int
    guid: uuid.UUID | None = None
    ui_name: str = ""
    raw: bytes = b""
    data: bytes = b""
    children: list["Section"] = field(default_factory=list)
    error: str = ""


@dataclass
class FfsFile:
    offset: int
    length: int
    guid: uuid.UUID
    ftype: str
    state: int
    ui_name: str = ""
    sections: list[Section] = field(default_factory=list)


@dataclass
class FirmwareVolume:
    offset: int
    length: int
    guid: uuid.UUID
    state: int
    attributes: int
    files: list[FfsFile] = field(default_factory=list)
    nested: list["FirmwareVolume"] = field(default_factory=list)


def _align(value: int, boundary: int = 8) -> int:
    return (value + boundary - 1) // boundary * boundary


def find_fv_headers(image: bytes) -> list[int]:
    """Offsets of plausible ``EFI_FIRMWARE_VOLUME_HEADER`` structures."""
    found = []
    pos = 0
    while True:
        pos = image.find(b"_FVH", pos)
        if pos < 0:
            return found
        base = pos - 0x28
        if base >= 0:
            zero_ok = image[base:base + 16] == b"\x00" * 16
            length = struct.unpack_from("<Q", image, base + 0x20)[0]
            hdr_len = struct.unpack_from("<H", image, base + 0x28 - 0x10)[0] if False else \
                struct.unpack_from("<H", image, base + 0x30)[0]
            extended = image[base + 0x2C] & 0x01
            if zero_ok and 0x100 <= length <= len(image) - base and (extended or hdr_len in (0x48, 0x60, 0x70)):
                found.append(base)
        pos += 1


def parse_volume(image: bytes, base: int, depth: int = 0) -> FirmwareVolume | None:
    try:
        fsguid = uuid.UUID(bytes_le=image[base + 0x10:base + 0x20])
        length = struct.unpack_from("<Q", image, base + 0x20)[0]
        state, attributes, hdr_len, ext, align = struct.unpack_from("<HBBBB", image, base + 0x28)
    except Exception:
        return None
    fv = FirmwareVolume(offset=base, length=int(length), guid=fsguid, state=state, attributes=attributes)
    if depth > 4 or not (0x100 <= length <= len(image) - base):
        return None
    body_start = base + _align(hdr_len, 8) if hdr_len else base + 0x60
    if hdr_len == 0:
        body_start = base + 0x60
    fv.files = walk_files(image, body_start, base + length, depth)
    for ffs in fv.files:
        for sec in ffs.sections:
            if sec.sec_type == 0x0B or sec.kind == "FIRMWARE_VOLUME_IMAGE":
                fv.nested.extend(parse_nested(image, sec.data, base))
    return fv


def parse_nested(image: bytes, blob: bytes, delta: int) -> list[FirmwareVolume]:
    out = []
    for off in find_fv_headers(blob):
        sub = parse_volume(blob, off, depth=3)
        if sub:
            sub.offset += delta
            out.append(sub)
    return out


def walk_files(image: bytes, start: int, end: int, depth: int) -> list[FfsFile]:
    files: list[FfsFile] = []
    pos = start
    while pos + 24 <= end:
        state = image[pos]
        ftype = image[pos + 1]
        if state == 0xFF or state == 0x00:
            break
        size = int.from_bytes(image[pos + 2:pos + 5], "little")
        if size < 24 or pos + size > end:
            break
        guid = uuid.UUID(bytes_le=image[pos + 8:pos + 24])
        header_len = 24 if ftype not in (0x07, 0xF0) else 20
        ffs = FfsFile(offset=pos, length=size, guid=guid, ftype=FILE_TYPES.get(ftype, f"0x{ftype:02X}"), state=state)
        ffs.sections = walk_sections(image, pos + header_len, pos + size, depth)
        for sec in ffs.sections:
            if sec.kind == "USER_INTERFACE":
                ffs.ui_name = sec.ui_name
        files.append(ffs)
        pos += size
        if size % 8:
            pos += 8 - (size % 8)
    return files


def walk_sections(image: bytes, start: int, end: int, depth: int) -> list[Section]:
    out: list[Section] = []
    pos = start
    while pos + 4 <= end:
        size = int.from_bytes(image[pos:pos + 3], "little")
        sec_type = image[pos + 3]
        if size < 4 or pos + size > end:
            break
        body = image[pos + 4:pos + size]
        sec = Section(offset=pos, length=size, kind=SECTION_NAMES.get(sec_type, f"0x{sec_type:02X}"), sec_type=sec_type)
        if sec_type == 0x09:
            try:
                sec.ui_name = body.decode("utf-16-le").strip("\x00")
            except Exception:
                sec.ui_name = repr(body[:40])
        elif sec_type == 0x02 and len(body) >= 20:
            sec.guid = uuid.UUID(bytes_le=body[:16])
            data_off, attrs = struct.unpack_from("<HH", body, 16)
            payload = body[data_off:] if data_off else body[20:]
            sec.raw = payload
            try:
                sec.data = guid_defined_decompress(sec.guid, payload)
            except Exception as exc:
                sec.error = f"{type(exc).__name__}: {exc}"
        elif sec_type == 0x01 and len(body) >= 24:
            import uuid as _u
            comp_guid = _u.UUID(bytes_le=body[:16])
            ctype = struct.unpack_from("<Q", body, 16)[0]
            payload = body[24:]
            sec.guid = comp_guid
            sec.raw = payload
            try:
                if ctype == COMPRESS_NORMAL:
                    sec.data = guid_defined_decompress(comp_guid, payload)
                else:
                    sec.error = f"unknown compression type {ctype}"
            except Exception as exc:
                sec.error = f"{type(exc).__name__}: {exc}"
        elif sec_type == 0x0B:
            sec.data = body
        else:
            sec.data = body
        if sec.data and sec_type in (0x01, 0x02, 0x0B) and depth < 4:
            sec.children = walk_sections(sec.data, 0, len(sec.data), depth + 1) if _looks_like_sections(sec.data) else []
        out.append(sec)
        pos += size
        if size % 4:
            pos += 4 - (size % 4)
    return out


def _looks_like_sections(blob: bytes) -> bool:
    if len(blob) < 8:
        return False
    size = int.from_bytes(blob[:3], "little")
    return 4 <= size <= len(blob) and blob[3] in SECTION_NAMES


def parse_image(image: bytes) -> list[FirmwareVolume]:
    vols = []
    for off in find_fv_headers(image):
        fv = parse_volume(image, off)
        if fv:
            vols.append(fv)
    # drop bogus parents that a later, correctly sized volume contains
    vols.sort(key=lambda v: (v.offset, -v.length))
    kept: list[FirmwareVolume] = []
    for fv in vols:
        if any(k is not fv and k.offset <= fv.offset and fv.offset < k.offset + k.length and k.length > fv.length
               and k.guid == FVFS_GUID and fv.guid != FVFS_GUID for k in vols):
            continue
        kept.append(fv)
    return kept
