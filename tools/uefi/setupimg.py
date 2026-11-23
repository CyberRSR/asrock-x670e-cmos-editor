"""Reader/writer for the ``A86`` setup-image container used by the AMI TSE dump.

Layout, confirmed byte for byte against X670E Taichi Carrara firmware 4.43::

    0x00  "A86\\0"            container signature
    0x20  " 4.10"            setup-layout version, NUL padded to 16 bytes
    0x38  u16                container format field (2 on this firmware)
    0x3A  u16                byte length of the record area that follows the header
    0x55  record[]           each record is  u32 little endian length + payload
                              a length of zero is a filler record
    tail                     zero padding up to the fixed container size

There is no checksum: 0x3A is the record-area length (verified on the 4.43 dump, where it
equals the distance from 0x55 to the last record), so edits only have to keep that field and
the record lengths consistent.

Every payload is the value of one EFI setup variable (``Setup``, ``AMITSESetup``,
``AmdSetupPHX`` ...); the container stores no names, so records are identified by comparing
their length and content with the factory defaults stored in the firmware image.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

SIGNATURE = b"A86\x00"
HEADER_SIZE = 0x55
VERSION_OFFSET = 0x20
FIELD_FORMAT = 0x38
FIELD_DATA_LENGTH = 0x3A


class SetupImageError(ValueError):
    pass


@dataclass
class Record:
    index: int
    offset: int
    length: int
    data: bytearray
    name: str = ""
    matched: str = ""       # "exact", "size" or "" when unidentified

    @property
    def end(self) -> int:
        return self.offset + 4 + self.length


@dataclass
class Varstore:
    """Byte accessors over one variable payload, addressed the way the IFR does."""

    name: str
    record: Record
    default: bytes | None = None
    _cache: dict[int, int] = field(default_factory=dict, repr=False)

    @property
    def size(self) -> int:
        return len(self.record.data)

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or offset + size > self.size:
            raise SetupImageError(f"{self.name}+{offset:#x}[{size}] outside {self.size:#x} byte store")
        return bytes(self.record.data[offset:offset + size])

    def read_int(self, offset: int, size: int) -> int:
        return int.from_bytes(self.read(offset, size), "little")

    def write(self, offset: int, value: int | bytes, size: int | None = None) -> None:
        if isinstance(value, bytes):
            payload, size = value, len(value)
        else:
            if size is None:
                raise SetupImageError("size required for integer writes")
            payload = int(value).to_bytes(size, "little")
        if offset < 0 or offset + size > self.size:
            raise SetupImageError(f"write to {self.name}+{offset:#x}[{size}] out of range")
        self.record.data[offset:offset + size] = payload

    def write_int(self, offset: int, value: int, size: int) -> None:
        self.write(offset, value, size)

    def dirty_offsets(self) -> list[int]:
        if self.default is None:
            return []
        return [i for i in range(min(self.size, len(self.default))) if self.record.data[i] != self.default[i]]


@dataclass
class SetupImage:
    path: Path | None
    header: bytearray
    records: list[Record]
    version: str
    tail: bytearray
    defaults: dict[str, bytes] = field(default_factory=dict, repr=False)

    # ---------- loading ----------
    @classmethod
    def load(cls, path: str | Path, defaults: dict[str, bytes] | None = None) -> "SetupImage":
        raw = Path(path).read_bytes()
        return cls.parse(raw, Path(path), defaults)

    @classmethod
    def parse(cls, raw: bytes, path: Path | None = None, defaults: dict[str, bytes] | None = None) -> "SetupImage":
        if not raw.startswith(SIGNATURE):
            raise SetupImageError(f"not an A86 setup image (found {raw[:4]!r})")
        if len(raw) < HEADER_SIZE + 4:
            raise SetupImageError("truncated A86 header")
        declared = struct.unpack_from("<H", raw, FIELD_DATA_LENGTH)[0]
        body_end = HEADER_SIZE + declared
        if declared < 4 or body_end > len(raw):
            raise SetupImageError(f"invalid record-area length {declared:#x}")
        records: list[Record] = []
        pos = HEADER_SIZE
        index = 0
        while pos < body_end:
            if pos + 4 > body_end:
                raise SetupImageError("truncated record header")
            length = struct.unpack_from("<I", raw, pos)[0]
            if length > 0x40000 or pos + 4 + length > body_end:
                raise SetupImageError(f"invalid record length {length:#x} at {pos:#x}")
            records.append(Record(index, pos, length, bytearray(raw[pos + 4:pos + 4 + length])))
            index += 1
            pos += 4 + length
        tail = bytearray(raw[body_end:])
        image = cls(
            path=path,
            header=bytearray(raw[:HEADER_SIZE]),
            records=records,
            version=raw[VERSION_OFFSET:VERSION_OFFSET + 16].split(b"\x00")[0].decode("latin1"),
            tail=tail,
            defaults=dict(defaults or {}),
        )
        image.identify()
        return image

    # ---------- saving ----------
    def refresh_header(self) -> None:
        """Keep the record-area length field in sync with the records."""
        body = sum(4 + len(rec.data) for rec in self.records)
        if body > 0xFFFF:
            raise SetupImageError(f"record area grew to {body:#x} bytes, container field is 16 bit")
        struct.pack_into("<H", self.header, FIELD_DATA_LENGTH, body)

    @property
    def declared_data_length(self) -> int:
        return struct.unpack_from("<H", self.header, FIELD_DATA_LENGTH)[0]

    def to_bytes(self) -> bytes:
        self.refresh_header()
        out = bytearray(self.header)
        for rec in self.records:
            out += struct.pack("<I", len(rec.data))
            out += rec.data
        out += self.tail
        return bytes(out)

    def save(self, path: str | Path | None = None) -> Path:
        destination = path or self.path
        if destination is None:
            raise SetupImageError("no destination path")
        target = Path(destination)
        target.write_bytes(self.to_bytes())
        self.path = target
        return target

    # ---------- identification ----------
    def identify(self) -> None:
        """Label records using the firmware defaults: identical bytes first, then length."""
        for rec in self.records:
            rec.name, rec.matched = "", ""
        taken: set[str] = set()
        for rec in self.records:
            for name, blob in self.defaults.items():
                if name in taken or len(blob) != rec.length:
                    continue
                if bytes(blob) == bytes(rec.data):
                    rec.name, rec.matched = name, "exact"
                    taken.add(name)
                    break
        for rec in self.records:
            if rec.name:
                continue
            for name, blob in self.defaults.items():
                if name in taken or len(blob) != rec.length:
                    continue
                rec.name, rec.matched = name, "size"
                taken.add(name)
                break
        aod_companions = {"AmdSetupRPL": "AodSetupRpl", "AmdSetupPHX": "AodSetupPhx",
                          "AmdSetupSTXKRK": "AodSetupStx"}
        for rec in self.records:
            if rec.name or rec.length != 0x320:
                continue
            for amd_name, aod_name in aod_companions.items():
                if amd_name in taken and aod_name not in taken:
                    rec.name, rec.matched = aod_name, "companion"
                    taken.add(aod_name)
                    break
        for rec in self.records:
            if not rec.name:
                rec.name = f"unknown{rec.index:02d}"

    # ---------- access ----------
    def varstores(self) -> list[Varstore]:
        return [Varstore(rec.name, rec, self.defaults.get(rec.name)) for rec in self.records if rec.length]

    def varstore(self, name: str) -> Varstore:
        for vs in self.varstores():
            if vs.name == name:
                return vs
        raise KeyError(f"varstore {name!r} not present in the image")

    def find_owner(self, name: str, offset: int, size: int) -> Varstore:
        vs = self.varstore(name)
        if offset + size > vs.size:
            raise SetupImageError(f"{name}+{offset:#x}+{size} exceeds store size {vs.size:#x}")
        return vs

    def summary(self) -> str:
        lines = [f"A86 setup image, version {self.version!r}, {len(self.records)} records"]
        for rec in self.records:
            dirty = ""
            default = self.defaults.get(rec.name)
            if default is not None and len(default) == rec.length:
                n = sum(1 for a, b in zip(rec.data, default) if a != b)
                dirty = f"  {n} byte(s) vs factory default" if n else "  identical to factory default"
            lines.append(f"  #{rec.index:02d} @{rec.offset:#06x} len={rec.length:#06x} {rec.name:<18s} [{rec.matched or 'unmatched'}]{dirty}")
        return "\n".join(lines)
