"""AMI Aptio V default variable store (``NVAR`` records) found in the SPI image.

The X670E Taichi Carrara keeps factory defaults for every setup variable in one firmware
volume at 0x1BC0000.  The first record, ``StdDefaults``, wraps the rest, so a store is read as
the wrapper plus the chained records that follow it.
"""
from __future__ import annotations

from dataclasses import dataclass

NVAR_MAGIC = b"NVAR"


@dataclass
class NvarEntry:
    name: str
    offset: int
    size: int
    data_offset: int
    data: bytes
    header: bytes

    @property
    def is_wrapper(self) -> bool:
        return self.name == "StdDefaults"


def parse_store(image: bytes, start: int, end: int | None = None) -> list[NvarEntry]:
    """Walk a chain of NVAR records; stops at the first record that does not fit."""
    end = len(image) if end is None else end
    entries: list[NvarEntry] = []
    pos = start
    while pos + 12 <= end and image[pos:pos + 4] == NVAR_MAGIC:
        size = int.from_bytes(image[pos + 4:pos + 6], "little")
        if size < 12 or pos + size > end:
            break
        raw_name = image[pos + 11:pos + 11 + 32].split(b"\x00")[0]
        try:
            name = raw_name.decode("utf-8")
        except UnicodeDecodeError:
            break
        data_off = pos + 11 + len(raw_name) + 1
        if data_off > pos + size:
            break
        entries.append(NvarEntry(name, pos, size, data_off, image[data_off:pos + size], image[pos:pos + 11]))
        pos += size
    return entries


def find_store(image: bytes) -> int:
    """Offset of the record chain that holds the factory defaults."""
    best, best_count = -1, 0
    pos = image.find(NVAR_MAGIC)
    while pos >= 0:
        count = len(parse_store(image, pos))
        if count > best_count:
            best, best_count = pos, count
        pos = image.find(NVAR_MAGIC, pos + 4)
    if best_count < 2:
        raise ValueError("no NVAR record chain found in image")
    return best


def load_defaults(image: bytes) -> dict[str, bytes]:
    """Factory default payload of every setup variable in the image."""
    start = find_store(image)
    entries = parse_store(image, start)
    if not entries:
        raise ValueError("empty NVAR store")
    defaults = {e.name: e.data for e in entries if not e.is_wrapper}
    if len(entries) > 1 and entries[0].is_wrapper:
        for e in parse_store(image, entries[0].data_offset, entries[0].data_offset + len(entries[0].data)):
            defaults.setdefault(e.name, e.data)
    return defaults
