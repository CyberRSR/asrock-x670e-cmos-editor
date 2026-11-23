"""Section payload decompression: EDK2 LZMA and Brotli GUID-defined sections."""
from __future__ import annotations

import lzma
import struct
import uuid

LZMA_GUID = uuid.UUID("EE4E5898-3914-4259-9D6E-DC7BD79403CF")
BROTLI_GUID = uuid.UUID("3D532050-2C6A-4583-A2B3-7AD099A0A42E")


def lzma_alone_decompress(payload: bytes, max_out: int = 1 << 28) -> bytes:
    """Decode an LZMA_Alone stream (1 byte props + 4 byte dict + 8 byte size + data)."""
    if len(payload) < 14:
        raise lzma.LZMAError("payload shorter than an LZMA_Alone header")
    props = payload[0]
    if props >= 0xE1:
        raise lzma.LZMAError(f"invalid LZMA properties byte {props:#02x}")
    dict_size = struct.unpack_from("<I", payload, 1)[0]
    out_size = struct.unpack_from("<Q", payload, 5)[0]
    if dict_size == 0xFFFFFFFFFFFFFFFF or dict_size == 0 or dict_size > (1 << 28):
        raise lzma.LZMAError(f"implausible dictionary size {dict_size}")
    lc = props % 9
    remainder = props // 9
    pb = remainder // 5
    lp = remainder % 5
    if pb > 4 or lp > 4:
        raise lzma.LZMAError("invalid LZMA lc/lp/pb split")
    limit = min(out_size, max_out) if out_size not in (0, 0xFFFFFFFFFFFFFFFF) else max_out
    dec = lzma.LZMADecompressor(
        format=lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": lc, "lp": lp, "pb": pb}],
    )
    return dec.decompress(payload[13:], max_length=limit)


def brotli_decompress(payload: bytes) -> bytes:
    """Decode an EDK2 Brotli payload (UINT64 uncompressed size, then raw Brotli stream)."""
    try:
        import brotli  # type: ignore
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("pip install brotli to decode Brotli sections") from exc
    body = payload[8:] if len(payload) > 8 else payload
    return brotli.decompress(body)


def guid_defined_decompress(guid: uuid.UUID, payload: bytes) -> bytes:
    if guid == LZMA_GUID:
        return lzma_alone_decompress(payload)
    if guid == BROTLI_GUID:
        return brotli_decompress(payload)
    raise ValueError(f"unsupported GUID-defined section {guid}")
