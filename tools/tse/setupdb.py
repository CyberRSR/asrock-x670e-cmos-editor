#!/usr/bin/env python3
"""Recover the AMI TSE setup database (menu schema) out of a decompressed Aptio V payload.

The ASRock X670E Taichi Carrara firmware ships no static HII form package: the setup menu is
built by AMI TSE out of one proprietary blob that holds three consecutive parts

    [ varstore descriptor table ][ IFR-like form opcode stream ][ HII string packages ]

which this module locates and decodes into a machine readable map
(offset in varstore -> prompt, type, options, visibility rules).

Usage::

    python tools/tse/setupdb.py out/payload/0x1118730_guid-section.bin -o out/settings_map.json
    python tools/tse/setupdb.py <payload> --rom X67ETCC4.43.ROM --validate 10
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
import uuid
from collections import defaultdict, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from uefi import nvarstore  # noqa: E402

# --------------------------------------------------------------------------- opcodes
OP_NAMES = {}
for _line in Path(__file__).with_name("ifr_opcodes.txt").read_text().splitlines():
    _n, _v = _line.split()
    OP_NAMES[int(_v, 16)] = _n

FORM_OP, SUBTITLE_OP, TEXT_OP = 0x01, 0x02, 0x03
ONE_OF_OP, CHECKBOX_OP, NUMERIC_OP, PASSWORD_OP = 0x05, 0x06, 0x07, 0x08
ONE_OF_OPTION_OP, SUPPRESS_IF_OP, ACTION_OP = 0x09, 0x0A, 0x0C
REF_OP, INCONSISTENT_IF_OP = 0x0F, 0x11
EQ_ID_VAL_OP, EQ_ID_ID_OP, EQ_ID_VAL_LIST_OP = 0x12, 0x13, 0x14
AND_OP, OR_OP, NOT_OP = 0x15, 0x16, 0x17
GRAY_OUT_IF_OP, DATE_OP, TIME_OP, STRING_OP = 0x19, 0x1A, 0x1B, 0x1C
DISABLE_IF_OP, VERSION_OP, END_OP = 0x1E, 0x28, 0x29
EQUAL_OP, NOT_EQUAL_OP = 0x2F, 0x30
UINT8_OP, UINT16_OP, UINT32_OP, UINT64_OP = 0x42, 0x43, 0x44, 0x45
TRUE_OP, FALSE_OP = 0x46, 0x47
QUESTION_REF1_OP, ZERO_OP, ONE_OP, ONES_OP = 0x40, 0x52, 0x53, 0x54
VALUE_OP, DEFAULT_OP, GUID_OP = 0x5A, 0x5B, 0x5F

QUESTIONS = {ONE_OF_OP: "one_of", CHECKBOX_OP: "checkbox", NUMERIC_OP: "numeric",
             PASSWORD_OP: "password", DATE_OP: "date", TIME_OP: "time", STRING_OP: "string"}
CONDITIONS = {SUPPRESS_IF_OP: "suppress_if", GRAY_OUT_IF_OP: "gray_out_if",
              DISABLE_IF_OP: "disable_if", INCONSISTENT_IF_OP: "inconsistent_if",
              0x10: "nosubmit_if", 0x63: "warning_if"}
# opcodes whose body is terminated by an EFI_IFR_END_OP in this database
SCOPE_OPS = {FORM_OP, SUBTITLE_OP, ONE_OF_OP, CHECKBOX_OP, NUMERIC_OP, PASSWORD_OP,
             DATE_OP, TIME_OP, STRING_OP} | set(CONDITIONS)
VALUE_WIDTHS = {0: 1, 1: 2, 2: 4, 3: 8}
READERS = {1: lambda d, o: d[o], 2: lambda d, o: struct.unpack_from("<H", d, o)[0],
           4: lambda d, o: struct.unpack_from("<I", d, o)[0],
           8: lambda d, o: struct.unpack_from("<Q", d, o)[0]}

# varstore descriptor tags seen in the table
VAR_TAG_SIMPLE = 0x24      # tag, attr, guid[16], varstore_id, size, name
VAR_TAG_EXTRA = 0x26       # tag, attr, varstore_id, guid[16], u32 flags, size, name


# --------------------------------------------------------------------------- strings
def parse_string_package(data: bytes, off: int) -> dict | None:
    """Decode an ``EFI_HII_STRING_PACKAGE_HDR`` plus its language block map."""
    if off + 0x34 > len(data) or data[off + 3] != 0x04:
        return None
    length = int.from_bytes(data[off:off + 3], "little")
    hdr_size, str_start = struct.unpack_from("<II", data, off + 4)
    if not (0x20 <= hdr_size <= 0x60) or str_start != hdr_size or length < hdr_size + 0x20:
        return None
    if off + length > len(data):
        return None
    end = off + hdr_size
    if data[end - 1] != 0:
        return None
    start = data.rfind(b"\x00", off + 0x10, end - 1) + 1
    try:
        lang = data[start:end - 1].decode("ascii")
    except UnicodeDecodeError:
        return None
    if not re.fullmatch(r"[A-Za-z]{2}(-[A-Za-z0-9]{2,4})*", lang):
        return None
    strings = _walk_string_blocks(data, off + str_start, off + length)
    if not strings:
        return None
    return {"offset": off, "length": length, "language": lang, "strings": strings}


def _walk_string_blocks(data: bytes, p: int, end: int) -> dict[int, str]:
    """Walk the HII string block stream of one language (``EFI_HII_SIBT_*``)."""
    strings: dict[int, str] = {}
    sid = 1

    def ucs2(p: int) -> tuple[str, int]:
        e = p
        while e + 1 < end and data[e:e + 2] != b"\x00\x00":
            e += 2
        return data[p:e].decode("utf-16-le", "replace"), e + 2

    def scsu(p: int) -> tuple[str, int]:
        e = data.index(b"\x00", p, end) if b"\x00" in data[p:end] else end
        return data[p:e].decode("latin-1"), e + 1

    while p < end:
        bt = data[p]
        p += 1
        if bt == 0x00:                                     # SIBT_END
            break
        if bt == 0x14:                                     # STRING_UCS2
            strings[sid], p = ucs2(p)
            sid += 1
        elif bt == 0x10:                                   # STRING_SCSU
            strings[sid], p = scsu(p)
            sid += 1
        elif bt == 0x16:                                   # STRINGS_UCS2
            n = struct.unpack_from("<H", data, p)[0]
            p += 2
            for _ in range(n):
                strings[sid], p = ucs2(p)
                sid += 1
        elif bt == 0x12:                                   # STRINGS_SCSU
            n = struct.unpack_from("<H", data, p)[0]
            p += 2
            for _ in range(n):
                strings[sid], p = scsu(p)
                sid += 1
        elif bt == 0x20:                                   # DUPLICATE
            src = struct.unpack_from("<H", data, p)[0]
            p += 2
            strings[sid] = strings.get(src, "")
            sid += 1
        elif bt == 0x21:                                   # SKIP2
            sid += struct.unpack_from("<H", data, p)[0]
            p += 2
        elif bt == 0x22:                                   # SKIP1
            sid += data[p]
            p += 1
        elif bt in (0x30, 0x31, 0x32, 0x40):               # EXT1 / EXT2 / EXT4 / FONT
            kind = {0x30: 1, 0x31: 2, 0x32: 4, 0x40: 2}[bt]
            size = int.from_bytes(data[p:p + kind], "little")
            p += kind + (size - kind if size >= kind else 0)
        else:
            break
    return strings


def find_string_packages(data: bytes, lo: int = 0, hi: int | None = None) -> list[dict]:
    """Every plausible string package in ``data[lo:hi]``."""
    hi = len(data) if hi is None else min(hi, len(data))
    out = []
    p = lo
    while p + 0x40 < hi:
        p = data.find(b"\x04", p, hi)
        if p < 0:
            break
        pkg = parse_string_package(data, p - 3)
        if pkg:
            out.append(pkg)
            p = pkg["offset"] + pkg["length"]
            continue
        p += 1
    return out


# --------------------------------------------------------------------------- varstores
def _name_at(data: bytes, p: int) -> tuple[str, int] | None:
    """``u16 size`` + NUL terminated printable name -> (name, offset after name)."""
    if p + 3 > len(data):
        return None
    size = struct.unpack_from("<H", data, p)[0]
    if not 1 <= size <= 0x4000:
        return None
    end = data.find(b"\x00", p + 2, p + 2 + 64)
    if end < 0 or end == p + 2:
        return None
    raw = data[p + 2:end]
    if not all(0x20 <= c < 0x7F for c in raw):
        return None
    return raw.decode("ascii"), size, end + 1


def _record_at(data: bytes, p: int) -> tuple[dict, int] | None:
    """One varstore descriptor ``[tag][attr][guid][id][size][name]``."""
    if p + 2 > len(data):
        return None
    tag, attr = data[p], data[p + 1]
    if tag == VAR_TAG_SIMPLE:
        guid = data[p + 2:p + 18]
        vid = struct.unpack_from("<H", data, p + 18)[0]
        got = _name_at(data, p + 20)
        tail = 20
    elif tag == VAR_TAG_EXTRA:
        vid = struct.unpack_from("<H", data, p + 2)[0]
        guid = data[p + 4:p + 20]
        got = _name_at(data, p + 24)
        tail = 24
    else:
        return None
    if not got:
        return None
    name, size, after = got
    rec = {"name": name, "size": size, "varstore_id": vid, "attr": attr,
           "tag": tag, "guid": str(uuid.UUID(bytes_le=guid)), "offset": p}
    return rec, after


def find_varstore_table(data: bytes, lo: int, hi: int) -> list[dict]:
    """Chained varstore descriptors that end just before ``hi``.

    Records carry no count or length, so the table is recovered by chaining: every candidate
    start is walked forward and the earliest one that reaches the end of the region wins.
    """
    starts = [p for p in range(lo, hi) if data[p] in (VAR_TAG_SIMPLE, VAR_TAG_EXTRA)
              and _record_at(data, p)]
    best: list[dict] = []
    for s in starts:
        recs, p = [], s
        while True:
            got = _record_at(data, p)
            if not got:
                break
            rec, p = got
            recs.append(rec)
            if p >= hi:
                break
        # the very last descriptor loses its tail to the opcode stream, so the chain only has to
        # come close to the end of the region
        if recs and (p == hi or (len(recs) >= 5 and p + 0x40 >= hi)) and len(recs) > len(best):
            best = recs
    return best


def table_selfcheck(data: bytes, recs: list[dict]) -> dict:
    """Byte +1 of every varstore descriptor is the descriptor's own length - prove it."""
    ok = bad = 0
    for a, b in zip(recs, recs[1:]):
        if data[a["offset"] + 1] == b["offset"] - a["offset"]:
            ok += 1
        else:
            bad += 1
    out: dict = {"records": len(recs), "len_byte_matches": ok, "len_byte_mismatches": bad}
    if recs:
        last = recs[-1]
        out["start"] = f"0x{recs[0]['offset']:x}"
        out["end"] = f"0x{last['offset'] + data[last['offset'] + 1]:x}"
    return out


# --------------------------------------------------------------------------- IFR stream
def walk_forms(data: bytes, start: int, end: int):
    """Decode the TSE form opcode stream; returns (forms, questions, goto list, notes).

    AMI closes the conditional wrappers with ``EFI_IFR_END_OP`` but mixes that with the standard
    "opcode opens a scope" convention, so nesting is not strictly LIFO here.  Items are therefore
    attributed to the most recent ``EFI_IFR_FORM_OP`` (forms are never nested in this database)
    and a condition stays pending until an item consumes it, which is what the observed
    ``SUPPRESS_IF <expr> <item> END`` pattern needs.
    """
    forms: dict[int, dict] = {}
    questions: list[dict] = []
    gotos: list[dict] = []
    notes: dict[str, int] = defaultdict(int)
    pending: list[dict] = []                    # open suppress/gray/disable wrappers
    cur_form: dict | None = None
    cur_q: dict | None = None
    p = start
    RD = READERS

    def cond_tokens() -> list | None:
        for c in reversed(pending):
            if not c["consumed"]:
                return c["tokens"]
        return None

    def take_conds() -> list[tuple[str, list]]:
        out = [(c["kind"], c["tokens"]) for c in pending]
        for c in pending:
            c["consumed"] = True
        return out

    def close_cond():
        """END closes the wrapper of the item that was just emitted.

        A stray END (AMI also terminates plain items with one) must not discard a condition that
        has not reached its item yet - the ``SUPPRESS_IF <expr> END <item>`` spelling is common.
        """
        for i in range(len(pending) - 1, -1, -1):
            if pending[i]["consumed"]:
                return pending.pop(i)
        notes["ignored_end"] += 1
        return None

    form_stack_len = 0
    while p + 2 <= end:
        op = data[p]
        ln = data[p + 1] & 0x7F
        if ln < 2 or op not in OP_NAMES:
            break
        b = p + 2
        if op == FORM_OP:
            pending.clear()
            cur_q = None
            fid, title = struct.unpack_from("<HH", data, b)
            cur_form = {"id": fid, "title_id": title, "offset": p, "gotos": [],
                        "items": [], "texts": [], "actions": []}
            forms.setdefault(fid, cur_form)
            form_stack_len += 1
        elif op == END_OP:
            close_cond()
        elif op in CONDITIONS:
            pending.append({"kind": CONDITIONS[op], "tokens": [], "consumed": False,
                            "offset": p})
        elif op in QUESTIONS:
            prompt, help_, qid, vs, off = struct.unpack_from("<HHHHH", data, b)
            width = VALUE_WIDTHS.get(data[b + 11] & 3, 1)
            q = {"type": QUESTIONS[op], "offset": p, "prompt_id": prompt, "help_id": help_,
                 "qid": qid, "varstore_id": vs, "var_offset": off, "size": width,
                 "flags": data[b + 10], "width_flags": data[b + 11],
                 "options": [], "defaults": [], "conditions": take_conds(),
                 "form": cur_form["id"] if cur_form else None, "opcode": op, "length": ln}
            if op in (ONE_OF_OP, NUMERIC_OP) and b + 12 + 3 * width <= p + ln:
                rd = RD[width]
                q["min"] = rd(data, b + 12)
                q["max"] = rd(data, b + 12 + width)
                q["step"] = rd(data, b + 12 + 2 * width)
                if op == NUMERIC_OP and q["min"] > q["max"]:
                    # two's complement bounds (e.g. Offset Voltage(mV) fffc..01f4 = -100..500)
                    sgn = struct.Struct({1: "<b", 2: "<h", 4: "<i", 8: "<q"}[width])
                    q["min"] = sgn.unpack_from(data, b + 12)[0]
                    q["max"] = sgn.unpack_from(data, b + 12 + width)[0]
                    if q["min"] <= q["max"]:
                        q["signed"] = True
                    else:                                   # not signed after all - keep unsigned
                        q["min"] = rd(data, b + 12)
                        q["max"] = rd(data, b + 12 + width)
            if op == PASSWORD_OP and b + 13 < p + ln:
                q["min"], q["max"] = data[b + 12], data[b + 13]
                q["size"] = None
            questions.append(q)
            cur_q = q
            if cur_form is not None:
                cur_form["items"].append(q)
        elif op == ONE_OF_OPTION_OP:
            text, flags = struct.unpack_from("<HH", data, b)
            w = cur_q["size"] if cur_q and cur_q["size"] else 1
            cur_q["options"].append({"text_id": text, "value": RD.get(w, RD[1])(data, b + 4),
                                     "flags": flags})
        elif op == DEFAULT_OP:
            # EFI_IFR_DEFAULT: u16 DefaultId, u8 Type (same 0/1/2/3 -> 1/2/4/8 byte code as the
            # width nibble of the question), then the value.  Length is always 5 + width, which is
            # what proves the layout (231/59/6 records with width 1/2/4).
            if cur_q is None:
                notes["default_without_question"] += 1
            else:
                did, dtype = struct.unpack_from("<HB", data, b)
                w = VALUE_WIDTHS.get(dtype & 3, cur_q["size"] or 1)
                cur_q["defaults"].append({"id": did, "type": dtype,
                                          "value": RD.get(w, RD[1])(data, b + 3),
                                          "offset": p})
        elif op == REF_OP:
            prompt, help_, qid, vs, off = struct.unpack_from("<HHHHH", data, b)
            tgt = struct.unpack_from("<H", data, b + 11)[0]
            ref = {"kind": "goto", "offset": p, "prompt_id": prompt, "help_id": help_,
                   "qid": qid, "target_form": tgt,
                   "target_guid": None, "conditions": take_conds(),
                   "form": cur_form["id"] if cur_form else None}
            if ln >= 33:
                ref["target_guid"] = str(uuid.UUID(bytes_le=data[b + 15:b + 31]))
            if cur_form is not None and tgt == cur_form["id"]:
                # "Save Changes and Exit" & friends: a REF that points at its own form is a
                # push-button action, not a submenu link.
                ref["kind"] = "action"
                cur_form["actions"].append(ref)
            elif cur_form is not None:
                cur_form["gotos"].append(ref)
            gotos.append(ref)
        elif op in (SUBTITLE_OP, TEXT_OP):
            prompt, help_ = struct.unpack_from("<HH", data, b)
            if cur_form is not None:
                cur_form["texts"].append(
                    {"kind": "subtitle" if op == SUBTITLE_OP else "text",
                     "offset": p, "prompt_id": prompt, "help_id": help_,
                     "conditions": take_conds()})
            else:
                take_conds()
        elif op == ACTION_OP:
            prompt, help_, qid = struct.unpack_from("<HHH", data, b)
            act = {"kind": "action", "offset": p, "prompt_id": prompt, "help_id": help_,
                   "qid": qid, "target_form": None, "target_guid": None,
                   "conditions": take_conds(), "form": cur_form["id"] if cur_form else None}
            if cur_form is not None:
                cur_form["actions"].append(act)
            gotos.append(act)
        elif op == EQ_ID_VAL_OP:
            qid, val = struct.unpack_from("<HH", data, b)
            c = cond_tokens()
            if c is not None:
                c.append(("eq", qid, val))
        elif op == EQ_ID_ID_OP:
            a, bqv = struct.unpack_from("<HH", data, b)
            c = cond_tokens()
            if c is not None:
                c.append(("eq_qid", a, bqv))
        elif op == EQ_ID_VAL_LIST_OP:
            qid, n = struct.unpack_from("<HH", data, b)
            vals = [struct.unpack_from("<H", data, b + 4 + 2 * i)[0] for i in range(n)]                 if b + 4 + 2 * n <= p + ln else []
            c = cond_tokens()
            if c is not None:
                c.append(("in", qid, vals))
        elif op in (AND_OP, OR_OP, NOT_OP, EQUAL_OP, NOT_EQUAL_OP, TRUE_OP, FALSE_OP,
                    ZERO_OP, ONE_OP, ONES_OP):
            c = cond_tokens()
            if c is not None:
                c.append((OP_NAMES[op].replace("EFI_IFR_", "").replace("_OP", "").lower(),))
        elif op in (UINT8_OP, UINT16_OP, UINT32_OP, UINT64_OP):
            w = VALUE_WIDTHS[{UINT8_OP: 0, UINT16_OP: 1, UINT32_OP: 2, UINT64_OP: 3}[op]]
            c = cond_tokens()
            if c is not None:
                c.append(("num", RD[w](data, b)))
        elif op == QUESTION_REF1_OP:
            c = cond_tokens()
            if c is not None:
                c.append(("qref", struct.unpack_from("<H", data, b)[0]))
        elif op in (VERSION_OP, GUID_OP):
            notes[OP_NAMES[op].lower()] += 1
        else:
            notes[f"unhandled_{op:#02x}"] += 1
        p += ln
    notes["open_conditions_at_end"] = len(pending)
    return forms, questions, gotos, dict(notes)


def probe_forms(data: bytes, start: int, limit: int = 0x400000) -> tuple[int, int, int]:
    """Walk the opcode stream at ``start``; return (end, forms, questions)."""
    p, nf, nq = start, 0, 0
    while p + 2 <= min(len(data), start + limit):
        op = data[p]
        ln = data[p + 1] & 0x7F
        if ln < 2 or op not in OP_NAMES:
            break
        if op == FORM_OP:
            nf += 1
        elif op in QUESTIONS:
            nq += 1
        p += ln
    return p, nf, nq


def find_form_blobs(data: bytes) -> list[dict]:
    """Maximal IFR-like opcode runs anchored on a FORM opcode."""
    blobs: list[dict] = []
    covered = 0
    for m in re.finditer(bytes([FORM_OP, 0x86]), data):
        if m.start() < covered:
            continue
        end, nf, nq = probe_forms(data, m.start())
        if nf >= 5 and nq >= 20 and end - m.start() >= 0x400:
            blobs.append({"start": m.start(), "end": end, "forms": nf, "questions": nq})
            covered = end
    return blobs


# --------------------------------------------------------------------------- assembly
def human_condition(tokens: list, names: dict[int, str]) -> str:
    """Render a condition token list (Polish notation) into readable text."""
    def qname(qid: int) -> str:
        return names.get(qid, f"Q{qid:#x}")

    out = []
    for t in tokens:
        if t[0] == "eq":
            out.append(f"[{qname(t[1])}]={t[2]:#x}")
        elif t[0] == "in":
            out.append(f"[{qname(t[1])}] in ({', '.join(hex(v) for v in t[2])})")
        elif t[0] == "eq_qid":
            out.append(f"[{qname(t[1])}]==[{qname(t[2])}]")
        elif t[0] == "num":
            out.append(hex(t[1]))
        elif t[0] == "qref":
            out.append(f"[{qname(t[1])}]")
        else:
            out.append({"and": "AND", "or": "OR", "not": "NOT", "equal": "==",
                        "not_equal": "!=", "true": "TRUE", "false": "FALSE",
                        "zero": "0", "one": "1", "ones": "-1"}.get(t[0], t[0].upper()))
    return " ".join(out)


def conds_dict(conds: list[tuple[str, list]], names: dict[int, str]) -> dict[str, str]:
    """Render the pending condition wrappers of an item into ``{kind: human readable text}``."""
    out: dict[str, str] = {}
    for kind, toks in conds:
        if toks:
            txt = human_condition(toks, names)
            out[kind] = out[kind] + " ; " + txt if kind in out else txt
    return out


def build_paths(forms: dict[int, dict], strings: dict[int, str]) -> dict[int, list[str]]:
    """Breadth first walk over goto (REF) opcodes -> breadcrumb for every reachable form."""
    def text(sid: int) -> str:
        return strings.get(sid, "").strip()

    root = None
    for f in forms.values():
        if text(f["title_id"]).lower() in ("setup", "startup setup utility"):
            root = f["id"]
            break
    if root is None:
        root = min(forms) if forms else None
    paths: dict[int, list[str]] = {}
    if root is None:
        return paths
    paths[root] = [text(forms[root]["title_id"]) or f"form {root:#x}"]
    dq = deque([root])
    while dq:
        fid = dq.popleft()
        for ref in forms[fid]["gotos"]:
            to = ref["target_form"]
            if to not in forms:
                continue
            label = text(ref["prompt_id"]) or text(forms[to]["title_id"]) or f"form {to:#x}"
            if to not in paths or (paths[to][0].startswith("form ") and not label.startswith("form ")):
                paths[to] = paths[fid] + [label]
                dq.append(to)
    return paths


def clean_text(text: str) -> str:
    """Strip the AMI TSE terminal directives embedded in the string pool.

    The pool stores prompts with colour/format directives, e.g. the raw bytes of the tCL prompt are
    ``1b 7b 61 31 23 "CAS# Latency (tCL)" 1b 7b 70 32 30 30 23 1b 5b 31 3b 33 37 3b 6d 25 64 1b 5b
    3b 3b 6d`` - ``ESC { <fmt> #`` opens a format field and ``ESC [ <n> ; <n> ; m`` is an ANSI SGR
    sequence.  Only those two forms occur in this image (131 + 100 of them).
    """
    if "\x1b" not in text:
        return text.strip()
    text = re.sub(r"\x1b\{[^#\n]*#?", "", text)
    text = re.sub(r"\x1b\[[0-9;]*m?", "", text)
    text = text.replace("\x1b", "")
    if text.endswith("%d"):                  # AMI appends the value placeholder to the prompt
        text = text[:-2]
    return re.sub(r"[ \t]+", " ", text).strip()


def build_formset_map(data: bytes, start: int, end: int, en: dict, table: list[dict],
                      guid_names: dict[str, str] | None = None) -> dict:
    pkgs = find_string_packages(data)
    forms, questions, gotos, notes = walk_forms(data, start, end)
    strings = {k: clean_text(v) for k, v in en["strings"].items()}
    paths = build_paths(forms, strings)
    by_vid = {r["varstore_id"]: r for r in table}
    tail = _tail_name(data, start)

    names: dict[int, str] = {}
    for q in questions:
        t = strings.get(q["prompt_id"], "").strip()
        if t and q["qid"] not in names:
            names[q["qid"]] = t

    def vs_name(vid: int) -> str:
        r = by_vid.get(vid)
        return r["name"] if r else (f"varstore_{vid:#06x}" if vid else "")

    items = []
    for q in questions:
        path = paths.get(q["form"]) or [f"(unreachable form {q['form']:#x})" if q["form"] else "?"]
        prompt = strings.get(q["prompt_id"], "").strip()
        rec = {
            "path": " > ".join(path + ([prompt] if prompt else [])),
            "menu": " > ".join(path),
            "name": prompt,
            "form": f"0x{q['form']:04x}" if q["form"] is not None else None,
            "varstore": vs_name(q["varstore_id"]),
            "varstore_id": f"0x{q['varstore_id']:04x}",
            "offset": q["var_offset"],
            "size": q["size"],
            "type": q["type"],
            "qid": f"0x{q['qid']:04x}",
            "help": strings.get(q["help_id"], "").strip(),
            "options": [{"value": o["value"], "text": strings.get(o["text_id"], "").strip(),
                         "flags": f"0x{o['flags']:04x}",
                         **({"is_default": True} if o["flags"] & 0x10 else {})}
                        for o in q["options"]],
        }
        for k in ("min", "max", "step"):
            if k in q:
                rec[k] = q[k]
        if q["flags"]:
            rec["flags"] = f"0x{q['flags']:02x}"
            if q["flags"] & 0x10:
                rec["reset_required"] = True
        if q.get("signed"):
            rec["signed"] = True            # numeric bounds stored two's complement
        if q["defaults"]:
            rec["defaults"] = [{"id": d["id"], "value": d["value"]} for d in q["defaults"]]
            std = [d for d in q["defaults"] if d["id"] == 0]
            if std:
                rec["default"] = std[0]["value"]
        if "default" not in rec:
            dfl = [o for o in q["options"] if o["flags"] & 0x10]     # EFI_IFR_OPTION_DEFAULT
            if dfl:
                rec["default"] = dfl[0]["value"]
                rec["default_source"] = "one_of_option_flag"
        conds = conds_dict(q["conditions"], names)
        if conds:
            rec["rules"] = conds
        rec["ifr_offset"] = f"0x{q['offset']:x}"
        items.append(rec)

    out_forms = []
    for fid in sorted(forms):
        f = forms[fid]
        out_forms.append({"id": f"0x{fid:04x}", "title": strings.get(f["title_id"], "").strip(),
                          "path": " > ".join(paths.get(fid, [])),
                          "questions": len(f["items"]), "submenus": len(f["gotos"]),
                          "buttons": len(f["actions"]),
                          "reachable": fid in paths, "ifr_offset": f"0x{f['offset']:x}"})

    gotos_out = []
    for ref in gotos:
        entry = {"kind": ref["kind"],
                 "form": f"0x{ref['form']:04x}" if ref["form"] is not None else None,
                 "label": strings.get(ref["prompt_id"], "").strip(),
                 "target_form": f"0x{ref['target_form']:04x}" if ref["target_form"] is not None else None,
                 "target_guid": ref["target_guid"], "qid": f"0x{ref['qid']:04x}",
                 "cross_formset": ref["target_guid"] is not None,
                 "ifr_offset": f"0x{ref['offset']:x}"}
        rules = conds_dict(ref["conditions"], names)
        if rules:
            entry["rules"] = rules
        gotos_out.append(entry)

    varstores = []
    used = defaultdict(lambda: [0, 0])
    for q in questions:
        u = used[q["varstore_id"]]
        u[0] += 1
        u[1] = max(u[1], q["var_offset"] + (q["size"] or 0))
    for r in sorted(table, key=lambda r: r["varstore_id"]):
        varstores.append({"name": r["name"], "size": r["size"], "guid": r["guid"],
                          "guid_name": (guid_names or {}).get(r["guid"], ""),
                          "id": f"0x{r['varstore_id']:04x}",
                          "questions": used[r["varstore_id"]][0],
                          "max_offset_used": used[r["varstore_id"]][1],
                          "db_offset": f"0x{r['offset']:x}"})

    # the string pool of this database: the en-US package plus every package chained right behind it
    pool, pos, seen = [en], en["offset"] + en["length"], {en["offset"]}
    while True:
        nxt = next((q for q in pkgs if q["offset"] == pos), None)
        if nxt is None or nxt["offset"] in seen:
            break
        pool.append(nxt)
        seen.add(nxt["offset"])
        pos = nxt["offset"] + nxt["length"]

    return {
        "meta": {
            "source": None,
            "ifr": {"offset": f"0x{start:x}", "end": f"0x{end:x}", "length": end - start},
            "string_package": {"offset": f"0x{en['offset']:x}", "length": en["length"],
                               "language": en["language"], "strings": len(en["strings"])},
            "languages": [{"language": q["language"], "offset": f"0x{q['offset']:x}",
                           "length": q["length"], "strings": len(q["strings"])} for q in pool],
            "notes": notes,
            "varstore_table": table_selfcheck(data, table),
            "text_cleaning": ("ESC '{' <fmt> '#' and ANSI 'ESC [' … 'm' directives removed from the "
                              "string pool, trailing '%d' value placeholder dropped"),
            "table_tail_names": [tail] if tail else [],
        },
        "varstores": varstores,
        "counts": {
            "varstores": len(varstores), "forms": len(out_forms),
            "reachable_forms": sum(1 for f in out_forms if f["reachable"]),
            "items": len(items), "items_with_options": sum(1 for i in items if i["options"]),
            "options": sum(len(i["options"]) for i in items),
            "goto_links": sum(1 for g in gotos_out if g["kind"] == "goto"),
            "buttons": sum(1 for g in gotos_out if g["kind"] == "action"),
            "items_with_rules": sum(1 for i in items if "rules" in i),
            "items_with_dynamic_options": sum(
                1 for i in items
                if i["options"] and not any(o["text"] for o in i["options"])),
            "items_with_rom_default": sum(1 for i in items if "rom_default" in i),
        },
        "forms": out_forms,
        "gotos": gotos_out,
        "items": items,
    }


def formset_candidates(data: bytes) -> list[dict]:
    pkgs = [p for p in find_string_packages(data) if p["language"].lower() == "en-us"]
    candidates = []
    for blob in find_form_blobs(data):
        start = blob["start"]
        nearby = [p for p in pkgs if abs(p["offset"] - start) < 0x100000]
        if not nearby:
            continue
        en = min(nearby, key=lambda p: abs(p["offset"] - start))
        end = min(blob["end"], en["offset"]) if en["offset"] > start else blob["end"]
        table = find_varstore_table(data, max(0, start - 0x2000), start)
        candidates.append({"start": start, "end": end, "pkg": en, "table": table,
                           "score": blob["questions"] + 1000 * len(table)})
    return candidates


def build_map(data: bytes, guid_names: dict[str, str] | None = None) -> dict:
    candidates = formset_candidates(data)
    if not candidates:
        raise SystemExit("no form stream with a matching en-US string package found")
    best = max(candidates, key=lambda c: c["score"])
    return build_formset_map(data, best["start"], best["end"], best["pkg"], best["table"], guid_names)


def build_all_maps(data: bytes, guid_names: dict[str, str] | None = None) -> dict:
    candidates = formset_candidates(data)
    if not candidates:
        raise SystemExit("no form stream with a matching en-US string package found")
    maps = [build_formset_map(data, c["start"], c["end"], c["pkg"], c["table"], guid_names)
            for c in candidates]
    if len(maps) == 1:
        return maps[0]
    combined = {"meta": {"formsets": []}, "varstores": [], "forms": [], "gotos": [], "items": [],
                "counts": defaultdict(int)}
    for mapping in maps:
        stores = [v["name"] for v in mapping["varstores"]]
        roots = [f["title"] for f in mapping["forms"]
                 if f["reachable"] and f["path"] and " > " not in f["path"]]
        root = roots[0] if roots else "HII formset"
        label = f"{root} ({', '.join(stores)})" if len(stores) == 1 else root
        mapping["meta"]["formset"] = label
        combined["meta"]["formsets"].append(mapping["meta"])
        for section in ("varstores", "forms", "gotos", "items"):
            for entry in mapping[section]:
                entry["formset"] = label
            combined[section].extend(mapping[section])
        for key, value in mapping["counts"].items():
            combined["counts"][key] += value
    combined["counts"] = dict(combined["counts"])
    combined["meta"]["string_package"] = maps[0]["meta"]["string_package"]
    combined["meta"]["ifr"] = maps[0]["meta"]["ifr"]
    combined["meta"]["languages"] = [lang for m in maps for lang in m["meta"]["languages"]]
    combined["meta"]["notes"] = {}
    return combined


def _tail_name(data: bytes, start: int) -> str | None:
    """Name of the last descriptor whose attribute tail is cut off by the form stream."""
    end = start - 1
    if end <= 0 or data[end] != 0:
        return None
    p = end - 1
    while p > 0 and 0x20 <= data[p] < 0x7F:
        p -= 1
    name = data[p + 1:end]
    if not 1 <= len(name) <= 48 or p < 2:
        return None
    if not (1 <= struct.unpack_from("<H", data, p - 2)[0] <= 0x4000):
        return None
    return name.decode("ascii", "replace")


# --------------------------------------------------------------------------- validation
def validate(mapping: dict, defaults: dict[str, bytes], count: int = 10) -> list[str]:
    """Decode values out of the factory defaults, spread over the varstores (proof rows)."""
    cand: dict[tuple, str] = {}
    for it in mapping["items"]:
        blob = defaults.get(it["varstore"])
        if blob is None or it["type"] == "password" or not it["name"]:
            continue
        off, size = it["offset"], it["size"]
        if size is None or off + size > len(blob):
            continue
        value = int.from_bytes(blob[off:off + size], "little")
        text = next((o["text"] for o in it["options"] if o["value"] == value), "")
        if it["type"] == "checkbox":
            text = "Enabled" if value else "Disabled"
        line = (f"{it['varstore']}+{off:#05x} ({size}B) = {value:#0{2 * size + 2}x} "
                f"{value:<6} {it['type']:8s} {it['name'][:38]:38s} -> {text}")
        key = (it["varstore"], off, size)
        if key not in cand or (text and not cand[key].split(" -> ")[-1]):
            cand[key] = line
    order: dict[str, list[str]] = defaultdict(list)
    for key, line in cand.items():
        order[key[0]].append(line)
    lines: list[str] = []
    rnd = 0
    while len(lines) < count and any(rnd < len(v) for v in order.values()):
        for name in sorted(order):
            if rnd < len(order[name]) and len(lines) < count:
                lines.append(order[name][rnd])
        rnd += 1
    return sorted(lines)


def check_offsets(mapping: dict) -> list[str]:
    """Report items whose [offset, offset+size) escapes the varstore size from the table."""
    bad = []
    by_name = {v["name"]: v for v in mapping["varstores"]}
    for it in mapping["items"]:
        v = by_name.get(it["varstore"])
        if not v or it["size"] is None:
            continue
        if it["offset"] + it["size"] > v["size"]:
            bad.append(f"{it['path']}: {it['offset']:#x}+{it['size']} > {it['varstore']} "
                       f"{v['size']} bytes (id {it['varstore_id']})")
    return bad


def load_guid_names(path: Path) -> dict[str, str]:
    out = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="latin-1").splitlines():
        parts = line.split(",", 1)
        if len(parts) == 2 and len(parts[0]) == 36:
            out[parts[0].strip().upper()] = parts[1].strip()
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("payload", type=Path)
    ap.add_argument("-o", "--output", type=Path, default=Path("out/settings_map.json"))
    ap.add_argument("--rom", type=Path, help="SPI image used for the factory default values")
    ap.add_argument("--main-only", action="store_true", help="decode only the largest formset")
    ap.add_argument("--guids", type=Path, default=Path("out/guids.csv"))
    ap.add_argument("--validate", type=int, default=5, metavar="N")
    args = ap.parse_args(argv)

    data = args.payload.read_bytes()
    guid_names = load_guid_names(args.guids)
    mapping = build_map(data, guid_names) if args.main_only else build_all_maps(data, guid_names)
    mapping["meta"]["source"] = str(args.payload)

    bad = check_offsets(mapping)
    n_def = 0
    if args.rom and args.rom.exists():
        defaults = nvarstore.load_defaults(args.rom.read_bytes())
        for it in mapping["items"]:
            blob = defaults.get(it["varstore"])
            if blob and it["size"] and it["offset"] + it["size"] <= len(blob):
                raw = blob[it["offset"]:it["offset"] + it["size"]]
                value = int.from_bytes(raw, "little")
                if it.get("signed") and value >= 1 << (8 * it["size"] - 1):
                    value -= 1 << (8 * it["size"])
                it["rom_default"] = value
                n_def += 1
        mapping["counts"]["items_with_rom_default"] = n_def
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(mapping, indent=1, ensure_ascii=False), encoding="utf-8")

    en = mapping["meta"]["string_package"]
    print(f"form stream   : {mapping['meta']['ifr']['offset']} .. {mapping['meta']['ifr']['end']}"
          f" ({mapping['meta']['ifr']['length']:#x} bytes)")
    print(f"strings       : {en['language']} @ {en['offset']} ({en['strings']} ids)")
    print(f"languages     : {', '.join(l['language'] for l in mapping['meta']['languages'])}")
    print(f"varstores     : {len(mapping['varstores'])}")
    print(f"forms         : {len(mapping['forms'])} "
          f"({sum(1 for f in mapping['forms'] if f['reachable'])} reachable)")
    print(f"items         : {len(mapping['items'])}, gotos {len(mapping['gotos'])}")
    print(f"rules         : {sum(1 for i in mapping['items'] if 'rules' in i)} items carry "
          f"suppress/gray-out conditions")
    print(f"rom defaults  : decoded for {n_def} items")
    print(f"offset errors : {len(bad)}")
    print(f"walk notes    : {mapping['meta']['notes']}")
    for b in bad[:10]:
        print("   ", b)
    if args.rom and args.validate:
        defaults = nvarstore.load_defaults(args.rom.read_bytes())
        print(f"\nvalidation against factory defaults ({args.validate} rows):")
        for line in validate(mapping, defaults, args.validate):
            print("   ", line)
    print(f"\nwrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
