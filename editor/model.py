"""Document model behind the CMOS settings editor: firmware defaults, the dumped A86 image and
the setting map extracted from the firmware, plus value encoding for every question type."""
from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from uefi.nvarstore import load_defaults          # noqa: E402
from uefi.setupimg import SetupImage, SetupImageError  # noqa: E402

DEFAULT_SCHEMA = ROOT / "out" / "settings_map.json"

CHECKBOX_OFF = ("Disabled", "Off", "No", "0")
CHECKBOX_ON = ("Enabled", "On", "Yes", "1")


@dataclass(frozen=True)
class Option:
    value: int
    text: str


@dataclass
class Item:
    """One editable setting: where it lives and how to present it."""

    path: tuple[str, ...]
    varstore: str
    offset: int
    size: int = 1
    kind: str = "raw"                     # one_of | checkbox | numeric | text | raw
    options: list[Option] = field(default_factory=list)
    minimum: int | None = None
    maximum: int | None = None
    step: int = 1
    qid: int | None = None
    help: str = ""
    default: int | None = None
    signed: bool = False
    read_only: bool = False
    dynamic: bool = False
    formset: str = ""

    @property
    def title(self) -> str:
        return self.path[-1] if self.path else f"{self.varstore}+{self.offset:#x}"

    @property
    def location(self) -> str:
        return f"{self.varstore}+{self.offset:#05x}"

    @property
    def menu(self) -> str:
        return " > ".join(self.path[:-1])


def _as_int(value, default=None) -> int | None:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return default
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text, 0)
    except ValueError:
        return default


def _normalise_options(raw) -> tuple[str, list[Option], int | None, int | None]:
    """Return (kind, options, minimum, maximum) from the loosely typed map entry."""
    options: list[Option] = []
    for entry in raw or []:
        if isinstance(entry, dict):
            value = _as_int(entry.get("value", entry.get("val")))
            text = str(entry.get("text", entry.get("label", entry.get("name", "")))).strip()
        else:                                    # ["value", "text"] or bare value
            value = _as_int(entry[0] if isinstance(entry, (list, tuple)) else entry)
            text = str(entry[1]).strip() if isinstance(entry, (list, tuple)) and len(entry) > 1 else ""
        if value is None:
            continue
        options.append(Option(value, text or f"{value:#x}"))
    return ("one_of" if len(options) > 1 else "raw"), options, None, None


def item_from_dict(entry: dict, index: int) -> Item | None:
    varstore = str(entry.get("varstore") or entry.get("store") or "").strip()
    offset = _as_int(entry.get("offset", entry.get("address")))
    if not varstore or offset is None:
        return None
    path_value = entry.get("path") or entry.get("menu") or entry.get("title") or f"item{index:04d}"
    if isinstance(path_value, str):
        path = tuple(part.strip() for part in path_value.replace("\\", ">").split(">") if part.strip())
    else:
        path = tuple(str(part).strip() for part in path_value if str(part).strip())
    size = _as_int(entry.get("size", entry.get("width", entry.get("length"))), 1) or 1
    kind = str(entry.get("type") or entry.get("kind") or "").lower().replace("-", "_").replace(" ", "_")

    raw_options = entry.get("options") or entry.get("values") or entry.get("choices")
    dynamic = bool(raw_options) and all(isinstance(o, dict) for o in raw_options) and not any(
        str(o.get("text", o.get("label", o.get("name", "")))).strip() for o in raw_options)
    options: list[Option] = []
    minimum = _as_int(entry.get("min", entry.get("minimum")))
    maximum = _as_int(entry.get("max", entry.get("maximum")))
    if raw_options:
        kind_from_options, options, _, _ = _normalise_options(raw_options)
        if not kind:
            kind = kind_from_options
    if not kind:
        if options:
            kind = "one_of"
        elif minimum is not None or maximum is not None:
            kind = "numeric"
        elif size == 1:
            kind = "byte"
        else:
            kind = "raw"
    if kind == "password" and entry.get("size") is None and maximum is not None:
        size = 2 * maximum
    signed = bool(entry.get("signed"))
    default = _as_int(entry.get("default"))
    if signed and default is not None and default >= 1 << (8 * size - 1):
        default -= 1 << (8 * size)
    item = Item(
        path=path or (f"item{index:04d}",),
        varstore=varstore,
        offset=offset,
        size=size,
        kind=kind,
        options=options,
        minimum=minimum,
        maximum=maximum,
        step=_as_int(entry.get("step"), 1) or 1,
        qid=_as_int(entry.get("qid", entry.get("question_id"))),
        help=str(entry.get("help") or entry.get("description") or ""),
        default=default,
        signed=signed,
        read_only=bool(entry.get("read_only")) or kind in ("date", "time"),
        dynamic=dynamic,
        formset=str(entry.get("formset") or ""),
    )
    if item.formset and item.path[0] != item.formset:
        item.path = (item.formset,) + item.path[1:]
    return item


class Document:
    """Everything the editor needs: the image being edited, its factory defaults and the map."""

    def __init__(self, dump_path: Path, rom_path: Path | None, schema_path: Path | None = None):
        self.dump_path = Path(dump_path)
        self.rom_path = Path(rom_path) if rom_path else None
        self.schema_path = Path(schema_path) if schema_path else (DEFAULT_SCHEMA if DEFAULT_SCHEMA.exists() else None)
        self.defaults: dict[str, bytes] = {}
        self.load_error: str = ""
        if self.rom_path and self.rom_path.exists():
            try:
                self.defaults = load_defaults(self.rom_path.read_bytes())
            except Exception as exc:                       # keep editing possible without the ROM
                self.load_error = f"firmware defaults unavailable: {type(exc).__name__}: {exc}"
        self.image = SetupImage.load(self.dump_path, self.defaults)
        self.items: list[Item] = []
        self.missing_items: list[Item] = []
        self.schema_error = ""
        self._load_schema()

    # ---------- schema ----------
    def _load_schema(self) -> None:
        if not self.schema_path or not self.schema_path.exists():
            self.schema_error = "no settings map found - run tools/tse/setupdb.py or open a map file"
            return
        try:
            data = json.loads(self.schema_path.read_text(encoding="utf-8"))
        except Exception as exc:
            self.schema_error = f"{type(exc).__name__}: {exc}"
            return
        entries = data.get("items") if isinstance(data, dict) else data
        if not isinstance(entries, list):
            self.schema_error = "settings map has no 'items' list"
            return
        available = {vs.name: vs for vs in self.image.varstores()}
        items: list[Item] = []
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict) or ("name" in entry and not str(entry.get("name") or "").strip()):
                continue
            item = item_from_dict(entry, index)
            if item is None:
                continue
            store = available.get(item.varstore)
            if store is None or item.offset + max(1, item.size) > store.size:
                self.missing_items.append(item)
                continue
            items.append(item)
        items.sort(key=lambda it: it.path)
        unique = {}
        for item in items:
            key = (item.varstore, item.offset, item.size, item.title, item.kind,
                   tuple((o.value, o.text) for o in item.options), item.minimum, item.maximum,
                   item.step, item.signed)
            unique.setdefault(key, item)
        self.items = list(unique.values())

    # ---------- values ----------
    def store(self, item: Item):
        return self.image.varstore(item.varstore)

    def raw_value(self, item: Item) -> int | bytes:
        store = self.store(item)
        data = store.read(item.offset, max(1, item.size))
        if item.kind in ("text", "password"):
            return data
        value = int.from_bytes(data, "little")
        if item.signed and value >= 1 << (8 * item.size - 1):
            value -= 1 << (8 * item.size)
        return value

    def option_label(self, item: Item, option: Option) -> str:
        if sum(o.text == option.text for o in self.options_for(item)) > 1:
            return f"{option.text} ({option.value:#x})"
        return option.text

    def value_text(self, item: Item) -> str:
        value = self.raw_value(item)
        if item.kind == "password":
            return value.hex() if any(value) else ""
        if item.kind == "text":
            try:
                return value.decode("utf-16-le", "replace").strip("\x00") or repr(value)
            except AttributeError:
                return repr(value)
        if item.kind in ("one_of", "checkbox"):
            for option in self.options_for(item):
                if option.value == value:
                    return self.option_label(item, option)
            return f"{value:#x} ({value})"
        if item.kind == "numeric":
            return str(value)
        return f"0x{value:0{2 * max(1, item.size)}x} ({value})"

    def options_for(self, item: Item) -> list[Option]:
        if item.options:
            return item.options
        if item.kind == "checkbox":
            return [Option(0, CHECKBOX_OFF[0]), Option(1, CHECKBOX_ON[0])]
        return []

    def choices(self, item: Item) -> list[str]:
        if item.read_only or item.dynamic:
            return []
        return [self.option_label(item, option) for option in self.options_for(item)]

    def set_value_text(self, item: Item, text: str) -> None:
        if item.read_only:
            raise ValueError("this value is read-only")
        text = text.strip()
        options = self.options_for(item)
        store = self.store(item)
        if item.kind == "password":
            if not text:
                payload = bytes(item.size)
            else:
                compact = "".join(text.split())
                if len(compact) != item.size * 2:
                    raise ValueError(f"password requires exactly {item.size * 2} hex digits, or blank to clear")
                try:
                    payload = bytes.fromhex(compact)
                except ValueError as exc:
                    raise ValueError("password must be hexadecimal, or blank to clear") from exc
            store.write(item.offset, payload)
            return
        if item.kind == "text":
            payload = text.encode("utf-16-le")
            if len(payload) > item.size:
                raise ValueError(f"text too long for a {item.size} byte field")
            store.record.data[item.offset:item.offset + item.size] = payload + b"\x00" * (item.size - len(payload))
            return
        if options and not item.dynamic:
            matches = [option for option in options
                       if text in (option.text, self.option_label(item, option))]
            if len(matches) == 1:
                store.write_int(item.offset, matches[0].value, max(1, item.size))
                return
            raise ValueError(f"{text!r} is not one of the allowed values")
        value = _as_int(text)
        if value is None:
            raise ValueError(f"{text!r} is not a number")
        if item.minimum is not None and value < item.minimum:
            raise ValueError(f"below the allowed minimum {item.minimum}")
        if item.maximum is not None and value > item.maximum:
            raise ValueError(f"above the allowed maximum {item.maximum}")
        if item.step > 1 and item.minimum is not None and (value - item.minimum) % item.step:
            raise ValueError(f"value must use step {item.step} from {item.minimum}")
        if value < 0 and not item.signed:
            raise ValueError("negative values require a signed field")
        store.write_int(item.offset, value & ((1 << (8 * item.size)) - 1), max(1, item.size))

    def default_value(self, item: Item) -> int | bytes | None:
        blob = self.defaults.get(item.varstore)
        if blob is None or item.offset + max(1, item.size) > len(blob):
            return item.default
        raw = blob[item.offset:item.offset + max(1, item.size)]
        if item.kind == "password":
            return raw
        value = int.from_bytes(raw, "little")
        if item.signed and value >= 1 << (8 * item.size - 1):
            value -= 1 << (8 * item.size)
        return value

    def default_text(self, item: Item) -> str:
        value = self.default_value(item)
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.hex() if any(value) else "(empty)"
        for option in self.options_for(item):
            if option.value == value:
                return self.option_label(item, option)
        return str(value)

    def is_changed(self, item: Item) -> bool:
        blob = self.defaults.get(item.varstore)
        if blob is not None and item.offset + max(1, item.size) <= len(blob):
            return blob[item.offset:item.offset + max(1, item.size)] != self.store(item).read(item.offset, max(1, item.size))
        default = self.default_value(item)
        return default is not None and self.raw_value(item) != default

    def reset_item(self, item: Item) -> bool:
        if item.read_only:
            return False
        blob = self.defaults.get(item.varstore)
        if blob is not None and item.offset + max(1, item.size) <= len(blob):
            self.store(item).record.data[item.offset:item.offset + max(1, item.size)] = blob[
                item.offset:item.offset + max(1, item.size)]
            return True
        default = self.default_value(item)
        if default is None:
            return False
        if isinstance(default, bytes):
            self.store(item).write(item.offset, default)
        else:
            self.store(item).write_int(item.offset, default & ((1 << (8 * item.size)) - 1), item.size)
        return True

    # ---------- persistence ----------
    def save(self, path: Path | None = None, *, backup: bool = True) -> Path:
        target = Path(path or self.dump_path)
        if backup and target.exists():
            shutil.copy2(target, target.with_name(target.name + ".bak"))
        saved = self.image.save(target)
        self.dump_path = saved
        return saved

    def changed_stores(self) -> list[tuple[str, int]]:
        out = []
        for vs in self.image.varstores():
            offsets = vs.dirty_offsets()
            if offsets:
                out.append((vs.name, len(offsets)))
        return out
