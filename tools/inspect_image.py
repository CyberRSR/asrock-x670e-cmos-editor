"""Show how a dumped A86 setup image maps onto the factory defaults of a firmware image.

    python tools/inspect_image.py [dump] [rom]
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from uefi.nvarstore import load_defaults
from uefi.setupimg import SetupImage

ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str]) -> int:
    dump = Path(argv[1]) if len(argv) > 1 else ROOT / "4.43-5400f"
    rom = Path(argv[2]) if len(argv) > 2 else ROOT / "X67ETCC4.43.ROM"
    defaults = load_defaults(rom.read_bytes())
    print(f"firmware defaults: {len(defaults)} variables "
          f"({', '.join(f'{n}:{len(b)}' for n, b in list(defaults.items())[:6])}, ...)")
    image = SetupImage.load(dump, defaults)
    print()
    print(image.summary())
    print()
    for vs in image.varstores():
        if vs.default is None:
            continue
        changed = vs.dirty_offsets()
        if changed:
            preview = ", ".join(f"+{o:#x}:{vs.record.data[o]:02x}<-{vs.default[o]:02x}" for o in changed[:12])
            print(f"{vs.name}: {len(changed)} changed byte(s): {preview}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
