"""GUI editor for an AMI Aptio V CMOS/setup dump (ASRock X670E Taichi Carrara).

    python editor/app.py [dump-file] [firmware.ROM] [settings_map.json]

Left: the settings tree taken from the firmware setting map.  Right: the value of the selected
setting, its factory default and help text.  The second tab edits the raw varstore bytes.
"""
from __future__ import annotations

import csv
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, str(Path(__file__).resolve().parent))

from model import Document, Item          # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
APP_TITLE = "CMOS settings editor - AMI Aptio V"


class SettingsEditor(tk.Tk):
    def __init__(self, dump: Path | None = None, rom: Path | None = None, schema: Path | None = None):
        super().__init__()
        self.title(APP_TITLE)
        width = min(1180, self.winfo_screenwidth() - 80)
        height = min(760, self.winfo_screenheight() - 100)
        x = max(0, (self.winfo_screenwidth() - width) // 2)
        y = max(0, (self.winfo_screenheight() - height) // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.doc: Document | None = None
        self.selected: Item | None = None
        self.modified = tk.BooleanVar(value=False)
        self._nodes: dict[str, Item] = {}
        self._build_menu()
        self._build_body()
        self._build_status()
        if dump:
            self.open_documents(dump, rom, schema)

    # ------------------------------------------------------------------ ui construction
    def _build_menu(self) -> None:
        bar = tk.Menu(self)
        filemenu = tk.Menu(bar, tearoff=0)
        filemenu.add_command(label="Open dump…", accelerator="Ctrl+O", command=self.cmd_open_dump)
        filemenu.add_command(label="Open firmware ROM…", command=self.cmd_open_rom)
        filemenu.add_command(label="Open settings map…", command=self.cmd_open_schema)
        filemenu.add_separator()
        filemenu.add_command(label="Save", accelerator="Ctrl+S", command=self.cmd_save)
        filemenu.add_command(label="Save as…", accelerator="Ctrl+Shift+S", command=self.cmd_save_as)
        filemenu.add_command(label="Export settings…", command=self.cmd_export)
        filemenu.add_separator()
        filemenu.add_command(label="Quit", command=self.cmd_quit)
        bar.add_cascade(label="File", menu=filemenu)
        view = tk.Menu(bar, tearoff=0)
        view.add_command(label="Reload document", command=self.cmd_reload)
        bar.add_cascade(label="View", menu=view)
        helpmenu = tk.Menu(bar, tearoff=0)
        helpmenu.add_command(label="About", command=self.cmd_about)
        bar.add_cascade(label="Help", menu=helpmenu)
        self.config(menu=bar)
        self.protocol("WM_DELETE_WINDOW", self.cmd_quit)
        self.bind_all("<Control-o>", lambda e: self.cmd_open_dump())
        self.bind_all("<Control-s>", lambda e: self.cmd_save())
        self.bind_all("<Control-S>", lambda e: self.cmd_save_as())

    def _build_body(self) -> None:
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)
        self.settings_frame = ttk.Frame(self.notebook)
        self.raw_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text="Settings")
        self.notebook.add(self.raw_frame, text="Raw varstores")
        self._build_settings_tab()
        self._build_raw_tab()

    def _build_settings_tab(self) -> None:
        top = ttk.Frame(self.settings_frame)
        top.pack(fill="x", padx=8, pady=6)
        ttk.Label(top, text="Search").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._rebuild_tree())
        ttk.Entry(top, textvariable=self.search_var, width=42).pack(side="left", padx=6)
        self.only_changed = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="only changed vs factory default", variable=self.only_changed,
                        command=self._rebuild_tree).pack(side="left", padx=6)
        self.count_label = ttk.Label(top, text="")
        self.count_label.pack(side="right")

        panes = ttk.Panedwindow(self.settings_frame, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        left = ttk.Frame(panes)
        right = ttk.Frame(panes)
        panes.add(left, weight=3)
        panes.add(right, weight=2)

        columns = ("value", "location", "kind")
        self.tree = ttk.Treeview(left, columns=columns, show="tree headings", selectmode="browse")
        self.tree.heading("#0", text="Menu / setting")
        self.tree.column("#0", width=430, stretch=True)
        for key, title, width in (("value", "Current value", 200), ("location", "Where", 165), ("kind", "Type", 80)):
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor="w", stretch=(key == "value"))
        self.tree.tag_configure("changed", foreground="#b8860b")
        self.tree.tag_configure("factory", foreground="#0a7d3c")
        scroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", lambda e: self.focus_value())

        details = ttk.LabelFrame(right, text="Selected setting")
        details.pack(fill="both", expand=True)
        self.detail_vars: dict[str, tk.StringVar] = {}
        for key, title in (("path", "Menu"), ("value", "Current value"), ("default", "Factory default"),
                           ("where", "Location"), ("qid", "Question id")):
            row = ttk.Frame(details)
            row.pack(fill="x", padx=8, pady=2)
            ttk.Label(row, text=title, width=15, anchor="w").pack(side="left")
            var = tk.StringVar()
            self.detail_vars[key] = var
            ttk.Label(row, textvariable=var, anchor="w", wraplength=330, justify="left").pack(side="left", fill="x")

        editor = ttk.LabelFrame(right, text="Change value")
        editor.pack(fill="x", padx=0, pady=8)
        self.value_var = tk.StringVar()
        self.value_widget = ttk.Combobox(editor, textvariable=self.value_var, state="disabled")
        self.value_widget.pack(fill="x", padx=8, pady=6)
        self.value_widget.bind("<Return>", lambda e: self.apply_value())
        buttons = ttk.Frame(editor)
        buttons.pack(fill="x", padx=8, pady=(0, 8))
        self.apply_button = ttk.Button(buttons, text="Apply", command=self.apply_value)
        self.apply_button.pack(side="left")
        self.reset_button = ttk.Button(buttons, text="Factory default", command=self.reset_selected)
        self.reset_button.pack(side="left", padx=6)
        ttk.Button(buttons, text="Reload value", command=self.show_item).pack(side="left")

        helpbox = ttk.LabelFrame(right, text="Help")
        helpbox.pack(fill="both", expand=False, pady=6)
        self.help_text = tk.Text(helpbox, height=6, wrap="word", state="disabled", relief="flat")
        self.help_text.pack(fill="both", expand=True, padx=8, pady=6)

    def _build_raw_tab(self) -> None:
        left = ttk.Frame(self.raw_frame)
        left.pack(side="left", fill="y", padx=8, pady=8)
        ttk.Label(left, text="Varstores in the dump").pack(anchor="w")
        self.store_list = tk.Listbox(left, width=34, exportselection=False)
        self.store_list.pack(fill="y", expand=True)
        self.store_list.bind("<<ListboxSelect>>", self._show_store)

        right = ttk.Frame(self.raw_frame)
        right.pack(side="left", fill="both", expand=True, padx=(0, 8), pady=8)
        self.hex_view = tk.Text(right, wrap="none", font=("Consolas", 10), relief="flat",
                                background="#fbfbfb")
        hexbar = ttk.Scrollbar(right, orient="vertical", command=self.hex_view.yview)
        self.hex_view.configure(yscrollcommand=hexbar.set)
        self.hex_view.pack(side="left", fill="both", expand=True)
        hexbar.pack(side="right", fill="y")

        form = ttk.Frame(self.raw_frame)
        form.pack(side="left", fill="y", padx=(0, 8), pady=8)
        ttk.Label(form, text="offset (hex)").pack(anchor="w")
        self.raw_offset = ttk.Entry(form, width=12)
        self.raw_offset.pack(anchor="w")
        ttk.Label(form, text="value (hex/dec)").pack(anchor="w", pady=(6, 0))
        self.raw_value = ttk.Entry(form, width=12)
        self.raw_value.pack(anchor="w")
        ttk.Label(form, text="size").pack(anchor="w", pady=(6, 0))
        self.raw_size = ttk.Spinbox(form, from_=1, to=8, width=10)
        self.raw_size.set(1)
        self.raw_size.pack(anchor="w")
        ttk.Button(form, text="Write", command=self.write_raw).pack(anchor="w", pady=10)
        ttk.Button(form, text="Diff vs default", command=self._show_store).pack(anchor="w")

    def _build_status(self) -> None:
        self.status = tk.StringVar(value="open a dump file")
        ttk.Label(self, textvariable=self.status, anchor="w", relief="sunken").pack(fill="x", side="bottom")

    # ------------------------------------------------------------------ document handling
    def open_documents(self, dump: Path, rom: Path | None, schema: Path | None) -> None:
        try:
            self.doc = Document(dump, rom, schema)
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"cannot open {dump}\n{type(exc).__name__}: {exc}")
            return
        self.title(f"{APP_TITLE} - {dump.name}")
        self.modified.set(False)
        self.selected = None
        messages = [f"{len(self.doc.items)} settings loaded"]
        if self.doc.load_error:
            messages.append(self.doc.load_error)
        if self.doc.schema_error:
            messages.append(self.doc.schema_error)
        elif self.doc.missing_items:
            messages.append(f"{len(self.doc.missing_items)} mapped setting(s) do not fit the dump and are hidden")
        self.status.set(" | ".join(messages) if messages else
                        f"{dump.name}: {len(self.doc.items)} settings, "
                        f"{len(self.doc.image.varstores())} varstores")
        self._refresh()
        if self.doc.load_error:
            self.status.set(self.doc.load_error)

    def _refresh(self) -> None:
        if not self.doc:
            return
        self._rebuild_tree()
        self.store_list.delete(0, "end")
        for vs in self.doc.image.varstores():
            self.store_list.insert("end", f"{vs.name}  [{vs.size:#x}]")
        if self.store_list.size():
            self.store_list.selection_set(0)
            self._show_store()

    # ------------------------------------------------------------------ tree
    def _visible_items(self) -> list[Item]:
        if not self.doc:
            return []
        needle = self.search_var.get().strip().lower()
        items = []
        for item in self.doc.items:
            if needle and needle not in " > ".join(item.path).lower():
                continue
            if self.only_changed.get() and not self.doc.is_changed(item):
                continue
            items.append(item)
        return items

    def _rebuild_tree(self) -> None:
        self.tree.delete(*self.tree.get_children(""))
        self._nodes = {}
        if not self.doc:
            return
        folders: dict[tuple[str, ...], str] = {}
        count = 0
        for item in self._visible_items():
            parent = ""
            for depth, part in enumerate(item.path[:-1]):
                key = item.path[:depth + 1]
                node = folders.get(key)
                if node is None:
                    node = self.tree.insert(parent, "end", text=part, open=True, tags=("folder",))
                    folders[key] = node
                parent = node
            tags = tuple(tag for tag in (self.doc.is_changed(item) and "changed" or "factory",) if tag)
            node = self.tree.insert(parent, "end", text=item.path[-1],
                                    values=(self.doc.value_text(item), item.location, item.kind), tags=tags)
            self._nodes[node] = item
            count += 1
        self.count_label.config(text=f"{count} settings")

    def _on_select(self, _event=None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        self.selected = self._nodes.get(selection[0])
        self.show_item()

    def show_item(self) -> None:
        item = self.selected
        if not item or not self.doc:
            return
        self.detail_vars["path"].set(" > ".join(item.path[:-1]))
        self.detail_vars["value"].set(self.doc.value_text(item))
        self.detail_vars["default"].set(self.doc.default_text(item) or "unknown")
        self.detail_vars["where"].set(f"{item.varstore} + 0x{item.offset:x}, {item.size} byte(s)")
        self.detail_vars["qid"].set("" if item.qid is None else f"{item.qid:#05x}")
        choices = self.doc.choices(item)
        state = "disabled" if item.read_only else ("readonly" if choices else "normal")
        self.value_widget.configure(values=choices, state=state)
        self.apply_button.configure(state="disabled" if item.read_only else "normal")
        self.reset_button.configure(state="disabled" if item.read_only else "normal")
        self.value_var.set(self.doc.value_text(item))
        self.help_text.configure(state="normal")
        self.help_text.delete("1.0", "end")
        help_text = item.help or "no help text in the firmware map"
        if item.kind == "password":
            help_text += f"\n\nUnlocked raw password field: enter exactly {item.size * 2} hex digits, or leave blank to clear."
        elif item.dynamic:
            help_text += "\n\nDynamic list: enter a numeric value; firmware option labels are unavailable."
        self.help_text.insert("1.0", help_text)
        self.help_text.configure(state="disabled")

    def focus_value(self) -> None:
        if self.value_widget.cget("state") == "readonly":
            self.value_widget.event_generate("<Button-1>")
        self.value_widget.focus_set()

    def apply_value(self) -> None:
        item = self.selected
        if not item or not self.doc:
            return
        try:
            self.doc.set_value_text(item, self.value_var.get())
        except Exception as exc:
            messagebox.showwarning(APP_TITLE, str(exc))
            return
        self.modified.set(True)
        self._rebuild_tree()
        node = next((n for n, it in self._nodes.items() if it is item), None)
        if node:
            self.tree.selection_set(node)
            self.tree.see(node)
        self.status.set(f"{item.location} = {self.doc.value_text(item)}   (not saved yet)")

    def reset_selected(self) -> None:
        item = self.selected
        if not item or not self.doc:
            return
        if self.doc.reset_item(item):
            self.modified.set(True)
            self.show_item()
            self._rebuild_tree()
            node = next((n for n, it in self._nodes.items() if it is item), None)
            if node:
                self.tree.selection_set(node)
                self.tree.see(node)
            self.status.set(f"{item.location} restored to the factory default   (not saved yet)")
        else:
            messagebox.showinfo(APP_TITLE, "no factory default known for this varstore")

    # ------------------------------------------------------------------ raw tab
    def _current_store(self):
        if not self.doc:
            return None
        selection = self.store_list.curselection()
        if not selection:
            return None
        stores = self.doc.image.varstores()
        index = selection[0]
        return stores[index] if index < len(stores) else None

    def _show_store(self, _event=None) -> None:
        store = self._current_store()
        self.hex_view.configure(state="normal")
        self.hex_view.delete("1.0", "end")
        if store is None:
            return
        data = bytes(store.record.data)
        base = store.default or b""
        blank = 0
        for start in range(0, len(data), 16):
            row = data[start:start + 16]
            if not any(row):
                blank += 1
                if blank > 1:
                    if blank == 2:
                        self.hex_view.insert("end", "     ...(zero padding)\n")
                    continue
            else:
                blank = 0
            ascii_text = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
            hex_text = " ".join(
                f"{b:02x}{'!' if start + i < len(base) and base[start + i] != b else ' '}"
                for i, b in enumerate(row))
            self.hex_view.insert("end", f"{start:04x}  {hex_text:<49}  {ascii_text}\n")
        self.hex_view.configure(state="disabled")

    def write_raw(self) -> None:
        store = self._current_store()
        if store is None:
            messagebox.showinfo(APP_TITLE, "pick a varstore first")
            return
        try:
            offset = int(self.raw_offset.get(), 16)
            size = int(self.raw_size.get())
            raw = self.raw_value.get().strip()
            try:
                value = int(raw, 16) if raw.lower().startswith("0x") else int(raw, 0)
            except ValueError:
                value = int(raw, 16)
            store.write_int(offset, value, size)
        except Exception as exc:
            messagebox.showwarning(APP_TITLE, str(exc))
            return
        self.modified.set(True)
        self._show_store()
        self._rebuild_tree()
        self.status.set(f"{store.name}+{offset:#x} <- {value:#x} ({size} byte(s))   (not saved yet)")

    # ------------------------------------------------------------------ commands
    def _confirm_discard(self) -> bool:
        if not self.modified.get():
            return True
        answer = messagebox.askyesnocancel(APP_TITLE, "Save the changes to the dump before continuing?")
        if answer is None:
            return False
        if answer:
            self.cmd_save()
            return not self.modified.get()
        return True

    def cmd_quit(self) -> None:
        if self._confirm_discard():
            self.destroy()

    def cmd_reload(self) -> None:
        if not self.doc or not self._confirm_discard():
            return
        self.open_documents(self.doc.dump_path, self.doc.rom_path, self.doc.schema_path)

    def cmd_open_dump(self) -> None:
        if not self._confirm_discard():
            return
        path = filedialog.askopenfilename(title="Open the dumped setup image", initialdir=str(ROOT))
        if path:
            rom = self.doc.rom_path if self.doc else None
            schema = self.doc.schema_path if self.doc else None
            self.open_documents(Path(path), rom, schema)

    def cmd_open_rom(self) -> None:
        if not self.doc or not self._confirm_discard():
            return
        path = filedialog.askopenfilename(title="Open the firmware ROM", initialdir=str(ROOT))
        if path:
            self.open_documents(self.doc.dump_path, Path(path), self.doc.schema_path)

    def cmd_open_schema(self) -> None:
        if not self.doc or not self._confirm_discard():
            return
        path = filedialog.askopenfilename(title="Open the settings map", initialdir=str(ROOT / "out"))
        if path:
            self.open_documents(self.doc.dump_path, self.doc.rom_path, Path(path))

    def cmd_save(self) -> None:
        if not self.doc:
            return
        try:
            target = self.doc.save()
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"cannot save the dump\n{type(exc).__name__}: {exc}")
            return
        self.modified.set(False)
        self.status.set(f"saved {target}")

    def cmd_save_as(self) -> None:
        if not self.doc:
            return
        path = filedialog.asksaveasfilename(title="Save the setup image", initialdir=str(ROOT),
                                            defaultextension="", initialfile=self.doc.dump_path.name)
        if path:
            try:
                target = self.doc.save(Path(path))
            except Exception as exc:
                messagebox.showerror(APP_TITLE, f"cannot save the dump\n{type(exc).__name__}: {exc}")
                return
            self.title(f"{APP_TITLE} - {target.name}")
            self.modified.set(False)
            self.status.set(f"saved {target}")

    def cmd_export(self) -> None:
        if not self.doc or not self.doc.items:
            messagebox.showinfo(APP_TITLE, "no settings map loaded")
            return
        path = filedialog.asksaveasfilename(title="Export settings", defaultextension=".csv",
                                            initialfile="settings.csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.writer(handle, delimiter=";")
            writer.writerow(["menu", "setting", "value", "factory default", "varstore", "offset", "size", "type", "help"])
            for item in self.doc.items:
                writer.writerow([" > ".join(item.path[:-1]), item.title, self.doc.value_text(item),
                                 self.doc.default_text(item), item.varstore, f"0x{item.offset:x}", item.size,
                                 item.kind, " ".join(item.help.split())])
        self.status.set(f"exported {path}")

    def cmd_about(self) -> None:
        messagebox.showinfo(
            APP_TITLE,
            "Edits the A86 setup dump of an AMI Aptio V board.\n\n"
            "Record layout and the varstore names come from the firmware image; the setting map "
            "is produced by tools/tse/setupdb.py.  The container has no checksum, only a 16 bit "
            "length field that is recomputed on save.\n\n"
            "A copy of the previous file is kept next to it as *.bak when saving over the dump.",
        )


def main(argv: list[str]) -> int:
    dump = Path(argv[1]) if len(argv) > 1 else (ROOT / "4.43-5400f")
    rom = Path(argv[2]) if len(argv) > 2 else (ROOT / "X67ETCC4.43.ROM")
    schema = Path(argv[3]) if len(argv) > 3 else None
    app = SettingsEditor(dump if dump.exists() else None, rom if rom.exists() else None, schema)
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
