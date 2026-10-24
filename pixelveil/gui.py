from __future__ import annotations

from pathlib import Path

from .core import PixelVeilError, clean_file, inspect_file


def launch_gui() -> None:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError as exc:
        raise RuntimeError("Tk is not installed for this Python interpreter") from exc

    root = tk.Tk()
    root.title("PixelVeil — image privacy, locally")
    root.geometry("760x520")
    root.minsize(620, 420)
    files: list[Path] = []
    remove_provenance = tk.BooleanVar(value=False)

    frame = ttk.Frame(root, padding=18)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="PixelVeil", font=("TkDefaultFont", 20, "bold")).pack(anchor="w")
    ttk.Label(frame, text="Inspect and clean JPEG, PNG, WebP, and GIF files on this device.").pack(anchor="w", pady=(2, 12))

    file_list = tk.Listbox(frame, height=8, selectmode="extended")
    file_list.pack(fill="both", expand=True)
    buttons = ttk.Frame(frame)
    buttons.pack(fill="x", pady=10)

    output_dir: list[Path | None] = [None]
    output_label = ttk.Label(frame, text="Output: next to each original (new files only)")
    output_label.pack(anchor="w")

    ttk.Checkbutton(
        frame,
        text="Remove C2PA/content provenance too (may remove authenticity information)",
        variable=remove_provenance,
    ).pack(anchor="w", pady=(8, 0))
    log = tk.Text(frame, height=8, wrap="word", state="disabled")
    log.pack(fill="both", expand=True, pady=(8, 0))

    def log_line(text: str) -> None:
        log.configure(state="normal")
        log.insert("end", text + "\n")
        log.see("end")
        log.configure(state="disabled")

    def add_files() -> None:
        chosen = filedialog.askopenfilenames(
            title="Choose images",
            filetypes=[("Supported images", "*.jpg *.jpeg *.png *.webp *.gif"), ("All files", "*.*")],
        )
        for name in chosen:
            path = Path(name)
            if path not in files:
                files.append(path)
                file_list.insert("end", path.name)

    def choose_output() -> None:
        selected = filedialog.askdirectory(title="Choose output folder")
        if selected:
            output_dir[0] = Path(selected)
            output_label.configure(text=f"Output: {output_dir[0]}")

    def inspect_selected() -> None:
        if not files:
            messagebox.showinfo("PixelVeil", "Choose one or more images first.")
            return
        for path in files:
            try:
                scan = inspect_file(path)
                kinds = ", ".join(str(item["kind"]) for item in scan.findings) or "none detected"
                log_line(f"{path.name}: {scan.format}; {kinds}")
            except PixelVeilError as exc:
                log_line(f"{path.name}: error: {exc}")

    def clean_selected() -> None:
        if not files:
            messagebox.showinfo("PixelVeil", "Choose one or more images first.")
            return
        if remove_provenance.get() and not messagebox.askyesno(
            "Remove provenance?",
            "This removes C2PA/content provenance blocks where detected. The signatures and authenticity history will no longer be available. Continue?",
        ):
            return
        for path in files:
            try:
                output, report = clean_file(path, output_dir[0], remove_provenance=remove_provenance.get())
                log_line(f"{path.name} → {output.name}: encoded image data unchanged; removed {len(report.removed)} item(s)")
            except PixelVeilError as exc:
                log_line(f"{path.name}: error: {exc}")

    ttk.Button(buttons, text="Add images…", command=add_files).pack(side="left")
    ttk.Button(buttons, text="Choose output…", command=choose_output).pack(side="left", padx=6)
    ttk.Button(buttons, text="Inspect", command=inspect_selected).pack(side="left", padx=6)
    ttk.Button(buttons, text="Clean copies", command=clean_selected).pack(side="right")
    root.mainloop()
