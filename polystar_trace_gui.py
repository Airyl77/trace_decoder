#!/usr/bin/env python3
"""Minimal tkinter front-end for polystar_trace_convert (stdlib only)."""
import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from polystar_trace_convert import convert


class App(ttk.Frame):
    def __init__(self, root):
        super().__init__(root, padding=10)
        self.grid(sticky="nsew")
        root.title("Polystar trace converter")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(3, weight=1)

        self.src = tk.StringVar()
        self.outdir = tk.StringVar()
        self.tz = tk.StringVar(value="1")
        self.custom_out = False  # True once the user picked an output dir manually

        ttk.Button(self, text="Input XML...", command=self.pick_src).grid(row=0, column=0, sticky="ew")
        ttk.Entry(self, textvariable=self.src, state="readonly").grid(row=0, column=1, sticky="ew", padx=5)
        ttk.Button(self, text="Output folder...", command=self.pick_out).grid(row=1, column=0, sticky="ew", pady=5)
        ttk.Entry(self, textvariable=self.outdir, state="readonly").grid(row=1, column=1, sticky="ew", padx=5)

        opts = ttk.Frame(self)
        opts.grid(row=2, column=0, columnspan=2, sticky="ew")
        ttk.Label(opts, text="Timezone offset (hours):").pack(side="left")
        ttk.Entry(opts, textvariable=self.tz, width=5).pack(side="left", padx=5)
        self.go = ttk.Button(opts, text="Convert", command=self.run, state="disabled")
        self.go.pack(side="right")

        self.log = scrolledtext.ScrolledText(self, height=12, width=70, state="disabled")
        self.log.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=(8, 0))

    def pick_src(self):
        path = filedialog.askopenfilename(
            title="Select trace XML", filetypes=[("XML files", "*.xml"), ("All files", "*.*")])
        if not path:
            return
        self.src.set(path)
        if not self.custom_out:
            self.outdir.set(os.path.dirname(path))
        self.go.config(state="normal")

    def pick_out(self):
        d = filedialog.askdirectory(title="Select output folder", initialdir=self.outdir.get() or None)
        if d:
            self.outdir.set(d)
            self.custom_out = True

    def write(self, line):
        self.log.config(state="normal")
        self.log.insert("end", line + "\n")
        self.log.see("end")
        self.log.config(state="disabled")
        self.update_idletasks()

    def run(self):
        try:
            off = float(self.tz.get())
        except ValueError:
            messagebox.showerror("Error", "Timezone offset must be a number, e.g. 1")
            return
        stem = os.path.splitext(os.path.basename(self.src.get()))[0]
        prefix = os.path.join(self.outdir.get(), stem)
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.config(state="disabled")
        try:
            convert(self.src.get(), prefix, off, log=self.write)
        except Exception as e:  # show any parse/IO error instead of a silent traceback
            self.write(f"ERROR: {e}")
            messagebox.showerror("Conversion failed", str(e))
            return
        self.write(f"\nWrote {prefix}.pcap\nWrote {prefix}.json")


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
