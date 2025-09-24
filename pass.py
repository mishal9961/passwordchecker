#!/usr/bin/env python3
"""
Password Auditor — GUI version (safe, defensive)

This tool audits password strength (entropy, patterns, common passwords),
but DOES NOT attempt to crack or break passwords.

Save as: password_auditor_gui.py
Run: python3 password_auditor_gui.py
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import math
import re
import csv
import json
from collections import Counter
from queue import Queue, Empty
from pathlib import Path

# ------------------------
# Analysis / Utility Functions
# ------------------------
BUILTIN_COMMON = {
    "123456","password","123456789","12345678","12345","qwerty","abc123","football",
    "monkey","letmein","dragon","111111","baseball","iloveyou","master","sunshine",
    "ashley","bailey","password1","welcome","admin","login","princess","qwerty123"
}

def estimate_entropy(password: str) -> float:
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'[0-9]', password): charset += 10
    if re.search(r'[^A-Za-z0-9]', password): charset += 32
    if charset == 0:
        return 0.0
    return len(password) * math.log2(charset)

def detect_repeated_patterns(pw: str):
    issues = []
    if re.search(r'(.)\1\1', pw):
        issues.append("repeated-char")
    seqs = ['0123456789','abcdefghijklmnopqrstuvwxyz','qwertyuiop','asdfghjkl','zxcvbnm']
    low = pw.lower()
    for seq in seqs:
        for i in range(len(seq)-3):
            s = seq[i:i+4]
            if s in low or s[::-1] in low:
                issues.append(f"sequence[{s}]")
                break
    if re.search(r'(qwert|asdfg|zxcvb|1234)', low):
        issues.append("keyboard-pattern")
    return list(dict.fromkeys(issues))

def pattern_score(password: str) -> int:
    score = 0
    L = len(password)
    if L >= 8: score += 10
    if L >= 12: score += 10
    if re.search(r'[a-z]', password): score += 5
    if re.search(r'[A-Z]', password): score += 5
    if re.search(r'[0-9]', password): score += 5
    if re.search(r'[^A-Za-z0-9]', password): score += 6
    if re.search(r'(.)\1\1', password): score -= 8
    if re.search(r'^(password|admin|welcome)', password, flags=re.IGNORECASE):
        score -= 12
    return score

def grade_from_entropy(entropy: float, length: int, is_common: bool, pattern_issues) -> str:
    if is_common or length < 8 or 'repeated-char' in pattern_issues:
        return "Weak"
    if entropy < 36 or length < 10:
        return "Weak"
    if entropy < 50 or length < 14:
        return "Moderate"
    return "Strong"

def mask_pw(pw: str, show=2, max_mask=6) -> str:
    if len(pw) <= show:
        return pw[0] + "*"*(len(pw)-1) if pw else ""
    visible = pw[:show]
    masked_len = min(len(pw)-show, max_mask)
    return visible + "*"*masked_len

def analyze_passwords_list(passwords, common_set, progress_callback=None):
    reports = []
    total = len(passwords)
    for idx, pw in enumerate(passwords, start=1):
        ent = estimate_entropy(pw)
        issues = detect_repeated_patterns(pw)
        is_common = (pw.lower() in common_set)
        score = pattern_score(pw)
        grade = grade_from_entropy(ent, len(pw), is_common, issues)
        recs = []
        if is_common:
            recs.append("Change immediately — common password.")
        if grade == "Weak":
            recs.append("Increase length (≥12), use mixed case, digits, symbols, avoid repeats.")
        elif grade == "Moderate":
            recs.append("Good start — increase length or add symbols to improve entropy.")
        else:
            recs.append("Strong — use passphrases and unique passwords.")
        reports.append({
            "password": pw,
            "masked": mask_pw(pw),
            "length": len(pw),
            "entropy_bits": round(ent, 2),
            "is_common": is_common,
            "pattern_issues": issues,
            "score": score,
            "grade": grade,
            "recommendation": " ".join(recs)
        })
        if progress_callback:
            progress_callback(idx, total)
    return reports

# ------------------------
# GUI Class
# ------------------------
class PasswordAuditorGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔒 Password Auditor — Safe GUI")
        self.geometry("1000x600")
        self.minsize(900, 500)
        self.configure(bg="#2c2f33")

        # Define marquee and title vars *before* building header
        self._marquee_text = " 🔒 Password Auditor — Defensive Only "
        self._marquee_index = 0
        self._title_colors = ["#ff6b6b", "#ffa94d", "#ffd43b", "#9ae66e", "#38d39f", "#4cc9f0", "#9b5de5"]
        self._color_index = 0

        # Style
        self.style = ttk.Style(self)
        self.style.theme_use('clam')
        self.style.configure("TLabel", background="#2c2f33", foreground="#ffffff", font=("Arial", 10))
        self.style.configure("Header.TLabel", font=("Arial", 18, "bold"))
        self.style.configure("TButton", font=("Arial", 10))
        self.style.configure("Treeview", font=("Arial", 10), rowheight=24)
        self.style.configure("TProgressbar", thickness=12)

        # Build UI components
        self._build_header()
        self._build_controls()
        self._build_table()
        self._build_statusbar()

        self.passwords = []
        self.common_set = set(BUILTIN_COMMON)
        self.analysis_thread = None
        self.result_queue = Queue()

        # Start title marquee animation
        self.after(150, self._animate_title)

    def _build_header(self):
        header_frame = tk.Frame(self, bg="#23272a", height=60)
        header_frame.pack(fill="x", padx=5, pady=5)

        self.lbl_title = tk.Label(header_frame, text=self._marquee_text, font=("Arial", 18, "bold"),
                                  bg="#23272a", fg=self._title_colors[0])
        self.lbl_title.pack(side="left", padx=20, pady=10)

        subtitle = tk.Label(header_frame, text="Safe auditing — no cracking functionality",
                            bg="#23272a", fg="#bdbdbd", font=("Arial", 10))
        subtitle.pack(side="left", padx=10, pady=14)

    def _animate_title(self):
        text = self._marquee_text
        i = self._marquee_index
        display = text[i:] + "  " + text[:i]
        self.lbl_title.config(text=display, fg=self._title_colors[self._color_index])
        self._marquee_index = (i + 1) % len(text)
        self._color_index = (self._color_index + 1) % len(self._title_colors)
        self.after(150, self._animate_title)

    def _build_controls(self):
        ctrl = tk.Frame(self, bg="#2c2f33")
        ctrl.pack(fill="x", padx=10, pady=8)

        btn_open = ttk.Button(ctrl, text="Open Passwords File", command=self.open_passwords_file)
        btn_open.pack(side="left", padx=(0, 8))

        btn_common = ttk.Button(ctrl, text="Load Common List (opt)", command=self.open_common_file)
        btn_common.pack(side="left", padx=(0, 8))

        self.btn_run = ttk.Button(ctrl, text="Run Analysis", command=self.run_analysis)
        self.btn_run.pack(side="left", padx=(0, 8))

        self.btn_export_csv = ttk.Button(ctrl, text="Export CSV", command=self.export_csv, state="disabled")
        self.btn_export_csv.pack(side="right", padx=(8, 0))

        self.btn_export_json = ttk.Button(ctrl, text="Export JSON", command=self.export_json, state="disabled")
        self.btn_export_json.pack(side="right", padx=(8, 0))

    def _build_table(self):
        table_frame = tk.Frame(self, bg="#2c2f33")
        table_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        cols = ("masked", "length", "entropy_bits", "grade", "issues", "recommendation")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("masked", text="Password")
        self.tree.heading("length", text="Len")
        self.tree.heading("entropy_bits", text="Entropy (bits)")
        self.tree.heading("grade", text="Grade")
        self.tree.heading("issues", text="Pattern Issues")
        self.tree.heading("recommendation", text="Recommendation")

        self.tree.column("masked", width=180, anchor="w")
        self.tree.column("length", width=60, anchor="center")
        self.tree.column("entropy_bits", width=120, anchor="center")
        self.tree.column("grade", width=80, anchor="center")
        self.tree.column("issues", width=180, anchor="w")
        self.tree.column("recommendation", width=320, anchor="w")

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        # Tags + coloring
        self.tree.tag_configure("Weak", background="#4e1a1a", foreground="#ff9999")
        self.tree.tag_configure("Moderate", background="#3c361a", foreground="#ffcc99")
        self.tree.tag_configure("Strong", background="#1a4e1a", foreground="#99ffcc")

    def _build_statusbar(self):
        status = tk.Frame(self, bg="#23272a", height=30)
        status.pack(fill="x", side="bottom")
        self.status_label = tk.Label(status, text="Ready", bg="#23272a", fg="#dddddd", font=("Arial", 10))
        self.status_label.pack(side="left", padx=8)

        self.progress = ttk.Progressbar(status, orient="horizontal", length=280, mode="determinate")
        self.progress.pack(side="right", padx=12, pady=4)

    # ------------------------
    # File handling
    # ------------------------
    def open_passwords_file(self):
        path = filedialog.askopenfilename(title="Open passwords file", filetypes=[("Text files","*.txt;*.list"),("All files","*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = [l.strip() for l in f if l.strip()]
            self.passwords = lines
            self.status_label.config(text=f"Loaded {len(lines)} passwords from {Path(path).name}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {e}")

    def open_common_file(self):
        path = filedialog.askopenfilename(title="Open common-password file", filetypes=[("Text files","*.txt;*.list"),("All files","*.*")])
        if not path:
            return
        try:
            s = set()
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for l in f:
                    p = l.strip()
                    if p:
                        s.add(p.lower())
            self.common_set = set(BUILTIN_COMMON)
            self.common_set.update(s)
            self.status_label.config(text=f"Loaded common list ({len(s)} entries) from {Path(path).name}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read common file: {e}")

    # ------------------------
    # Run analysis (threaded)
    # ------------------------
    def run_analysis(self):
        if not self.passwords:
            messagebox.showwarning("No passwords", "Please load a passwords file first.")
            return
        if self.analysis_thread and self.analysis_thread.is_alive():
            messagebox.showinfo("Working", "Analysis already running.")
            return

        # Clear table
        for r in self.tree.get_children():
            self.tree.delete(r)
        self.progress["value"] = 0
        self.progress["maximum"] = len(self.passwords)
        self.status_label.config(text="Starting analysis...")
        self.btn_run.config(state="disabled")
        self.btn_export_csv.config(state="disabled")
        self.btn_export_json.config(state="disabled")

        # Start background thread
        self.analysis_thread = threading.Thread(target=self._analysis_worker, daemon=True)
        self.analysis_thread.start()
        self.after(200, self._poll_results)

    def _analysis_worker(self):
        def progress_cb(i, total):
            self.result_queue.put(("progress", i, total))
        reports = analyze_passwords_list(self.passwords, self.common_set, progress_callback=progress_cb)
        self.result_queue.put(("done", reports))

    def _poll_results(self):
        try:
            while True:
                item = self.result_queue.get_nowait()
                if not item:
                    continue
                tag = item[0]
                if tag == "progress":
                    _, i, total = item
                    self.progress["value"] = i
                    self.status_label.config(text=f"Analyzing... {i}/{total}")
                elif tag == "done":
                    _, reports = item
                    self._on_analysis_done(reports)
        except Empty:
            if self.analysis_thread and self.analysis_thread.is_alive():
                self.after(150, self._poll_results)
            else:
                self.btn_run.config(state="normal")
                self.status_label.config(text="Ready")
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {e}")
            self.btn_run.config(state="normal")
            self.status_label.config(text="Ready")

    def _on_analysis_done(self, reports):
        for r in reports:
            issues_str = ", ".join(r["pattern_issues"]) if r["pattern_issues"] else ""
            row = (r["masked"], r["length"], r["entropy_bits"], r["grade"], issues_str, r["recommendation"])
            self.tree.insert("", "end", values=row, tags=(r["grade"],))
        stats = Counter(r['grade'] for r in reports)
        total = len(reports)
        self.status_label.config(text=f"Done: {total} passwords — Weak: {stats.get('Weak',0)}  Moderate: {stats.get('Moderate',0)}  Strong: {stats.get('Strong',0)}")
        self.progress["value"] = self.progress["maximum"]
        self.btn_run.config(state="normal")
        self.btn_export_csv.config(state="normal")
        self.btn_export_json.config(state="normal")
        self.last_reports = reports

    # ------------------------
    # Export
    # ------------------------
    def export_csv(self):
        if not getattr(self, "last_reports", None):
            messagebox.showwarning("No data", "No analysis results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")], title="Save CSV report")
        if not path:
            return
        keys = ["password","masked","length","entropy_bits","is_common","pattern_issues","score","grade","recommendation"]
        try:
            with open(path, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                for r in self.last_reports:
                    rr = r.copy()
                    rr["pattern_issues"] = ";".join(rr["pattern_issues"])
                    writer.writerow({k: rr.get(k, "") for k in keys})
            messagebox.showinfo("Saved", f"CSV exported to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save CSV: {e}")

    def export_json(self):
        if not getattr(self, "last_reports", None):
            messagebox.showwarning("No data", "No analysis results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")], title="Save JSON report")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.last_reports, f, indent=2, ensure_ascii=False)
            messagebox.showinfo("Saved", f"JSON exported to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save JSON: {e}")

# ------------------------
# Entry point
# ------------------------
def main():
    app = PasswordAuditorGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
