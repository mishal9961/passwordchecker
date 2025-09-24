# 🔐 Password Auditor — GUI Tool

A safe, user-friendly password analysis tool that **audits** password strength, patterns, and entropy — **without attempting to crack or guess passwords**.

> ✅ Defensive Only — No cracking, no brute-force, no leaks used.

---

## 🖥️ Features

- Beautiful and responsive **Tkinter GUI**
- Analyzes passwords for:
  - **Length**
  - **Entropy (bits)**
  - **Common patterns** (keyboard, repeated characters, etc.)
  - **Weak/common passwords**
- Grades each password: `Weak`, `Moderate`, or `Strong`
- Supports:
  - `.txt` or `.list` files with one password per line
  - Optional common password lists
- Export results as **CSV** or **JSON**
- Built-in animated UI header and themed interface

---

## 📦 Requirements

- Python **3.7+**
- No third-party dependencies (pure `tkinter`, `math`, `csv`, `json`, etc.)

---

## 🚀 Getting Started

### 1. Clone the Repo

```bash
git clone https://github.com/yourusername/password-auditor-gui.git
cd password-auditor-gui
