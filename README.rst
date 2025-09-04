# ICSREF (Python 3) — Installation & Setup

ICSREF was originally Python 2–based; this guide explains how to install and run it with **Python 3** on **Ubuntu/Debian**, **macOS**, and **Windows**. It also includes a ready-to-use `requirements.txt`.

---

## 0) Quick checklist

- Python **3.10+** (3.11 recommended)
- A C/C++ build toolchain (needed for some wheels)
- `radare2` (CLI) in your PATH
- `graphviz` and its headers (for `pygraphviz`)
- A virtual environment activated before pip installs

---

## 1) Ubuntu / Debian (Linux)

### 1.1 System packages

Some dependencies (like `radare2` and `graphviz`) are not pip-installable.

```bash
sudo apt update
sudo apt install -y   python3 python3-dev python3-venv python3-pip   build-essential   graphviz   libgraphviz-dev   pkg-config   git
```

### 1.2 Install radare2 (pick one)

- **APT (stable, may be older):**
  ```bash
  sudo apt install radare2
  ```
- **Snap (often newer):**
  ```bash
  sudo snap install radare2 --classic
  ```
- **From source (bleeding-edge):**
  ```bash
  git clone https://github.com/radareorg/radare2.git
  cd radare2
  sys/install.sh
  ```

**Verify installation:**
```bash
r2 -v
dot -V
```

---

## 2) macOS (Intel & Apple Silicon)

### 2.1 Install prerequisites (Homebrew)

If you don’t have Homebrew:
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Install packages:
```bash
brew install python@3.11 radare2 graphviz git
```

**Verify:**
```bash
r2 -v
dot -V
```

> Apple Silicon note: Homebrew usually installs under `/opt/homebrew`.

---

## 3) Windows 10/11

### 3.1 Install prerequisites

- **Python 3.10+**: https://www.python.org/downloads/windows/  
  During installation, check **“Add Python to PATH”**.
- **Git for Windows**: https://git-scm.com/download/win
- **Graphviz (MSI)**: https://graphviz.org/download/  
  During install, check **“Add Graphviz to the system PATH”**.
- **radare2 (zip release)**: https://github.com/radareorg/radare2/releases  
  Extract and **add the `bin/` folder to PATH**.

**Verify in PowerShell:**
```powershell
r2 -v
dot -V
```

---

## 4) Create & activate a virtual environment (all platforms)

```bash
cd /path/to/ICSREF
python3 -m venv venv

# Linux/macOS
source venv/bin/activate

# Windows (PowerShell)
.env\Scripts\Activate.ps1

python -V   # should show Python 3.x
pip install --upgrade pip setuptools wheel
```

---

## 5) Install Python dependencies

### Option A — Use the provided `requirements.txt` (recommended)
Save the `requirements.txt` from the section at the end of this document, then run:
```bash
pip install -r requirements.txt
```

### Option B — Install without pins
```bash
pip install r2pipe angr dill ujson pygraphviz cmd2 networkx pydot z3-solver
```

> **pygraphviz tips**
> - **Linux**: ensure `libgraphviz-dev` is installed (already in step 1.1).
> - **macOS**: if compilation fails, point to Homebrew paths:
>   ```bash
>   pip install pygraphviz >     --config-settings="--global-option=build_ext" >     --config-settings="--global-option=-I/opt/homebrew/include" >     --config-settings="--global-option=-L/opt/homebrew/lib"
>   ```
> - **Windows**: if needed, specify include/lib paths:
>   ```powershell
>   pip install pygraphviz `
>     --install-option="--include-path=C:\Program Files\Graphviz\include" `
>     --install-option="--library-path=C:\Program Files\Graphviz\lib"
>   ```

---

## 6) Verify your environment

```bash
python - <<'PY'
import sys, r2pipe, angr, dill, ujson, cmd2, pygraphviz
print("Python:", sys.version.split()[0])
print("ICSREF deps OK")
PY
```

Expected:
```
Python: 3.x.y
ICSREF deps OK
```

---

## 7) Run ICSREF

```bash
python icsref/icsref.py
```

You should see the prompt:
```
reversing@icsref:$
```

---

## 8) Troubleshooting

- **`r2 -v` / `dot -V` fails** → (Re)install `radare2` / Graphviz and ensure PATH is set.
- **`pygraphviz` build fails** → Install Graphviz **and** dev headers (Linux), or pass include/lib flags (macOS/Windows).
- **Z3 / Claripy errors** → Ensure `z3-solver` installed; sometimes `pip install --upgrade z3-solver` helps.
- **Multiple Pythons** → Make sure your venv is **activated** (check `python -V` and `which python` / `where python`).
- **`cmd2` complaints** → We removed old args (like `use_ipython`); ensure you’re on a modern `cmd2`.

---

## 9) Optional: check Python version inside venv

```bash
python --version
python -c "import sys; print(sys.executable)"
```
You should see the Python 3 version and an executable path **inside your project’s `venv/`**.

---

# requirements.txt

> **Note:** These pins are a reasonable starting point across platforms. If you hit platform-specific solver or wheel issues, loosen a pin (e.g., `angr` or `z3-solver`) and reinstall.

```
# Core
cmd2==2.4.3
dill==0.3.8
ujson==5.9.0

# Analysis stack
angr==9.2.90
z3-solver==4.12.5.0
r2pipe==1.8.0
networkx==3.2.1
pydot==2.0.0

# Graphing
pygraphviz==1.12
```

---

## Uninstall / Clean

To remove the venv:
```bash
deactivate  # if active
rm -rf venv  # Linux/macOS
rmdir /s /q venv  # Windows PowerShell
```

To remove generated results:
```bash
# from ICSREF console:
reversing@icsref:$ cleanup
```
