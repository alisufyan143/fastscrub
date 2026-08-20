# Installation Guide 📦

`fastscrub` is distributed as pre-compiled binary wheels on PyPI for all major platforms and Python versions.

---

## 1. Standard Installation (Recommended)

Install the latest release directly via `pip`:

```bash
pip install --upgrade fastscrub
```

### Supported Platforms & Architectures

| Operating System | Architecture | Python Versions | Binary Wheel Format |
|---|---|---|---|
| **Linux** | `x86_64` | 3.10, 3.11, 3.12, 3.13 | `manylinux_2_28`, `musllinux_1_2` |
| **Windows** | `x86_64` (AMD64) | 3.10, 3.11, 3.12, 3.13 | `win_amd64` |
| **macOS** | Apple Silicon (`arm64`) | 3.10, 3.11, 3.12, 3.13 | `macosx_10_13_arm64` |
| **macOS** | Intel (`x86_64`) | 3.10, 3.11, 3.12, 3.13 | `macosx_10_13_x86_64` |

*No C++ compiler or build tools are needed when installing pre-compiled wheels.*

---

## 2. Building from Source

If you are on a specialized architecture (such as RISC-V or ARM Linux) or contributing to `fastscrub` development, you can build from source.

### Requirements
* **Python**: `3.10` or newer
* **CMake**: `3.20` or newer
* **C++ Compiler**: A compiler supporting **C++20**:
    * GCC 10+
    * Clang 10+ / AppleClang 15+
    * MSVC 19.29+ (Visual Studio 2019 / 2022)
* **Ninja** (optional, recommended for fast builds)

### Step-by-Step Build Commands

```bash
# 1. Clone the repository
git clone https://github.com/alisufyan143/fastscrub.git
cd fastscrub

# 2. Install build dependencies
pip install scikit-build-core nanobind pytest

# 3. Build and install locally (in-place development mode)
pip install --no-build-isolation -ve .

# 4. Verify installation by running the test suite
pytest tests/ -v
```

---

## 3. Verifying Installation

Run a quick Python command to verify that the C++ backend compiled and loaded successfully:

```bash
python -c "import fastscrub; print('fastscrub version:', fastscrub.__version__); print('Backend Engine:', fastscrub.Engine)"
```

Expected output:
```text
fastscrub version: 0.1.3
Backend Engine: <class 'fastscrub_backend.Engine'>
```
