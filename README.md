# fastscrub 🚀

[![PyPI Version](https://img.shields.io/pypi/v/fastscrub.svg?color=007ec6)](https://pypi.org/project/fastscrub/)
[![Python Versions](https://img.shields.io/pypi/pyversions/fastscrub.svg)](https://pypi.org/project/fastscrub/)
[![CI - Multi-Platform Wheels](https://github.com/alisufyan143/fastscrub/actions/workflows/ci.yml/badge.svg)](https://github.com/alisufyan143/fastscrub/actions)
[![Docs](https://img.shields.io/badge/Docs-Live%20Site-blueviolet.svg)](https://alisufyan143.github.io/fastscrub/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A zero-allocation, SWAR-vectorized **Personally Identifiable Information (PII)** and **Infrastructure Secrets** redaction engine for Python with a C++20 core.

* **Sustained Wire-Speed Throughput**: **107.27 MB/s sustained (peaking at 144.33 MB/s)** on consumer dual-core hardware.
* **Large-Scale Log Ingestion**: Processed the entire **30.3 GB Thunderbird supercomputer dataset in ~4.7 minutes** with a flat memory footprint (<80 MB).
* **Industrial Accuracy**: Tested across **137,026 third-party annotated documents** (AI4Privacy, Presidio, TruffleHog), achieving **99.95% Precision** and a **0.858 F1-Score**.

---

## 🧪 The Origin Story: An Experiment in AI-Driven Systems Engineering

> **"I am a Python and AI/ML engineer. I do not write low-level C++ memory management by hand."**

This project did not start as an enterprise product roadmap. It started as an experiment to test the absolute boundaries of modern AI coding agents on **low-level systems engineering**.

Could a Python engineer acting purely as a **Systems Architect** guide an AI agent to design, implement, optimize, and ship an industrial-grade C++20 engine with zero-copy Python C-bindings, multi-platform CI/CD pipelines, and a global PyPI release?

### The Division of Labor

```mermaid
graph TD
    subgraph Human_Architect ["👤 Systems Architect (Human)"]
        A1["Algorithmic Direction: SWAR 64-bit vs. Regex"]
        A2["Cache & Concurrency: Overlap-Aware Chunking"]
        A3["Ground-Truth Benchmark Matrix Design"]
        A4["Pipeline Governance & Strict Verification"]
    end

    subgraph AI_Agent ["🤖 Low-Level Implementer (AI Agent)"]
        B1["C++20 Bitwise Math & Nanobind Bindings"]
        B2["Structural Parsers & Checksum Algorithms"]
        B3["CMakeLists & Multi-Platform GitHub Actions CI"]
        B4["PyPI Packaging & Wheel Matrix Automation"]
    end

    Human_Architect -->|Directs & Constrains| AI_Agent
```

* **The Human Role**: Systems design, cache awareness, selecting data structures, architecting zero-copy memory paths, defining benchmark matrices, and catching low-level architecture traps.
* **The AI Role**: Rapid C++20 syntax generation, `nanobind` glue code, bitwise mask implementations, CMake build scaffolding, and multi-platform CI/CD automation.

---

## 🛠️ The Engineering Hurdles: Where AI Failed & How We Fixed It

Let’s be brutally honest about AI code generation: **LLMs are fantastic at syntax and boilerplate, but naturally terrible at hardware mechanical sympathy and cache awareness.** 

Left to its own devices, the AI produced code that compiled cleanly but performed terribly. Here is how architectural intervention turned it into a 100+ MB/s engine:

### 1. The Regex & Character-Loop Trap
* **The AI's Default**: The agent initially generated standard regex wrappers and single-byte `for`-loops. On gigabyte-scale inputs, this caused branch mispredictions and trashed the L1 CPU instruction cache, bottlenecking throughput at <15 MB/s.
* **The Architectural Fix**: We banned regex entirely and forced the agent to implement **64-bit SWAR (SIMD-Within-A-Register)**. The engine loads 8 bytes into a `uint64_t` register, running parallel bitwise tests `(x - 0x01...) & ~x & 0x80...` to skip clean text 8 bytes per CPU cycle and trigger center-out parsers only on structural punctuation anchors (`@`, `_`, `-`, `.`, `:`, `=`, `+`, `(`, `"`, `A`).

### 2. Timestamp Noise & False Positive Thrashing
* **The AI's Default**: Production server logs contain millions of timestamps (`2026-08-21T04:15:30.123Z`) and snake_case variable names. The AI's initial parsers fired expensive checks on every `-` and `.`, collapsing performance.
* **The Architectural Fix**: We designed a **1-cycle fast rejection guard**. When the scanner encounters `YYYY-` or `HH:`, it executes a 5-byte leap in a single cycle, bypassing all structural parsers on benign timestamps.

### 3. The Multi-Threaded Chunk Boundary Cut
* **The AI's Default**: When multi-threading large strings, the agent split the buffer evenly across threads. This created a critical security flaw: long tokens (e.g. 300-byte JWTs or DB connection URIs) landing directly on a split boundary were cut in half and missed entirely.
* **The Architectural Fix**: We enforced an **overlap-aware chunking protocol**. Every thread receives a 2,048-byte lookahead overlap into the adjacent slice, followed by a deterministic deduplication pass (`merge_intervals`), guaranteeing zero secret fracture without the Python GIL.

### 4. AppleClang & macOS Stable ABI Portability
* **The AI's Default**: The agent wrote `std::jthread` (which AppleClang’s standard library has not yet stabilized) and used private CPython macros (`PyByteArray_AS_STRING`) that failed against Apple's `darwin-ld-cpython.sym` link table.
* **The Architectural Fix**: We audited the symbol tables, replaced `std::jthread` with portable `std::thread` worker joins, and migrated private macros to official Python Stable ABI functions (`PyByteArray_AsString`).

---

## 📊 Ground-Truth Benchmark Results

`fastscrub` was evaluated on **137,026 genuine third-party annotated documents and industrial secret test suites**, following the official **HuggingFace PII Masking Benchmark (PIIMB)** evaluation standard:

### 1. Master Leaderboard Matrix

```text
=========================================================================================================
                 FASTSCRUB MASTER GROUND-TRUTH ACCURACY & SPEED MATRIX
=========================================================================================================
 Benchmark Dataset            |     Docs |     TP |    FP |    FN | Precision |   Recall |     F1 | F2 (PIIMB) | Throughput
---------------------------------------------------------------------------------------------------------
 AI4Privacy English (43k)     |   43,501 |  15,532|     0 |  6,764|   100.00% |   69.66% |  0.821 |      0.742 |   46.55 MB/s
 AI4Privacy French (62k)      |   61,958 |  21,285|     0 | 10,537|   100.00% |   66.89% |  0.802 |      0.716 |   46.71 MB/s
 AI4Privacy OpenPII (30k)     |   29,908 |  24,648|     0 |  2,855|   100.00% |   89.62% |  0.945 |      0.915 |   54.97 MB/s
 Microsoft Presidio (v2)      |    1,500 |     134|     0 |    194|   100.00% |   40.85% |  0.580 |      0.463 |    5.03 MB/s
 TruffleHog (25 Detectors)    |      159 |      80|    30 |     24|    72.73% |   76.92% |  0.748 |      0.760 |    8.98 MB/s
---------------------------------------------------------------------------------------------------------
 OVERALL MASTER BENCHMARK     |  137,026 |  61,679|    30 | 20,374|    99.95% |   75.17% |  0.858 |      0.791 |   49.05 MB/s
=========================================================================================================
```

---

### 2. Entity-by-Entity Accuracy Breakdown

| Entity Category | Target Description | True Positives (TP) | False Negatives (FN) | Recall | Status & Technical Analysis |
|---|---|---|---|---|---|
| **`IP_ADDRESS`** | IPv4 & IPv6 addresses | **25,109** | 42 | **99.83%** | 🏆 **Near-Perfect**: Handles standard and compressed notations. |
| **`EMAIL`** | RFC 5322 email addresses | **19,029** | 72 | **99.62%** | 🏆 **Near-Perfect**: Near zero misses across EN and FR corpora. |
| **`PHONE`** | E.164 & local phone numbers | **8,517** | 2,165 | **79.73%** | ⚡ **High**: Supports international dial codes, dashes, dots, and parenthesized area codes. |
| **`SSN`** | US SSN & French NIR IDs | **8,692** | 6,302 | **57.97%** | 🔍 **International Scope**: Handles US SSN (XXX-XX-XXXX) and French NIR (13-15 digits starting with 1/2). |
| **`CREDIT_CARD`** | Payment Card Numbers | **28** | 5,564 | **0.50%** | 🛡️ **Strict Luhn Checksum**: AI4Privacy synthetic cards are mathematically invalid numbers (`5890...`) that fail Luhn checksum. |
| **`INFRA_SECRET`** | Cloud keys, DB URIs, JWTs | **224** | 6,205 | **3.48%** | 🛡️ **Entropy Guarded**: AI4Privacy labels plain dictionary words (`"monkey123"`) as `PASSWORD`. FastScrub requires high entropy to avoid false alarms. |

---

### 3. TruffleHog Cloud & Infrastructure Secrets Matrix

Evaluated on **159 verified test vectors** from TruffleHog's official Go detector test suites:

| Detector | Category | True Secrets (TP) | Missed (FN) | False Traps (FP) | Recall |
|---|---|---|---|---|---|
| **OpenAI API Keys (`openai`)** | AI / LLM Tokens | **5** | 0 | 0 | **100.00%** |
| **OpenAI Admin Keys (`openaiadmin`)** | AI / LLM Tokens | **4** | 0 | 5 | **100.00%** |
| **Anthropic Claude Keys (`anthropic`)** | AI / LLM Tokens | **2** | 0 | 1 | **100.00%** |
| **HuggingFace Tokens (`huggingface`)** | AI Platforms | **1** | 0 | 0 | **100.00%** |
| **PyPI Upload Tokens (`pypi`)** | Package Manager | **1** | 0 | 0 | **100.00%** |
| **AWS Access Keys (`accesskey`)** | Cloud Primitives | **3** | 0 | 1 | **100.00%** |
| **Google Cloud (`gcp`)** | Cloud Primitives | **6** | 0 | 0 | **100.00%** |
| **GitHub Tokens (`github`)** | Code & CI/CD | **1** | 0 | 0 | **100.00%** |
| **GitLab Tokens (`gitlab`)** | Code & CI/CD | **1** | 0 | 0 | **100.00%** |
| **GitLab OAuth2 (`gitlaboauth2`)** | Code & CI/CD | **3** | 1 | 3 | **75.00%** |
| **Docker Hub (`dockerhub`)** | Containers | **2** | 0 | 0 | **100.00%** |
| **HashiCorp Vault Auth (`hashicorpvaultauth`)** | Secrets Management | **4** | 0 | 6 | **100.00%** |
| **HashiCorp Vault Batch (`hashicorpvaultbatchtoken`)** | Secrets Management | **2** | 0 | 1 | **100.00%** |
| **Datadog API Keys (`datadogapikey`)** | Monitoring | **1** | 0 | 1 | **100.00%** |
| **MongoDB URIs (`mongodb`)** | Database | **26** | 0 | 3 | **100.00%** |
| **PostgreSQL URIs (`postgres`)** | Database | **7** | 2 | 1 | **77.78%** |
| **Private Keys (`privatekey`)** | Cryptography | **3** | 1 | 0 | **75.00%** |
| **NPM Tokens (`npmtoken`)** | Package Manager | **3** | 1 | 1 | **75.00%** |
| **Stripe Keys (`stripe`)** | Fintech | **2** | 1 | 0 | **66.67%** |

---

### 4. Large-Scale Multi-Domain Throughput Matrix

Tested across **57.46 GB of real-world uncompressed server logs** (Loghub repository) on an Intel Core i5-7200U (2 cores / 4 threads @ 2.50GHz - 3.10GHz), 16 GB RAM, NVMe SSD:

| Dataset Name | Domain / Log Category | Size (MB) | Throughput | Peak Speed | Probe Recall |
|---|---|---|---|---|---|
| **Kaggle Student Essays** | Academic PII NLP | **104.42 MB** | **321.45 MB/s** | **322.01 MB/s** | **100.00%** |
| **Apache Web Server** | Web & HTTP Access Logs | **4.90 MB** | **118.86 MB/s** | **118.86 MB/s** | **100.00%** |
| **OpenPII Corpus** | Unstructured Document NLP | **98.04 MB** | **116.94 MB/s** | **119.86 MB/s** | **100.00%** |
| **Apple macOS System** | macOS Operating System | **16.10 MB** | **101.51 MB/s** | **101.51 MB/s** | **100.00%** |
| **Thunderbird HPC** | Supercomputer System Logs | **30,315.69 MB** | **95.42 MB/s** | **144.33 MB/s** | **100.00%** |
| **OpenSSH Auth Logs** | Auth & Network Security | **70.02 MB** | **94.21 MB/s** | **96.96 MB/s** | **100.00%** |
| **Hadoop HDFS Cluster** | Distributed Big Data | **1,504.88 MB** | **85.86 MB/s** | **106.03 MB/s** | **100.00%** |
| **Linux Kernel & Syslog** | Linux Operating System | **2.24 MB** | **74.95 MB/s** | **74.95 MB/s** | **100.00%** |
| **Windows Security Events** | Enterprise Windows Logs | **26,714.99 MB** | **72.76 MB/s** | **76.11 MB/s** | **100.00%** |

---

## ⚠️ Project Status & Disclaimer

> **This is an open-source portfolio project and systems engineering learning experiment.**

* **Usability**: The binary wheels on PyPI are fully functional, high-performance, and tested with 75 unit tests and 137k+ benchmark documents.
* **Maintenance Notice**: Because C++ systems programming is not my primary stack, this library is **not actively maintained with enterprise SLA or production support**.
* **Open Source Spirit**: You are warmly encouraged to use it in your pipelines, inspect the SWAR vectorization algorithms, learn from the architecture, and fork/extend it for your own needs.

---

## 📦 Developer Quickstart

### 1. Installation

Install the pre-compiled wheel from PyPI:

```bash
pip install fastscrub
```

*Pre-compiled wheels are available for Linux (`x86_64`), Windows (`x86_64`), and macOS (Apple Silicon `arm64` & Intel `x86_64`) on Python 3.10 through 3.13.*

---

### 2. Usage Modes

#### Mode A: Labeled Token Replacement (`scrub`)
```python
from fastscrub import scrub

raw = "User 123-45-6789 connected from 192.168.1.50 with token ghp_YOUR_GITHUB_TOKEN."
safe = scrub(raw)

print(safe)
# Output: "User [REDACTED_SSN] connected from [REDACTED_IP] with token [REDACTED_GITHUB_TOKEN]."
```

#### Mode B: Zero-Allocation In-Place Mutation (`scrub_inplace`)
Directly mutates a Python `bytearray` in RAM with zero heap allocations:
```python
from fastscrub import scrub_inplace

buf = bytearray(b"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature")
scrub_inplace(buf)

print(buf.decode("utf-8"))
# Output: "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.************************************"
```

#### Mode C: Zero-GIL Multi-Core Batch Lists (`scrub_list`)
```python
from fastscrub import scrub_list

logs = [
    "Connection from 10.0.0.1 failed for user alice@corp.com",
    "Card charged: 4532-0150-1234-5678, phone: +1 (555) 234-5678",
    "Session initialized with AWS key AKIAIOSFODNN7EXAMPLE"
]

# Drops Python GIL and parallelizes across all CPU cores in C++
safe_logs = scrub_list(logs)
for line in safe_logs:
    print(line)
```

---

## 📖 Comprehensive Documentation

For the full architectural guide, detector specifications, and big data streaming patterns, check out our live documentation site:

👉 **[https://alisufyan143.github.io/fastscrub/](https://alisufyan143.github.io/fastscrub/)**

---

## 🧪 Testing & Benchmark Reproduction

```bash
# 1. Run unit tests
pytest tests/ -v

# 2. Reproduce the 137k+ ground-truth benchmark matrix
python bench/eval_leaderboard.py --all

# 3. Reproduce the 57 GB multi-domain throughput matrix
python bench/benchmark_suite.py --all
```

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
