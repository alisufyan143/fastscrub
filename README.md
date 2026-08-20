# fastscrub 🚀

[![PyPI Version](https://img.shields.io/pypi/v/fastscrub.svg?color=007ec6)](https://pypi.org/project/fastscrub/)
[![Python Versions](https://img.shields.io/pypi/pyversions/fastscrub.svg)](https://pypi.org/project/fastscrub/)
[![CI - Multi-Platform Wheels](https://github.com/alisufyan143/fastscrub/actions/workflows/ci.yml/badge.svg)](https://github.com/alisufyan143/fastscrub/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A high-performance, zero-allocation **Personally Identifiable Information (PII)** and **Infrastructure Secrets** redaction engine for Python, powered by a vectorized C++20 backend.

`fastscrub` is engineered to solve a fundamental challenge in data pipelines and security compliance: **redacting tens of gigabytes or terabytes of messy production logs, database dumps, and unstructured text at wire speed without memory bloat or Python GIL lock contention.**

---

## 📦 Quick Installation

Install pre-compiled binary wheels directly from PyPI (Linux, macOS, Windows):

```bash
pip install fastscrub
```

*No C++ compiler required for wheel installs on x86_64 and ARM64 (Apple Silicon).*

---

## ⚡ 30-Second Quickstart

### 1. Basic Redaction (Mode A: Labeled Tokens)
Returns a safe, redacted string with descriptive `[REDACTED_*]` tags:

```python
from fastscrub import scrub

raw = "User 123-45-6789 connected from 192.168.1.50 with token ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8."
safe = scrub(raw)

print(safe)
# Output: "User [REDACTED_SSN] connected from [REDACTED_IP] with token [REDACTED_GITHUB_TOKEN]."
```

### 2. High-Throughput In-Place Redaction (Mode B: `*` Masking)
Directly mutates a Python `bytearray` in RAM. **Zero allocations, zero memory copying, maximum throughput.**

```python
from fastscrub import scrub_inplace

buf = bytearray(b"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.c2lnbmF0dXJl")
scrub_inplace(buf)

print(buf.decode("utf-8"))
# Output: "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.************************************"
```

### 3. Multi-Core Batch Processing
Drops the Python GIL and distributes lists of strings across all CPU cores in C++:

```python
from fastscrub import scrub_list

logs = [
    "Connection from 10.0.0.1 failed for user alice@corp.com",
    "Card charged: 4532-0150-1234-5678, phone: +1 (555) 234-5678",
    "Session 550e8400-e29b-41d4-a716-446655440000 used key AKIAIOSFODNN7EXAMPLE"
]

safe_logs = scrub_list(logs)
for line in safe_logs:
    print(line)
```

---

## 🌟 Key Highlights

* **Vectorized Center-Out SWAR Scanning**: Skips clean ASCII text 8 bytes per CPU cycle using 64-bit SIMD-Within-A-Register (SWAR) bit-twiddling and triggers center-out structural lookups on high-entropy punctuation anchors (`@`, `_`, `-`, `.`, `:`, `=`, `+`, `(`, `"`, `A`).
* **True Zero-Allocation In-Place Mutation (Mode B)**: Directly mutates Python `bytearray` buffers in RAM by overwriting sensitive positions with `*` while preserving buffer length and context structure. Zero heap allocations and zero sorting passes.
* **100+ MB/s End-to-End Throughput**: Processes a massive **30.3 GB real-world server log dataset (`Thunderbird.log`) in ~4.7 minutes** on modest quad-core consumer hardware, achieving **107.27 MB/s sustained throughput (peaking at 124.61 MB/s)**.
* **Genuine Industrial Ground-Truth Accuracy**: Evaluated across **137,026 third-party annotated documents** (AI4Privacy, Microsoft Presidio, TruffleHog), achieving **99.97% Precision**, **0.852 F1-Score**, and **0.783 F2-Score (PIIMB)**.
* **Overlap-Aware Multi-Core Concurrency**: Features an overlap-preserving chunking architecture (2048-byte boundary overlap) with native C++ worker thread pools that drop the Python GIL, guaranteeing large secrets (such as multi-hundred-byte JWTs or DB connection strings) are never fractured across thread splits.

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

## ⚡ Large-Scale Multi-Domain Throughput Matrix

Tested across **57.46 GB of real-world server logs** (Loghub repository) on an Intel Core i5-7200U (2 cores / 4 threads @ 2.50GHz - 3.10GHz), 16 GB RAM, NVMe SSD:

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

## 🛡️ Supported Detectors

### Infrastructure & Cloud Secrets
| Redaction Tag | Target Description & Prefix Rules |
|---|---|
| `[REDACTED_AWS_KEY]` | AWS Access Keys (`AKIA...`, `ASIA...`, `ABIA...`, `AROA...`, `AIDA...`) |
| `[REDACTED_GCP_KEY]` | Google Cloud Platform API Keys (`AIza...`) |
| `[REDACTED_GITHUB_TOKEN]` | GitHub Personal Access Tokens (`ghp_...`, `gho_...`, `github_pat_...`) |
| `[REDACTED_SLACK_TOKEN]` | Slack Bot & User Tokens (`xoxb-...`, `xoxp-...`, `xoxa-...`, `xoxr-...`, `xoxs-...`) |
| `[REDACTED_STRIPE_KEY]` | Stripe Live and Test API Keys (`sk_live_...`, `sk_test_...`, `pk_...`, `rk_...`) |
| `[REDACTED_JWT]` | JSON Web Tokens (`eyJ... . eyJ... . signature`) |
| `[REDACTED_PRIVATE_KEY]` | RSA, DSA, EC, and OpenSSH Private Key blocks (`-----BEGIN ... PRIVATE KEY-----`) |
| `[REDACTED_DB_CONN]` | Database Connection Strings (`postgres://`, `mysql://`, `mongodb://`, `redis://`, etc.) |
| `[REDACTED_SECRET]` | OpenAI (`sk-proj-`), Anthropic (`sk-ant-`), GitLab (`glpat-`), PyPI (`pypi-`), Vault (`hvs.`), HuggingFace (`hf_`), and Key-Value secrets (`api_key=`, `secret:`, `password=`) |

### Structural PII
| Redaction Tag | Target Description & Validation |
|---|---|
| `[REDACTED_EMAIL]` | RFC-compliant Email Addresses |
| `[REDACTED_IP]` | IPv4 & IPv6 Addresses (Standard and Compressed) |
| `[REDACTED_MAC]` | MAC Addresses (`00:1A:2B:3C:4D:5E` and `00-1A-2B-3C-4D-5E` formats) |
| `[REDACTED_UUID]` | UUIDs (v1 through v5, Case-Insensitive) |
| `[REDACTED_SSN]` | US Social Security Numbers & French NIR National IDs |
| `[REDACTED_PHONE]` | US and International E.164 Phone Numbers |
| `[REDACTED_CREDIT_CARD]` | Credit Card Numbers (**Strictly Luhn-checksum validated**) |

---

## 🔬 Architecture Deep-Dive

### 1. Vectorized Center-Out SWAR Scanning
Traditional regex engines inspect text character-by-character, suffering from branch mispredictions. `fastscrub` uses 64-bit integer registers to check 8 bytes simultaneously in 1 CPU cycle for key punctuation anchors (`@`, `_`, `-`, `.`, `:`, `=`, `+`, `(`, `"`, `A`).

### 2. 1-Cycle Fast Rejection Guards
Server logs contain millions of timestamps (`2026-08-20T10:15:30.123Z`) and snake_case variables. Recognizing `YYYY-` or `HH:` immediately leaps forward 5 bytes in 1 CPU cycle, bypassing all structural parsers on clean timestamps.

### 3. True Zero-Allocation Mode B In-Place Masking
When scrubbing mutable buffers (`bytearray`), worker threads overwrite `'*'` directly into their assigned memory slice during the scan pass. This completely avoids allocating `std::vector<PiiInterval>` objects and eliminates sorting passes.

---

## 🧪 Testing & Reproduction

```bash
# 1. Run the complete unit test suite (75 tests)
pytest tests/ -v

# 2. Run the Master Ground-Truth Leaderboard Benchmark (137k+ Docs)
python bench/eval_leaderboard.py --all

# 3. Run the Multi-Domain Large-Scale Loghub Throughput Matrix
python bench/benchmark_suite.py --all
```

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
