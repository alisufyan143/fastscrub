# fastscrub 🚀

A radically high-performance, zero-allocation Personally Identifiable Information (PII) and Infrastructure Secrets redaction engine for Python, powered by a vectorized C++20 backend.

`fastscrub` is engineered to solve a fundamental challenge in data engineering and security compliance: **redacting tens of gigabytes or terabytes of messy production logs, database dumps, and unstructured text at wire speed without memory bloat or Python GIL lock contention.**

---

## 🌟 Key Highlights

* **Vectorized Center-Out SWAR Scanning**: Skips clean ASCII text 8 bytes per CPU cycle using 64-bit SIMD-Within-A-Register (SWAR) bit-twiddling and triggers center-out structural lookups on high-entropy punctuation anchors (`@`, `_`, `-`, `.`, `:`, `=`, `+`, `(`, `"`, `A`).
* **True Zero-Allocation In-Place Mutation (Mode B)**: Directly mutates Python `bytearray` buffers in RAM by overwriting sensitive positions with `*` while preserving buffer length and context structure. Zero heap allocations and zero sorting passes.
* **100+ MB/s End-to-End Throughput**: Processes a massive **30.3 GB real-world server log dataset (`Thunderbird.log`) in ~4.7 minutes** on modest quad-core consumer hardware, achieving **107.27 MB/s sustained throughput (peaking at 124.61 MB/s)**.
* **Genuine Industrial Ground-Truth Accuracy**: Evaluated across **137,026 third-party annotated documents** (AI4Privacy, Microsoft Presidio, TruffleHog), achieving **99.97% Precision**, **0.852 F1-Score**, and **0.783 F2-Score (PIIMB)**.
* **Overlap-Aware Multi-Core Concurrency**: Features an overlap-preserving chunking architecture (2048-byte boundary overlap) with native `std::jthread` worker pools that drops the Python GIL, guaranteeing large secrets (such as multi-hundred-byte JWTs or DB connection strings) are never fractured across thread splits.

---

## 📊 Industrial Ground-Truth Leaderboard Results

`fastscrub` was evaluated on **137,026 genuine third-party annotated documents and industrial secret test suites**, following the official **HuggingFace PII Masking Benchmark (PIIMB)** evaluation standard:

### 1. Master Leaderboard Matrix

```text
=========================================================================================================
                 FASTSCRUB MASTER GROUND-TRUTH ACCURACY & SPEED MATRIX
=========================================================================================================
 Benchmark Dataset            |     Docs |     TP |    FP |    FN | Precision |   Recall |     F1 | F2 (PIIMB) | Throughput
---------------------------------------------------------------------------------------------------------
 AI4Privacy English (43k)     |   43,501 |  15,486|     0 |  6,810|   100.00% |   69.46% |  0.820 |      0.740 |   52.39 MB/s
 AI4Privacy French (62k)      |   61,958 |  21,220|     0 | 10,602|   100.00% |   66.68% |  0.800 |      0.714 |   41.73 MB/s
 AI4Privacy OpenPII (30k)     |   29,908 |  24,034|     0 |  3,469|   100.00% |   87.39% |  0.933 |      0.896 |   54.31 MB/s
 Microsoft Presidio (v2)      |    1,500 |     131|     0 |    197|   100.00% |   39.94% |  0.571 |      0.454 |    5.85 MB/s
 TruffleHog (25 Detectors)    |      159 |      65|    21 |     39|    75.58% |   62.50% |  0.684 |      0.647 |   17.60 MB/s
---------------------------------------------------------------------------------------------------------
 OVERALL MASTER BENCHMARK     |  137,026 |  60,936|    21 | 21,117|    99.97% |   74.26% |  0.852 |      0.783 |   47.94 MB/s
=========================================================================================================
```

---

### 2. Entity-by-Entity Accuracy Breakdown

| Entity Category | Target Description | True Positives (TP) | False Negatives (FN) | Recall | Status & Technical Analysis |
|---|---|---|---|---|---|
| **`IP_ADDRESS`** | IPv4 & IPv6 addresses | **25,109** | 42 | **99.83%** | 🏆 **Near-Perfect**: Handles standard and compressed notations. |
| **`EMAIL`** | RFC 5322 email addresses | **19,029** | 72 | **99.62%** | 🏆 **Near-Perfect**: Near zero misses across EN and FR corpora. |
| **`PHONE`** | E.164 & local phone numbers | **8,515** | 2,167 | **79.71%** | ⚡ **High**: Misses some local French dot-separated formats. |
| **`SSN`** | US Social Security Numbers | **7,967** | 7,027 | **53.13%** | 🔍 **US Scope**: AI4Privacy labels 13-digit French NIRs as `SSN`. |
| **`CREDIT_CARD`** | Payment Card Numbers | **27** | 5,565 | **0.48%** | 🛡️ **Strict Luhn Checksum**: AI4Privacy synthetic cards are mathematically invalid numbers (`5890...`) that fail Luhn checksum. |
| **`INFRA_SECRET`** | Cloud keys, DB URIs, JWTs | **224** | 6,205 | **3.48%** | 🛡️ **Entropy Guarded**: AI4Privacy labels plain dictionary words (`"monkey123"`) as `PASSWORD`. FastScrub requires high entropy to avoid false alarms. |

---

### 3. TruffleHog Cloud & Infrastructure Secrets Matrix

Evaluated on **159 verified test vectors** from TruffleHog's official Go detector test suites:

| Detector | Category | True Secrets (TP) | Missed (FN) | False Traps (FP) | Recall |
|---|---|---|---|---|---|
| **AWS Access Keys (`accesskey`)** | Cloud Primitives | **3** | 0 | 1 | **100.00%** |
| **Google Cloud (`gcp`)** | Cloud Primitives | **6** | 0 | 0 | **100.00%** |
| **GitHub Tokens (`github`)** | Code & CI/CD | **1** | 0 | 0 | **100.00%** |
| **GitLab Tokens (`gitlab`)** | Code & CI/CD | **1** | 0 | 0 | **100.00%** |
| **Docker Hub (`dockerhub`)** | Containers | **2** | 0 | 0 | **100.00%** |
| **HuggingFace (`huggingface`)** | AI Platforms | **1** | 0 | 0 | **100.00%** |
| **MongoDB URIs (`mongodb`)** | Database | **26** | 0 | 2 | **100.00%** |
| **PostgreSQL URIs (`postgres`)** | Database | **7** | 2 | 1 | **77.78%** |
| **Private Keys (`privatekey`)** | Cryptography | **3** | 1 | 0 | **75.00%** |
| **NPM Tokens (`npmtoken`)** | Package Manager | **3** | 1 | 1 | **75.00%** |
| **Stripe Keys (`stripe`)** | Fintech | **1** | 2 | 0 | **33.33%** |
| **OpenAI / Anthropic Keys** | LLM API Keys | 0 | 9 | 0 | 🔄 *Next release roadmap* |

---

## ⚡ Large-Scale Multi-Domain Throughput Matrix

Tested across **61.64 GB of real-world server logs** (Loghub repository) on an Intel Core i5-7200U (2 cores / 4 threads @ 2.50GHz - 3.10GHz), 16 GB RAM, 256 GB NVMe SSD:

| Dataset Name | Domain / Log Category | Size (MB) | Throughput | Peak Speed | Secret Recall |
|---|---|---|---|---|---|
| **Thunderbird** | Supercomputer System Logs | **30,315.69 MB** | **107.27 MB/s** | **124.61 MB/s** | **100.00%** |
| **Windows OS** | Windows Server Event Logs | **26,715.00 MB** | **104.18 MB/s** | **121.50 MB/s** | **100.00%** |
| **HDFS Logs** | Hadoop Distributed File System | **1,504.88 MB** | **98.45 MB/s** | **116.20 MB/s** | **100.00%** |
| **OpenSSH Logs** | Network Auth & Security | **70.02 MB** | **111.87 MB/s** | **113.28 MB/s** | **100.00%** |
| **Mac OS Logs** | macOS Kernel & Syslog | **16.10 MB** | **94.22 MB/s** | **94.22 MB/s** | **100.00%** |
| **Apache ZooKeeper**| Distributed Coordination | **9.94 MB** | **92.40 MB/s** | **92.40 MB/s** | **100.00%** |
| **Apache HTTP** | Web Server Access Logs | **4.90 MB** | **125.98 MB/s** | **125.98 MB/s** | **100.00%** |
| **Linux Kernel** | Linux Operating System | **2.24 MB** | **71.14 MB/s** | **71.14 MB/s** | **100.00%** |

---

## 🔬 How It Works: Architectural Deep-Dive

### 1. Vectorized Center-Out SWAR Scanning
Traditional regex engines inspect text character-by-character, suffering from branch mispredictions and catastrophic backtracking. `fastscrub` uses 64-bit integer registers to check 8 bytes simultaneously in 1 CPU cycle for key punctuation anchors:
* `@` $\rightarrow$ Emails
* `_` $\rightarrow$ GitHub tokens (`ghp_`), Stripe keys (`sk_live_`)
* `-` $\rightarrow$ Private key blocks (`-----`), Slack tokens (`xoxb-`), UUIDs, SSNs, MAC addresses
* `.` $\rightarrow$ JWTs (`eyJ...`), IPv4 addresses
* `:` $\rightarrow$ Database connection strings (`postgresql://`), IPv6, MAC addresses
* `A` $\rightarrow$ Floating AWS access keys (`AKIA`, `ASIA`, `ABIA`, `AROA`, `AIDA`)

### 2. 1-Cycle Fast Rejection Guards & 1-Leap Bypasses
Server logs contain millions of timestamps (`2026-08-20T10:15:30.123Z`) and snake_case variables. To prevent false parser stops:
* **ISO8601 1-Leap Bypass**: Recognizing `YYYY-` or `HH:` immediately leaps forward 5 bytes in 1 CPU cycle, bypassing all structural parsers on clean timestamps.
* **Direct Token Extraction in `has_context_word`**: Key-value secrets (`password:`, `secret=`, `api_key=`) extract only the single preceding token and validate length (`5 <= len <= 14`) before equality checks, completely eliminating millions of sliding-window substring searches.
* **Anchor Guards**: `.` only invokes `parse_jwt` if preceded by `eyJ`, and `:` only invokes `parse_connection_string` if followed by `://`.

### 3. True Zero-Allocation Mode B In-Place Masking
When scrubbing mutable buffers (`bytearray`), worker threads overwrite `'*'` directly into their assigned memory slice during the scan pass. This completely avoids allocating `std::vector<PiiInterval>` objects and eliminates sorting hundreds of thousands of interval objects per chunk.

---

## 🛡️ Supported Detectors

### Infrastructure Secrets
| Redaction Tag | Target Description & Prefix Rules |
|---|---|
| `[REDACTED_AWS_KEY]` | AWS Access Keys (`AKIA...`, `ASIA...`, `ABIA...`, `AROA...`, `AIDA...`) |
| `[REDACTED_GCP_KEY]` | Google Cloud Platform API Keys (`AIza...`) |
| `[REDACTED_GITHUB_TOKEN]` | GitHub Personal Access Tokens (`ghp_...`, `gho_...`, `github_pat_...`) |
| `[REDACTED_SLACK_TOKEN]` | Slack Bot & User Tokens (`xoxb-...`, `xoxp-...`, `xoxa-...`, `xoxr-...`) |
| `[REDACTED_STRIPE_KEY]` | Stripe Live and Test API Keys (`sk_live_...`, `sk_test_...`, `pk_...`, `rk_...`) |
| `[REDACTED_JWT]` | JSON Web Tokens (`eyJ... . eyJ... . signature`) |
| `[REDACTED_PRIVATE_KEY]` | RSA, DSA, EC, and OpenSSH Private Key blocks (`-----BEGIN ... PRIVATE KEY-----`) |
| `[REDACTED_DB_CONN]` | Database Connection Strings (`postgres://`, `mysql://`, `mongodb://`, `redis://`, etc.) |
| `[REDACTED_SECRET]` | High-entropy Key-Value secrets (`api_key=`, `secret:`, `password=`, `token:`, etc.) |

### Structural PII
| Redaction Tag | Target Description & Validation |
|---|---|
| `[REDACTED_EMAIL]` | RFC-compliant Email Addresses |
| `[REDACTED_IP]` | IPv4 & IPv6 Addresses (Standard and Compressed) |
| `[REDACTED_MAC]` | MAC Addresses (`00:1A:2B:3C:4D:5E` and `00-1A-2B-3C-4D-5E` formats) |
| `[REDACTED_UUID]` | UUIDs (v1 through v5, Case-Insensitive) |
| `[REDACTED_SSN]` | US Social Security Numbers (Hyphenated and Continuous) |
| `[REDACTED_PHONE]` | US and International E.164 Phone Numbers |
| `[REDACTED_CREDIT_CARD]` | Credit Card Numbers (**Strictly Luhn-checksum validated**) |

---

## 📦 Installation

`fastscrub` requires **Python 3.10+** and a **C++20** compatible compiler (GCC 10+, Clang 10+, or MSVC 19.29+).

```bash
# Clone the repository
git clone https://github.com/alisufyan143/fastscrub.git
cd fastscrub

# Build and install the wheel locally
pip install .
```

---

## 💻 Python Usage

### 1. Single String Scrubbing (Mode A: Labeled Replacement)
Returns a new redacted string with explicit `[REDACTED_*]` labels.

```python
from fastscrub import scrub

text = "User account 123-45-6789 created by admin@example.com with session 550e8400-e29b-41d4-a716-446655440000."
safe_text = scrub(text)
print(safe_text)
# Output: "User account [REDACTED_SSN] created by [REDACTED_EMAIL] with session [REDACTED_UUID]."
```

### 2. Zero-Allocation In-Place Mutation (Mode B: `*` Masking)
Directly mutates a Python `bytearray` in RAM by overwriting sensitive positions with `*`. Preserves buffer length and context.

```python
from fastscrub import scrub_inplace

buf = bytearray(b"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.c2lnbmF0dXJl")
scrub_inplace(buf)

print(buf.decode('utf-8'))
# Output: "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.************************************"
```

### 3. Concurrent Batch Processing
Drops the Python GIL and distributes lists of strings across all available CPU worker threads.

```python
from fastscrub import scrub_list

logs = [
    "Connection from 192.168.1.100 failed for user alice@corp.com",
    "Payment processed for card 4532-0150-1234-5678, phone: +1 (555) 234-5678",
    "Session 550e8400-e29b-41d4-a716-446655440000 loaded AWS key AKIAIOSFODNN7EXAMPLE"
]

safe_logs = scrub_list(logs)
for log in safe_logs:
    print(log)
```

---

## 🧪 Testing & Reproduction Commands

```powershell
# 1. Run the complete unit test suite (70/70 tests)
python -m pytest tests/ -v

# 2. Run the Master Ground-Truth Leaderboard Benchmark (137k+ Docs)
python bench/eval_leaderboard.py --all

# 3. Run the Multi-Domain Large-Scale Loghub Throughput Matrix
python bench/benchmark_suite.py --all
```

---

## 📄 License

MIT License.
