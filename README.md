# fastscrub 🚀

A radically high-performance, zero-allocation Personally Identifiable Information (PII) and Infrastructure Secrets redaction engine for Python, powered by a vectorized C++20 backend.

`fastscrub` is engineered to solve a fundamental challenge in data engineering and security compliance: **redacting tens of gigabytes or terabytes of messy production logs, database dumps, and unstructured text at wire speed without memory bloat or Python GIL lock contention.**

---

## 🌟 Key Highlights

* **Vectorized Center-Out SWAR Scanning**: Skips clean ASCII text 8 bytes per CPU cycle using 64-bit SIMD-Within-A-Register (SWAR) bit-twiddling and triggers center-out structural lookups on high-entropy punctuation anchors (`@`, `_`, `-`, `.`, `:`, `=`, `+`, `(`, `"`, `A`).
* **True Zero-Allocation In-Place Mutation (Mode B)**: Directly mutates Python `bytearray` buffers in RAM by overwriting sensitive positions with `*` while preserving buffer length and context structure. Zero heap allocations and zero sorting passes.
* **100+ MB/s End-to-End Throughput**: Processes a massive **30.3 GB real-world server log dataset (`Thunderbird.log`) in ~4.7 minutes** on modest quad-core consumer hardware, achieving **107.27 MB/s sustained throughput (peaking at 124.61 MB/s)**.
* **100.00% Recall on Ground-Truth Datasets**: Successfully detected **47,400 out of 47,400** secrets injected across 30.3 GB of logs, with **0% false positives** on high-entropy noise traps and full Luhn validation on credit card numbers.
* **Overlap-Aware Multi-Core Concurrency**: Features an overlap-preserving chunking architecture (2048-byte boundary overlap) with native `std::jthread` worker pools that drops the Python GIL, guaranteeing large secrets (such as multi-hundred-byte JWTs or DB connection strings) are never fractured across thread splits.

---

## 📊 Benchmark Results

### 1. Large-Scale 30.3 GB Production Benchmark (`Thunderbird.log`)
Tested on an Intel Core i5-7200U (2 physical cores / 4 threads @ 2.50GHz - 3.10GHz), 16 GB RAM, 256 GB NVMe SSD:

```text
===============================================================
           FASTSCRUB 30.3 GB PYTHON BENCHMARK
===============================================================
[*] Dataset Size      : 30,315.69 MB (30.3 GB)
[*] Chunk Size        : 64.00 MB
[*] Boundary Safe     : 2048 bytes overlap retained per chunk
---------------------------------------------------------------
[Progress] 100% (30316 MB) - Peak Speed: 124.61 MB/s
---------------------------------------------------------------
Total CPU Time        : 282.60 seconds (~4.7 minutes)
Sustained Throughput  : 107.27 MB/s
True Positives        : 47,400 / 47,400 secrets
Recall Rate           : 100.00%
===============================================================
```

### 2. Performance Engineering Progression

| Milestone / Optimization Stage | 30.3 GB Time | Throughput | Peak Speed | Secret Recall (TruffleHog) | Unit Tests |
|---|---|---|---|---|---|
| **Baseline (Initial State)** | `1,567.28 s` (~26.1 min) | `19.34 MB/s` | `24.0 MB/s` | `100.00%` (47,400 / 47,400) | 70 / 70 |
| **Stage 1: Multi-Threading Wiring** | `893.71 s` (~14.9 min) | `33.92 MB/s` | `40.2 MB/s` | `100.00%` (47,398 / 47,400) | 69 / 70 |
| **Stage 2: Zero-Allocation Mode B** | `781.12 s` (~13.0 min) | `38.81 MB/s` | `48.4 MB/s` | `100.00%` (47,400 / 47,400) | 70 / 70 |
| **Stage 3: Substring Elimination & Fast Guards** | **`282.60 s` (~4.7 min)** | **`107.27 MB/s`** | **`124.61 MB/s`** | **`100.00%` (47,400 / 47,400)** | **70 / 70** |

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

## 🧪 Testing & Benchmarking

```powershell
# Run the complete test suite (70/70 tests)
python -m pytest tests/ -v

# Run the scientific bottleneck diagnostic tool
python bench/diagnose_bottlenecks.py tests/data/Thunderbird.log

# Run the full-scale 30.3 GB throughput benchmark
python bench/bench_throughput.py tests/data/Thunderbird.log
```

---

## 📄 License

MIT License.
