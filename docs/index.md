---
title: "fastscrub — Wire-Speed PII & Secret Redaction Engine"
description: "Ultra high-performance zero-allocation Personally Identifiable Information (PII) and Secrets redaction engine for Python, powered by C++20 and SWAR vectorization."
---

# fastscrub 🚀

<div class="badges" style="margin-bottom: 20px;">
  <a href="https://pypi.org/project/fastscrub/"><img src="https://img.shields.io/pypi/v/fastscrub.svg?color=007ec6" alt="PyPI Version"></a>
  <a href="https://pypi.org/project/fastscrub/"><img src="https://img.shields.io/pypi/pyversions/fastscrub.svg" alt="Python Versions"></a>
  <a href="https://github.com/alisufyan143/fastscrub/actions"><img src="https://img.shields.io/github/actions/workflow/status/alisufyan143/fastscrub/ci.yml?branch=main&label=CI%20Build" alt="CI Status"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT"></a>
</div>

**`fastscrub`** is a radically fast, zero-allocation **Personally Identifiable Information (PII)** and **Infrastructure Secrets** redaction engine for Python, powered by a vectorized **C++20** core.

It is engineered to solve a critical bottleneck in data pipelines, ML preprocessing, and security compliance: **redacting tens of gigabytes or terabytes of production logs, database dumps, and unstructured text at wire speed without memory bloat or Python GIL lock contention.**

---

## ⚡ 30-Second Quick Demo

=== "Mode A: Labeled Tokens"
    ```python
    from fastscrub import scrub

    raw_log = "User 123-45-6789 connected from 192.168.1.50 with API key sk_live_YOUR_STRIPE_KEY."
    clean_log = scrub(raw_log)

    print(clean_log)
    # Output:
    # "User [REDACTED_SSN] connected from [REDACTED_IP] with API key [REDACTED_STRIPE_KEY]."
    ```

=== "Mode B: Zero-Allocation In-Place (`*` Mask)"
    ```python
    from fastscrub import scrub_inplace

    # Direct memory mutation with ZERO heap allocation
    buf = bytearray(b"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.c2lnbmF0dXJl")
    scrub_inplace(buf)

    print(buf.decode("utf-8"))
    # Output:
    # "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.************************************"
    ```

=== "Mode C: Multi-Core Batch Processing"
    ```python
    from fastscrub import scrub_list

    lines = [
        "Payment card: 4532-0150-1234-5678 processed for user alice@corp.com",
        "AWS session loaded credential: AKIAIOSFODNN7EXAMPLE",
        "Database connected at postgresql://postgres:SuperSecret123@db.internal:5432/prod"
    ]

    # Drops the Python GIL and distributes across all CPU worker threads in C++
    safe_lines = scrub_list(lines)
    for line in safe_lines:
        print(line)
    ```

---

## 🌟 Why fastscrub?

```mermaid
graph TD
    A[Unstructured Text / Log Streams] --> B[64-Bit SWAR Vectorized Scanner]
    B -->|Clean ASCII 8 Bytes/Cycle| C[Fast Leap Forward]
    B -->|Entropy Punctuation Anchor| D[Center-Out Structural Parsers]
    D -->|Luhn Checksum / Prefix Verify| E{Is Genuine PII?}
    E -->|Yes| F[Mask / Redact]
    E -->|No / Timestamp| G[1-Cycle Rejection Leap]
    F --> H[Clean Compliant Output]
    G --> H
```

### 1. Vectorized SWAR 64-Bit Scanning
Traditional regex engines inspect text character-by-character, suffering from frequent branch mispredictions. `fastscrub` uses 64-bit integer registers (`uint64_t`) to inspect **8 bytes simultaneously in 1 CPU cycle**, jumping over clean alphanumeric characters and triggering center-out parsers only on structural punctuation anchors (`@`, `_`, `-`, `.`, `:`, `=`, `+`, `(`, `"`, `A`).

### 2. 100+ MB/s Real-World Throughput
Evaluated on the **30.3 GB Thunderbird supercomputer dataset**, `fastscrub` processed the entire dataset in **~4.7 minutes** on modest quad-core consumer hardware, achieving **107.27 MB/s sustained throughput (peaking at 124.61 MB/s)**.

### 3. Industrial Ground-Truth Accuracy
Tested against **137,026 third-party annotated documents** across AI4Privacy, Microsoft Presidio, and TruffleHog suites:
* **99.95% Precision**
* **0.858 F1-Score**
* **0.791 F2-Score (PIIMB)**
* **100% Probe Recall** across 57.46 GB of multi-domain logs.

### 4. Overlap-Aware Multi-Threading
When processing massive strings, `fastscrub` splits text across native C++ worker threads using a **2048-byte safe boundary overlap**. This completely drops the Python GIL and guarantees that long secrets (such as multi-hundred-byte JWTs or DB connection strings) are never fractured or missed.

---

## 🧭 Navigation Guide

* **[Quickstart Guide](getting-started/quickstart.md)** — Step-by-step tutorial with practical examples.
* **[Installation Guide](getting-started/installation.md)** — Pre-compiled wheels, source builds, and supported environments.
* **[Operational Modes](guides/modes.md)** — Choosing between Mode A (labeled replacement) and Mode B (zero-allocation mutation).
* **[Supported Detectors](detectors/pii.md)** — Complete catalog of all 16+ PII and Secrets detection rules.
* **[SWAR Vectorization Deep-Dive](architecture/swar_vectorization.md)** — Under-the-hood bitwise algorithms and SIMD logic.
* **[Benchmark Leaderboards](benchmarks/ground_truth.md)** — Reproducible evaluations and throughput metrics.
* **[API Reference](api/reference.md)** — Full Python signatures, types, and docstrings.
