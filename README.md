# fastscrub 🚀

A radically high-performance, zero-allocation Personally Identifiable Information (PII) scrubbing engine for Python, powered by a concurrent C++20 backend.

`fastscrub` is designed to solve a single problem: redacting terabytes of messy production logs, data streams, and unstructured text as fast as physically possible without blowing up your memory or locking your Python threads.

## Features

- **Blazing Fast**: Achieves **~30 MB/s** throughput on single-core, scaling linearly with multi-threading.
- **Zero Lock Contention**: The `scrub_batch` API safely drops the Python Global Interpreter Lock (GIL) and utilizes native `std::jthread` thread pools to process massive data payloads across all available CPU cores.
- **Zero-Allocation Parsing**: Extracts entities using highly optimized `std::string_view` boundary isolation.
- **Industrial Grade Validation**: Heavily benchmarked against the **Microsoft Presidio** dataset and the **Kaggle PII Data Detection** student essay corpus, ensuring rigorous precision and recall calculations against ground-truth labels.
- **Modern Architecture**: Uses `nanobind` for lightweight C++ bindings and `scikit-build-core` with a standard Python `src/` layout to completely prevent import shadowing.

## Installation

`fastscrub` requires a C++20 compatible compiler (e.g., GCC 10+, Clang 10+, MSVC 19.29+) and CMake.

```bash
# Clone the repository
git clone https://github.com/yourusername/fastscrub.git
cd fastscrub

# Build and install the Python package
pip install .
```

## Usage

### Single String Scrubbing
Perfect for lightweight, synchronous redaction.

```python
from fastscrub import scrub

text = "User account ID 123-45-6789 created by admin@example.com."
safe_text = scrub(text)
print(safe_text)
# Output: "User account ID [REDACTED_SSN] created by [REDACTED_EMAIL]."
```

### High-Throughput Batch Processing
Designed for heavy workloads. `scrub_batch` drops the GIL and processes your array concurrently using native C++ threads.

```python
from fastscrub import scrub_batch

logs = [
    "Connection from 192.168.1.100 failed.",
    "Payment processed for card 4454794511390933",
    "Session 550e8400-e29b-41d4-a716-446655440000 terminated."
]

# Provide your list of strings. The engine automatically scales to your CPU cores.
safe_logs = scrub_batch(logs)

for log in safe_logs:
    print(log)
```

## Supported PII Types
Currently, `fastscrub` strictly isolates and redacts structural and pattern-based PII:
- `[REDACTED_EMAIL]`: Email Addresses
- `[REDACTED_IP]`: IPv4 & IPv6 Addresses
- `[REDACTED_MAC]`: MAC Addresses
- `[REDACTED_UUID]`: UUIDs (v1-v5)
- `[REDACTED_SSN]`: US Social Security Numbers
- `[REDACTED_PHONE]`: Phone Numbers
- `[REDACTED_CREDIT_CARD]`: Credit Cards (Validates strictly against the Luhn Algorithm to prevent false positives)

## Benchmarking
To run the evaluation suite against ground-truth datasets:

1. Download the Kaggle `train.json` and Presidio `synth_dataset_v2.json` into `tests/data/`.
2. Run the benchmarking script:
```bash
python tests/benchmark_comprehensive.py
```

## License
MIT License
