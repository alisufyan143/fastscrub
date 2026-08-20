# 5-Minute Quickstart ⏱️

This guide gets you up and running with `fastscrub` in under 5 minutes.

---

## 1. Installation

Install the pre-compiled binary wheel from PyPI:

```bash
pip install fastscrub
```

Verify that `fastscrub` is correctly installed:

```python
import fastscrub
print(fastscrub.__version__)  # Output: 0.1.3
```

---

## 2. Basic Text Redaction

The simplest way to redact sensitive data is using the top-level `scrub()` function:

```python
from fastscrub import scrub

text = """
Order #89324 received from client john.doe@company.com (Phone: +1-555-839-2041).
Payment processed for Visa card 4532-0150-1234-5678.
Session token: ghp_YOUR_GITHUB_TOKEN
"""

safe_text = scrub(text)
print(safe_text)
```

**Output:**
```text
Order #89324 received from client [REDACTED_EMAIL] (Phone: [REDACTED_PHONE]).
Payment processed for Visa card [REDACTED_CREDIT_CARD].
Session token: [REDACTED_GITHUB_TOKEN]
```

---

## 3. High-Performance In-Place Masking

When processing high-volume data streams (such as Kafka topics or network sockets), creating new Python strings causes garbage collection overhead. 

Use **`scrub_inplace()`** to mutate a mutable `bytearray` directly in memory with zero heap allocations:

```python
from fastscrub import scrub_inplace

# Create a mutable bytearray buffer
buffer = bytearray(b"User IP 192.168.1.104 connected to db postgresql://admin:MyPass123@10.0.0.1:5432/analytics")

# Mutate the buffer in-place (replaces sensitive characters with '*')
scrub_inplace(buffer)

print(buffer.decode('utf-8'))
```

**Output:**
```text
User IP ************* connected to db ********************************************************
```

---

## 4. Multi-Core Batch Processing

If you have a list of millions of log lines, processing them in Python with a for-loop is constrained by the Global Interpreter Lock (GIL). 

**`scrub_list()`** sends the entire list into the C++ engine, drops the Python GIL, and parallelizes across all available CPU cores:

```python
from fastscrub import scrub_list

log_lines = [
    "2026-08-21T04:15:00Z auth_service: user alice@domain.org logged in from 10.0.1.20",
    "2026-08-21T04:15:01Z payment_service: card 4000-1234-5678-9010 authorized",
    "2026-08-21T04:15:02Z cloud_service: AWS secret AKIAIOSFODNN7EXAMPLE initialized",
    "2026-08-21T04:15:03Z health_check: system healthy, status=200"
]

# Process across all CPU cores simultaneously
redacted_lines = scrub_list(log_lines)

for line in redacted_lines:
    print(line)
```

---

## 5. Reusable Engine Instance

If you are performing repeated scrubbing in a long-running service, instantiate the `Engine` class once:

```python
from fastscrub import Engine

# Initialize engine with custom thread count (0 = auto-detect CPU cores)
engine = Engine(worker_count=4)

# 1. Scrub single string
clean = engine.scrub("Admin email is root@datacenter.net")

# 2. Bulk parallel scrub of a multi-megabyte string
large_clean = engine.scrub_bulk(large_log_string)

# 3. In-place parallel buffer masking
engine.scrub_bulk_inplace(large_bytearray)
```

---

## Next Steps
* Learn about the performance differences in **[Operational Modes](../guides/modes.md)**.
* Check the complete list of supported entities in **[Supported Detectors](../detectors/pii.md)**.
