# Python API Reference 📚

Complete reference documentation and type signatures for the `fastscrub` Python package.

---

## 1. Top-Level Functions

### `fastscrub.scrub(text: str) -> str`
Redacts all detected PII and secrets from a string using labeled replacement tokens (Mode A).

* **Parameters**:
    * `text` (`str`): The raw input text.
* **Returns**:
    * `str`: A sanitized string with sensitive entities replaced by descriptive tokens (`[REDACTED_EMAIL]`, `[REDACTED_IP]`, etc.). If no entities are detected, returns the original string with zero allocations.

```python
from fastscrub import scrub

result = scrub("Admin user: alice@corp.net from IP 192.168.1.1")
# Returns: "Admin user: [REDACTED_EMAIL] from IP [REDACTED_IP]"
```

---

### `fastscrub.scrub_inplace(buffer: bytearray) -> None`
Mutates a mutable Python `bytearray` directly in RAM, overwriting sensitive entity bytes with `*` (Mode B).

* **Parameters**:
    * `buffer` (`bytearray`): The mutable memory buffer to scrub in-place.
* **Returns**:
    * `None`: Mutates the buffer in-place. Zero heap allocation is performed.

```python
from fastscrub import scrub_inplace

buf = bytearray(b"Session key: AKIAIOSFODNN7EXAMPLE")
scrub_inplace(buf)
# buf is now: bytearray(b"Session key: ********************")
```

---

### `fastscrub.scrub_list(inputs: List[str], worker_count: int = 0) -> List[str]`
Drops the Python GIL and parallelizes redaction across all available CPU cores using native C++ threads.

* **Parameters**:
    * `inputs` (`List[str]`): A list of strings to scrub.
    * `worker_count` (`int`, optional): Number of worker threads to spawn. Defaults to `0` (auto-detects physical CPU cores).
* **Returns**:
    * `List[str]`: A new list containing sanitized strings.

```python
from fastscrub import scrub_list

logs = ["User 123-45-6789", "Token ghp_YOUR_GITHUB_TOKEN"]
clean = scrub_list(logs, worker_count=4)
```

---

## 2. Engine Class

### `class fastscrub.Engine(worker_count: int = 0)`
High-level scrubbing engine instance. Compiles all pattern matchers once upon construction and exposes single-string, bulk-string, and buffer methods.

#### Constructor
```python
engine = fastscrub.Engine(worker_count=0)
```
* **Parameters**:
    * `worker_count` (`int`, optional): Number of worker threads for parallel operations. `0` uses `std::thread::hardware_concurrency()`.

#### Methods

##### `engine.scrub(input: str) -> str`
Sequentially redacts a single string.

##### `engine.scrub_bulk(input: str) -> str`
Parallelized bulk string redaction. Splits input into overlap-aware chunks and executes across worker threads with the GIL released.

##### `engine.scrub_inplace(buffer: bytearray) -> None`
Sequential in-place bytearray mutation.

##### `engine.scrub_bulk_inplace(buffer: bytearray) -> None`
Parallelized in-place bytearray mutation across worker threads with the GIL released.
