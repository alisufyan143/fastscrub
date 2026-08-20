# Processing Multi-Gigabyte Production Logs 📂

Redacting multi-gigabyte or terabyte server logs, database dumps, and telemetry files requires careful memory management to prevent out-of-memory (OOM) crashes.

---

## Strategy 1: Streaming File Chunks (Zero-Copy)

For massive files (e.g. 10 GB to 100+ GB), do not load the entire file into memory as a single Python string. Instead, stream the file in 16 MB or 64 MB chunks using `bytearray` and `scrub_inplace`:

```python
import os
from fastscrub import scrub_inplace

def scrub_large_file(input_path: str, output_path: str, chunk_size: int = 16 * 1024 * 1024):
    """
    Streams and redacts massive log files in 16 MB chunks with zero memory bloat.
    """
    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        while True:
            # Read chunk directly into a mutable buffer
            chunk = bytearray(fin.read(chunk_size))
            if not chunk:
                break
            
            # Redact chunk in-place in RAM (C++ wire speed)
            scrub_inplace(chunk)
            
            # Write sanitized chunk to disk
            fout.write(chunk)

# Example usage
scrub_large_file("production_access.log", "sanitized_access.log")
```

---

## Strategy 2: Line-by-Line Parallel Batching

If you need labeled tokens (Mode A) for each line in a file:

```python
from fastscrub import scrub_list

def scrub_file_line_batches(input_path: str, output_path: str, batch_size: int = 50_000):
    """
    Reads lines in batches and distributes them across all CPU cores in C++.
    """
    with open(input_path, "r", encoding="utf-8", errors="replace") as fin, \
         open(output_path, "w", encoding="utf-8") as fout:
        
        batch = []
        for line in fin:
            batch.append(line.rstrip("\r\n"))
            if len(batch) >= batch_size:
                # Parallel C++ batch redaction
                sanitized_batch = scrub_list(batch)
                for clean_line in sanitized_batch:
                    fout.write(clean_line + "\n")
                batch.clear()
        
        # Flush remaining lines
        if batch:
            sanitized_batch = scrub_list(batch)
            for clean_line in sanitized_batch:
                fout.write(clean_line + "\n")
```

---

## Strategy 3: Fast Parallel Bulk String Processing

If you have a file that fits in RAM (e.g. 500 MB to 4 GB) and you want the fastest possible single-call redaction:

```python
from fastscrub import Engine
from pathlib import Path

# Initialize Engine with all CPU cores
engine = Engine()

# Read file
raw_text = Path("server_dump.log").read_text(encoding="utf-8", errors="replace")

# C++ engine automatically chunks the text across worker threads with 2048-byte safe overlap
sanitized_text = engine.scrub_bulk(raw_text)

Path("server_dump_clean.log").write_text(sanitized_text, encoding="utf-8")
```
