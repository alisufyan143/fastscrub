"""
download_benchmarks.py

Fetches real-world PII-masking text data from Hugging Face (ai4privacy/pii-masking-200k)
and writes a sampled subset to tests/data/messy_production_logs.txt for use as benchmark
input to the FastScrub C++ engine tests.

Usage:
    python tests/download_benchmarks.py
"""

import random
import sys
from pathlib import Path

from datasets import load_dataset

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATASET_ID = "ai4privacy/pii-masking-200k"
SPLIT = "train"
TARGET_ROWS = 3000  # within the 1,000–5,000 range; keeps footprint lean
SEED = 42

# Resolve paths relative to the repository root (parent of tests/)
SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / "data"
OUTPUT_FILE = DATA_DIR / "messy_production_logs.txt"


def main() -> None:
    print(f"[1/4] Loading dataset '{DATASET_ID}' (split='{SPLIT}', streaming)...")
    dataset = load_dataset(DATASET_ID, split=SPLIT, streaming=True)

    # ------------------------------------------------------------------
    # Collect a reservoir-sampled pool from the stream so we get diverse
    # rows without downloading the entire 200 k dataset.
    # We over-read by a factor of ~3× and then sub-sample.
    # ------------------------------------------------------------------
    RESERVOIR_SIZE = TARGET_ROWS * 3  # read up to 9 000 rows
    print(f"[2/4] Streaming up to {RESERVOIR_SIZE} rows into reservoir...")

    reservoir: list[str] = []
    seen = 0

    for example in dataset:
        text = example.get("source_text") or example.get("text") or ""
        text = text.strip()
        if not text:
            continue

        seen += 1

        # Classic reservoir sampling (Algorithm R)
        if len(reservoir) < RESERVOIR_SIZE:
            reservoir.append(text)
        else:
            j = random.randint(0, seen - 1)
            if j < RESERVOIR_SIZE:
                reservoir[j] = text

        # Safety cap – stop streaming after enough rows
        if seen >= RESERVOIR_SIZE:
            break

    if len(reservoir) < TARGET_ROWS:
        print(
            f"  [WARN] Only collected {len(reservoir)} non-empty rows "
            f"(target was {TARGET_ROWS}). Continuing with what we have.",
            file=sys.stderr,
        )

    # Sub-sample down to exactly TARGET_ROWS (or fewer if not enough data)
    rng = random.Random(SEED)
    rng.shuffle(reservoir)
    sampled = reservoir[:TARGET_ROWS]
    print(f"  -> Selected {len(sampled)} diverse rows.")

    # ------------------------------------------------------------------
    # Write to disk
    # ------------------------------------------------------------------
    print(f"[3/4] Ensuring output directory exists: {DATA_DIR}")
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    print(f"[4/4] Writing to {OUTPUT_FILE} ...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        for line in sampled:
            fh.write(line + "\n")

    byte_size = OUTPUT_FILE.stat().st_size
    print(
        f"  [OK] Done - {len(sampled)} rows, "
        f"{byte_size / 1024:.1f} KiB written to {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    random.seed(SEED)
    main()
