"""
benchmark_comprehensive.py

Rigorous benchmarking suite for the fastscrub library.
Evaluates throughput (MB/s), and true Precision, Recall, and F1-score
using the Presidio and Kaggle PII datasets.
"""

import os
import json
import time
import sys
import difflib
import tracemalloc
from pathlib import Path

# Inject project root into PYTHONPATH to resolve local fastscrub package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fastscrub import scrub, scrub_batch

TESTS_DIR = Path(__file__).resolve().parent
DATA_DIR = TESTS_DIR / "data"

PRESIDIO_FILE = DATA_DIR / "synth_dataset_v2.json"
KAGGLE_FILE = DATA_DIR / "train.json"

# Entities that fastscrub is designed to detect
PRESIDIO_TARGETS = {"EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IP_ADDRESS"}
KAGGLE_TARGETS = {"EMAIL", "PHONE_NUM", "ID_NUM"}

def get_predicted_spans(original: str, scrubbed: str) -> list[tuple[int, int]]:
    """Extracts character spans from original text where [REDACTED_...] was inserted."""
    matcher = difflib.SequenceMatcher(None, original, scrubbed)
    spans = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == 'replace' and '[REDACTED_' in scrubbed[j1:j2]:
            spans.append((i1, i2))
    return spans

def calculate_metrics(ground_truth_spans: list[tuple[int, int]], predicted_spans: list[tuple[int, int]]):
    """Calculates Precision, Recall, and F1 based on span overlaps."""
    # Check which GT spans are covered by at least one prediction
    matched_gt = set()
    for i, (g_start, g_end) in enumerate(ground_truth_spans):
        for p_start, p_end in predicted_spans:
            if max(p_start, g_start) < min(p_end, g_end):
                matched_gt.add(i)
                break
                
    tp = len(matched_gt)
    fn = len(ground_truth_spans) - tp
    
    # Check which predicted spans cover at least one GT span
    matched_pred = set()
    for j, (p_start, p_end) in enumerate(predicted_spans):
        for g_start, g_end in ground_truth_spans:
            if max(p_start, g_start) < min(p_end, g_end):
                matched_pred.add(j)
                break
                
    fp = len(predicted_spans) - len(matched_pred)
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    
    return tp, fp, fn, precision, recall, f1

def evaluate_presidio():
    if not PRESIDIO_FILE.exists():
        print(f"[-] Presidio dataset not found at {PRESIDIO_FILE}")
        return None
        
    print("[*] Loading Presidio Dataset...")
    with open(PRESIDIO_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    texts = []
    all_gt_spans = []
    
    for row in data:
        texts.append(row["full_text"])
        gt_spans = []
        for span in row.get("spans", []):
            if span["entity_type"] in PRESIDIO_TARGETS:
                gt_spans.append((span["start_position"], span["end_position"]))
        all_gt_spans.append(gt_spans)
        
    return run_evaluation("Presidio (synth_dataset_v2)", texts, all_gt_spans)

def evaluate_kaggle():
    if not KAGGLE_FILE.exists():
        print(f"[-] Kaggle dataset not found at {KAGGLE_FILE}")
        return None
        
    print("[*] Loading Kaggle Dataset...")
    with open(KAGGLE_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    texts = []
    all_gt_spans = []
    
    for row in data:
        texts.append(row["full_text"])
        
        # Reconstruct spans from tokens
        tokens = row["tokens"]
        ws = row["trailing_whitespace"]
        labels = row["labels"]
        
        text = ""
        gt_spans = []
        
        curr_start = -1
        curr_end = -1
        curr_label = None
        
        for t, has_ws, label in zip(tokens, ws, labels):
            start = len(text)
            text += t
            end = len(text)
            
            base_label = label.split("-")[-1] if "-" in label else label
            
            if base_label in KAGGLE_TARGETS:
                if curr_label == base_label and start <= curr_end + 1:
                    curr_end = end
                else:
                    if curr_label is not None:
                        gt_spans.append((curr_start, curr_end))
                    curr_start = start
                    curr_end = end
                    curr_label = base_label
            else:
                if curr_label is not None:
                    gt_spans.append((curr_start, curr_end))
                    curr_label = None
                    
            if has_ws:
                text += " "
                
        if curr_label is not None:
            gt_spans.append((curr_start, curr_end))
            
        all_gt_spans.append(gt_spans)
        
    return run_evaluation("Kaggle PII Detection", texts, all_gt_spans)

def run_evaluation(name: str, texts: list[str], all_gt_spans: list[list[tuple[int, int]]]):
    byte_size = sum(len(t.encode('utf-8')) for t in texts)
    size_mb = byte_size / (1024 * 1024)
    
    print(f"  -> Scrubbing {name} ({size_mb:.2f} MB)...")
    
    tracemalloc.start()
    start_time = time.perf_counter()
    
    # Run the fastscrub C++ engine
    scrubbed_texts = scrub_batch(texts)
    
    elapsed = time.perf_counter() - start_time
    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    speed_mb_s = size_mb / elapsed if elapsed > 0 else 0
    
    print(f"  -> Calculating Metrics (Python difflib alignment)...")
    
    total_tp, total_fp, total_fn = 0, 0, 0
    for original, scrubbed, gt_spans in zip(texts, scrubbed_texts, all_gt_spans):
        pred_spans = get_predicted_spans(original, scrubbed)
        tp, fp, fn, _, _, _ = calculate_metrics(gt_spans, pred_spans)
        total_tp += tp
        total_fp += fp
        total_fn += fn
        
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    
    return {
        "name": name,
        "size_mb": size_mb,
        "time_s": elapsed,
        "speed_mb_s": speed_mb_s,
        "precision": precision * 100,
        "recall": recall * 100,
        "f1": f1 * 100
    }

def main():
    print("="*90)
    print(" FASTSCRUB INDUSTRIAL BENCHMARK SUITE")
    print("="*90)
    
    results = []
    
    res_presidio = evaluate_presidio()
    if res_presidio:
        results.append(res_presidio)
        
    res_kaggle = evaluate_kaggle()
    if res_kaggle:
        results.append(res_kaggle)
        
    print("\n" + "="*95)
    print(" BENCHMARK RESULTS")
    print("="*95)
    print(f"| {'Dataset Name':<25} | {'Size (MB)':<10} | {'Speed (MB/s)':<12} | {'Precision (%)':<13} | {'Recall (%)':<10} | {'F1 Score':<10} |")
    print(f"|{'-'*27}|{'-'*12}|{'-'*14}|{'-'*15}|{'-'*12}|{'-'*12}|")
    
    for r in results:
        print(f"| {r['name']:<25} | {r['size_mb']:<10.2f} | {r['speed_mb_s']:<12.2f} | {r['precision']:<13.1f} | {r['recall']:<10.1f} | {r['f1']:<10.1f} |")
        
    print("="*95)

if __name__ == "__main__":
    main()
