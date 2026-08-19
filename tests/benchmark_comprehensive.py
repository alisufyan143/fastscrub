"""
benchmark_comprehensive.py

Rigorous benchmarking suite for the fastscrub library.
Evaluates throughput (MB/s), and true Precision, Recall, and F1-score
using various PII datasets.
"""

import os
import json
import time
import sys
import difflib
import tracemalloc
import re
from pathlib import Path

try:
    import pandas as pd
except ImportError:
    pd = None

# Inject project root into PYTHONPATH to resolve local fastscrub package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fastscrub import scrub, scrub_batch

TESTS_DIR = Path(__file__).resolve().parent
DATA_DIR = TESTS_DIR / "data"

PRESIDIO_FILE = DATA_DIR / "synth_dataset_v2.json"
KAGGLE_FILE = DATA_DIR / "train.json"
AI4PRIVACY_FILE = DATA_DIR / "1english_openpii_30k.jsonl"
REDACTION_FILE = DATA_DIR / "test-00000-of-00001.parquet"
MESSY_LOGS_FILE = DATA_DIR / "messy_production_logs.txt"

# Entities that fastscrub is designed to detect
PRESIDIO_TARGETS = {"EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IP_ADDRESS"}
KAGGLE_TARGETS = {"EMAIL", "PHONE_NUM", "ID_NUM"}
AI4PRIVACY_TARGETS = {"EMAIL", "PHONE", "PHONE_NUMBER", "CREDIT_CARD", "SSN", "IP_ADDRESS", "MAC_ADDRESS", "USERNAME", "ID_NUM", "SOCIALNUMBER", "PASSPORT", "IP", "IPv4", "IPv6", "CREDITCARDNUMBER", "CREDITCARD"}

def get_predicted_spans(original: str, scrubbed: str) -> list[tuple[int, int]]:
    """Extracts character spans from original text where [REDACTED_...] was inserted."""
    matcher = difflib.SequenceMatcher(None, original, scrubbed)
    spans = []
    
    redactions = [(m.start(), m.end()) for m in re.finditer(r'\[REDACTED_[A-Z_]+\]', scrubbed)]
    
    for r_start, r_end in redactions:
        orig_start = len(original)
        orig_end = 0
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            # If the opcode overlaps with the redacted span in the scrubbed text
            if max(r_start, j1) < min(r_end, j2):
                orig_start = min(orig_start, i1)
                orig_end = max(orig_end, i2)
        if orig_start < orig_end:
            spans.append((orig_start, orig_end))
            
    return spans

def calculate_metrics(ground_truth_spans: list[tuple[int, int]], predicted_spans: list[tuple[int, int]]):
    """Calculates Precision, Recall, and F1 based on span overlaps."""
    matched_gt = set()
    for i, (g_start, g_end) in enumerate(ground_truth_spans):
        for p_start, p_end in predicted_spans:
            if max(p_start, g_start) < min(p_end, g_end):
                matched_gt.add(i)
                break
                
    tp = len(matched_gt)
    fn = len(ground_truth_spans) - tp
    
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

def run_evaluation(name: str, texts: list[str], all_gt_spans: list[list[tuple[int, int]]] = None):
    byte_size = sum(len(t.encode('utf-8')) for t in texts)
    size_mb = byte_size / (1024 * 1024)
    
    if size_mb == 0: return None
    
    print(f"  -> Scrubbing {name} ({size_mb:.2f} MB)...")
    
    tracemalloc.start()
    start_time = time.perf_counter()
    
    scrubbed_texts = scrub_batch(texts)
    
    elapsed = time.perf_counter() - start_time
    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    speed_mb_s = size_mb / elapsed if elapsed > 0 else 0
    
    precision, recall, f1 = 0.0, 0.0, 0.0
    if all_gt_spans:
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
        "speed_mb_s": speed_mb_s,
        "precision": precision * 100 if all_gt_spans else None,
        "recall": recall * 100 if all_gt_spans else None,
        "f1": f1 * 100 if all_gt_spans else None
    }

def evaluate_presidio():
    if not PRESIDIO_FILE.exists(): return None
    print("[*] Loading Presidio Dataset...")
    with open(PRESIDIO_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    texts, all_gt_spans = [], []
    for row in data:
        texts.append(row["full_text"])
        all_gt_spans.append([(s["start_position"], s["end_position"]) for s in row.get("spans", []) if s["entity_type"] in PRESIDIO_TARGETS])
    return run_evaluation("Presidio", texts, all_gt_spans)

def evaluate_kaggle():
    if not KAGGLE_FILE.exists(): return None
    print("[*] Loading Kaggle Dataset...")
    with open(KAGGLE_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    texts, all_gt_spans = [], []
    for row in data:
        texts.append(row["full_text"])
        text, gt_spans = "", []
        curr_start, curr_end, curr_label = -1, -1, None
        for t, has_ws, label in zip(row["tokens"], row["trailing_whitespace"], row["labels"]):
            start, text, end = len(text), text + t, len(text) + len(t)
            base_label = label.split("-")[-1] if "-" in label else label
            if base_label in KAGGLE_TARGETS:
                if curr_label == base_label and start <= curr_end + 1: curr_end = end
                else:
                    if curr_label is not None: gt_spans.append((curr_start, curr_end))
                    curr_start, curr_end, curr_label = start, end, base_label
            else:
                if curr_label is not None: gt_spans.append((curr_start, curr_end))
                curr_label = None
            if has_ws: text += " "
        if curr_label is not None: gt_spans.append((curr_start, curr_end))
        all_gt_spans.append(gt_spans)
    return run_evaluation("Kaggle", texts, all_gt_spans)

def evaluate_ai4privacy():
    if not AI4PRIVACY_FILE.exists(): return None
    print("[*] Loading ai4privacy Dataset...")
    texts, all_gt_spans = [], []
    with open(AI4PRIVACY_FILE, "r", encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            texts.append(row.get("source_text", ""))
            gt_spans = []
            for span in row.get("privacy_mask", []):
                if span["label"] in AI4PRIVACY_TARGETS:
                    gt_spans.append((span["start"], span["end"]))
            all_gt_spans.append(gt_spans)
    return run_evaluation("ai4privacy", texts, all_gt_spans)

def evaluate_redactionbench():
    if not REDACTION_FILE.exists() or pd is None: return None
    print("[*] Loading RedactionBench Dataset...")
    try:
        df = pd.read_parquet(REDACTION_FILE)
        texts = df["raw_text"].dropna().astype(str).tolist()
        return run_evaluation("RedactionBench", texts, None)
    except Exception as e:
        print(f"[-] Failed to load RedactionBench: {e}")
        return None

def evaluate_messy_logs():
    if not MESSY_LOGS_FILE.exists(): return None
    print("[*] Loading Messy Logs Dataset...")
    text = MESSY_LOGS_FILE.read_text(encoding="utf-8", errors="ignore")
    # Multiply to create a meaningful payload
    texts = (text * 5).splitlines()
    return run_evaluation("Messy Logs", texts, None)

def main():
    print("="*90)
    print(" FASTSCRUB COMPREHENSIVE BENCHMARK SUITE")
    print("="*90)
    
    results = []
    
    for eval_func in [evaluate_presidio, evaluate_kaggle, evaluate_ai4privacy, evaluate_redactionbench, evaluate_messy_logs]:
        res = eval_func()
        if res: results.append(res)
        
    print("\n" + "="*95)
    print(" BENCHMARK RESULTS")
    print("="*95)
    print(f"| {'Dataset Name':<20} | {'Size (MB)':<10} | {'Speed (MB/s)':<12} | {'Precision (%)':<13} | {'Recall (%)':<10} | {'F1 Score':<10} |")
    print(f"|{'-'*22}|{'-'*12}|{'-'*14}|{'-'*15}|{'-'*12}|{'-'*12}|")
    
    for r in results:
        p = f"{r['precision']:.1f}" if r['precision'] is not None else "N/A"
        rec = f"{r['recall']:.1f}" if r['recall'] is not None else "N/A"
        f1 = f"{r['f1']:.1f}" if r['f1'] is not None else "N/A"
        print(f"| {r['name']:<20} | {r['size_mb']:<10.2f} | {r['speed_mb_s']:<12.2f} | {p:<13} | {rec:<10} | {f1:<10} |")
        
    print("="*95)

if __name__ == "__main__":
    main()
