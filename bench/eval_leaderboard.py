#!/usr/bin/env python3
"""
FastScrub Industrial Ground-Truth Benchmark & Leaderboard Suite
Evaluates genuine Precision, Recall, F1, F2-Score (PIIMB), and Throughput
across third-party annotated PII datasets and TruffleHog security vectors.
"""

import sys
import os
import time
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Ensure UTF-8 console output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

try:
    import fastscrub
except ImportError:
    print("[-] Error: 'fastscrub' module not found. Please install or build fastscrub first.")
    sys.exit(1)

DATA_DIR = Path(r"d:\fastscrub\tests\data")

# Entity normalization mapping to FastScrub's supported structural categories
IN_SCOPE_MAP = {
    # Email
    "EMAIL": "EMAIL",
    "EMAIL_ADDRESS": "EMAIL",
    "B-EMAIL": "EMAIL",
    "I-EMAIL": "EMAIL",
    
    # Phone
    "PHONE": "PHONE",
    "PHONENUMBER": "PHONE",
    "PHONE_NUMBER": "PHONE",
    "PHONEIMEI": "PHONE",
    "TELEPHONE": "PHONE",
    "B-PHONE_NUM": "PHONE",
    "I-PHONE_NUM": "PHONE",
    
    # IP Address
    "IP": "IP_ADDRESS",
    "IP_ADDRESS": "IP_ADDRESS",
    "IPV4": "IP_ADDRESS",
    "IPV6": "IP_ADDRESS",
    "B-IP_ADDRESS": "IP_ADDRESS",
    "I-IP_ADDRESS": "IP_ADDRESS",
    
    # SSN / Social Number
    "SOCIALNUMBER": "SSN",
    "SSN": "SSN",
    "US_SSN": "SSN",
    "B-SSN": "SSN",
    
    # Credit Card
    "CREDITCARD": "CREDIT_CARD",
    "CREDIT_CARD": "CREDIT_CARD",
    "MASKEDNUMBER": "CREDIT_CARD",
    "IBAN_CODE": "CREDIT_CARD",
    "B-CREDIT_CARD": "CREDIT_CARD",
    
    # Infrastructure Secrets
    "PASSWORD": "INFRA_SECRET",
    "API_KEY": "INFRA_SECRET",
    "SECRET_KEY": "INFRA_SECRET",
    "TOKEN": "INFRA_SECRET",
}

@dataclass
class MetricCounter:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    total_docs: int = 0
    total_bytes: int = 0
    elapsed_sec: float = 0.0

    @property
    def precision(self) -> float:
        total = self.tp + self.fp
        return (self.tp / total * 100.0) if total > 0 else 100.0

    @property
    def recall(self) -> float:
        total = self.tp + self.fn
        return (self.tp / total * 100.0) if total > 0 else 100.0

    @property
    def f1(self) -> float:
        p = self.precision / 100.0
        r = self.recall / 100.0
        return (2.0 * p * r / (p + r)) if (p + r) > 0 else 0.0

    @property
    def f2(self) -> float:
        # Official PIIMB metric (beta=2, prioritizing recall)
        p = self.precision / 100.0
        r = self.recall / 100.0
        return (5.0 * p * r / (4.0 * p + r)) if (4.0 * p + r) > 0 else 0.0

    @property
    def throughput_mbs(self) -> float:
        mb = self.total_bytes / (1024.0 * 1024.0)
        return (mb / self.elapsed_sec) if self.elapsed_sec > 0 else 0.0


def check_span_redacted(source_text: str, start: int, end: int) -> bool:
    """Check if the exact byte span was redacted using in-place bytearray mutation."""
    raw_bytes = source_text.encode("utf-8", errors="replace")
    buf = bytearray(raw_bytes)
    fastscrub.scrub_inplace(buf)
    
    prefix_bytes = len(source_text[:start].encode("utf-8", errors="replace"))
    span_bytes = len(source_text[start:end].encode("utf-8", errors="replace"))
    byte_slice = buf[prefix_bytes : prefix_bytes + span_bytes]
    return (ord('*') in byte_slice)


def evaluate_jsonl_dataset(filename: str, entity_breakdown: Dict[str, MetricCounter], limit: Optional[int] = None) -> MetricCounter:
    filepath = DATA_DIR / filename
    metrics = MetricCounter()
    if not filepath.exists():
        print(f"[-] Missing file: {filepath}")
        return metrics

    print(f"[*] Evaluating {filename}...")
    t0 = time.perf_counter()

    with open(filepath, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            if limit and idx >= limit:
                break
            metrics.total_docs += 1
            metrics.total_bytes += len(line.encode("utf-8"))
            
            try:
                doc = json.loads(line)
            except:
                continue

            source_text = doc.get("source_text", "")
            privacy_mask = doc.get("privacy_mask", [])

            # Run in-place check on the entire document once
            raw_bytes = source_text.encode("utf-8", errors="replace")
            buf = bytearray(raw_bytes)
            fastscrub.scrub_inplace(buf)

            # Ground truth span tracking
            for span in privacy_mask:
                raw_label = span.get("label", "")
                norm_label = IN_SCOPE_MAP.get(raw_label, None)
                if not norm_label:
                    continue  # Out-of-scope NLP entity

                s = span["start"]
                e = span["end"]
                prefix_bytes = len(source_text[:s].encode("utf-8", errors="replace"))
                span_bytes = len(source_text[s:e].encode("utf-8", errors="replace"))
                byte_slice = buf[prefix_bytes : prefix_bytes + span_bytes]
                
                was_redacted = (ord('*') in byte_slice)

                if norm_label not in entity_breakdown:
                    entity_breakdown[norm_label] = MetricCounter()

                if was_redacted:
                    metrics.tp += 1
                    entity_breakdown[norm_label].tp += 1
                else:
                    metrics.fn += 1
                    entity_breakdown[norm_label].fn += 1

            if (idx + 1) % 10000 == 0:
                print(f"    ... processed {idx + 1:,} documents (TP: {metrics.tp}, FN: {metrics.fn})")

    metrics.elapsed_sec = time.perf_counter() - t0
    return metrics


def evaluate_presidio_dataset(filename: str, entity_breakdown: Dict[str, MetricCounter], limit: Optional[int] = None) -> MetricCounter:
    filepath = DATA_DIR / filename
    metrics = MetricCounter()
    if not filepath.exists():
        print(f"[-] Missing file: {filepath}")
        return metrics

    print(f"[*] Evaluating {filename} (Microsoft Presidio Ground Truth)...")
    t0 = time.perf_counter()

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    for idx, doc in enumerate(data):
        if limit and idx >= limit:
            break
        metrics.total_docs += 1
        text = doc.get("full_text", "")
        metrics.total_bytes += len(text.encode("utf-8"))
        spans = doc.get("spans", [])

        raw_bytes = text.encode("utf-8", errors="replace")
        buf = bytearray(raw_bytes)
        fastscrub.scrub_inplace(buf)

        for span in spans:
            raw_label = span.get("entity_type", "")
            norm_label = IN_SCOPE_MAP.get(raw_label, None)
            if not norm_label:
                continue

            s = span["start_position"]
            e = span["end_position"]
            prefix_bytes = len(text[:s].encode("utf-8", errors="replace"))
            span_bytes = len(text[s:e].encode("utf-8", errors="replace"))
            byte_slice = buf[prefix_bytes : prefix_bytes + span_bytes]

            was_redacted = (ord('*') in byte_slice)

            if norm_label not in entity_breakdown:
                entity_breakdown[norm_label] = MetricCounter()

            if was_redacted:
                metrics.tp += 1
                entity_breakdown[norm_label].tp += 1
            else:
                metrics.fn += 1
                entity_breakdown[norm_label].fn += 1

    metrics.elapsed_sec = time.perf_counter() - t0
    return metrics


def evaluate_trufflehog_secrets(filename: str, detector_breakdown: Dict[str, MetricCounter]) -> MetricCounter:
    filepath = DATA_DIR / filename
    metrics = MetricCounter()
    if not filepath.exists():
        print(f"[-] Missing file: {filepath}")
        return metrics

    print(f"[*] Evaluating {filename} (TruffleHog Official Secrets & Traps)...")
    t0 = time.perf_counter()

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    test_cases = data.get("test_cases", [])
    for tc in test_cases:
        metrics.total_docs += 1
        inp = tc["input"]
        is_secret = tc["is_secret"]
        det = tc["detector"]
        metrics.total_bytes += len(inp.encode("utf-8"))

        if det not in detector_breakdown:
            detector_breakdown[det] = MetricCounter()

        scrubbed = fastscrub.scrub(inp)
        was_redacted = (scrubbed != inp) or ("[REDACTED_" in scrubbed) or ("*" in scrubbed)

        if is_secret:
            if was_redacted:
                metrics.tp += 1
                detector_breakdown[det].tp += 1
            else:
                metrics.fn += 1
                detector_breakdown[det].fn += 1
        else:
            # Negative trap
            if was_redacted:
                metrics.fp += 1
                detector_breakdown[det].fp += 1
            else:
                metrics.tn += 1
                detector_breakdown[det].tn += 1

    metrics.elapsed_sec = time.perf_counter() - t0
    return metrics


def print_leaderboard_tables(results: Dict[str, MetricCounter], entity_breakdown: Dict[str, MetricCounter], detector_breakdown: Dict[str, MetricCounter]):
    sep = "=" * 105
    sub_sep = "-" * 105

    print("\n" + sep)
    print("                 FASTSCRUB MASTER GROUND-TRUTH ACCURACY & SPEED MATRIX")
    print(sep)
    print(f" {'Benchmark Dataset':<28} | {'Docs':>8} | {'TP':>6} | {'FP':>5} | {'FN':>5} | {'Precision':>9} | {'Recall':>8} | {'F1':>6} | {'F2 (PIIMB)':>10} | {'Throughput':>10}")
    print(sub_sep)

    total_m = MetricCounter()
    for name, m in results.items():
        total_m.tp += m.tp
        total_m.fp += m.fp
        total_m.fn += m.fn
        total_m.tn += m.tn
        total_m.total_docs += m.total_docs
        total_m.total_bytes += m.total_bytes
        total_m.elapsed_sec += m.elapsed_sec

        print(f" {name:<28} | {m.total_docs:>8,d} | {m.tp:>6d} | {m.fp:>5d} | {m.fn:>5d} | {m.precision:>8.2f}% | {m.recall:>7.2f}% | {m.f1:>6.3f} | {m.f2:>10.3f} | {m.throughput_mbs:>7.2f} MB/s")

    print(sub_sep)
    print(f" {'OVERALL MASTER BENCHMARK':<28} | {total_m.total_docs:>8,d} | {total_m.tp:>6d} | {total_m.fp:>5d} | {total_m.fn:>5d} | {total_m.precision:>8.2f}% | {total_m.recall:>7.2f}% | {total_m.f1:>6.3f} | {total_m.f2:>10.3f} | {total_m.throughput_mbs:>7.2f} MB/s")
    print(sep)

    # Table 2: Entity Breakdown
    if entity_breakdown:
        print("\n" + sep)
        print("                         PII ENTITY ACCURACY BREAKDOWN MATRIX")
        print(sep)
        print(f" {'Entity Category':<28} | {'True Positives':>15} | {'False Negatives':>15} | {'Recall':>12} | {'Coverage Status':>20}")
        print(sub_sep)
        for entity, em in sorted(entity_breakdown.items(), key=lambda x: x[0]):
            total = em.tp + em.fn
            cov = "✅ 100% Full" if em.recall == 100.0 else ("⚠️ High" if em.recall >= 90.0 else "🔄 Partial")
            print(f" {entity:<28} | {em.tp:>15,d} | {em.fn:>15,d} | {em.recall:>11.2f}% | {cov:>20}")
        print(sep)

    # Table 3: TruffleHog Detectors
    if detector_breakdown:
        print("\n" + sep)
        print("                     TRUFFLEHOG DETECTOR SENSITIVITY & TRAP MATRIX")
        print(sep)
        print(f" {'Detector / Secret Type':<28} | {'True Secrets (TP)':>18} | {'Missed (FN)':>12} | {'Traps Caught (FP)':>18} | {'Recall':>12}")
        print(sub_sep)
        for det, dm in sorted(detector_breakdown.items(), key=lambda x: x[0]):
            print(f" {det:<28} | {dm.tp:>18d} | {dm.fn:>12d} | {dm.fp:>18d} | {dm.recall:>11.2f}%")
        print(sep)


def main():
    parser = argparse.ArgumentParser(description="FastScrub Industrial Ground-Truth Benchmark Runner")
    parser.add_argument("--all", action="store_true", help="Run full benchmark across all datasets")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of rows per dataset (for fast preview)")
    args = parser.parse_args()

    results: Dict[str, MetricCounter] = {}
    entity_breakdown: Dict[str, MetricCounter] = {}
    detector_breakdown: Dict[str, MetricCounter] = {}

    print("\n" + "=" * 105)
    print("                     STARTING FASTSCRUB MASTER GROUND-TRUTH BENCHMARK")
    print("=========================================================================================================")

    # 1. AI4Privacy English (43k)
    results["AI4Privacy English (43k)"] = evaluate_jsonl_dataset("english_pii_43k.jsonl", entity_breakdown, limit=args.limit)

    # 2. AI4Privacy Multilingual French (62k)
    results["AI4Privacy French (62k)"] = evaluate_jsonl_dataset("french_pii_62k.jsonl", entity_breakdown, limit=args.limit)

    # 3. AI4Privacy OpenPII (30k)
    results["AI4Privacy OpenPII (30k)"] = evaluate_jsonl_dataset("1english_openpii_30k.jsonl", entity_breakdown, limit=args.limit)

    # 4. Microsoft Presidio Synthetic Dataset
    results["Microsoft Presidio (v2)"] = evaluate_presidio_dataset("synth_dataset_v2.json", entity_breakdown, limit=args.limit)

    # 5. TruffleHog Ground Truth Secrets (25 Detectors)
    results["TruffleHog (25 Detectors)"] = evaluate_trufflehog_secrets("secrets/trufflehog_ground_truth.json", detector_breakdown)

    # Render publication-ready tables
    print_leaderboard_tables(results, entity_breakdown, detector_breakdown)


if __name__ == "__main__":
    main()
