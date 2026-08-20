import argparse
import json
import random
import sys
import time
from pathlib import Path
from typing import Dict, List, Any, Optional

from fastscrub import scrub, scrub_inplace, _ENGINE

# ---------------------------------------------------------------------------
# Global Constants & Ground-Truth Test Probes
# ---------------------------------------------------------------------------
OVERLAP = 2048
CHUNK_SIZE = 64 * 1024 * 1024  # 64 MB
RESULTS_FILE = Path("bench/benchmark_results.json")

# Authentic Ground-Truth Injected Secret Probes (TruffleHog standard format)
TEST_PROBES = [
    b"aws credentials{\n  id: ABIAS9L8MS5IPHTZPPUQ\n  secret: .v2QPKHl7LcdVYsjaR4LgQiZ1zw3MAnMyiondXC63;\n}",
    b"{AKIAWGXZ9OPDOWUJMZGI}",
    b"-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASC...\n-----END PRIVATE KEY-----\n",
    b"xoxb" + b"-1234567890-1234567890-abcdefghijklmnopqrstuvwx",
    b"sk_live_" + b"1234567890abcdefghijklmnopqrstuvwxyz"
]

DATASET_METADATA = {
    "Apache.log": {"name": "Apache Web Server", "category": "Web & HTTP Access Logs"},
    "SSH.log": {"name": "OpenSSH Auth Logs", "category": "Auth & Network Security"},
    "HDFS.log": {"name": "Hadoop HDFS Cluster", "category": "Distributed Big Data"},
    "Zookeeper.log": {"name": "Apache ZooKeeper", "category": "Consensus & Coordination"},
    "Linux.log": {"name": "Linux Kernel & Syslog", "category": "Linux Operating System"},
    "Mac.log": {"name": "Apple macOS System", "category": "macOS Operating System"},
    "Thunderbird.log": {"name": "Thunderbird HPC", "category": "Supercomputing Logs"},
    "Windows.log": {"name": "Windows Security Events", "category": "Enterprise Windows Logs"},
    "train.json": {"name": "Kaggle Student Essays", "category": "Academic PII NLP"},
    "1english_openpii_30k.jsonl": {"name": "OpenPII Corpus", "category": "Unstructured Document NLP"},
    "synth_dataset_v2.json": {"name": "Microsoft Presidio", "category": "Presidio Synthetic Ground Truth"},
    "messy_production_logs.txt": {"name": "ai4privacy Production", "category": "Real-World Production Logs"},
}

# ---------------------------------------------------------------------------
# Core Benchmark Runner (DRY)
# ---------------------------------------------------------------------------
def run_dataset_benchmark(file_path: Path, max_bytes: Optional[int] = None) -> Dict[str, Any]:
    file_name = file_path.name
    meta = DATASET_METADATA.get(file_name, {"name": file_name, "category": "Custom Dataset"})
    file_size = file_path.stat().st_size
    bytes_to_process = min(file_size, max_bytes) if max_bytes else file_size
    
    print("\n" + "=" * 80)
    print(f"[*] BENCHMARKING: {meta['name']} ({meta['category']})")
    print(f"[*] File Path    : {file_path}")
    print(f"[*] Dataset Size : {bytes_to_process / (1024**2):.2f} MB ({bytes_to_process:,} bytes)")
    print(f"[*] Chunk Size   : {CHUNK_SIZE / (1024**2):.0f} MB | Boundary Overlap: {OVERLAP} bytes")
    print("-" * 80)
    
    # 1. Sample 3 lines for Before / After visual diff verification
    sample_before = []
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for _ in range(3):
            line = f.readline()
            if not line: break
            sample_before.append(line.rstrip())
            
    sample_after = [scrub(l) for l in sample_before]
    
    # 2. Benchmark Streaming Execution
    total_cpu_time = 0.0
    total_injections = 0
    total_detected = 0
    peak_speed = 0.0
    
    with open(file_path, "rb") as f:
        file_offset = 0
        alloc_size = min(bytes_to_process, CHUNK_SIZE + OVERLAP)
        chunk_buf = bytearray(alloc_size)
        
        while file_offset < bytes_to_process:
            read_size = min(CHUNK_SIZE, bytes_to_process - file_offset)
            read_offset = 0 if file_offset == 0 else OVERLAP
            
            bytes_read = f.readinto(memoryview(chunk_buf)[read_offset:read_offset + read_size])
            if bytes_read == 0: break
            
            valid_size = read_offset + bytes_read
            if valid_size < len(chunk_buf):
                del chunk_buf[valid_size:]
                
            # Inject ground-truth probes into the stream
            injected_positions = []
            num_inj = 20 if valid_size > 100000 else 2
            for _ in range(num_inj):
                p = random.choice(TEST_PROBES)
                padded_p = b" " + p + b" "
                if valid_size - len(padded_p) - 1 > OVERLAP:
                    idx = random.randint(OVERLAP if file_offset > 0 else 0, valid_size - len(padded_p) - 1)
                    chunk_buf[idx:idx+len(padded_p)] = padded_p
                    injected_positions.append((idx + 1, len(p)))
                    total_injections += 1
            
            # Isolated C++ Multi-Threaded In-Place Scrubbing
            t0 = time.perf_counter()
            scrub_inplace(chunk_buf)
            t1 = time.perf_counter()
            
            dt = t1 - t0
            total_cpu_time += dt
            file_offset += bytes_read
            
            chunk_speed = (bytes_read / (1024**2)) / dt if dt > 0 else 0
            if chunk_speed > peak_speed:
                peak_speed = chunk_speed
                
            # Probe Recall Verification
            for idx, length in injected_positions:
                target = chunk_buf[idx:idx+length]
                if b"[REDACTED" in target or b"**" in target:
                    total_detected += 1
                    
            if file_offset < bytes_to_process and valid_size > OVERLAP:
                chunk_buf[:OVERLAP] = chunk_buf[valid_size - OVERLAP:valid_size]
                
            pct = int((file_offset * 100) / bytes_to_process)
            print(f"\r[Progress] {pct:3d}% ({file_offset / (1024**2):7.1f} MB) | Speed: {chunk_speed:6.2f} MB/s | Peak: {peak_speed:6.2f} MB/s", end="", flush=True)
            
    throughput = (bytes_to_process / (1024**2)) / total_cpu_time if total_cpu_time > 0 else 0.0
    recall = (total_detected / total_injections * 100.0) if total_injections > 0 else 100.0
    
    print(f"\n[+] Execution Time: {total_cpu_time:6.2f} s | Sustained Speed: {throughput:6.2f} MB/s | Peak Speed: {peak_speed:6.2f} MB/s")
    print(f"[+] Secret Recall : {total_detected} / {total_injections} ({recall:.2f}%)")
    
    # 3. Print Sample Before/After Diff
    print("\n--- [SAMPLE REDACTION DIFF (First 3 lines)] ---")
    for i, (orig, masked) in enumerate(zip(sample_before, sample_after)):
        print(f" [Line {i+1} RAW ]: {orig[:110]}..." if len(orig) > 110 else f" [Line {i+1} RAW ]: {orig}")
        print(f" [Line {i+1} MASK]: {masked[:110]}..." if len(masked) > 110 else f" [Line {i+1} MASK]: {masked}")
    print("-" * 80)
    
    record = {
        "file": file_name,
        "name": meta["name"],
        "category": meta["category"],
        "size_mb": round(bytes_to_process / (1024**2), 2),
        "time_s": round(total_cpu_time, 2),
        "speed_mbs": round(throughput, 2),
        "peak_mbs": round(peak_speed, 2),
        "recall_pct": round(recall, 2),
        "probes_detected": total_detected,
        "probes_injected": total_injections
    }
    
    # Save/update persistent results cache
    save_result(record)
    return record

# ---------------------------------------------------------------------------
# Results Persistence & Summary Printing
# ---------------------------------------------------------------------------
def save_result(record: Dict[str, Any]):
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    all_results = {}
    if RESULTS_FILE.exists():
        try:
            with open(RESULTS_FILE, "r", encoding="utf-8") as f:
                all_results = json.load(f)
        except Exception:
            all_results = {}
            
    all_results[record["file"]] = record
    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)

def print_summary_table():
    if not RESULTS_FILE.exists():
        print("No benchmark results found.")
        return
        
    with open(RESULTS_FILE, "r", encoding="utf-8") as f:
        results = json.load(f)
        
    print("\n" + "=" * 98)
    print("                     FASTSCRUB MASTER MULTI-DOMAIN BENCHMARK MATRIX                      ")
    print("=" * 98)
    print(f"| {'Dataset Name':<24} | {'Domain / Category':<24} | {'Size (MB)':<10} | {'Throughput':<11} | {'Peak Speed':<11} | {'Recall':<8} |")
    print(f"|{'-'*26}|{'-'*26}|{'-'*12}|{'-'*13}|{'-'*13}|{'-'*10}|")
    
    total_size_mb = 0.0
    total_time_s = 0.0
    total_inj = 0
    total_det = 0
    
    for r in results.values():
        total_size_mb += r["size_mb"]
        total_time_s += r["time_s"]
        total_inj += r["probes_injected"]
        total_det += r["probes_detected"]
        print(f"| {r['name']:<24} | {r['category']:<24} | {r['size_mb']:8.2f} MB | {r['speed_mbs']:7.2f} MB/s | {r['peak_mbs']:7.2f} MB/s | {r['recall_pct']:6.2f} % |")
        
    avg_speed = (total_size_mb / total_time_s) if total_time_s > 0 else 0
    overall_recall = (total_det / total_inj * 100.0) if total_inj > 0 else 100.0
    
    print("=" * 98)
    print(f"[*] Total Data Processed       : {total_size_mb / 1024:.2f} GB ({total_size_mb:,.2f} MB)")
    print(f"[*] Total CPU Processing Time  : {total_time_s:.2f} seconds ({total_time_s / 60:.2f} minutes)")
    print(f"[*] Overall Average Throughput : {avg_speed:.2f} MB/s")
    print(f"[*] Overall Secret Recall Rate : {total_det} / {total_inj} ({overall_recall:.2f}%)")
    print("==========================================================================================\n")

# ---------------------------------------------------------------------------
# CLI Argument Parser
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="FastScrub Multi-Domain Benchmark Suite")
    parser.add_argument("dataset", nargs="?", help="Path to a single dataset to benchmark (e.g. tests/data/Apache.log)")
    parser.add_argument("--all", action="store_true", help="Run benchmarks across all available datasets in tests/data/")
    parser.add_argument("--summary", action="store_true", help="Print the cumulative benchmark summary table")
    parser.add_argument("--limit-gb", type=float, help="Optional limit in GB per dataset (e.g. --limit-gb 1.0 for large files)")
    
    args = parser.parse_args()
    
    if args.summary:
        print_summary_table()
        return
        
    data_dir = Path("tests/data")
    
    if args.all:
        print("[*] Starting Full Multi-Domain Benchmark Sweep...")
        available_files = [f for f in data_dir.iterdir() if f.is_file() and f.name in DATASET_METADATA]
        for f in available_files:
            max_bytes = int(args.limit_gb * 1024**3) if args.limit_gb else None
            run_dataset_benchmark(f, max_bytes)
        print_summary_table()
        
    elif args.dataset:
        fpath = Path(args.dataset)
        if not fpath.exists():
            print(f"Error: File '{fpath}' does not exist.")
            sys.exit(1)
        max_bytes = int(args.limit_gb * 1024**3) if args.limit_gb else None
        run_dataset_benchmark(fpath, max_bytes)
        print_summary_table()
        
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
