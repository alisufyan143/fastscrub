import time
import sys
from pathlib import Path
import fastscrub
from fastscrub import Engine, scrub_inplace

def diagnose(file_path: str):
    p = Path(file_path)
    if not p.exists():
        print(f"Error: {file_path} not found.")
        return

    print("===============================================================")
    print("        FASTSCRUB SCIENTIFIC BOTTLENECK DIAGNOSTIC TOOL        ")
    print("===============================================================")
    
    # 1. Load exact 64 MB from real log file into RAM
    SAMPLE_SIZE = 64 * 1024 * 1024
    print(f"[*] Reading {SAMPLE_SIZE / (1024**2):.0f} MB sample from '{p.name}' into RAM...")
    with open(p, "rb") as f:
        raw_bytes = f.read(SAMPLE_SIZE)
    
    actual_len = len(raw_bytes)
    print(f"[+] Loaded {actual_len / (1024**2):.2f} MB ({actual_len:,} bytes) into memory.\n")
    
    # -------------------------------------------------------------
    # EXPERIMENT 1: Single-Thread vs Multi-Thread Core Scaling
    # -------------------------------------------------------------
    print(">>> [EXPERIMENT 1] CPU Worker Thread Scaling (64 MB In-Memory):")
    print("    Tests whether multi-threading scales linearly or hits thread/lock stalls.")
    print("    " + "-" * 55)
    
    worker_configs = [1, 2, 3, 4, 8]
    t_single = None
    
    for w in worker_configs:
        engine = Engine(worker_count=w)
        
        # Fresh buffer copy to ensure identical starting state
        buf = bytearray(raw_bytes)
        
        # Warmup run
        engine.scrub_bulk_inplace(buf)
        
        # Timed run (average of 3 runs for stability)
        times = []
        for _ in range(3):
            buf = bytearray(raw_bytes)
            t0 = time.perf_counter()
            engine.scrub_bulk_inplace(buf)
            t1 = time.perf_counter()
            times.append(t1 - t0)
            
        avg_time = sum(times) / len(times)
        speed = (actual_len / (1024**2)) / avg_time
        
        if w == 1:
            t_single = avg_time
            scaling = "1.00x (Baseline)"
        else:
            speedup = t_single / avg_time if avg_time > 0 else 0
            scaling = f"{speedup:.2f}x speedup"
            
        print(f"    [*] Workers = {w:2d} | Time: {avg_time*1000:6.1f} ms | Throughput: {speed:6.2f} MB/s | Scaling: {scaling}")
        
    print("    " + "-" * 55 + "\n")

    # -------------------------------------------------------------
    # EXPERIMENT 2: Chunk Size Sensitivity (L1/L2/L3 Cache Impact)
    # -------------------------------------------------------------
    print(">>> [EXPERIMENT 2] Chunk Size vs CPU Cache Locality (4 Workers):")
    print("    Tests if large 64MB buffers thrash L3 CPU cache compared to 4MB/16MB.")
    print("    " + "-" * 55)
    
    engine_4w = Engine(worker_count=4)
    chunk_sizes = [1 * 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024, 64 * 1024 * 1024]
    
    for cs in chunk_sizes:
        if cs > actual_len:
            continue
        buf = bytearray(raw_bytes[:cs])
        times = []
        for _ in range(5):
            buf = bytearray(raw_bytes[:cs])
            t0 = time.perf_counter()
            engine_4w.scrub_bulk_inplace(buf)
            t1 = time.perf_counter()
            times.append(t1 - t0)
            
        avg_t = sum(times) / len(times)
        speed = (cs / (1024**2)) / avg_t
        print(f"    [*] Chunk: {cs / (1024**2):4.1f} MB | Time: {avg_t*1000:6.1f} ms | Throughput: {speed:6.2f} MB/s")
        
    print("    " + "-" * 55 + "\n")

    # -------------------------------------------------------------
    # EXPERIMENT 3: Python Wrapper vs Direct C++ Invocation
    # -------------------------------------------------------------
    print(">>> [EXPERIMENT 3] Python Wrapper Overhead Breakdown:")
    print("    " + "-" * 55)
    
    buf = bytearray(raw_bytes)
    
    # Direct _ENGINE.scrub_bulk_inplace
    t0 = time.perf_counter()
    fastscrub._ENGINE.scrub_bulk_inplace(buf)
    t_engine = time.perf_counter() - t0
    
    # fastscrub.scrub_inplace() Python wrapper
    buf = bytearray(raw_bytes)
    t0 = time.perf_counter()
    fastscrub.scrub_inplace(buf)
    t_wrapper = time.perf_counter() - t0
    
    print(f"    [*] Direct _ENGINE.scrub_bulk_inplace : {t_engine*1000:.2f} ms ({actual_len/(1024**2)/t_engine:.2f} MB/s)")
    print(f"    [*] fastscrub.scrub_inplace() wrapper : {t_wrapper*1000:.2f} ms ({actual_len/(1024**2)/t_wrapper:.2f} MB/s)")
    print("    " + "-" * 55 + "\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python bench/diagnose_bottlenecks.py <logfile>")
        sys.exit(1)
    diagnose(sys.argv[1])
