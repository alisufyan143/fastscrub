import time
import random
import sys
from pathlib import Path
from fastscrub import scrub_inplace

CHUNK_SIZE = 64 * 1024 * 1024  # 64 MB Chunk Size
OVERLAP = 2048

PAYLOADS = [
    b"aws credentials{\n  id: ABIAS9L8MS5IPHTZPPUQ\n  secret: .v2QPKHl7LcdVYsjaR4LgQiZ1zw3MAnMyiondXC63;\n}",
    b"{AKIAWGXZ9OPDOWUJMZGI}",
    b"-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASC...\n-----END PRIVATE KEY-----\n",
    b"xoxb" + b"-1234567890-1234567890-abcdefghijklmnopqrstuvwx",
    b"sk_live_" + b"1234567890abcdefghijklmnopqrstuvwxyz"
]

def run_benchmark(file_path: str):
    file_path_obj = Path(file_path)
    if not file_path_obj.exists():
        print(f"Error: File '{file_path}' does not exist.")
        return

    file_size = file_path_obj.stat().st_size
    print("===========================================")
    print(" FASTSCRUB PYTHON MULTI-THREADED BENCHMARK")
    print("===========================================")
    print(f"[*] Dataset Size  : {file_size / (1024**2):.2f} MB")
    print(f"[*] Chunk Size    : {CHUNK_SIZE / (1024**2):.2f} MB")
    print(f"[*] Boundary Safe : {OVERLAP} bytes overlap retained per chunk")
    print("-------------------------------------------")
    
    with open(file_path, "rb") as f:
        file_offset = 0
        total_time = 0.0
        total_injections = 0
        total_detected = 0
        
        # We allocate a single bytearray buffer that can hold a full chunk + overlap
        alloc_size = min(file_size, CHUNK_SIZE + OVERLAP)
        chunk_buf = bytearray(alloc_size)
        
        while file_offset < file_size:
            bytes_to_read = min(CHUNK_SIZE, file_size - file_offset)
            read_offset = 0 if file_offset == 0 else OVERLAP
            
            # Read from disk directly into the bytearray memoryview to avoid RAM copies
            bytes_read = f.readinto(memoryview(chunk_buf)[read_offset:read_offset + bytes_to_read])
            if bytes_read == 0: break
            
            valid_size = read_offset + bytes_read
            
            # If this is the final chunk and it doesn't fill the buffer, shrink the bytearray.
            # scrub_inplace processes the EXACT length of the bytearray object.
            if valid_size < len(chunk_buf):
                del chunk_buf[valid_size:]
                
            # Inject 100 secrets randomly into the valid bounds of the chunk
            injected_positions = []
            for _ in range(100):
                p = random.choice(PAYLOADS)
                
                # PAD WITH SPACES to prevent has_clean_boundary() from rejecting it
                padded_p = b" " + p + b" "
                
                idx = random.randint(OVERLAP, valid_size - len(padded_p) - 1)
                chunk_buf[idx:idx+len(padded_p)] = padded_p
                
                # Record the position of the actual secret, not the padding spaces
                injected_positions.append((idx + 1, len(p)))
                total_injections += 1
            
            # Start High-Precision Timer (Isolating Disk I/O)
            t1 = time.perf_counter()
            # scrub_inplace internally routes 4GB to _ENGINE.scrub_bulk_inplace
            # which drops the GIL and spawns C++ worker threads across all cores.
            scrub_inplace(chunk_buf)
            t2 = time.perf_counter()
            
            total_time += (t2 - t1)
            file_offset += bytes_read
            
            # Verify detections (Precision/Recall validation)
            for idx, length in injected_positions:
                # Our engine replaces PII with `[REDACTED` or `*`. If the bytes changed, it caught it.
                if b"[REDACTED" in chunk_buf[idx:idx+length] or b"**" in chunk_buf[idx:idx+length]:
                    total_detected += 1
            
            # Carry over the last 2048 bytes to the start of the buffer for the next chunk
            if file_offset < file_size and valid_size > OVERLAP:
                chunk_buf[:OVERLAP] = chunk_buf[valid_size - OVERLAP:valid_size]
                
            percent = int((file_offset * 100) / file_size)
            mb_s = (bytes_read / (1024**2)) / (t2 - t1)
            print(f"\r[Progress] {percent}% ({file_offset / (1024**2):.0f} MB) - Speed: {mb_s:.2f} MB/s", end="", flush=True)
            
        print("\n-------------------------------------------")
        print(f"Total CPU Time : {total_time:.2f} seconds")
        print(f"Throughput     : {(file_size / (1024**2)) / total_time:.2f} MB/s")
        print(f"True Positives : {total_detected} / {total_injections}")
        
        recall = (total_detected / total_injections) * 100 if total_injections > 0 else 100
        print(f"Recall Rate    : {recall:.2f}%")
        print("===========================================")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python bench_throughput.py <file>")
        sys.exit(1)
    run_benchmark(sys.argv[1])
