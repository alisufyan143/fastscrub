import os
import sys
import time
import subprocess

def compile_and_install(force_scalar=False):
    env = os.environ.copy()
    if force_scalar:
        # We must explicitly include the pyproject.toml cmake args so they aren't clobbered
        env["SKBUILD_CMAKE_ARGS"] = "-GNinja;-DCMAKE_CXX_COMPILER=g++;-DCMAKE_C_COMPILER=gcc;-DFASTSCRUB_FORCE_SCALAR=1"
    else:
        env.pop("SKBUILD_CMAKE_ARGS", None)
    
    # Force recompilation by disabling pip's cache and passing --no-build-isolation
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "--no-cache-dir", "--force-reinstall", "."],
        env=env,
        check=True
    )

def run_benchmark():
    # We spawn the benchmark in a fresh subprocess so that the Windows OS 
    # file lock on fastscrub.pyd is immediately released when the child exits.
    code = """
import os, time
import fastscrub
data_path = os.path.join("tests", "data", "synth_dataset_v2.json")
if not os.path.exists(data_path):
    print("0.0")
else:
    with open(data_path, "r", encoding="utf-8") as f: text = f.read()
    fastscrub.scrub(text[:1000])
    start = time.perf_counter()
    for _ in range(5): fastscrub.scrub(text)
    duration = (time.perf_counter() - start) / 5.0
    mb = len(text.encode('utf-8')) / (1024 * 1024)
    print(str(mb / duration))
    """
    
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True
    )
    
    return float(result.stdout.strip())

def main():
    print("===========================================")
    print(" SWAR vs SCALAR BENCHMARK")
    print("===========================================")
    
    # 1. Compile and bench SWAR
    print("[*] Compiling with SWAR (Default)...")
    compile_and_install(force_scalar=False)
    swar_speed = run_benchmark()
    print(f"  -> SWAR Throughput:   {swar_speed:.2f} MB/s")
    
    # 2. Compile and bench Scalar
    print("[*] Compiling with SCALAR (Legacy)...")
    compile_and_install(force_scalar=True)
    scalar_speed = run_benchmark()
    print(f"  -> Scalar Throughput: {scalar_speed:.2f} MB/s")
    
    # 3. Restore SWAR
    print("[*] Restoring default SWAR build...")
    compile_and_install(force_scalar=False)
    
    if scalar_speed > 0:
        speedup = swar_speed / scalar_speed
        print("===========================================")
        print(f" SWAR Speedup Multiplier: {speedup:.2f}x")
        print("===========================================")
        
        with open("tests/swar_benchmark_results.txt", "w") as f:
            f.write(f"SWAR: {swar_speed:.2f} MB/s\n")
            f.write(f"Scalar: {scalar_speed:.2f} MB/s\n")
            f.write(f"Speedup: {speedup:.2f}x\n")

if __name__ == "__main__":
    main()
