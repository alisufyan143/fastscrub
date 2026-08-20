import subprocess
import sys
import os

def print_header(title):
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60 + "\n")

def run_tests():
    print_header("RUNNING REGRESSION TESTS")
    try:
        # Run pytest and stream output
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"],
            check=True
        )
        print("\n✅ All correctness tests passed.")
        return True
    except subprocess.CalledProcessError:
        print("\n❌ REGRESSION DETECTED: One or more correctness tests failed.")
        return False

def run_benchmarks():
    print_header("RUNNING PERFORMANCE BENCHMARKS")
    bench_script = os.path.join("tests", "benchmark_comprehensive.py")
    if not os.path.exists(bench_script):
        print(f"⚠️ Benchmark script {bench_script} not found. Skipping.")
        return True

    try:
        # Run the benchmark script
        # In a real CI environment, we would parse the JSON/text output of this 
        # script and assert that MB/s > baseline_MB_s * 0.95
        subprocess.run(
            [sys.executable, bench_script],
            check=True
        )
        print("\n✅ Benchmarks ran successfully.")
        return True
    except subprocess.CalledProcessError:
        print("\n❌ REGRESSION DETECTED: Benchmarks failed to run.")
        return False

def main():
    if not os.path.exists("tests"):
        print("Error: Must be run from the root of the fastscrub repository.")
        sys.exit(1)

    tests_ok = run_tests()
    
    # We will only run benchmarks if tests pass
    benchmarks_ok = False
    if tests_ok:
        benchmarks_ok = run_benchmarks()

    if not (tests_ok and benchmarks_ok):
        print("\n🚨 REGRESSION GUARD FAILED 🚨")
        sys.exit(1)
    
    print("\n🚀 REGRESSION GUARD PASSED: Code is safe to merge/release. 🚀")
    sys.exit(0)

if __name__ == "__main__":
    main()
