# 57 GB Multi-Domain Throughput Matrix ⚡

To measure end-to-end processing throughput on real-world production data, `fastscrub` was evaluated across **57.46 GB of raw uncompressed logs** from the University of Toronto Loghub repository and Kaggle datasets.

---

## 1. Hardware Test Bed

* **CPU**: Intel Core i5-7200U (2 physical cores / 4 threads @ 2.50 GHz - 3.10 GHz Turbo)
* **RAM**: 16 GB DDR4
* **Storage**: NVMe PCIe M.2 SSD
* **OS**: Windows 10 x64 / Ubuntu 22.04 LTS (x86_64)

---

## 2. Multi-Domain Master Throughput Leaderboard

| Dataset Name | Domain / Log Category | Size (MB) | Throughput | Peak Speed | Probe Recall |
|---|---|---|---|---|---|
| **Kaggle Student Essays** | Academic PII NLP | **104.42 MB** | **321.45 MB/s** | **322.01 MB/s** | **100.00%** |
| **Apache Web Server** | Web & HTTP Access Logs | **4.90 MB** | **118.86 MB/s** | **118.86 MB/s** | **100.00%** |
| **OpenPII Corpus** | Unstructured Document NLP | **98.04 MB** | **116.94 MB/s** | **119.86 MB/s** | **100.00%** |
| **Apple macOS System** | macOS Operating System | **16.10 MB** | **101.51 MB/s** | **101.51 MB/s** | **100.00%** |
| **Thunderbird HPC** | Supercomputer System Logs | **30,315.69 MB** | **95.42 MB/s** | **144.33 MB/s** | **100.00%** |
| **OpenSSH Auth Logs** | Auth & Network Security | **70.02 MB** | **94.21 MB/s** | **96.96 MB/s** | **100.00%** |
| **Hadoop HDFS Cluster** | Distributed Big Data | **1,504.88 MB** | **85.86 MB/s** | **106.03 MB/s** | **100.00%** |
| **Linux Kernel & Syslog** | Linux Operating System | **2.24 MB** | **74.95 MB/s** | **74.95 MB/s** | **100.00%** |
| **Windows Security Events** | Enterprise Windows Logs | **26,714.99 MB** | **72.76 MB/s** | **76.11 MB/s** | **100.00%** |

---

## 3. Thunderbird 30.3 GB Benchmark Deep-Dive

The **Thunderbird** supercomputer dataset is a standard 30.3 GB raw log benchmark containing millions of timestamped diagnostic records, IP addresses, node identifiers, and error traces.

* **Total Dataset Size**: 30,315.69 MB (30.3 GB)
* **Total Execution Time**: **282.68 seconds (~4.7 minutes)**
* **Sustained End-to-End Speed**: **107.27 MB/s**
* **Peak Core Burst Speed**: **144.33 MB/s**
* **Memory Footprint**: Flat, constant memory under 80 MB throughout the entire run.

---

## 4. Reproducing Throughput Benchmarks

Run the complete multi-domain throughput benchmark suite:

```bash
python bench/benchmark_suite.py --all
```
