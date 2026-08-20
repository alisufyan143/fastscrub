#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include <thread>
#include <future>
#include <random>
#include <fstream>
#include <cstring>
#include <algorithm>

#include "../src/include/swar_scanner.hpp"
#include "../src/include/matcher.hpp"
#include "../src/include/engine.hpp"

using namespace fastscrub;

// Sample representative log lines containing varied mix of clean text, PII, and secrets
static const std::vector<std::string> SAMPLE_LOG_LINES = {
    "2026-08-20T10:15:30.123Z [INFO] worker-01: User alice.smith@enterprise-corp.com logged in from 192.168.1.105 with session 550e8400-e29b-41d4-a716-446655440000",
    "2026-08-20T10:15:31.456Z [DEBUG] db-pool: Connected to postgresql://admin:SuperSecretPass123@db.internal.net:5432/production_db successfully",
    "2026-08-20T10:15:32.789Z [WARN] auth-svc: Failed payment attempt for card 4532-0150-1234-5678, user phone +1 (555) 234-5678, SSN 000-12-3456",
    "2026-08-20T10:15:33.012Z [INFO] api-gateway: Handled GET /v1/status HTTP/1.1 200 OK 14ms host=gw-prod-02",
    std::string("2026-08-20T10:15:34.345Z [DEBUG] secrets-loader: Loaded token ") + "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 and stripe " + "sk_live_" + "51Abcdefghijklmnopqrstuvwx",
    "2026-08-20T10:15:35.678Z [INFO] network-monitor: Interface eth0 MAC 00:1A:2B:3C:4D:5E received 1048576 packets with zero dropped frames",
    "2026-08-20T10:15:36.901Z [DEBUG] kernel: [ 12345.678901] CPU0: Core temperature 42C, frequency scaled to 3100MHz, normal state",
    "2026-08-20T10:15:37.234Z [INFO] app-server: Processing transaction with trace_id=8f7e6d5c-4b3a-210f-e8d7-c6b5a4938271 duration=3.4ms"
};

// Generate an in-memory synthetic log buffer of exact requested size
static std::string generate_synthetic_log_buffer(std::size_t target_bytes) {
    std::string buffer;
    buffer.reserve(target_bytes + 4096);
    
    std::size_t line_idx = 0;
    while (buffer.size() < target_bytes) {
        const auto& line = SAMPLE_LOG_LINES[line_idx % SAMPLE_LOG_LINES.size()];
        buffer.append(line);
        buffer.push_back('\n');
        line_idx++;
    }
    return buffer;
}

int main(int argc, char* argv[]) {
    std::cout << "===============================================================\n";
    std::cout << "       FASTSCRUB HARDWARE PERFORMANCE & SPEED LIMIT TEST       \n";
    std::cout << "===============================================================\n";

    unsigned int num_cores = std::thread::hardware_concurrency();
    if (num_cores == 0) num_cores = 4;
    std::cout << "[*] CPU Detected Hardware Cores / Threads: " << num_cores << "\n";

    // -------------------------------------------------------------------------
    // TEST 1: RAW SWAR 64-BIT ANCHOR SCANNER IN-MEMORY CEILING (1 Core)
    // -------------------------------------------------------------------------
    std::cout << "\n>>> [TEST 1] Raw SWAR 64-bit Vectorized Scanner (Single-Core In-Memory)...\n";
    const std::size_t TEST1_SIZE = 512ULL * 1024 * 1024; // 512 MB in RAM
    std::cout << "    Generating 512 MB realistic log buffer in RAM...\n";
    std::string test1_buf = generate_synthetic_log_buffer(TEST1_SIZE);

    const int TEST1_ITERATIONS = 4; // Scan 2.0 GB total
    std::size_t anchor_count = 0;

    auto t1_start = std::chrono::steady_clock::now();
    for (int it = 0; it < TEST1_ITERATIONS; ++it) {
        std::size_t pos = 0;
        const char* data = test1_buf.data();
        std::size_t len = test1_buf.size();
        while (pos < len) {
            pos = SwarScanner::find_next_anchor(data, len, pos);
            if (pos < len) {
                anchor_count++;
                pos++;
            }
        }
    }
    auto t1_end = std::chrono::steady_clock::now();
    double t1_secs = std::chrono::duration<double>(t1_end - t1_start).count();
    double t1_mb = (static_cast<double>(TEST1_SIZE) * TEST1_ITERATIONS) / (1024.0 * 1024.0);
    double t1_speed = t1_mb / t1_secs;

    std::cout << "    [+] Scanned Data      : " << t1_mb << " MB\n";
    std::cout << "    [+] Anchors Found     : " << anchor_count << "\n";
    std::cout << "    [+] Elapsed Time      : " << std::fixed << std::setprecision(3) << t1_secs << " s\n";
    std::cout << "    [+] SWAR Raw Speed    : " << std::fixed << std::setprecision(2) << t1_speed << " MB/s (" 
              << (t1_speed / 1024.0) << " GB/s)\n";

    // -------------------------------------------------------------------------
    // TEST 2: FULL MATCHER SCAN + SCRUB_INPLACE (Single-Core In-Memory)
    // -------------------------------------------------------------------------
    std::cout << "\n>>> [TEST 2] Full Matcher (PII + Secrets + Scrub In-Place) (Single-Core In-Memory)...\n";
    const std::size_t TEST2_SIZE = 256ULL * 1024 * 1024; // 256 MB
    std::cout << "    Generating 256 MB fresh log buffer in RAM...\n";
    std::string test2_buf = generate_synthetic_log_buffer(TEST2_SIZE);

    Matcher matcher;
    auto t2_start = std::chrono::steady_clock::now();
    matcher.scrub_inplace(&test2_buf[0], test2_buf.size());
    auto t2_end = std::chrono::steady_clock::now();
    
    double t2_secs = std::chrono::duration<double>(t2_end - t2_start).count();
    double t2_mb = static_cast<double>(TEST2_SIZE) / (1024.0 * 1024.0);
    double t2_speed = t2_mb / t2_secs;

    std::cout << "    [+] Processed Data    : " << t2_mb << " MB\n";
    std::cout << "    [+] Elapsed Time      : " << std::fixed << std::setprecision(3) << t2_secs << " s\n";
    std::cout << "    [+] Single-Core Speed : " << std::fixed << std::setprecision(2) << t2_speed << " MB/s\n";

    // -------------------------------------------------------------------------
    // TEST 3: MULTI-THREADED PARALLEL IN-MEMORY SPEED (All Cores Saturated)
    // -------------------------------------------------------------------------
    std::cout << "\n>>> [TEST 3] Multi-Threaded In-Memory Engine (" << num_cores << " Workers)...\n";
    const std::size_t TEST3_SIZE = 512ULL * 1024 * 1024; // 512 MB
    std::cout << "    Generating 512 MB fresh log buffer in RAM...\n";
    std::string test3_buf = generate_synthetic_log_buffer(TEST3_SIZE);

    Engine parallel_engine(num_cores);
    auto t3_start = std::chrono::steady_clock::now();
    parallel_engine.scrub_inplace(&test3_buf[0], test3_buf.size());
    auto t3_end = std::chrono::steady_clock::now();

    double t3_secs = std::chrono::duration<double>(t3_end - t3_start).count();
    double t3_mb = static_cast<double>(TEST3_SIZE) / (1024.0 * 1024.0);
    double t3_speed = t3_mb / t3_secs;

    std::cout << "    [+] Processed Data    : " << t3_mb << " MB\n";
    std::cout << "    [+] Elapsed Time      : " << std::fixed << std::setprecision(3) << t3_secs << " s\n";
    std::cout << "    [+] Multi-Core Speed  : " << std::fixed << std::setprecision(2) << t3_speed << " MB/s ("
              << (t3_speed / 1024.0) << " GB/s)\n";

    // -------------------------------------------------------------------------
    // TEST 4: REAL DISK FILE STREAMING TEST (If file supplied as argument)
    // -------------------------------------------------------------------------
    if (argc >= 2) {
        std::string file_path = argv[1];
        std::cout << "\n>>> [TEST 4] Real File Disk Streaming Test on: " << file_path << "\n";
        
        std::ifstream file(file_path, std::ios::binary | std::ios::ate);
        if (!file) {
            std::cout << "    [-] Could not open file: " << file_path << "\n";
        } else {
            std::streamsize file_size = file.tellg();
            file.seekg(0, std::ios::beg);

            // Test on first 1 GB of file to get instantaneous speed report
            std::size_t test_limit = std::min(static_cast<std::size_t>(file_size), 1024ULL * 1024 * 1024);
            std::cout << "    [*] Streaming first " << (test_limit / (1024.0 * 1024.0)) << " MB from disk...\n";

            const std::size_t CHUNK_SIZE = 64ULL * 1024 * 1024; // 64 MB chunk
            std::string chunk_buf(CHUNK_SIZE + Engine::OVERLAP, '\0');
            
            std::size_t processed = 0;
            double io_wait_time = 0.0;
            double cpu_scrub_time = 0.0;

            while (processed < test_limit) {
                std::size_t to_read = std::min(CHUNK_SIZE, test_limit - processed);
                std::size_t read_offset = (processed == 0) ? 0 : Engine::OVERLAP;

                // Measure Disk Read Time
                auto io_t1 = std::chrono::steady_clock::now();
                file.read(&chunk_buf[read_offset], to_read);
                std::size_t bytes_read = file.gcount();
                auto io_t2 = std::chrono::steady_clock::now();
                io_wait_time += std::chrono::duration<double>(io_t2 - io_t1).count();

                if (bytes_read == 0) break;

                // Measure CPU Scrubbing Time
                auto cpu_t1 = std::chrono::steady_clock::now();
                parallel_engine.scrub_inplace(&chunk_buf[0], read_offset + bytes_read);
                auto cpu_t2 = std::chrono::steady_clock::now();
                cpu_scrub_time += std::chrono::duration<double>(cpu_t2 - cpu_t1).count();

                processed += bytes_read;
                if (read_offset + bytes_read > Engine::OVERLAP) {
                    std::memcpy(&chunk_buf[0], &chunk_buf[read_offset + bytes_read - Engine::OVERLAP], Engine::OVERLAP);
                }
            }

            double streamed_mb = static_cast<double>(processed) / (1024.0 * 1024.0);
            double total_time = io_wait_time + cpu_scrub_time;

            std::cout << "    -----------------------------------------------------------\n";
            std::cout << "    [+] Disk Read Wait Time   : " << std::fixed << std::setprecision(3) << io_wait_time << " s (" 
                      << std::fixed << std::setprecision(2) << (streamed_mb / io_wait_time) << " MB/s Disk Read Bandwidth)\n";
            std::cout << "    [+] CPU Scrubbing Time    : " << std::fixed << std::setprecision(3) << cpu_scrub_time << " s (" 
                      << std::fixed << std::setprecision(2) << (streamed_mb / cpu_scrub_time) << " MB/s CPU Processing Speed)\n";
            std::cout << "    [+] Total End-to-End Time : " << std::fixed << std::setprecision(3) << total_time << " s (" 
                      << std::fixed << std::setprecision(2) << (streamed_mb / total_time) << " MB/s Total End-to-End)\n";
        }
    }

    std::cout << "\n===============================================================\n";
    std::cout << "                      TEST COMPLETE                            \n";
    std::cout << "===============================================================\n";

    return 0;
}
