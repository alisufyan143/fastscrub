#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include "../src/include/engine.hpp"

using namespace fastscrub;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <test_file>\n";
        return 1;
    }

    std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Failed to open file: " << argv[1] << "\n";
        return 1;
    }

    std::streamsize file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    if (file_size == 0) {
        std::cerr << "File is empty.\n";
        return 1;
    }

    // Use 500 MB chunk size. Extremely safe for RAM, perfect for streaming.
    const std::size_t CHUNK_SIZE = 500ULL * 1024 * 1024;
    const std::size_t OVERLAP = Engine::OVERLAP; // 2048 bytes overlap guarantee

    std::size_t buffer_size = std::min(static_cast<std::size_t>(file_size), CHUNK_SIZE + OVERLAP);
    std::string work_buf(buffer_size, '\0');

    std::cout << "===========================================\n";
    std::cout << " FASTSCRUB C++ RAW ENGINE BENCHMARK\n";
    std::cout << "===========================================\n";
    std::cout << "[*] Dataset Size  : " << (file_size / (1024.0 * 1024.0)) << " MB\n";
    std::cout << "[*] Chunk Size    : " << (CHUNK_SIZE / (1024.0 * 1024.0)) << " MB\n";
    std::cout << "[*] Boundary Safe : " << OVERLAP << " bytes overlap retained per chunk\n";
    std::cout << "[*] Workers       : 1 (Raw Single-Threaded)\n";
    std::cout << "-------------------------------------------\n";

    Engine engine(1); // Single threaded for raw matcher speed
    
    auto total_scrub_time = std::chrono::duration<double>::zero();
    std::size_t total_processed_bytes = 0; // Excludes overlap double-counting
    std::size_t file_offset = 0;

    while (file_offset < file_size) {
        // Calculate how much new data to read from disk
        std::size_t bytes_to_read = std::min(CHUNK_SIZE, static_cast<std::size_t>(file_size - file_offset));
        
        // If this is not the first chunk, we have OVERLAP bytes already at the start of work_buf.
        // We read the new data right after the overlap.
        std::size_t read_offset = (file_offset == 0) ? 0 : OVERLAP;
        
        // 1. TIMER PAUSED: Wait for the hard drive to load the chunk into RAM
        file.read(&work_buf[read_offset], bytes_to_read);
        std::size_t bytes_read = file.gcount();
        if (bytes_read == 0) break;

        std::size_t valid_chunk_size = read_offset + bytes_read;

        // 2. START THE MONOTONIC STOPWATCH
        auto t1 = std::chrono::steady_clock::now();
        
        // 3. Process the chunk in RAM
        engine.scrub_inplace(&work_buf[0], valid_chunk_size);

        // 4. PAUSE THE STOPWATCH
        auto t2 = std::chrono::steady_clock::now();
        total_scrub_time += std::chrono::duration_cast<std::chrono::duration<double>>(t2 - t1);
        
        // Tally only the NEW bytes read from disk to prevent artificially inflating the MB/s score
        total_processed_bytes += bytes_read; 
        file_offset += bytes_read;

        // Save the last OVERLAP bytes to the beginning of the buffer for the next chunk
        // This completely prevents the False Negative / False Positive edge case where a secret gets cut in half
        if (file_offset < file_size && valid_chunk_size > OVERLAP) {
            std::copy(work_buf.begin() + valid_chunk_size - OVERLAP, 
                      work_buf.begin() + valid_chunk_size, 
                      work_buf.begin());
        }

        // Progress bar
        int percent = (file_offset * 100) / file_size;
        std::cout << "\r[";
        for (int p = 0; p < 50; ++p) {
            if (p < percent / 2) std::cout << "=";
            else if (p == percent / 2) std::cout << ">";
            else std::cout << " ";
        }
        std::cout << "] " << percent << "% (" << (file_offset / (1024*1024)) << " MB)" << std::flush;
    }
    std::cout << "\n-------------------------------------------\n";

    double total_mb = static_cast<double>(total_processed_bytes) / (1024.0 * 1024.0);
    double mb_per_sec = total_mb / total_scrub_time.count();

    std::cout << "Total CPU time : " << total_scrub_time.count() << " seconds\n";
    std::cout << "Throughput     : " << std::fixed << std::setprecision(2) << mb_per_sec << " MB/s\n";
    std::cout << "===========================================\n";

    return 0;
}
