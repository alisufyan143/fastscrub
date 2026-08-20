#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include "../src/include/swar_scanner.hpp"
#include "../src/include/secret_parsers.hpp"

using namespace fastscrub;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: profile_anchors <logfile>\n";
        return 1;
    }

    std::string path = argv[1];
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open " << path << "\n";
        return 1;
    }

    // Read 64 MB of real log data into RAM
    const std::size_t SAMPLE_SIZE = 64 * 1024 * 1024;
    std::vector<char> buffer(SAMPLE_SIZE);
    file.read(buffer.data(), SAMPLE_SIZE);
    std::size_t bytes_read = file.gcount();
    
    std::cout << "===============================================================\n";
    std::cout << "       FASTSCRUB C++ LOW-LEVEL ANCHOR & PARSER PROFILER        \n";
    std::cout << "===============================================================\n";
    std::cout << "[*] Analyzed Sample : " << (bytes_read / (1024.0 * 1024.0)) << " MB from " << path << "\n\n";

    const char* data = buffer.data();
    const std::size_t len = bytes_read;

    // Anchor count statistics
    uint64_t count_at = 0;
    uint64_t count_underscore = 0;
    uint64_t count_hyphen = 0;
    uint64_t count_dot = 0;
    uint64_t count_colon = 0;
    uint64_t count_equal = 0;
    uint64_t count_plus = 0;
    uint64_t count_paren = 0;
    uint64_t count_quote = 0;
    uint64_t count_A = 0;
    uint64_t total_swar_stops = 0;
    uint64_t swar_8byte_skips = 0;

    auto t_start = std::chrono::high_resolution_clock::now();

    std::size_t i = 0;
    while (i < len) {
        std::size_t prev_i = i;
        i = SwarScanner::find_next_anchor(data, len, i);
        if (i >= len) break;

        swar_8byte_skips += (i - prev_i) / 8;
        total_swar_stops++;

        char c = data[i];
        switch (c) {
            case '@': count_at++; break;
            case '_': count_underscore++; break;
            case '-': count_hyphen++; break;
            case '.': count_dot++; break;
            case ':': count_colon++; break;
            case '=': count_equal++; break;
            case '+': count_plus++; break;
            case '(': count_paren++; break;
            case '"': count_quote++; break;
            case 'A': count_A++; break;
            default: break;
        }
        i++;
    }

    auto t_end = std::chrono::high_resolution_clock::now();
    double scan_ms = std::chrono::duration<double, std::milli>(t_end - t_start).count();

    std::cout << ">>> [ANCHOR DISTRIBUTION IN 64 MB REAL LOG DATA]\n";
    std::cout << "---------------------------------------------------------------\n";
    std::cout << "  Anchor Char | Total Occurrences | % of All SWAR Stops\n";
    std::cout << "---------------------------------------------------------------\n";
    
    auto print_row = [&](std::string name, uint64_t cnt) {
        double pct = (total_swar_stops > 0) ? (cnt * 100.0 / total_swar_stops) : 0.0;
        std::cout << "      " << std::left << std::setw(8) << name 
                  << " | " << std::right << std::setw(17) << cnt 
                  << " | " << std::fixed << std::setprecision(2) << std::setw(18) << pct << " %\n";
    };

    print_row("'.'  (Dot)", count_dot);
    print_row("':'  (Colon)", count_colon);
    print_row("'-'  (Hyphen)", count_hyphen);
    print_row("'A'  (Cap A)", count_A);
    print_row("'='  (Equal)", count_equal);
    print_row("'_'  (Under)", count_underscore);
    print_row("'\"'  (Quote)", count_quote);
    print_row("'@'  (At)", count_at);
    print_row("'+'  (Plus)", count_plus);
    print_row("'('  (Paren)", count_paren);
    std::cout << "---------------------------------------------------------------\n";
    std::cout << "  TOTAL STOPS : " << total_swar_stops << " stops in " << scan_ms << " ms ("
              << (bytes_read / (1024.0 * 1024.0)) / (scan_ms / 1000.0) << " MB/s raw jump speed)\n";
    std::cout << "  8-BYTE SKIPS: " << swar_8byte_skips << " fast leaps\n";
    std::cout << "===============================================================\n";

    return 0;
}
