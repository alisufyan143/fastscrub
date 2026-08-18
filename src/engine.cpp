#include "include/engine.hpp"

#include <thread>
#include <vector>
#include <cctype>

namespace fastscrub {

Engine::Engine(unsigned worker_count)
    : matcher_() {
    if (worker_count == 0) {
        workers_ = std::thread::hardware_concurrency();
        if (workers_ == 0) {
            workers_ = 4; // Fallback
        }
    } else {
        workers_ = worker_count;
    }
}

std::string Engine::scrub(std::string_view input) const {
    return matcher_.scrub(input);
}

std::size_t Engine::snap_to_whitespace(std::string_view input, std::size_t pos) noexcept {
    while (pos < input.size()) {
        char c = input[pos];
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '\v' || c == '\f') {
            return pos;
        }
        ++pos;
    }
    return input.size();
}

std::string Engine::scrub_bulk(std::string_view input) const {
    if (input.empty()) {
        return "";
    }
    
    // Fast path for small inputs or single worker
    if (workers_ <= 1 || input.size() < 4096) {
        return matcher_.scrub(input);
    }

    std::size_t chunk_size = input.size() / workers_;
    std::vector<std::string_view> chunks;
    chunks.reserve(workers_);

    std::size_t current_pos = 0;
    for (unsigned i = 0; i < workers_ - 1; ++i) {
        std::size_t target_pos = current_pos + chunk_size;
        if (target_pos >= input.size()) {
            break;
        }
        
        std::size_t end_pos = snap_to_whitespace(input, target_pos);
        if (end_pos > current_pos) {
            chunks.push_back(input.substr(current_pos, end_pos - current_pos));
            current_pos = end_pos;
        }
    }
    
    if (current_pos < input.size()) {
        chunks.push_back(input.substr(current_pos));
    }

    std::vector<std::string> results(chunks.size());
    
    {
        std::vector<std::jthread> threads;
        threads.reserve(chunks.size());
        for (std::size_t i = 0; i < chunks.size(); ++i) {
            threads.emplace_back([this, &chunks, &results, i]() {
                results[i] = matcher_.scrub(chunks[i]);
            });
        }
        // std::jthread automatically joins on destruction.
        // Leaving this scope ensures all threads have completed.
    }

    std::size_t total_length = 0;
    for (const auto& r : results) {
        total_length += r.size();
    }
    
    std::string combined;
    combined.reserve(total_length);
    for (const auto& r : results) {
        combined.append(r);
    }
    
    return combined;
}

} // namespace fastscrub
