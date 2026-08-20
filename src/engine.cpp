#include "include/engine.hpp"

#include <thread>
#include <vector>
#include <algorithm>
#include <cstring>
#include <atomic>

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

std::optional<std::string> Engine::scrub(std::string_view input) const {
    return scrub_bulk(input);
}

void Engine::scrub_inplace(char* data, std::size_t len) const {
    scrub_bulk_inplace(data, len);
}

std::vector<ChunkRange> Engine::compute_chunks(
    std::size_t input_size, unsigned workers) noexcept
{
    std::vector<ChunkRange> chunks;
    if (input_size == 0 || workers == 0) return chunks;

    std::size_t chunk_size = input_size / workers;
    if (chunk_size == 0) chunk_size = input_size;

    chunks.reserve(workers);
    for (unsigned i = 0; i < workers; ++i) {
        ChunkRange c;
        c.start = i * chunk_size;
        c.end = (i == workers - 1) ? input_size : (i + 1) * chunk_size;
        c.scan_end = std::min(c.end + OVERLAP, input_size);
        if (c.start >= input_size) break;
        chunks.push_back(c);
    }
    return chunks;
}

void Engine::merge_intervals(std::vector<PiiInterval>& intervals) noexcept {
    if (intervals.empty()) return;

    std::sort(intervals.begin(), intervals.end());

    std::vector<PiiInterval> merged;
    merged.reserve(intervals.size());
    merged.push_back(intervals[0]);

    for (std::size_t i = 1; i < intervals.size(); ++i) {
        auto& prev = merged.back();
        const auto& curr = intervals[i];

        // Duplicate or overlapping interval
        if (curr.start < prev.start + prev.len) {
            std::size_t new_end = std::max(prev.start + prev.len, curr.start + curr.len);
            // Keep the mask of the longer match
            if (curr.len > prev.len) {
                prev.mask = curr.mask;
                prev.inplace_offset = curr.inplace_offset;
                prev.inplace_len = curr.inplace_len;
            }
            prev.len = new_end - prev.start;
        } else {
            merged.push_back(curr);
        }
    }

    intervals = std::move(merged);
}

std::vector<PiiInterval> Engine::scan_bulk_intervals(std::string_view input) const {
    auto chunks = compute_chunks(input.size(), workers_);
    if (chunks.empty()) {
        std::vector<PiiInterval> local_intervals;
        local_intervals.reserve(256);
        matcher_.scan(input, local_intervals);
        return local_intervals;
    }

    std::vector<std::vector<PiiInterval>> thread_intervals(chunks.size());

    {
        std::vector<std::thread> threads;
        threads.reserve(chunks.size());
        for (std::size_t i = 0; i < chunks.size(); ++i) {
            threads.emplace_back([this, &input, &chunks, &thread_intervals, i]() {
                std::string_view chunk_view = input.substr(chunks[i].start, chunks[i].scan_end - chunks[i].start);
                std::vector<PiiInterval> local_intervals;
                local_intervals.reserve(256);
                matcher_.scan(chunk_view, local_intervals);
                
                for (auto& iv : local_intervals) {
                    iv.start += chunks[i].start;
                }
                thread_intervals[i] = std::move(local_intervals);
            });
        }
        for (auto& th : threads) {
            if (th.joinable()) th.join();
        }
    }

    std::vector<PiiInterval> all_intervals;
    std::size_t total = 0;
    for (const auto& ti : thread_intervals) total += ti.size();
    all_intervals.reserve(total);
    for (auto& ti : thread_intervals) {
        all_intervals.insert(all_intervals.end(), ti.begin(), ti.end());
    }

    if (!all_intervals.empty()) {
        merge_intervals(all_intervals);
    }
    return all_intervals;
}

std::optional<std::string> Engine::scrub_bulk(std::string_view input) const {
    if (input.empty()) {
        return std::nullopt;
    }
    
    // Fast path for small inputs or single worker
    if (workers_ <= 1 || input.size() < 4096) {
        return matcher_.scrub(input);
    }

    auto all_intervals = scan_bulk_intervals(input);

    if (all_intervals.empty()) {
        return std::nullopt;
    }

    // Assemble output string
    std::size_t final_size = input.size();
    for (const auto& iv : all_intervals) {
        final_size -= iv.len;
        final_size += iv.mask.size();
    }

    std::string result;
    result.reserve(final_size);

    std::size_t cursor = 0;
    for (const auto& iv : all_intervals) {
        if (iv.start > cursor) {
            result.append(input.data() + cursor, iv.start - cursor);
        }
        result.append(iv.mask.data(), iv.mask.size());
        cursor = iv.start + iv.len;
    }
    if (cursor < input.size()) {
        result.append(input.data() + cursor, input.size() - cursor);
    }

    return result;
}

void Engine::scrub_bulk_inplace(char* data, std::size_t len) const {
    if (len == 0 || data == nullptr) return;

    // Fast path for small inputs or single worker
    if (workers_ <= 1 || len < 4096) {
        matcher_.scrub_inplace(data, len);
        return;
    }

    auto chunks = compute_chunks(len, workers_);
    if (chunks.empty()) {
        matcher_.scrub_inplace(data, len);
        return;
    }

    // Direct multi-threaded in-place masking: ZERO vector allocations, ZERO sorting
    std::vector<std::thread> threads;
    threads.reserve(chunks.size());
    for (std::size_t i = 0; i < chunks.size(); ++i) {
        threads.emplace_back([this, data, &chunks, i]() {
            char* chunk_ptr = data + chunks[i].start;
            std::size_t chunk_len = chunks[i].scan_end - chunks[i].start;
            matcher_.scrub_inplace(chunk_ptr, chunk_len);
        });
    }
    for (auto& th : threads) {
        if (th.joinable()) th.join();
    }
}

} // namespace fastscrub
