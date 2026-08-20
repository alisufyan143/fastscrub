#pragma once

#include "matcher.hpp"
#include "pii_interval.hpp"

#include <string>
#include <string_view>
#include <cstddef>
#include <vector>

namespace fastscrub {

/// Chunk range for parallel processing with overlap.
struct ChunkRange {
    std::size_t start;      ///< Start byte of the chunk (inclusive).
    std::size_t end;        ///< End byte of the chunk (exclusive) — the "owned" region.
    std::size_t scan_end;   ///< End byte for scanning (= end + OVERLAP or input.size()).
};

/// High-level scrubbing engine with parallel batch processing.
///
/// Owns a single compiled Matcher and exposes both single-string and
/// bulk-text entry points.  Bulk scrubbing splits the input into
/// overlap-aware chunks and processes them concurrently using
/// std::thread (C++20, parallel joining).
class Engine {
public:
    /// Construct the engine, compiling all PII patterns once.
    /// An optional worker_count of 0 (default) auto-detects from
    /// std::thread::hardware_concurrency().
    explicit Engine(unsigned worker_count = 0);

    /// Scrub a single string.  Thin delegate to Matcher::scrub().
    std::optional<std::string> scrub(std::string_view input) const;

    /// Scrub a large text buffer in parallel.
    /// The input is sliced into overlap-aware chunks so that no PII
    /// token is ever split across worker threads.
    std::optional<std::string> scrub_bulk(std::string_view input) const;

    /// Scrub a single buffer in-place.  Thin delegate to Matcher::scrub_inplace().
    void scrub_inplace(char* data, std::size_t len) const;

    /// Scrub a large buffer in-place using parallel workers.
    void scrub_bulk_inplace(char* data, std::size_t len) const;

    /// Overlap size in bytes for parallel chunking.
    /// Must be large enough to cover the longest possible secret (JWTs > 800 bytes).
    static constexpr std::size_t OVERLAP = 2048;

private:
    Matcher  matcher_;
    unsigned workers_;

    /// Compute overlap-aware chunk ranges for parallel processing.
    static std::vector<ChunkRange> compute_chunks(
        std::size_t input_size, unsigned workers) noexcept;

    /// Merge overlapping/duplicate intervals found by multiple threads.
    static void merge_intervals(std::vector<PiiInterval>& intervals) noexcept;

    /// Spawns worker threads, scans all chunks, and returns the merged intervals.
    /// This abstracts the duplicate multi-threading logic away from the final output step.
    std::vector<PiiInterval> scan_bulk_intervals(std::string_view input) const;
};

} // namespace fastscrub
