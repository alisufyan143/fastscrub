#pragma once

#include "matcher.hpp"

#include <string>
#include <string_view>
#include <cstddef>

namespace fastscrub {

/// High-level scrubbing engine with parallel batch processing.
///
/// Owns a single compiled Matcher and exposes both single-string and
/// bulk-text entry points.  Bulk scrubbing splits the input into
/// whitespace-aligned chunks and processes them concurrently using
/// std::jthread (C++20, auto-joining).
class Engine {
public:
    /// Construct the engine, compiling all PII patterns once.
    /// An optional worker_count of 0 (default) auto-detects from
    /// std::thread::hardware_concurrency().
    explicit Engine(unsigned worker_count = 0);

    /// Scrub a single string.  Thin delegate to Matcher::scrub().
    std::string scrub(std::string_view input) const;

    /// Scrub a large text buffer in parallel.
    /// The input is sliced on whitespace boundaries so that no PII
    /// token is ever split across worker threads.
    std::string scrub_bulk(std::string_view input) const;

private:
    Matcher  matcher_;
    unsigned workers_;

    /// Find the nearest whitespace-safe split point at or after `pos`.
    /// Returns `pos` itself if it already lands on whitespace or at the
    /// end of the input.  Never advances past `input.size()`.
    static std::size_t snap_to_whitespace(
        std::string_view input, std::size_t pos) noexcept;
};

} // namespace fastscrub
