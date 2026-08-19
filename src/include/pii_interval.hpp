#pragma once
#include <cstddef>
#include <string_view>

namespace fastscrub {

/// Represents a detected PII or secret interval within the input text.
/// Used by both the string-copy path (Mode A) and the in-place mutation path (Mode B).
struct PiiInterval {
    std::size_t start;        ///< Byte offset of the match start in the input.
    std::size_t len;          ///< Length of the matched PII/secret in bytes.
    std::string_view mask;    ///< Mask token for Mode A, e.g. "[REDACTED_EMAIL]".
    std::size_t inplace_offset; ///< Offset from `start` where in-place masking begins.
    std::size_t inplace_len;    ///< Length of the region to mask in-place. If 0, no in-place masking.

    /// Comparison for sorting by start position.
    bool operator<(const PiiInterval& other) const noexcept {
        return start < other.start;
    }

    /// Check if this interval overlaps with another.
    bool overlaps(const PiiInterval& other) const noexcept {
        return start < other.start + other.len && other.start < start + len;
    }
};

} // namespace fastscrub
