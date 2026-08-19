#pragma once
#include <string>
#include <string_view>
#include <optional>
#include <vector>

#include "pii_interval.hpp"

namespace fastscrub {

class Matcher {
public:
    /// Initializes the single-pass matcher logic.
    Matcher();

    /// Scan the input and replace all detected PII with mask tokens.
    /// Input is read via string_view (zero-copy); returns a new std::string
    /// with replacements applied.
    std::optional<std::string> scrub(std::string_view input) const;

    /// Scan the input for PII/secret intervals WITHOUT modifying it.
    /// Appends detected intervals to `out`. Returns true if any PII was found.
    bool scan(std::string_view input, std::vector<PiiInterval>& out) const;

    /// Scrub PII in-place by overwriting detected regions with '*'.
    /// Zero allocation — mutates the buffer directly.
    /// For secrets with prefix_len > 0, the prefix is preserved.
    void scrub_inplace(char* data, std::size_t len) const;

private:

    /// Luhn / Modulo-10 checksum validation.
    /// Extracts digits from candidate into a fixed stack buffer and
    /// iterates backward in a single pass. Non-allocating.
    static bool luhn_validate(std::string_view candidate) noexcept;

    /// Returns true when the match at [start, start+length) sits at a
    /// clean token boundary (not embedded inside a larger alphanumeric run).
    static bool has_clean_boundary(
        std::string_view input,
        std::size_t match_start,
        std::size_t match_length
    ) noexcept;
};

} // namespace fastscrub
