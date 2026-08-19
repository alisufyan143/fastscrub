#pragma once
#include <string>
#include <string_view>
#include <optional>

namespace fastscrub {

class Matcher {
public:
    /// Initializes the single-pass matcher logic.
    Matcher();

    /// Scan the input and replace all detected PII with mask tokens.
    /// Input is read via string_view (zero-copy); returns a new std::string
    /// with replacements applied.
    std::optional<std::string> scrub(std::string_view input) const;

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
