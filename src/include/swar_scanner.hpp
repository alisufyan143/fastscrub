#pragma once
#include <cstddef>
#include <cstdint>

namespace fastscrub {

class SwarScanner {
public:
    /// Returns the offset of the next anchor character at or after `start`.
    /// Returns `len` if no anchor is found.
    static std::size_t find_next_anchor(
        const char* data, std::size_t len, std::size_t start) noexcept;

private:
    /// Check if a 64-bit word contains any anchor byte.
    /// Returns the byte offset within the word (0-7) or 8 if none found.
    static unsigned check_word(std::uint64_t word) noexcept;
};

} // namespace fastscrub
