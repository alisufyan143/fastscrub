#include "include/swar_scanner.hpp"
#include <bit>
#include <cstring>

namespace fastscrub {

static constexpr uint64_t LO = 0x0101010101010101ULL;
static constexpr uint64_t HI = 0x8080808080808080ULL;

static inline uint64_t has_byte(uint64_t word, uint8_t target) noexcept {
    uint64_t pattern = LO * target;
    uint64_t x = word ^ pattern;
    return (x - LO) & ~x & HI;
}

unsigned SwarScanner::check_word(uint64_t word) noexcept {
    // Punctuation + 'A' for floating AWS keys
    uint64_t mask = has_byte(word, '@')
                  | has_byte(word, '_')
                  | has_byte(word, '-')
                  | has_byte(word, '.')
                  | has_byte(word, ':')
                  | has_byte(word, '=')
                  | has_byte(word, '+')
                  | has_byte(word, '(')
                  | has_byte(word, '"')
                  | has_byte(word, 'A');

    if (mask == 0) return 8; 
    return static_cast<unsigned>(std::countr_zero(mask)) / 8;
}

std::size_t SwarScanner::find_next_anchor(
    const char* data, std::size_t len, std::size_t start) noexcept
{
    std::size_t i = start;
    
    // Process unaligned prefix
    while (i < len && (reinterpret_cast<std::uintptr_t>(data + i) & 7) != 0) {
        char c = data[i];
        if (c=='@'||c=='_'||c=='-'||c=='.'||c==':'||c=='='||c=='+'||c=='('||c=='"'||c=='A') return i;
        ++i;
    }
    
    // Process aligned 8-byte chunks at maximum speed
    while (i + 8 <= len) {
        uint64_t word;
        std::memcpy(&word, data + i, 8); 
        unsigned offset = check_word(word);
        if (offset < 8) return i + offset;
        i += 8;
    }
    
    // Process tail
    while (i < len) {
        char c = data[i];
        if (c=='@'||c=='_'||c=='-'||c=='.'||c==':'||c=='='||c=='+'||c=='('||c=='"'||c=='A') return i;
        ++i;
    }
    
    return len;
}

} // namespace fastscrub
