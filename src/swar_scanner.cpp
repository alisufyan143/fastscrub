#include "include/swar_scanner.hpp"
#include <bit>       // std::countr_zero (C++20)
#include <cstring>   // std::memcpy

namespace fastscrub {

// SWAR zero-byte detection constant
static constexpr uint64_t LO = 0x0101010101010101ULL;
static constexpr uint64_t HI = 0x8080808080808080ULL;

// Check if any byte in `word` equals `target`
static inline uint64_t has_byte(uint64_t word, uint8_t target) noexcept {
    uint64_t pattern = LO * target;
    uint64_t x = word ^ pattern;
    return (x - LO) & ~x & HI;
}

unsigned SwarScanner::check_word(uint64_t word) noexcept {
    // OR together all anchor checks — any match sets the high bit of that byte
    uint64_t mask = has_byte(word, '@')
                  | has_byte(word, ':')
                  | has_byte(word, 'A')
                  | has_byte(word, 'e')
                  | has_byte(word, 'g')
                  | has_byte(word, 'x')
                  | has_byte(word, 's')
                  | has_byte(word, 'r')
                  | has_byte(word, 'p')
                  | has_byte(word, '-')
                  | has_byte(word, '=')
                  | has_byte(word, '+')
                  | has_byte(word, '(')
                  | has_byte(word, '.');
    
    if (mask == 0) return 8;  // No anchor in this word
    return static_cast<unsigned>(std::countr_zero(mask)) / 8;
}

std::size_t SwarScanner::find_next_anchor(
    const char* data, std::size_t len, std::size_t start) noexcept
{
    std::size_t i = start;
    
    // Process unaligned prefix bytes one at a time
    while (i < len && (reinterpret_cast<std::uintptr_t>(data + i) & 7) != 0) {
        // Check if current byte is any anchor character
        char c = data[i];
        if (c == '@' || c == ':' || c == 'A' || c == 'e' || c == 'g' ||
            c == 'x' || c == 's' || c == 'r' || c == 'p' || c == '-' || 
            c == '=' || c == '+' || c == '(' || c == '.') {
            return i;
        }
        ++i;
    }
    
    // Process aligned 8-byte chunks
    while (i + 8 <= len) {
        uint64_t word;
        std::memcpy(&word, data + i, 8);  // Safe, aligned read
        
        unsigned offset = check_word(word);
        if (offset < 8) {
            return i + offset;
        }
        i += 8;
    }
    
    // Process tail bytes
    while (i < len) {
        char c = data[i];
        if (c == '@' || c == ':' || c == 'A' || c == 'e' || c == 'g' ||
            c == 'x' || c == 's' || c == 'r' || c == 'p' || c == '-' || 
            c == '=' || c == '+' || c == '(' || c == '.') {
            return i;
        }
        ++i;
    }
    
    return len;  // No anchor found
}

} // namespace fastscrub
