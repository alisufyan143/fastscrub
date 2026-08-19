#include "include/matcher.hpp"

#include <cctype>
#include <vector>

namespace fastscrub {

namespace {

inline bool is_hex(char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

inline bool is_digit(char c) noexcept {
    return (c >= '0' && c <= '9');
}

inline bool is_email_local(char c) noexcept {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '%' || c == '+' || c == '-';
}

inline bool is_email_domain(char c) noexcept {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-';
}

inline bool has_context_word(std::string_view input, std::size_t pos, const std::string_view* keywords, size_t num_keywords) noexcept {
    std::size_t start = (pos > 40) ? pos - 40 : 0;
    std::string_view window = input.substr(start, pos - start);
    
    char lower_window[64];
    std::size_t win_len = window.size();
    if (win_len > 64) win_len = 64; 
    
    for (std::size_t i = 0; i < win_len; ++i) {
        lower_window[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(window[i])));
    }
    std::string_view l_win(lower_window, win_len);
    
    for (size_t i = 0; i < num_keywords; ++i) {
        if (l_win.find(keywords[i]) != std::string_view::npos) {
            return true;
        }
    }
    return false;
}

std::size_t parse_id_num(std::string_view s, std::size_t pos) noexcept {
    std::size_t curr = pos;
    while (curr < s.size() && is_digit(s[curr])) {
        curr++;
    }
    std::size_t len = curr - pos;
    if (len >= 8 && len <= 15) {
        static constexpr std::string_view keywords[] = {"id", "student", "number", "ssn", "tax", "account", "no.", "num"};
        if (has_context_word(s, pos, keywords, 8)) {
            return len;
        }
    }
    return 0;
}

std::size_t parse_uuid(std::string_view s, std::size_t pos) noexcept {
    if (pos + 36 > s.size()) return 0;
    int layout[] = {8, 4, 4, 4, 12};
    std::size_t curr = pos;
    for (int i = 0; i < 5; ++i) {
        for (int j = 0; j < layout[i]; ++j) {
            if (!is_hex(s[curr++])) return 0;
        }
        if (i < 4) {
            if (s[curr++] != '-') return 0;
        }
    }
    return 36;
}

std::size_t parse_mac(std::string_view s, std::size_t pos) noexcept {
    if (pos + 17 > s.size()) return 0;
    if (!is_hex(s[pos]) || !is_hex(s[pos+1])) return 0;
    char sep = s[pos+2];
    if (sep != ':' && sep != '-') return 0;
    std::size_t curr = pos + 3;
    for (int i = 0; i < 5; ++i) {
        if (!is_hex(s[curr]) || !is_hex(s[curr+1])) return 0;
        curr += 2;
        if (i < 4) {
            if (s[curr] != sep) return 0;
            curr++;
        }
    }
    return 17;
}

std::size_t parse_ipv4(std::string_view s, std::size_t pos) noexcept {
    std::size_t curr = pos;
    for (int i = 0; i < 4; ++i) {
        std::size_t start = curr;
        while (curr < s.size() && is_digit(s[curr]) && curr - start < 3) curr++;
        if (curr == start) return 0;
        int val = 0;
        for (std::size_t j = start; j < curr; ++j) {
            val = val * 10 + (s[j] - '0');
        }
        if (val > 255) return 0;
        if (i < 3) {
            if (curr >= s.size() || s[curr] != '.') return 0;
            curr++;
        }
    }
    return curr - pos;
}

std::size_t parse_ssn(std::string_view s, std::size_t pos) noexcept {
    if (pos + 9 <= s.size()) {
        bool all_digits = true;
        for (int i = 0; i < 9; ++i) {
            if (!is_digit(s[pos+i])) { all_digits = false; break; }
        }
        if (all_digits) return 9;
    }
    
    if (pos + 11 <= s.size()) {
        int layout[] = {3, 2, 4};
        std::size_t curr = pos;
        bool match = true;
        for (int i = 0; i < 3 && match; ++i) {
            for (int j = 0; j < layout[i]; ++j) {
                if (!is_digit(s[curr++])) { match = false; break; }
            }
            if (match && i < 2) {
                if (s[curr++] != '-') match = false;
            }
        }
        if (match) return 11;
    }
    return 0;
}

std::size_t parse_credit_card(std::string_view s, std::size_t pos) noexcept {
    std::size_t curr = pos;
    int groups = 0;
    while (curr < s.size() && groups < 4) {
        std::size_t start = curr;
        while (curr < s.size() && is_digit(s[curr])) curr++;
        std::size_t group_len = curr - start;
        if (groups < 3 && group_len != 4) break;
        if (groups == 3 && (group_len < 1 || group_len > 4)) break;
        groups++;
        
        if (groups < 4) {
            if (curr >= s.size()) break;
            char c = s[curr];
            if (c != ' ' && c != '-') break;
            curr++;
        }
    }
    if (groups == 4) return curr - pos;

    curr = pos;
    while (curr < s.size() && is_digit(s[curr])) curr++;
    std::size_t len = curr - pos;
    if (len >= 13 && len <= 19) return len;
    
    return 0;
}

std::size_t parse_phone(std::string_view s, std::size_t pos) noexcept {
    std::size_t curr = pos;
    int digits = 0;
    std::size_t valid_end = 0;
    std::size_t first_chunk = 0;
    bool counting_first = true;
    
    if (curr < s.size() && s[curr] == '+') {
        curr++;
    }
    
    while (curr < s.size()) {
        char c = s[curr];
        if (is_digit(c)) {
            if (counting_first) first_chunk++;
            digits++;
            curr++;
            if (digits >= 7 && digits <= 15) {
                valid_end = curr;
            }
        } else if (c == ' ' || c == '.' || c == '-' || c == '(' || c == ')') {
            if (counting_first && first_chunk > 0) counting_first = false;
            curr++;
        } else if ((c == 'x' || c == 'X') && digits >= 7) {
            curr++;
            bool ext_digits = false;
            while (curr < s.size() && is_digit(s[curr])) {
                ext_digits = true;
                digits++;
                curr++;
            }
            if (ext_digits && digits <= 15) {
                valid_end = curr;
            }
            break;
        } else {
            break;
        }
    }
    
    if (first_chunk == 4 || first_chunk == 8) return 0; // Reject 2021-xx-xx dates
    if (valid_end > 0) return valid_end - pos;
    
    return 0;
}

std::size_t parse_ipv6(std::string_view s, std::size_t pos) noexcept {
    std::size_t curr = pos;
    int groups = 0;
    bool has_double_colon = false;
    
    if (curr + 1 < s.size() && s[curr] == ':' && s[curr+1] == ':') {
        has_double_colon = true;
        curr += 2;
    }
    
    std::size_t valid_end = 0;
    if (has_double_colon) valid_end = curr;
    
    while (curr < s.size()) {
        std::size_t start = curr;
        while (curr < s.size() && is_hex(s[curr])) curr++;
        std::size_t len = curr - start;
        
        if (len == 0) break;
        if (len > 4) break;
        groups++;
        
        if (!has_double_colon && groups == 8) valid_end = curr;
        if (has_double_colon && groups <= 7) valid_end = curr;
        
        if (curr < s.size() && s[curr] == ':') {
            if (curr + 1 < s.size() && s[curr+1] == ':') {
                if (has_double_colon) break; 
                has_double_colon = true;
                curr += 2;
                if (groups <= 7) valid_end = curr; 
            } else {
                curr++;
                if (curr >= s.size() || !is_hex(s[curr])) {
                    break;
                }
            }
        } else {
            break;
        }
    }
    
    if (valid_end > 0) return valid_end - pos;
    return 0;
}

} // anonymous namespace

Matcher::Matcher() {
    // Zero allocations required during initialization
}

bool Matcher::luhn_validate(std::string_view candidate) noexcept {
    int digits[20];
    int count = 0;

    for (std::size_t i = 0; i < candidate.size() && count < 20; ++i) {
        const char ch = candidate[i];
        if (ch >= '0' && ch <= '9') {
            digits[count++] = ch - '0';
        }
    }

    if (count < 13 || count > 19) return false;

    int sum = 0;
    bool should_double = false;

    for (int i = count - 1; i >= 0; --i) {
        int d = digits[i];
        if (should_double) {
            d *= 2;
            if (d > 9) d -= 9;
        }
        sum += d;
        should_double = !should_double;
    }

    return (sum % 10) == 0;
}

bool Matcher::has_clean_boundary(std::string_view input, std::size_t match_start, std::size_t match_length) noexcept {
    if (match_start > 0
        && std::isalnum(static_cast<unsigned char>(input[match_start]))
        && std::isalnum(static_cast<unsigned char>(input[match_start - 1]))) {
        return false;
    }

    const std::size_t match_end = match_start + match_length;
    if (match_end < input.size()
        && match_length > 0
        && std::isalnum(static_cast<unsigned char>(input[match_end - 1]))
        && std::isalnum(static_cast<unsigned char>(input[match_end]))) {
        return false;
    }

    return true;
}

std::optional<std::string> Matcher::scrub(std::string_view input) const {
    if (input.empty()) return std::nullopt;

    struct PiiInterval {
        std::size_t start;
        std::size_t len;
        std::string_view mask;
    };

    std::vector<PiiInterval> intervals;
    intervals.reserve(1024);

    std::size_t i = 0;

    while (i < input.size()) {
        char c = input[i];

        // 1. Email check via '@' anchor
        if (c == '@') {
            std::size_t start = i;
            while (start > 0 && is_email_local(input[start - 1])) {
                start--;
            }
            if (start < i && i - start <= 128) {
                std::size_t end = i + 1;
                while (end < input.size() && is_email_domain(input[end])) {
                    end++;
                }

                while (end > i + 1 && !std::isalpha(static_cast<unsigned char>(input[end - 1]))) {
                    end--;
                }

                std::size_t dot_pos = input.find_last_of('.', end - 1);
                if (dot_pos != std::string_view::npos && dot_pos > i) {
                    std::size_t tld_len = end - 1 - dot_pos;
                    if (tld_len >= 2 && tld_len <= 4) {
                        bool valid_tld = true;
                        for (std::size_t k = dot_pos + 1; k < end; ++k) {
                            if (!std::isalpha(static_cast<unsigned char>(input[k]))) { valid_tld = false; break; }
                        }
                        if (valid_tld && end - i - 1 <= 128) {
                            if (has_clean_boundary(input, start, end - start)) {
                                intervals.push_back({start, end - start, "[REDACTED_EMAIL]"});
                                i = end;
                                continue;
                            }
                        }
                    }
                }
            }
        }

        // 2. Structural checks starting with specific anchor chars
        bool left_boundary_ok = (i == 0 || !std::isalnum(static_cast<unsigned char>(input[i])) || !std::isalnum(static_cast<unsigned char>(input[i-1])));
        
        if (left_boundary_ok) {
            std::size_t match_len = 0;
            std::string_view mask;
            bool requires_luhn = false;

            if (is_hex(c) || c == ':') {
                if ((match_len = parse_uuid(input, i)) > 0) { mask = "[REDACTED_UUID]"; }
                else if ((match_len = parse_ipv6(input, i)) > 0) { mask = "[REDACTED_IP]"; }
                else if ((match_len = parse_mac(input, i)) > 0) { mask = "[REDACTED_MAC]"; }
            }
            
            if (match_len == 0 && (is_digit(c) || c == '+' || c == '(')) {
                if ((match_len = parse_credit_card(input, i)) > 0) { mask = "[REDACTED_CREDIT_CARD]"; requires_luhn = true; }
                else if ((match_len = parse_ipv4(input, i)) > 0) { mask = "[REDACTED_IP]"; }
                else if ((match_len = parse_ssn(input, i)) > 0) { mask = "[REDACTED_SSN]"; }
                else if ((match_len = parse_phone(input, i)) > 0) { mask = "[REDACTED_PHONE]"; }
                else if ((match_len = parse_id_num(input, i)) > 0) { mask = "[REDACTED_ID]"; }
            }

            if (match_len > 0) {
                if (has_clean_boundary(input, i, match_len)) {
                    if (!requires_luhn || luhn_validate(std::string_view(input.data() + i, match_len))) {
                        intervals.push_back({i, match_len, mask});
                        i += match_len;
                        continue;
                    }
                }
            }
        }

        ++i;
    }

    if (intervals.empty()) {
        return std::nullopt; // ZERO COPY!
    }

    // Pre-calculate exactly how large the redacted string will be to avoid reallocation
    std::size_t final_size = input.size();
    for (const auto& iv : intervals) {
        final_size -= iv.len;
        final_size += iv.mask.size();
    }

    std::string result;
    result.reserve(final_size);

    std::size_t cursor = 0;
    for (const auto& iv : intervals) {
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

} // namespace fastscrub
