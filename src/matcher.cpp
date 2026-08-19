#include "include/matcher.hpp"

#include <cctype>
#include <cstring>
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

inline bool is_base62(char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

inline bool is_base62_ext(char c) noexcept {
    return is_base62(c) || c == '_' || c == '-';
}

inline bool is_base64url(char c) noexcept {
    return is_base62(c) || c == '_' || c == '-' || c == '=';
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

// ---------------------------------------------------------------------------
// Existing PII parsers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Infrastructure secret parsers (Phase 3)
// ---------------------------------------------------------------------------

std::size_t parse_aws_key(std::string_view s, std::size_t pos) noexcept {
    // Pattern: AKIA[0-9A-Z]{16} = exactly 20 chars
    if (pos + 20 > s.size()) return 0;
    if (s[pos] != 'A' || s[pos+1] != 'K' || s[pos+2] != 'I' || s[pos+3] != 'A') return 0;
    for (std::size_t i = pos + 4; i < pos + 20; ++i) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z'))) return 0;
    }
    return 20;
}

std::size_t parse_github_token(std::string_view s, std::size_t pos) noexcept {
    // ghp_ or gho_ + 36 base62 chars = 40 total
    if (pos + 40 <= s.size()) {
        if ((s[pos] == 'g' && s[pos+1] == 'h' && s[pos+2] == 'p' && s[pos+3] == '_') ||
            (s[pos] == 'g' && s[pos+1] == 'h' && s[pos+2] == 'o' && s[pos+3] == '_')) {
            std::size_t curr = pos + 4;
            while (curr < s.size() && is_base62(s[curr])) curr++;
            std::size_t body_len = curr - (pos + 4);
            if (body_len >= 36 && body_len <= 82) return curr - pos;
        }
    }
    // github_pat_ + 22+ base62/underscore chars
    if (pos + 33 <= s.size()) {
        if (s.substr(pos, 11) == "github_pat_") {
            std::size_t curr = pos + 11;
            while (curr < s.size() && (is_base62(s[curr]) || s[curr] == '_')) curr++;
            std::size_t body_len = curr - (pos + 11);
            if (body_len >= 22) return curr - pos;
        }
    }
    return 0;
}

std::size_t parse_gcp_key(std::string_view s, std::size_t pos) noexcept {
    // AIza + 35 chars of [0-9A-Za-z\-_] = 39 total
    if (pos + 39 > s.size()) return 0;
    if (s[pos] != 'A' || s[pos+1] != 'I' || s[pos+2] != 'z' || s[pos+3] != 'a') return 0;
    for (std::size_t i = pos + 4; i < pos + 39; ++i) {
        if (!is_base62_ext(s[i])) return 0;
    }
    return 39;
}

std::size_t parse_slack_token(std::string_view s, std::size_t pos) noexcept {
    // xoxb- or xoxp- + hyphen-separated blocks, total 40-70 chars
    if (pos + 40 > s.size()) return 0;
    if (s[pos] != 'x' || s[pos+1] != 'o' || s[pos+2] != 'x') return 0;
    char type = s[pos+3];
    if (type != 'b' && type != 'p') return 0;
    if (s[pos+4] != '-') return 0;
    
    std::size_t curr = pos + 5;
    int blocks = 0;
    while (curr < s.size() && blocks < 6) {
        std::size_t block_start = curr;
        while (curr < s.size() && (is_base62(s[curr]))) curr++;
        if (curr == block_start) break;
        blocks++;
        if (curr < s.size() && s[curr] == '-') {
            curr++;
        } else {
            break;
        }
    }
    std::size_t total_len = curr - pos;
    if (blocks >= 3 && total_len >= 40 && total_len <= 80) return total_len;
    return 0;
}

std::size_t parse_stripe_key(std::string_view s, std::size_t pos) noexcept {
    // sk_live_, rk_live_, sk_test_, rk_test_, pk_live_, pk_test_ + 24 alnum
    if (pos + 32 > s.size()) return 0;
    char c0 = s[pos], c1 = s[pos+1];
    if (!((c0 == 's' || c0 == 'r' || c0 == 'p') && c1 == 'k')) return 0;
    if (s[pos+2] != '_') return 0;
    
    // Check live_ or test_
    std::string_view mode = s.substr(pos + 3, 5);
    if (mode != "live_" && mode != "test_") return 0;
    
    std::size_t body_start = pos + 8;
    std::size_t curr = body_start;
    while (curr < s.size() && is_base62(s[curr])) curr++;
    std::size_t body_len = curr - body_start;
    if (body_len >= 24 && body_len <= 48) return curr - pos;
    return 0;
}

std::size_t parse_private_key(std::string_view s, std::size_t pos) noexcept {
    // Anchor on "-----BEGIN"
    if (pos + 27 > s.size()) return 0;
    if (s.substr(pos, 11) != "-----BEGIN ") return 0;
    
    // Find "PRIVATE KEY-----"
    std::size_t header_end = s.find("PRIVATE KEY-----", pos + 11);
    if (header_end == std::string_view::npos || header_end > pos + 50) return 0;
    header_end += 16; // length of "PRIVATE KEY-----"
    
    // Find matching "-----END ... PRIVATE KEY-----"
    std::size_t end_marker = s.find("-----END ", header_end);
    if (end_marker == std::string_view::npos) return 0;
    
    std::size_t final_end = s.find("PRIVATE KEY-----", end_marker);
    if (final_end == std::string_view::npos) return 0;
    final_end += 16;
    
    return final_end - pos;
}

struct JwtMatch {
    std::size_t total_len;
    std::size_t header_len; // segment 1 length (preserved in Mode B)
};

JwtMatch parse_jwt(std::string_view s, std::size_t pos) noexcept {
    // Anchor on "eyJ"
    if (pos + 20 > s.size()) return {0, 0};
    if (s[pos] != 'e' || s[pos+1] != 'y' || s[pos+2] != 'J') return {0, 0};
    
    std::size_t curr = pos + 3;
    int dots = 0;
    std::size_t dot1_pos = 0;
    std::size_t seg_start = pos;
    
    while (curr < s.size()) {
        char c = s[curr];
        if (c == '.') {
            std::size_t seg_len = curr - seg_start;
            if (seg_len < 4) return {0, 0};
            dots++;
            if (dots == 1) {
                dot1_pos = curr;
                // Segment 2 must start with "eyJ"
                if (curr + 3 >= s.size() || s[curr+1] != 'e' || s[curr+2] != 'y' || s[curr+3] != 'J') {
                    return {0, 0};
                }
            }
            if (dots >= 2) {
                // Scan segment 3 (signature)
                curr++;
                seg_start = curr;
                while (curr < s.size() && is_base64url(s[curr]) && s[curr] != '.') curr++;
                std::size_t seg3_len = curr - seg_start;
                if (seg3_len < 4) return {0, 0};
                std::size_t total = curr - pos;
                if (total >= 20) {
                    return {total, dot1_pos - pos}; // header_len = segment 1
                }
                return {0, 0};
            }
            seg_start = curr + 1;
            curr++;
        } else if (is_base64url(c)) {
            curr++;
        } else {
            break;
        }
    }
    return {0, 0};
}

std::size_t parse_connection_string(std::string_view s, std::size_t pos, std::size_t& password_start, std::size_t& password_len) noexcept {
    // Anchor on "://"
    if (pos + 3 > s.size()) return 0;
    if (s[pos] != ':' || s[pos+1] != '/' || s[pos+2] != '/') return 0;
    
    // Walk backward to find scheme
    std::size_t scheme_start = pos;
    while (scheme_start > 0 && std::isalpha(static_cast<unsigned char>(s[scheme_start - 1]))) {
        scheme_start--;
    }
    if (scheme_start == pos) return 0;
    
    std::string_view scheme_sv = s.substr(scheme_start, pos - scheme_start);
    // Lowercase compare
    char scheme_lower[20];
    if (scheme_sv.size() > 19) return 0;
    for (std::size_t i = 0; i < scheme_sv.size(); ++i) {
        scheme_lower[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(scheme_sv[i])));
    }
    std::string_view scheme(scheme_lower, scheme_sv.size());
    
    static constexpr std::string_view db_schemes[] = {
        "postgres", "postgresql", "mysql", "mongodb", "redis",
        "amqp", "mssql", "oracle", "sqlserver"
    };
    bool valid_scheme = false;
    for (const auto& ds : db_schemes) {
        if (scheme == ds) { valid_scheme = true; break; }
    }
    // Also handle "mongodb+srv"
    if (!valid_scheme && scheme_sv.size() >= 7) {
        // Check if original text has "mongodb+srv"
        if (scheme_start + 11 <= pos && s.substr(scheme_start, 11) == "mongodb+srv") {
            valid_scheme = true;
        }
    }
    if (!valid_scheme) return 0;
    
    // Walk forward from "://" to find user:password@host
    std::size_t curr = pos + 3; // past "://"
    
    // Find '@' (separates credentials from host)
    std::size_t at_pos = std::string_view::npos;
    for (std::size_t i = curr; i < s.size(); ++i) {
        char c = s[i];
        if (c == '@') { at_pos = i; break; }
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '"' || c == '\'') break;
    }
    if (at_pos == std::string_view::npos) return 0;
    
    // Find ':' between user and password (between "://" and "@")
    std::size_t colon_pos = std::string_view::npos;
    for (std::size_t i = curr; i < at_pos; ++i) {
        if (s[i] == ':') { colon_pos = i; break; }
    }
    if (colon_pos == std::string_view::npos) return 0;
    
    // Password is between colon+1 and at_pos
    password_start = colon_pos + 1;
    password_len = at_pos - password_start;
    if (password_len == 0) return 0;
    
    // Walk forward from '@' to find end of connection string
    std::size_t end = at_pos + 1;
    while (end < s.size()) {
        char c = s[end];
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '"' || c == '\'' || c == ',' || c == ';') break;
        end++;
    }
    
    return end - scheme_start;
}

std::size_t parse_kv_secret(std::string_view s, std::size_t pos, std::size_t& value_start, std::size_t& value_len) noexcept {
    // Anchor on '=' or ':'
    char anchor = s[pos];
    if (anchor != '=' && anchor != ':') return 0;
    
    // Check for context keyword backward (max 30 chars)
    static constexpr std::string_view kv_keywords[] = {
        "password", "passwd", "secret", "api_key", "apikey", "api_secret",
        "access_token", "auth_token", "private_key", "client_secret",
        "token", "bearer", "credential"
    };
    if (!has_context_word(s, pos, kv_keywords, 13)) return 0;
    
    // Skip whitespace and optional quote after '=' or ':'
    std::size_t curr = pos + 1;
    while (curr < s.size() && (s[curr] == ' ' || s[curr] == '\t')) curr++;
    
    char quote = 0;
    if (curr < s.size() && (s[curr] == '"' || s[curr] == '\'')) {
        quote = s[curr];
        curr++;
    }
    
    value_start = curr;
    
    // Walk forward to end of value
    while (curr < s.size()) {
        char c = s[curr];
        if (quote) {
            if (c == quote) break;
        } else {
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == ',' || c == ';' || c == '}' || c == ']') break;
        }
        curr++;
    }
    
    value_len = curr - value_start;
    if (value_len < 6) return 0;
    
    // Entropy check: must contain at least 1 letter and 1 digit
    bool has_letter = false, has_digit = false;
    for (std::size_t i = value_start; i < value_start + value_len; ++i) {
        if (std::isalpha(static_cast<unsigned char>(s[i]))) has_letter = true;
        if (is_digit(s[i])) has_digit = true;
    }
    if (!has_letter || !has_digit) return 0;
    
    // Total match: from the keyword context to end of value
    // But we return: anchor_pos to end_of_value (including quote)
    std::size_t end = curr;
    if (quote && end < s.size() && s[end] == quote) end++;
    
    return end - pos;
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

// ---------------------------------------------------------------------------
// scan(): The core single-pass scanner. Populates intervals without modifying input.
// ---------------------------------------------------------------------------
bool Matcher::scan(std::string_view input, std::vector<PiiInterval>& intervals) const {
    if (input.empty()) return false;

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
                                intervals.push_back({start, end - start, "[REDACTED_EMAIL]", 0, end - start});
                                i = end;
                                continue;
                            }
                        }
                    }
                }
            }
        }

        // 2. Infrastructure secret checks based on anchor chars
        // AWS key: anchors on 'A' (AKIA prefix)
        if (c == 'A') {
            std::size_t len = parse_aws_key(input, i);
            if (len > 0 && has_clean_boundary(input, i, len)) {
                intervals.push_back({i, len, "[REDACTED_AWS_KEY]", 4, len - 4});
                i += len;
                continue;
            }
        }

        // GCP key: anchors on 'A' (AIza prefix) — check after AWS
        if (c == 'A') {
            std::size_t len = parse_gcp_key(input, i);
            if (len > 0 && has_clean_boundary(input, i, len)) {
                intervals.push_back({i, len, "[REDACTED_GCP_KEY]", 4, len - 4});
                i += len;
                continue;
            }
        }

        // GitHub token: anchors on 'g'
        if (c == 'g') {
            std::size_t len = parse_github_token(input, i);
            if (len > 0 && has_clean_boundary(input, i, len)) {
                std::size_t prefix = (len >= 11 && input.substr(i, 11) == "github_pat_") ? 11 : 4;
                intervals.push_back({i, len, "[REDACTED_GITHUB_TOKEN]", prefix, len - prefix});
                i += len;
                continue;
            }
        }

        // Slack token: anchors on 'x'
        if (c == 'x') {
            std::size_t len = parse_slack_token(input, i);
            if (len > 0 && has_clean_boundary(input, i, len)) {
                intervals.push_back({i, len, "[REDACTED_SLACK_TOKEN]", 5, len - 5});
                i += len;
                continue;
            }
        }

        // Stripe key: anchors on 's', 'r', 'p'
        if (c == 's' || c == 'r' || c == 'p') {
            std::size_t len = parse_stripe_key(input, i);
            if (len > 0 && has_clean_boundary(input, i, len)) {
                intervals.push_back({i, len, "[REDACTED_STRIPE_KEY]", 8, len - 8});
                i += len;
                continue;
            }
        }

        // JWT: anchors on 'e' (eyJ prefix)
        if (c == 'e') {
            auto jwt = parse_jwt(input, i);
            if (jwt.total_len > 0 && has_clean_boundary(input, i, jwt.total_len)) {
                std::size_t offset = jwt.header_len + 1; // Keep the dot
                std::size_t in_len = jwt.total_len - offset;
                intervals.push_back({i, jwt.total_len, "[REDACTED_JWT]", offset, in_len});
                i += jwt.total_len;
                continue;
            }
        }

        // Private key: anchors on '-' (-----BEGIN)
        if (c == '-') {
            std::size_t len = parse_private_key(input, i);
            if (len > 0) {
                intervals.push_back({i, len, "[REDACTED_PRIVATE_KEY]", 0, len});
                i += len;
                continue;
            }
        }

        // DB connection string: anchors on ':' (://)
        if (c == ':') {
            std::size_t pw_start = 0, pw_len = 0;
            std::size_t total_len = parse_connection_string(input, i, pw_start, pw_len);
            if (total_len > 0) {
                std::size_t scheme_start = i;
                while (scheme_start > 0 && std::isalpha(static_cast<unsigned char>(input[scheme_start - 1]))) {
                    scheme_start--;
                }
                intervals.push_back({scheme_start, total_len, "[REDACTED_DB_CONN]", pw_start - scheme_start, pw_len});
                i = scheme_start + total_len;
                continue;
            }
        }

        // K/V secret: anchors on '=' or ':'
        if (c == '=' || (c == ':' && i + 1 < input.size() && input[i+1] != '/')) {
            std::size_t val_start = 0, val_len = 0;
            std::size_t total_len = parse_kv_secret(input, i, val_start, val_len);
            if (total_len > 0) {
                intervals.push_back({i, total_len, "[REDACTED_SECRET]", val_start - i, val_len});
                i += total_len;
                continue;
            }
        }

        // 3. Structural PII checks starting with specific anchor chars
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
                        intervals.push_back({i, match_len, mask, 0, match_len});
                        i += match_len;
                        continue;
                    }
                }
            }
        }

        ++i;
    }

    return !intervals.empty();
}

// ---------------------------------------------------------------------------
// scrub(): Mode A — returns a new string with labeled [REDACTED_*] tokens.
// ---------------------------------------------------------------------------
std::optional<std::string> Matcher::scrub(std::string_view input) const {
    if (input.empty()) return std::nullopt;

    std::vector<PiiInterval> intervals;
    intervals.reserve(1024);

    if (!scan(input, intervals)) {
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

// ---------------------------------------------------------------------------
// scrub_inplace(): Mode B — zero-allocation in-place mutation with '*'.
// ---------------------------------------------------------------------------
void Matcher::scrub_inplace(char* data, std::size_t len) const {
    if (len == 0 || data == nullptr) return;

    std::string_view view(data, len);
    std::vector<PiiInterval> intervals;
    intervals.reserve(1024);

    if (!scan(view, intervals)) return;

    for (const auto& iv : intervals) {
        if (iv.inplace_len > 0) {
            std::size_t mask_start = iv.start + iv.inplace_offset;
            if (mask_start + iv.inplace_len <= len) {
                std::memset(data + mask_start, '*', iv.inplace_len);
            }
        }
    }
}

} // namespace fastscrub
