#include "include/matcher.hpp"
#include "include/swar_scanner.hpp"
#include "include/secret_parsers.hpp"
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
        if (secrets::has_context_word(s, pos, keywords, 8)) {
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
    // 1. US SSN (XXX-XX-XXXX) -> 11 chars
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
    
    // 2. French NIR (Numéro de Sécurité Sociale) e.g. "1 85 12 75 108 105 42" or "1-85-12-75-108-105"
    if (pos < s.size() && (s[pos] == '1' || s[pos] == '2')) {
        std::size_t curr = pos;
        int digit_count = 0;
        while (curr < s.size()) {
            char ch = s[curr];
            if (is_digit(ch)) {
                digit_count++;
            } else if (ch == ' ' || ch == '-' || ch == '.') {
                // separator
            } else {
                break;
            }
            curr++;
            if (digit_count == 13 || digit_count == 15) {
                if (curr >= s.size() || !is_digit(s[curr])) {
                    return curr - pos;
                }
            }
        }
        if (digit_count >= 13 && digit_count <= 15) {
            return curr - pos;
        }
    }

    // 3. Continuous 9-digit US SSN
    if (pos + 9 <= s.size()) {
        bool all_digits = true;
        for (int i = 0; i < 9; ++i) {
            if (!is_digit(s[pos+i])) { all_digits = false; break; }
        }
        if (all_digits && (pos + 9 == s.size() || !is_digit(s[pos+9]))) {
            return 9;
        }
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

// Infrastructure secret parsers have been moved to src/secret_parsers.cpp

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

    const char* data = input.data();
    const std::size_t len = input.size();
    std::size_t i = 0;

    while (i < len) {
#ifndef FASTSCRUB_FORCE_SCALAR
        // SWAR hunts strictly for punctuation
        i = SwarScanner::find_next_anchor(data, len, i);
        if (i >= len) break;
#endif

        char c = data[i];
        std::size_t match_start = 0;
        std::size_t match_len = 0;
        std::string_view mask;
        std::size_t inplace_offset = 0;
        std::size_t inplace_len = 0;
        bool requires_luhn = false;

        // 1. Email anchored on '@'
        if (c == '@') {
            std::size_t start = i;
            while (start > 0 && is_email_local(input[start - 1])) start--;
            if (start < i && i - start <= 128) {
                std::size_t end = i + 1;
                while (end < input.size() && is_email_domain(input[end])) end++;
                while (end > i + 1 && !std::isalpha(static_cast<unsigned char>(input[end - 1]))) end--;

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
                                i = end; continue;
                            }
                        }
                    }
                }
            }
        }

        // 2. Center-Out Parsers anchored on '_' (GitHub, Stripe, HuggingFace)
        else if (c == '_') {
            bool is_github = false;
            if (i >= 3) {
                if (input[i-3] == 'g' && input[i-2] == 'h' && 
                    (input[i-1] == 'p' || input[i-1] == 'o' || input[i-1] == 'u' || input[i-1] == 's' || input[i-1] == 'r')) {
                    is_github = true;
                } else if (i >= 10 && input.substr(i-10, 11) == "github_pat_") {
                    is_github = true;
                }
            }
            if (is_github && (match_len = secrets::parse_github_token(input, i, match_start)) > 0) {
                std::size_t prefix = (match_len >= 22 && input.substr(match_start, 11) == "github_pat_") ? 11 : 4;
                intervals.push_back({match_start, match_len, "[REDACTED_GITHUB_TOKEN]", prefix, match_len - prefix});
                i = match_start + match_len; continue;
            }

            bool is_stripe = false;
            if (i >= 2) {
                char p1 = input[i-2], p2 = input[i-1];
                if ((p1 == 's' || p1 == 'p' || p1 == 'r') && p2 == 'k') {
                    is_stripe = true;
                } else if (i >= 7 && (input.substr(i-5, 5) == "_live" || input.substr(i-5, 5) == "_test")) {
                    is_stripe = true;
                }
            }
            if (is_stripe && (match_len = secrets::parse_stripe_key(input, i, match_start)) > 0) {
                intervals.push_back({match_start, match_len, "[REDACTED_STRIPE_KEY]", 8, match_len - 8});
                i = match_start + match_len; continue;
            }

            if ((match_len = secrets::parse_huggingface_token(input, i, match_start)) > 0) {
                intervals.push_back({match_start, match_len, "[REDACTED_SECRET]", 3, match_len - 3});
                i = match_start + match_len; continue;
            }
        }

        // 3. Center-Out Parsers anchored on '-' (AI/DevOps Tokens, Private Keys, Slack, UUID, MAC, CC, SSN, Phone)
        else if (c == '-') {
            // Fast bypass for date stamps YYYY-MM-DD (e.g. 2026-08-20)
            if (i >= 4 && i + 5 < len && is_digit(input[i-4]) && is_digit(input[i-3]) && is_digit(input[i-2]) && is_digit(input[i-1]) &&
                is_digit(input[i+1]) && is_digit(input[i+2]) && input[i+3] == '-' && is_digit(input[i+4]) && is_digit(input[i+5])) {
                i += 5; // Leap past the date stamp
                continue;
            }

            // Anthropic Claude key (sk-ant-...)
            if ((match_len = secrets::parse_anthropic_key(input, i, match_start)) > 0) {
                intervals.push_back({match_start, match_len, "[REDACTED_SECRET]", 7, match_len - 7});
                i = match_start + match_len; continue;
            }

            // OpenAI API key (sk-proj-..., sk-admin-..., sk-...)
            if ((match_len = secrets::parse_openai_key(input, i, match_start)) > 0) {
                intervals.push_back({match_start, match_len, "[REDACTED_SECRET]", 3, match_len - 3});
                i = match_start + match_len; continue;
            }

            // GitLab Token (glpat-...)
            if ((match_len = secrets::parse_gitlab_token(input, i, match_start)) > 0) {
                intervals.push_back({match_start, match_len, "[REDACTED_SECRET]", 6, match_len - 6});
                i = match_start + match_len; continue;
            }

            // PyPI Token (pypi-...)
            if ((match_len = secrets::parse_pypi_token(input, i, match_start)) > 0) {
                intervals.push_back({match_start, match_len, "[REDACTED_SECRET]", 5, match_len - 5});
                i = match_start + match_len; continue;
            }

            // Slack token requires "xox"
            if (i >= 4 && input[i-4] == 'x' && input[i-3] == 'o' && input[i-2] == 'x' &&
                (input[i-1] == 'b' || input[i-1] == 'p' || input[i-1] == 'a' || input[i-1] == 'r' || input[i-1] == 's')) {
                if ((match_len = secrets::parse_slack_token(input, i, match_start)) > 0) {
                    intervals.push_back({match_start, match_len, "[REDACTED_SLACK_TOKEN]", 5, match_len - 5});
                    i = match_start + match_len; continue;
                }
            }

            // Private key requires "-----"
            if (i + 15 < len && input.substr(i, 5) == "-----") {
                if ((match_len = secrets::parse_private_key(input, i)) > 0) {
                    intervals.push_back({i, match_len, "[REDACTED_PRIVATE_KEY]", 0, match_len});
                    i += match_len; continue;
                }
            }
            
            // Structural PII fallbacks: MUST be preceded by hex or digit
            if (i > 0) {
                char prev = input[i - 1];
                if (is_hex(prev)) {
                    std::size_t start = i;
                    while (start > 0 && i - start < 8 && is_hex(input[start - 1])) start--;
                    if (i - start == 8 && (match_len = parse_uuid(input, start)) > 0 && start + match_len > i) {
                        match_start = start; mask = "[REDACTED_UUID]"; inplace_len = match_len;
                    }
                    if (match_len == 0 && i - start <= 2) {
                        if ((match_len = parse_mac(input, start)) > 0 && start + match_len > i) {
                            match_start = start; mask = "[REDACTED_MAC]"; inplace_len = match_len;
                        }
                    }
                }
                if (match_len == 0 && is_digit(prev)) {
                    std::size_t start = i;
                    while (start > 0 && i - start < 4 && is_digit(input[start - 1])) start--;
                    if ((match_len = parse_credit_card(input, start)) > 0 && start + match_len > i) {
                        match_start = start; mask = "[REDACTED_CREDIT_CARD]"; inplace_len = match_len; requires_luhn = true;
                    } else if ((match_len = parse_ssn(input, start)) > 0 && start + match_len > i) {
                        match_start = start; mask = "[REDACTED_SSN]"; inplace_len = match_len;
                    } else if ((match_len = parse_phone(input, start)) > 0 && start + match_len > i) {
                        match_start = start; mask = "[REDACTED_PHONE]"; inplace_len = match_len;
                    }
                }
            }
        }

        // 4. Center-Out Parsers anchored on '.' (JWT, Vault, IPv4)
        else if (c == '.') {
            // Vault token (hvs., hvb., s.)
            if ((match_len = secrets::parse_vault_token(input, i, match_start)) > 0) {
                intervals.push_back({match_start, match_len, "[REDACTED_SECRET]", 2, match_len - 2});
                i = match_start + match_len; continue;
            }

            // JWT: check for "eyJ" in header segment before calling parse_jwt
            if (i >= 4) {
                std::size_t back = i;
                while (back > 0 && i - back < 256 && (std::isalnum(static_cast<unsigned char>(input[back - 1])) || input[back - 1] == '-' || input[back - 1] == '_')) back--;
                if (i - back >= 3 && input[back] == 'e' && input[back+1] == 'y' && input[back+2] == 'J') {
                    auto jwt = secrets::parse_jwt(input, i, match_start);
                    if (jwt.total_len > 0) {
                        std::size_t offset = jwt.header_len + 1; 
                        intervals.push_back({match_start, jwt.total_len, "[REDACTED_JWT]", offset, jwt.total_len - offset});
                        i = match_start + jwt.total_len; continue;
                    }
                }
            }
            
            // IPv4: requires digit before '.' AND digit after '.'
            if (i > 0 && is_digit(input[i - 1]) && i + 1 < len && is_digit(input[i + 1])) {
                std::size_t start = i;
                while (start > 0 && i - start < 3 && is_digit(input[start - 1])) start--;
                if (start < i && (match_len = parse_ipv4(input, start)) > 0 && start + match_len > i) {
                    match_start = start; mask = "[REDACTED_IP]"; inplace_len = match_len;
                }
            }
        }

        // 5. Center-Out Parsers anchored on ':' (DB Connection, IPv6, MAC)
        else if (c == ':') {
            // Fast bypass for time stamps HH:MM:SS (e.g. 10:15:30)
            if (i >= 2 && i + 5 < len && is_digit(input[i-2]) && is_digit(input[i-1]) &&
                is_digit(input[i+1]) && is_digit(input[i+2]) && input[i+3] == ':' && is_digit(input[i+4]) && is_digit(input[i+5]) &&
                (i + 6 >= len || input[i+6] != ':')) {
                i += 5; // Leap past the time stamp
                continue;
            }

            // Connection string: strictly requires "://"
            if (i + 2 < len && input[i+1] == '/' && input[i+2] == '/') {
                std::size_t pw_start = 0, pw_len = 0;
                if ((match_len = secrets::parse_connection_string(input, i, pw_start, pw_len)) > 0) {
                    std::size_t scheme_start = i;
                    while (scheme_start > 0 && std::isalpha(static_cast<unsigned char>(input[scheme_start - 1]))) scheme_start--;
                    intervals.push_back({scheme_start, match_len, "[REDACTED_DB_CONN]", pw_start - scheme_start, pw_len});
                    i = scheme_start + match_len; continue;
                }
            }

            // IPv6 / MAC: strictly requires hex on BOTH sides (or compressed ::)
            if (i > 0 && (is_hex(input[i-1]) || (i + 1 < len && input[i+1] == ':'))) {
                std::size_t start = i;
                while (start > 0 && i - start < 4 && is_hex(input[start - 1])) start--;
                if ((match_len = parse_ipv6(input, start)) > 0 && start + match_len > i) {
                    match_start = start; mask = "[REDACTED_IP]"; inplace_len = match_len;
                } else if (i + 1 < len && is_hex(input[i+1])) {
                    start = i;
                    while (start > 0 && i - start < 2 && is_hex(input[start - 1])) start--;
                    if ((match_len = parse_mac(input, start)) > 0 && start + match_len > i) {
                        match_start = start; mask = "[REDACTED_MAC]"; inplace_len = match_len;
                    }
                }
            }
        }

        // 6. Phone numbers anchored on '+' or '('
        else if (c == '+' || c == '(') {
            if ((match_len = parse_phone(input, i)) > 0) {
                match_start = i; mask = "[REDACTED_PHONE]"; inplace_len = match_len;
            }
        }

        // 7. Center-Out Parsers anchored on '"' (quoted AWS/GCP keys)
        else if (c == '"') {
            if (i + 20 <= len && (match_len = secrets::parse_aws_key(input, i + 1)) > 0) {
                match_start = i + 1; mask = "[REDACTED_AWS_KEY]"; inplace_offset = 4; inplace_len = match_len - 4;
            } else if (i + 39 <= len && (match_len = secrets::parse_gcp_key(input, i + 1)) > 0) {
                match_start = i + 1; mask = "[REDACTED_GCP_KEY]"; inplace_offset = 4; inplace_len = match_len - 4;
            }
        }

        // 8. Generic K/V Secrets and continuous numbers anchored on '=' or ':'
        if (match_len == 0 && (c == '=' || (c == ':' && i + 1 < len && input[i+1] != '/'))) {
            std::size_t val_start = 0, val_len = 0;
            if ((match_len = secrets::parse_kv_secret(input, i, val_start, val_len)) > 0) {
                if (secrets::parse_aws_key(input, val_start) > 0) {
                    intervals.push_back({val_start, val_len, "[REDACTED_AWS_KEY]", 4, val_len - 4});
                } else if (secrets::parse_gcp_key(input, val_start) > 0) {
                    intervals.push_back({val_start, val_len, "[REDACTED_GCP_KEY]", 4, val_len - 4});
                } else {
                    intervals.push_back({i, match_len, "[REDACTED_SECRET]", val_start - i, val_len});
                }
                i += match_len; continue;
            }
            
            // Attached secrets / structured PII after ':' or '='
            std::size_t curr = i + 1;
            while (curr < len && (input[curr] == ' ' || input[curr] == '"' || input[curr] == '\'')) curr++;
            if (curr < len) {
                if ((match_len = secrets::parse_gcp_key(input, curr)) > 0) {
                    match_start = curr; mask = "[REDACTED_GCP_KEY]"; inplace_offset = 4; inplace_len = match_len - 4;
                } else if ((match_len = secrets::parse_aws_key(input, curr)) > 0) {
                    match_start = curr; mask = "[REDACTED_AWS_KEY]"; inplace_offset = 4; inplace_len = match_len - 4;
                } else if (is_digit(input[curr])) {
                    // --- TIMESTAMP LOOKAHEAD BYPASS ---
                    // If digits immediately hit another colon (e.g. HH:MM:SS), it's a timestamp. Skip parsing.
                    std::size_t temp = curr;
                    while (temp < len && is_digit(input[temp])) temp++;
                    
                    if (temp < len && input[temp] == ':') {
                        // Do nothing. It is a timestamp. CPU is saved.
                    } else {
                        if ((match_len = parse_credit_card(input, curr)) > 0) {
                            match_start = curr; mask = "[REDACTED_CREDIT_CARD]"; inplace_len = match_len; requires_luhn = true;
                        } else if ((match_len = parse_ipv4(input, curr)) > 0) {
                            match_start = curr; mask = "[REDACTED_IP]"; inplace_len = match_len;
                        } else if ((match_len = parse_ssn(input, curr)) > 0) {
                            match_start = curr; mask = "[REDACTED_SSN]"; inplace_len = match_len;
                        } else if ((match_len = parse_id_num(input, curr)) > 0) {
                            match_start = curr; mask = "[REDACTED_ID]"; inplace_len = match_len;
                        } else if ((match_len = parse_phone(input, curr)) > 0) {
                            match_start = curr; mask = "[REDACTED_PHONE]"; inplace_len = match_len;
                        }
                    }
                }
            }
        }

        // 9. Floating AWS Keys (Ultra-fast inline prefix reject)
        // Directly checks 3 bytes before invoking parse_aws_key
        else if (c == 'A') {
            if (i + 19 < len) {
                char c1 = input[i+1], c2 = input[i+2], c3 = input[i+3];
                if ((c1 == 'K' && c2 == 'I' && c3 == 'A') || 
                    (c1 == 'S' && c2 == 'I' && c3 == 'A') || 
                    (c1 == 'B' && c2 == 'I' && c3 == 'A') || 
                    (c1 == 'R' && c2 == 'O' && c3 == 'A') || 
                    (c1 == 'I' && c2 == 'D' && c3 == 'A')) {
                    
                    if ((match_len = secrets::parse_aws_key(input, i)) > 0) {
                        match_start = i; mask = "[REDACTED_AWS_KEY]"; inplace_offset = 4; inplace_len = match_len - 4;
                    }
                }
            }
        }

        // Execute validations (like Luhn math) and store the match
        if (match_len > 0) {
            if (has_clean_boundary(input, match_start, match_len)) {
                if (!requires_luhn || luhn_validate(std::string_view(input.data() + match_start, match_len))) {
                    intervals.push_back({match_start, match_len, mask, inplace_offset, inplace_len});
                    i = std::max(i + 1, match_start + match_len);
                    continue;
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
// scrub_inplace(): Mode B — TRUE ZERO-ALLOCATION direct in-place mutation with '*'.
// Completely eliminates std::vector heap allocations and sorting overhead.
// ---------------------------------------------------------------------------
void Matcher::scrub_inplace(char* data, std::size_t len) const {
    if (len == 0 || data == nullptr) return;

    std::string_view input(data, len);
    std::size_t i = 0;

    while (i < len) {
#ifndef FASTSCRUB_FORCE_SCALAR
        i = SwarScanner::find_next_anchor(data, len, i);
        if (i >= len) break;
#endif

        char c = data[i];
        std::size_t match_start = 0;
        std::size_t match_len = 0;
        std::size_t inplace_offset = 0;
        std::size_t inplace_len = 0;
        bool requires_luhn = false;

        // 1. Email anchored on '@'
        if (c == '@') {
            std::size_t start = i;
            while (start > 0 && is_email_local(input[start - 1])) start--;
            if (start < i && i - start <= 128) {
                std::size_t end = i + 1;
                while (end < input.size() && is_email_domain(input[end])) end++;
                while (end > i + 1 && !std::isalpha(static_cast<unsigned char>(input[end - 1]))) end--;

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
                                std::memset(data + start, '*', end - start);
                                i = end; continue;
                            }
                        }
                    }
                }
            }
        }

        // 2. Center-Out Parsers anchored on '_' (GitHub, Stripe, HuggingFace)
        else if (c == '_') {
            bool is_github = false;
            if (i >= 3) {
                if (input[i-3] == 'g' && input[i-2] == 'h' && 
                    (input[i-1] == 'p' || input[i-1] == 'o' || input[i-1] == 'u' || input[i-1] == 's' || input[i-1] == 'r')) {
                    is_github = true;
                } else if (i >= 10 && input.substr(i-10, 11) == "github_pat_") {
                    is_github = true;
                }
            }
            if (is_github && (match_len = secrets::parse_github_token(input, i, match_start)) > 0) {
                std::size_t prefix = (match_len >= 22 && input.substr(match_start, 11) == "github_pat_") ? 11 : 4;
                std::memset(data + match_start + prefix, '*', match_len - prefix);
                i = match_start + match_len; continue;
            }

            bool is_stripe = false;
            if (i >= 2) {
                char p1 = input[i-2], p2 = input[i-1];
                if ((p1 == 's' || p1 == 'p' || p1 == 'r') && p2 == 'k') {
                    is_stripe = true;
                } else if (i >= 7 && (input.substr(i-5, 5) == "_live" || input.substr(i-5, 5) == "_test")) {
                    is_stripe = true;
                }
            }
            if (is_stripe && (match_len = secrets::parse_stripe_key(input, i, match_start)) > 0) {
                std::memset(data + match_start + 8, '*', match_len - 8);
                i = match_start + match_len; continue;
            }

            if ((match_len = secrets::parse_huggingface_token(input, i, match_start)) > 0) {
                std::memset(data + match_start + 3, '*', match_len - 3);
                i = match_start + match_len; continue;
            }
        }

        // 3. Center-Out Parsers anchored on '-' (AI/DevOps Tokens, Private Keys, Slack, UUID, MAC, CC, SSN, Phone)
        else if (c == '-') {
            // Fast bypass for date stamps YYYY-MM-DD (e.g. 2026-08-20)
            if (i >= 4 && i + 5 < len && is_digit(input[i-4]) && is_digit(input[i-3]) && is_digit(input[i-2]) && is_digit(input[i-1]) &&
                is_digit(input[i+1]) && is_digit(input[i+2]) && input[i+3] == '-' && is_digit(input[i+4]) && is_digit(input[i+5])) {
                i += 5; continue;
            }

            // Anthropic Claude key (sk-ant-...)
            if ((match_len = secrets::parse_anthropic_key(input, i, match_start)) > 0) {
                std::memset(data + match_start + 7, '*', match_len - 7);
                i = match_start + match_len; continue;
            }

            // OpenAI API key (sk-proj-..., sk-admin-..., sk-...)
            if ((match_len = secrets::parse_openai_key(input, i, match_start)) > 0) {
                std::memset(data + match_start + 3, '*', match_len - 3);
                i = match_start + match_len; continue;
            }

            // GitLab Token (glpat-...)
            if ((match_len = secrets::parse_gitlab_token(input, i, match_start)) > 0) {
                std::memset(data + match_start + 6, '*', match_len - 6);
                i = match_start + match_len; continue;
            }

            // PyPI Token (pypi-...)
            if ((match_len = secrets::parse_pypi_token(input, i, match_start)) > 0) {
                std::memset(data + match_start + 5, '*', match_len - 5);
                i = match_start + match_len; continue;
            }

            // Slack token requires "xox"
            if (i >= 4 && input[i-4] == 'x' && input[i-3] == 'o' && input[i-2] == 'x' &&
                (input[i-1] == 'b' || input[i-1] == 'p' || input[i-1] == 'a' || input[i-1] == 'r' || input[i-1] == 's')) {
                if ((match_len = secrets::parse_slack_token(input, i, match_start)) > 0) {
                    std::memset(data + match_start + 5, '*', match_len - 5);
                    i = match_start + match_len; continue;
                }
            }

            // Private key requires "-----"
            if (i + 15 < len && input.substr(i, 5) == "-----") {
                if ((match_len = secrets::parse_private_key(input, i)) > 0) {
                    std::memset(data + i, '*', match_len);
                    i += match_len; continue;
                }
            }
            
            // Structural PII fallbacks: MUST be preceded by hex or digit
            if (i > 0) {
                char prev = input[i - 1];
                if (is_hex(prev)) {
                    std::size_t start = i;
                    while (start > 0 && i - start < 8 && is_hex(input[start - 1])) start--;
                    if (i - start == 8 && (match_len = parse_uuid(input, start)) > 0 && start + match_len > i) {
                        match_start = start; inplace_len = match_len;
                    }
                    if (match_len == 0 && i - start <= 2) {
                        if ((match_len = parse_mac(input, start)) > 0 && start + match_len > i) {
                            match_start = start; inplace_len = match_len;
                        }
                    }
                }
                if (match_len == 0 && is_digit(prev)) {
                    std::size_t start = i;
                    while (start > 0 && i - start < 4 && is_digit(input[start - 1])) start--;
                    if ((match_len = parse_credit_card(input, start)) > 0 && start + match_len > i) {
                        match_start = start; inplace_len = match_len; requires_luhn = true;
                    } else if ((match_len = parse_ssn(input, start)) > 0 && start + match_len > i) {
                        match_start = start; inplace_len = match_len;
                    } else if ((match_len = parse_phone(input, start)) > 0 && start + match_len > i) {
                        match_start = start; inplace_len = match_len;
                    }
                }
            }
        }

        // 4. Center-Out Parsers anchored on '.' (JWT, Vault, IPv4)
        else if (c == '.') {
            // Vault token (hvs., hvb., s.)
            if ((match_len = secrets::parse_vault_token(input, i, match_start)) > 0) {
                std::memset(data + match_start + 2, '*', match_len - 2);
                i = match_start + match_len; continue;
            }

            // JWT: check for "eyJ" in header segment before calling parse_jwt
            if (i >= 4) {
                std::size_t back = i;
                while (back > 0 && i - back < 256 && (std::isalnum(static_cast<unsigned char>(input[back - 1])) || input[back - 1] == '-' || input[back - 1] == '_')) back--;
                if (i - back >= 3 && input[back] == 'e' && input[back+1] == 'y' && input[back+2] == 'J') {
                    auto jwt = secrets::parse_jwt(input, i, match_start);
                    if (jwt.total_len > 0) {
                        std::size_t offset = jwt.header_len + 1; 
                        std::memset(data + match_start + offset, '*', jwt.total_len - offset);
                        i = match_start + jwt.total_len; continue;
                    }
                }
            }
            
            // IPv4: requires digit before '.' AND digit after '.'
            if (i > 0 && is_digit(input[i - 1]) && i + 1 < len && is_digit(input[i + 1])) {
                std::size_t start = i;
                while (start > 0 && i - start < 3 && is_digit(input[start - 1])) start--;
                if (start < i && (match_len = parse_ipv4(input, start)) > 0 && start + match_len > i) {
                    match_start = start; inplace_len = match_len;
                }
            }
        }

        // 5. Center-Out Parsers anchored on ':' (DB Connection, IPv6, MAC)
        else if (c == ':') {
            // Fast bypass for time stamps HH:MM:SS (e.g. 10:15:30)
            if (i >= 2 && i + 5 < len && is_digit(input[i-2]) && is_digit(input[i-1]) &&
                is_digit(input[i+1]) && is_digit(input[i+2]) && input[i+3] == ':' && is_digit(input[i+4]) && is_digit(input[i+5]) &&
                (i + 6 >= len || input[i+6] != ':')) {
                i += 5; continue;
            }

            // Connection string: strictly requires "://"
            if (i + 2 < len && input[i+1] == '/' && input[i+2] == '/') {
                std::size_t pw_start = 0, pw_len = 0;
                if ((match_len = secrets::parse_connection_string(input, i, pw_start, pw_len)) > 0) {
                    std::memset(data + pw_start, '*', pw_len);
                    std::size_t scheme_start = i;
                    while (scheme_start > 0 && std::isalpha(static_cast<unsigned char>(input[scheme_start - 1]))) scheme_start--;
                    i = scheme_start + match_len; continue;
                }
            }

            // IPv6 / MAC: strictly requires hex on BOTH sides (or compressed ::)
            if (i > 0 && (is_hex(input[i-1]) || (i + 1 < len && input[i+1] == ':'))) {
                std::size_t start = i;
                while (start > 0 && i - start < 4 && is_hex(input[start - 1])) start--;
                if ((match_len = parse_ipv6(input, start)) > 0 && start + match_len > i) {
                    match_start = start; inplace_len = match_len;
                } else if (i + 1 < len && is_hex(input[i+1])) {
                    start = i;
                    while (start > 0 && i - start < 2 && is_hex(input[start - 1])) start--;
                    if ((match_len = parse_mac(input, start)) > 0 && start + match_len > i) {
                        match_start = start; inplace_len = match_len;
                    }
                }
            }
        }

        // 6. Phone numbers anchored on '+' or '('
        else if (c == '+' || c == '(') {
            if ((match_len = parse_phone(input, i)) > 0) {
                match_start = i; inplace_len = match_len;
            }
        }

        // 7. Center-Out Parsers anchored on '"' (quoted AWS/GCP keys)
        else if (c == '"') {
            if (i + 20 <= len && (match_len = secrets::parse_aws_key(input, i + 1)) > 0) {
                match_start = i + 1; inplace_offset = 4; inplace_len = match_len - 4;
            } else if (i + 39 <= len && (match_len = secrets::parse_gcp_key(input, i + 1)) > 0) {
                match_start = i + 1; inplace_offset = 4; inplace_len = match_len - 4;
            }
        }

        // 8. Generic K/V Secrets and continuous numbers anchored on '=' or ':'
        if (match_len == 0 && (c == '=' || (c == ':' && i + 1 < len && input[i+1] != '/'))) {
            std::size_t val_start = 0, val_len = 0;
            if ((match_len = secrets::parse_kv_secret(input, i, val_start, val_len)) > 0) {
                if (secrets::parse_aws_key(input, val_start) > 0) {
                    std::memset(data + val_start + 4, '*', val_len - 4);
                } else if (secrets::parse_gcp_key(input, val_start) > 0) {
                    std::memset(data + val_start + 4, '*', val_len - 4);
                } else {
                    std::memset(data + val_start, '*', val_len);
                }
                i += match_len; continue;
            }
            
            // Attached secrets / structured PII after ':' or '='
            std::size_t curr = i + 1;
            while (curr < len && (input[curr] == ' ' || input[curr] == '"' || input[curr] == '\'')) curr++;
            if (curr < len) {
                if ((match_len = secrets::parse_gcp_key(input, curr)) > 0) {
                    match_start = curr; inplace_offset = 4; inplace_len = match_len - 4;
                } else if ((match_len = secrets::parse_aws_key(input, curr)) > 0) {
                    match_start = curr; inplace_offset = 4; inplace_len = match_len - 4;
                } else if (is_digit(input[curr])) {
                    // --- TIMESTAMP LOOKAHEAD BYPASS ---
                    std::size_t temp = curr;
                    while (temp < len && is_digit(input[temp])) temp++;
                    
                    if (temp < len && input[temp] == ':') {
                        // Fast-reject timestamp
                    } else {
                        if ((match_len = parse_credit_card(input, curr)) > 0) {
                            match_start = curr; inplace_len = match_len; requires_luhn = true;
                        } else if ((match_len = parse_ipv4(input, curr)) > 0) {
                            match_start = curr; inplace_len = match_len;
                        } else if ((match_len = parse_ssn(input, curr)) > 0) {
                            match_start = curr; inplace_len = match_len;
                        } else if ((match_len = parse_id_num(input, curr)) > 0) {
                            match_start = curr; inplace_len = match_len;
                        } else if ((match_len = parse_phone(input, curr)) > 0) {
                            match_start = curr; inplace_len = match_len;
                        }
                    }
                }
            }
        }

        // 9. Floating AWS Keys (Ultra-fast inline prefix reject)
        else if (c == 'A') {
            if (i + 19 < len) {
                char c1 = input[i+1], c2 = input[i+2], c3 = input[i+3];
                if ((c1 == 'K' && c2 == 'I' && c3 == 'A') || 
                    (c1 == 'S' && c2 == 'I' && c3 == 'A') || 
                    (c1 == 'B' && c2 == 'I' && c3 == 'A') || 
                    (c1 == 'R' && c2 == 'O' && c3 == 'A') || 
                    (c1 == 'I' && c2 == 'D' && c3 == 'A')) {
                    
                    if ((match_len = secrets::parse_aws_key(input, i)) > 0) {
                        match_start = i; inplace_offset = 4; inplace_len = match_len - 4;
                    }
                }
            }
        }

        // Execute validations and mutate memory directly
        if (match_len > 0) {
            if (has_clean_boundary(input, match_start, match_len)) {
                if (!requires_luhn || luhn_validate(std::string_view(input.data() + match_start, match_len))) {
                    std::memset(data + match_start + inplace_offset, '*', inplace_len);
                    i = std::max(i + 1, match_start + match_len);
                    continue;
                }
            }
        }

        ++i;
    }
}

} // namespace fastscrub
