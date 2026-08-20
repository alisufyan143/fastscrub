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
        // SWAR: Jump to next anchor character (skips clean bytes 8 at a time)
        i = SwarScanner::find_next_anchor(data, len, i);
        if (i >= len) break;
#endif

        char c = data[i];

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
            std::size_t len = secrets::parse_aws_key(input, i);
            if (len > 0 && has_clean_boundary(input, i, len)) {
                intervals.push_back({i, len, "[REDACTED_AWS_KEY]", 4, len - 4});
                i += len;
                continue;
            }
        }

        // GCP key: anchors on 'A' (AIza prefix) — check after AWS
        if (c == 'A') {
            std::size_t len = secrets::parse_gcp_key(input, i);
            if (len > 0 && has_clean_boundary(input, i, len)) {
                intervals.push_back({i, len, "[REDACTED_GCP_KEY]", 4, len - 4});
                i += len;
                continue;
            }
        }

        // GitHub token: anchors on 'g'
        if (c == 'g') {
            std::size_t len = secrets::parse_github_token(input, i);
            if (len > 0 && has_clean_boundary(input, i, len)) {
                std::size_t prefix = (len >= 11 && input.substr(i, 11) == "github_pat_") ? 11 : 4;
                intervals.push_back({i, len, "[REDACTED_GITHUB_TOKEN]", prefix, len - prefix});
                i += len;
                continue;
            }
        }

        // Slack token: anchors on 'x'
        if (c == 'x') {
            std::size_t len = secrets::parse_slack_token(input, i);
            if (len > 0 && has_clean_boundary(input, i, len)) {
                intervals.push_back({i, len, "[REDACTED_SLACK_TOKEN]", 5, len - 5});
                i += len;
                continue;
            }
        }

        // Stripe key: anchors on 's', 'r', 'p'
        if (c == 's' || c == 'r' || c == 'p') {
            std::size_t len = secrets::parse_stripe_key(input, i);
            if (len > 0 && has_clean_boundary(input, i, len)) {
                intervals.push_back({i, len, "[REDACTED_STRIPE_KEY]", 8, len - 8});
                i += len;
                continue;
            }
        }

        // JWT: anchors on 'e' (eyJ prefix)
        if (c == 'e') {
            auto jwt = secrets::parse_jwt(input, i);
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
            std::size_t len = secrets::parse_private_key(input, i);
            if (len > 0) {
                intervals.push_back({i, len, "[REDACTED_PRIVATE_KEY]", 0, len});
                i += len;
                continue;
            }
        }

        // DB connection string: anchors on ':' (://)
        if (c == ':') {
            std::size_t pw_start = 0, pw_len = 0;
            std::size_t total_len = secrets::parse_connection_string(input, i, pw_start, pw_len);
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
            std::size_t total_len = secrets::parse_kv_secret(input, i, val_start, val_len);
            if (total_len > 0) {
                intervals.push_back({i, total_len, "[REDACTED_SECRET]", val_start - i, val_len});
                i += total_len;
                continue;
            }
        }

        // 3. Center-Out Structural PII checks based on anchor punctuation
        std::size_t match_start = 0;
        std::size_t match_len = 0;
        std::string_view mask;
        bool requires_luhn = false;

        if (c == '.') {
            std::size_t start = i;
            while (start > 0 && i - start < 3 && is_digit(input[start - 1])) start--;
            if (start < i) {
                if ((match_len = parse_ipv4(input, start)) > 0 && start + match_len > i) {
                    match_start = start; mask = "[REDACTED_IP]";
                } else if ((match_len = parse_phone(input, start)) > 0 && start + match_len > i) {
                    match_start = start; mask = "[REDACTED_PHONE]";
                }
            }
        }
        else if (c == '-') {
            std::size_t start = i;
            while (start > 0 && i - start < 8 && is_hex(input[start - 1])) start--;
            if ((match_len = parse_uuid(input, start)) > 0 && start + match_len > i) {
                match_start = start; mask = "[REDACTED_UUID]";
            }
            if (match_len == 0) {
                start = i;
                while (start > 0 && i - start < 2 && is_hex(input[start - 1])) start--;
                if ((match_len = parse_mac(input, start)) > 0 && start + match_len > i) {
                    match_start = start; mask = "[REDACTED_MAC]";
                }
            }
            if (match_len == 0) {
                start = i;
                while (start > 0 && i - start < 4 && is_digit(input[start - 1])) start--;
                if ((match_len = parse_credit_card(input, start)) > 0 && start + match_len > i) {
                    match_start = start; mask = "[REDACTED_CREDIT_CARD]"; requires_luhn = true;
                } else if ((match_len = parse_ssn(input, start)) > 0 && start + match_len > i) {
                    match_start = start; mask = "[REDACTED_SSN]";
                } else if ((match_len = parse_phone(input, start)) > 0 && start + match_len > i) {
                    match_start = start; mask = "[REDACTED_PHONE]";
                }
            }
        }
        else if (c == ':') {
            std::size_t start = i;
            while (start > 0 && i - start < 4 && is_hex(input[start - 1])) start--;
            if ((match_len = parse_ipv6(input, start)) > 0 && start + match_len > i) {
                match_start = start; mask = "[REDACTED_IP]";
            }
            if (match_len == 0) {
                start = i;
                while (start > 0 && i - start < 2 && is_hex(input[start - 1])) start--;
                if ((match_len = parse_mac(input, start)) > 0 && start + match_len > i) {
                    match_start = start; mask = "[REDACTED_MAC]";
                }
            }
        }
        else if (c == '+' || c == '(') {
            if ((match_len = parse_phone(input, i)) > 0) {
                match_start = i; mask = "[REDACTED_PHONE]";
            }
        }

        if (match_len == 0 && (c == ':' || c == '=')) {
            std::size_t curr = i + 1;
            while (curr < len && (input[curr] == ' ' || input[curr] == '"' || input[curr] == '\'')) curr++;
            if (curr < len && is_digit(input[curr])) {
                if ((match_len = parse_credit_card(input, curr)) > 0) {
                    match_start = curr; mask = "[REDACTED_CREDIT_CARD]"; requires_luhn = true;
                } else if ((match_len = parse_ipv4(input, curr)) > 0) {
                    match_start = curr; mask = "[REDACTED_IP]";
                } else if ((match_len = parse_ssn(input, curr)) > 0) {
                    match_start = curr; mask = "[REDACTED_SSN]";
                } else if ((match_len = parse_id_num(input, curr)) > 0) {
                    match_start = curr; mask = "[REDACTED_ID]";
                } else if ((match_len = parse_phone(input, curr)) > 0) {
                    match_start = curr; mask = "[REDACTED_PHONE]";
                }
            }
        }

        if (match_len > 0) {
            if (has_clean_boundary(input, match_start, match_len)) {
                if (!requires_luhn || luhn_validate(std::string_view(input.data() + match_start, match_len))) {
                    intervals.push_back({match_start, match_len, mask, 0, match_len});
                    i = match_start + match_len;
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
