#include "include/secret_parsers.hpp"
#include <cctype>

namespace fastscrub {
namespace secrets {

namespace {

inline bool is_digit(char c) noexcept {
    return (c >= '0' && c <= '9');
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

} // anonymous namespace

bool has_context_word(std::string_view input, std::size_t pos, const std::string_view* keywords, std::size_t num_keywords) noexcept {
    if (pos == 0) return false;
    std::size_t k_end = pos;
    while (k_end > 0 && (input[k_end-1] == ' ' || input[k_end-1] == '"' || input[k_end-1] == '\'')) k_end--;
    if (k_end == 0) return false;
    
    std::size_t k_start = k_end;
    while (k_start > 0 && (std::isalnum(static_cast<unsigned char>(input[k_start-1])) || input[k_start-1] == '_')) k_start--;
    std::size_t k_len = k_end - k_start;
    
    // Fast length reject: all valid keywords are between 4 and 16 chars
    if (k_len < 4 || k_len > 16) return false;
    
    char lower_kw[20];
    for (std::size_t i = 0; i < k_len; ++i) {
        lower_kw[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(input[k_start + i])));
    }
    std::string_view word(lower_kw, k_len);
    
    for (std::size_t i = 0; i < num_keywords; ++i) {
        if (word == keywords[i]) {
            return true;
        }
    }
    return false;
}

std::size_t parse_aws_key(std::string_view s, std::size_t pos) noexcept {
    if (pos + 20 > s.size()) return 0;
    if (s[pos] != 'A') return 0;
    
    char c1 = s[pos+1], c2 = s[pos+2], c3 = s[pos+3];
    
    // Accept AKIA, ASIA, ABIA, AROA, AIDA
    bool valid_prefix = (c1 == 'K' && c2 == 'I' && c3 == 'A') || 
                        (c1 == 'S' && c2 == 'I' && c3 == 'A') || 
                        (c1 == 'B' && c2 == 'I' && c3 == 'A') || 
                        (c1 == 'R' && c2 == 'O' && c3 == 'A') || 
                        (c1 == 'I' && c2 == 'D' && c3 == 'A');
                        
    if (!valid_prefix) return 0;
    
    for (std::size_t i = pos + 4; i < pos + 20; ++i) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z'))) return 0;
    }
    return 20;
}

// Center-Out GitHub token parser: pos points to '_'
std::size_t parse_github_token(std::string_view s, std::size_t pos, std::size_t& match_start) noexcept {
    // 1. ghp_ or gho_ or ghu_ or ghs_ or ghr_ (pos is the '_' at start+3)
    if (pos >= 3 && pos + 30 <= s.size()) {
        if (s[pos-3] == 'g' && s[pos-2] == 'h' && 
           (s[pos-1] == 'p' || s[pos-1] == 'o' || s[pos-1] == 'u' || s[pos-1] == 's' || s[pos-1] == 'r')) {
            std::size_t start = pos - 3;
            std::size_t curr = pos + 1;
            while (curr < s.size() && is_base62(s[curr])) curr++;
            std::size_t body_len = curr - (pos + 1);
            if (body_len >= 30 && body_len <= 82) {
                match_start = start;
                return curr - start;
            }
        }
    }
    // 2. github_pat_ (pos is the second '_' at start+10)
    if (pos >= 10 && pos + 22 <= s.size()) {
        if (s.substr(pos - 10, 11) == "github_pat_") {
            std::size_t start = pos - 10;
            std::size_t curr = pos + 1;
            while (curr < s.size() && (is_base62(s[curr]) || s[curr] == '_')) curr++;
            std::size_t body_len = curr - (pos + 1);
            if (body_len >= 22) {
                match_start = start;
                return curr - start;
            }
        }
    }
    // 3. github_pat_ (pos is the first '_' at start+6)
    if (pos >= 6 && pos + 26 <= s.size()) {
        if (s.substr(pos - 6, 11) == "github_pat_") {
            std::size_t start = pos - 6;
            std::size_t curr = pos + 5; // after "pat_"
            while (curr < s.size() && (is_base62(s[curr]) || s[curr] == '_')) curr++;
            std::size_t body_len = curr - (pos + 5);
            if (body_len >= 22) {
                match_start = start;
                return curr - start;
            }
        }
    }
    return 0;
}

std::size_t parse_gcp_key(std::string_view s, std::size_t pos) noexcept {
    if (pos + 39 > s.size()) return 0;
    if (s[pos] != 'A' || s[pos+1] != 'I' || s[pos+2] != 'z' || s[pos+3] != 'a') return 0;
    for (std::size_t i = pos + 4; i < pos + 39; ++i) {
        if (!is_base62_ext(s[i])) return 0;
    }
    return 39;
}

// Center-Out Slack token parser: pos points to '-'
std::size_t parse_slack_token(std::string_view s, std::size_t pos, std::size_t& match_start) noexcept {
    if (pos >= 4 && pos + 30 <= s.size()) {
        if (s[pos-4] == 'x' && s[pos-3] == 'o' && s[pos-2] == 'x' && 
           (s[pos-1] == 'b' || s[pos-1] == 'p' || s[pos-1] == 'a' || s[pos-1] == 'r' || s[pos-1] == 's')) {
            std::size_t start = pos - 4;
            std::size_t curr = pos + 1;
            int blocks = 0;
            while (curr < s.size() && blocks < 6) {
                std::size_t block_start = curr;
                while (curr < s.size() && is_base62(s[curr])) curr++;
                if (curr == block_start) break;
                blocks++;
                if (curr < s.size() && s[curr] == '-') {
                    curr++;
                } else {
                    break;
                }
            }
            std::size_t total_len = curr - start;
            if (blocks >= 2 && total_len >= 32 && total_len <= 90) {
                match_start = start;
                return total_len;
            }
        }
    }
    return 0;
}

// Center-Out Stripe key parser: pos points to '_'
std::size_t parse_stripe_key(std::string_view s, std::size_t pos, std::size_t& match_start) noexcept {
    // Case 1: pos is the first underscore (e.g. sk_live_, rk_live_, pk_live_)
    if (pos >= 2 && pos + 30 <= s.size()) {
        char c0 = s[pos-2], c1 = s[pos-1];
        if ((c0 == 's' || c0 == 'r' || c0 == 'p') && c1 == 'k') {
            std::string_view mode = s.substr(pos + 1, 5);
            if (mode == "live_" || mode == "test_") {
                std::size_t start = pos - 2;
                std::size_t body_start = pos + 6;
                std::size_t curr = body_start;
                while (curr < s.size() && is_base62(s[curr])) curr++;
                std::size_t body_len = curr - body_start;
                if (body_len >= 24 && body_len <= 64) {
                    match_start = start;
                    return curr - start;
                }
            }
        }
    }
    // Case 2: pos is the second underscore (e.g. sk_live_)
    if (pos >= 7 && pos + 24 <= s.size()) {
        std::string_view mode = s.substr(pos - 4, 5); // "live_" or "test_"
        if (mode == "live_" || mode == "test_") {
            if (s[pos-5] == '_') {
                char c0 = s[pos-7], c1 = s[pos-6];
                if ((c0 == 's' || c0 == 'r' || c0 == 'p') && c1 == 'k') {
                    std::size_t start = pos - 7;
                    std::size_t body_start = pos + 1;
                    std::size_t curr = body_start;
                    while (curr < s.size() && is_base62(s[curr])) curr++;
                    std::size_t body_len = curr - body_start;
                    if (body_len >= 24 && body_len <= 64) {
                        match_start = start;
                        return curr - start;
                    }
                }
            }
        }
    }
    return 0;
}

std::size_t parse_private_key(std::string_view s, std::size_t pos) noexcept {
    if (pos + 27 > s.size()) return 0;
    if (s.substr(pos, 11) != "-----BEGIN ") return 0;
    
    std::size_t header_end = s.find("PRIVATE KEY-----", pos + 11);
    if (header_end == std::string_view::npos || header_end > pos + 50) return 0;
    header_end += 16;
    
    std::size_t end_marker = s.find("-----END ", header_end);
    if (end_marker == std::string_view::npos) return 0;
    
    std::size_t final_end = s.find("PRIVATE KEY-----", end_marker);
    if (final_end == std::string_view::npos) return 0;
    final_end += 16;
    
    return final_end - pos;
}

// Center-Out JWT parser: pos points to '.'
JwtMatch parse_jwt(std::string_view s, std::size_t pos, std::size_t& match_start) noexcept {
    // Look backward for segment 1 (header, starts with eyJ)
    std::size_t seg1_start = pos;
    while (seg1_start > 0 && is_base64url(s[seg1_start - 1])) {
        seg1_start--;
    }
    std::size_t header_len = pos - seg1_start;
    if (header_len < 4) return {0, 0};
    if (seg1_start + 3 > s.size() || s[seg1_start] != 'e' || s[seg1_start+1] != 'y' || s[seg1_start+2] != 'J') {
        return {0, 0};
    }
    
    // Check segment 2 (payload, starts with eyJ)
    if (pos + 4 >= s.size() || s[pos+1] != 'e' || s[pos+2] != 'y' || s[pos+3] != 'J') {
        return {0, 0};
    }
    
    std::size_t curr = pos + 1;
    while (curr < s.size() && is_base64url(s[curr])) curr++;
    if (curr >= s.size() || s[curr] != '.') return {0, 0};
    
    std::size_t dot2 = curr;
    std::size_t seg2_len = dot2 - (pos + 1);
    if (seg2_len < 4) return {0, 0};
    
    // Segment 3 (signature)
    curr = dot2 + 1;
    std::size_t seg3_start = curr;
    while (curr < s.size() && is_base64url(s[curr]) && s[curr] != '.') curr++;
    std::size_t seg3_len = curr - seg3_start;
    if (seg3_len < 4) return {0, 0};
    
    std::size_t total = curr - seg1_start;
    if (total >= 20) {
        match_start = seg1_start;
        return {total, header_len};
    }
    return {0, 0};
}

std::size_t parse_connection_string(std::string_view s, std::size_t pos, std::size_t& password_start, std::size_t& password_len) noexcept {
    if (pos + 3 > s.size()) return 0;
    if (s[pos] != ':' || s[pos+1] != '/' || s[pos+2] != '/') return 0;
    
    std::size_t scheme_start = pos;
    while (scheme_start > 0 && (std::isalpha(static_cast<unsigned char>(s[scheme_start - 1])) || s[scheme_start - 1] == '+')) {
        scheme_start--;
    }
    if (scheme_start == pos) return 0;
    
    std::string_view scheme_sv = s.substr(scheme_start, pos - scheme_start);
    char scheme_lower[20];
    if (scheme_sv.size() > 19) return 0;
    for (std::size_t i = 0; i < scheme_sv.size(); ++i) {
        scheme_lower[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(scheme_sv[i])));
    }
    std::string_view scheme(scheme_lower, scheme_sv.size());
    
    static constexpr std::string_view db_schemes[] = {
        "postgres", "postgresql", "mysql", "mongodb", "redis",
        "amqp", "mssql", "oracle", "sqlserver", "mongodb+srv"
    };
    bool valid_scheme = false;
    for (const auto& ds : db_schemes) {
        if (scheme == ds) { valid_scheme = true; break; }
    }
    if (!valid_scheme) return 0;
    
    std::size_t curr = pos + 3;
    std::size_t at_pos = std::string_view::npos;
    for (std::size_t i = curr; i < s.size(); ++i) {
        char c = s[i];
        if (c == '@') { at_pos = i; break; }
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '"' || c == '\'') break;
    }
    if (at_pos == std::string_view::npos) return 0;
    
    std::size_t colon_pos = std::string_view::npos;
    for (std::size_t i = curr; i < at_pos; ++i) {
        if (s[i] == ':') { colon_pos = i; break; }
    }
    if (colon_pos == std::string_view::npos) return 0;
    
    password_start = colon_pos + 1;
    password_len = at_pos - password_start;
    if (password_len == 0) return 0;
    
    std::size_t end = at_pos + 1;
    while (end < s.size()) {
        char c = s[end];
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '"' || c == '\'' || c == ',' || c == ';') break;
        end++;
    }
    
    return end - scheme_start;
}

std::size_t parse_kv_secret(std::string_view s, std::size_t pos, std::size_t& value_start, std::size_t& value_len) noexcept {
    char anchor = s[pos];
    if (anchor != '=' && anchor != ':') return 0;
    
    static constexpr std::string_view kv_keywords[] = {
        "password", "passwd", "secret", "api_key", "apikey", "api_secret",
        "access_token", "auth_token", "private_key", "client_secret",
        "token", "bearer", "credential", "dd_api_secret", "dd_app"
    };
    if (!has_context_word(s, pos, kv_keywords, 15)) return 0;
    
    std::size_t curr = pos + 1;
    while (curr < s.size() && (s[curr] == ' ' || s[curr] == '\t')) curr++;
    
    char quote = 0;
    if (curr < s.size() && (s[curr] == '"' || s[curr] == '\'')) {
        quote = s[curr];
        curr++;
    }
    
    value_start = curr;
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
    
    bool has_letter = false, has_digit = false;
    for (std::size_t i = value_start; i < value_start + value_len; ++i) {
        if (std::isalpha(static_cast<unsigned char>(s[i]))) has_letter = true;
        if (is_digit(s[i])) has_digit = true;
    }
    if (!has_letter || !has_digit) return 0;
    
    std::size_t end = curr;
    if (quote && end < s.size() && s[end] == quote) end++;
    
    return end - pos;
}

// ---------------------------------------------------------------------------
// Modern AI, DevOps & Security Token Parsers
// ---------------------------------------------------------------------------

// OpenAI API Key (sk-proj-, sk-admin-, sk-svcacct-, legacy sk-)
std::size_t parse_openai_key(std::string_view s, std::size_t pos, std::size_t& match_start) noexcept {
    // Anchor pos is '-' in "sk-" or start of 's'
    if (pos >= 2 && pos + 40 <= s.size()) {
        if (s[pos-2] == 's' && s[pos-1] == 'k' && s[pos] == '-') {
            std::size_t start = pos - 2;
            std::size_t curr = pos + 1;
            
            // Check sub-prefixes: proj-, admin-, svcacct-
            if (curr + 5 <= s.size() && s.substr(curr, 5) == "proj-") curr += 5;
            else if (curr + 6 <= s.size() && s.substr(curr, 6) == "admin-") curr += 6;
            else if (curr + 8 <= s.size() && s.substr(curr, 8) == "svcacct-") curr += 8;
            
            std::size_t body_start = curr;
            while (curr < s.size() && is_base62_ext(s[curr])) curr++;
            std::size_t body_len = curr - body_start;
            
            if (body_len >= 32) {
                match_start = start;
                return curr - start;
            }
        }
    }
    return 0;
}

// Anthropic Claude Key (sk-ant-api03-, sk-ant-admin01-, sk-ant-)
std::size_t parse_anthropic_key(std::string_view s, std::size_t pos, std::size_t& match_start) noexcept {
    // Anchor pos is '-' in "sk-ant-"
    if (pos >= 6 && pos + 40 <= s.size()) {
        if (s.substr(pos - 6, 7) == "sk-ant-") {
            std::size_t start = pos - 6;
            std::size_t curr = pos + 1;
            
            if (curr + 6 <= s.size() && s.substr(curr, 6) == "api03-") curr += 6;
            else if (curr + 8 <= s.size() && s.substr(curr, 8) == "admin01-") curr += 8;
            
            std::size_t body_start = curr;
            while (curr < s.size() && is_base62_ext(s[curr])) curr++;
            std::size_t body_len = curr - body_start;
            
            if (body_len >= 40) {
                match_start = start;
                return curr - start;
            }
        }
    }
    return 0;
}

// GitLab Token (glpat-, glcbt-, glft-)
std::size_t parse_gitlab_token(std::string_view s, std::size_t pos, std::size_t& match_start) noexcept {
    if (pos >= 5 && pos + 20 <= s.size()) {
        if (s[pos] == '-' && s[pos-5] == 'g' && s[pos-4] == 'l' && 
           (s.substr(pos - 3, 3) == "pat" || s.substr(pos - 3, 3) == "cbt" || s.substr(pos - 3, 3) == "ft-")) {
            std::size_t start = pos - 5;
            std::size_t curr = pos + 1;
            while (curr < s.size() && is_base62_ext(s[curr])) curr++;
            std::size_t body_len = curr - (pos + 1);
            if (body_len >= 20 && body_len <= 64) {
                match_start = start;
                return curr - start;
            }
        }
    }
    return 0;
}

// PyPI Token (pypi-AgEI...)
std::size_t parse_pypi_token(std::string_view s, std::size_t pos, std::size_t& match_start) noexcept {
    if (pos >= 4 && pos + 30 <= s.size()) {
        if (s[pos] == '-' && s.substr(pos - 4, 4) == "pypi") {
            std::size_t start = pos - 4;
            std::size_t curr = pos + 1;
            while (curr < s.size() && is_base62_ext(s[curr])) curr++;
            std::size_t body_len = curr - (pos + 1);
            if (body_len >= 30) {
                match_start = start;
                return curr - start;
            }
        }
    }
    return 0;
}

// HashiCorp Vault Token (hvs., hvb., s.)
std::size_t parse_vault_token(std::string_view s, std::size_t pos, std::size_t& match_start) noexcept {
    // pos is '.'
    if (pos >= 3 && pos + 24 <= s.size()) {
        if (s[pos] == '.' && (s.substr(pos - 3, 3) == "hvs" || s.substr(pos - 3, 3) == "hvb")) {
            std::size_t start = pos - 3;
            std::size_t curr = pos + 1;
            while (curr < s.size() && is_base62_ext(s[curr])) curr++;
            std::size_t body_len = curr - (pos + 1);
            if (body_len >= 24) {
                match_start = start;
                return curr - start;
            }
        }
    }
    if (pos >= 1 && pos + 24 <= s.size()) {
        if (s[pos] == '.' && s[pos-1] == 's') {
            std::size_t start = pos - 1;
            std::size_t curr = pos + 1;
            while (curr < s.size() && is_base62(s[curr])) curr++;
            std::size_t body_len = curr - (pos + 1);
            if (body_len == 24) {
                match_start = start;
                return curr - start;
            }
        }
    }
    return 0;
}

// HuggingFace Token (hf_...)
std::size_t parse_huggingface_token(std::string_view s, std::size_t pos, std::size_t& match_start) noexcept {
    if (pos >= 2 && pos + 30 <= s.size()) {
        if (s[pos] == '_' && s[pos-2] == 'h' && s[pos-1] == 'f') {
            std::size_t start = pos - 2;
            std::size_t curr = pos + 1;
            while (curr < s.size() && is_base62(s[curr])) curr++;
            std::size_t body_len = curr - (pos + 1);
            if (body_len >= 30 && body_len <= 45) {
                match_start = start;
                return curr - start;
            }
        }
    }
    return 0;
}

} // namespace secrets
} // namespace fastscrub
