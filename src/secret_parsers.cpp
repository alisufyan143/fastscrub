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
    std::size_t start = (pos > 40) ? pos - 40 : 0;
    std::string_view window = input.substr(start, pos - start);
    
    char lower_window[64];
    std::size_t win_len = window.size();
    if (win_len > 64) win_len = 64; 
    
    for (std::size_t i = 0; i < win_len; ++i) {
        lower_window[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(window[i])));
    }
    std::string_view l_win(lower_window, win_len);
    
    for (std::size_t i = 0; i < num_keywords; ++i) {
        if (l_win.find(keywords[i]) != std::string_view::npos) {
            return true;
        }
    }
    return false;
}

std::size_t parse_aws_key(std::string_view s, std::size_t pos) noexcept {
    if (pos + 20 > s.size()) return 0;
    if (s[pos] != 'A' || s[pos+1] != 'K' || s[pos+2] != 'I' || s[pos+3] != 'A') return 0;
    for (std::size_t i = pos + 4; i < pos + 20; ++i) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z'))) return 0;
    }
    return 20;
}

std::size_t parse_github_token(std::string_view s, std::size_t pos) noexcept {
    if (pos + 40 <= s.size()) {
        if ((s[pos] == 'g' && s[pos+1] == 'h' && s[pos+2] == 'p' && s[pos+3] == '_') ||
            (s[pos] == 'g' && s[pos+1] == 'h' && s[pos+2] == 'o' && s[pos+3] == '_')) {
            std::size_t curr = pos + 4;
            while (curr < s.size() && is_base62(s[curr])) curr++;
            std::size_t body_len = curr - (pos + 4);
            if (body_len >= 36 && body_len <= 82) return curr - pos;
        }
    }
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
    if (pos + 39 > s.size()) return 0;
    if (s[pos] != 'A' || s[pos+1] != 'I' || s[pos+2] != 'z' || s[pos+3] != 'a') return 0;
    for (std::size_t i = pos + 4; i < pos + 39; ++i) {
        if (!is_base62_ext(s[i])) return 0;
    }
    return 39;
}

std::size_t parse_slack_token(std::string_view s, std::size_t pos) noexcept {
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
    if (pos + 32 > s.size()) return 0;
    char c0 = s[pos], c1 = s[pos+1];
    if (!((c0 == 's' || c0 == 'r' || c0 == 'p') && c1 == 'k')) return 0;
    if (s[pos+2] != '_') return 0;
    
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

JwtMatch parse_jwt(std::string_view s, std::size_t pos) noexcept {
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
                if (curr + 3 >= s.size() || s[curr+1] != 'e' || s[curr+2] != 'y' || s[curr+3] != 'J') {
                    return {0, 0};
                }
            }
            if (dots >= 2) {
                curr++;
                seg_start = curr;
                while (curr < s.size() && is_base64url(s[curr]) && s[curr] != '.') curr++;
                std::size_t seg3_len = curr - seg_start;
                if (seg3_len < 4) return {0, 0};
                std::size_t total = curr - pos;
                if (total >= 20) {
                    return {total, dot1_pos - pos};
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
    if (pos + 3 > s.size()) return 0;
    if (s[pos] != ':' || s[pos+1] != '/' || s[pos+2] != '/') return 0;
    
    std::size_t scheme_start = pos;
    while (scheme_start > 0 && std::isalpha(static_cast<unsigned char>(s[scheme_start - 1]))) {
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
        "amqp", "mssql", "oracle", "sqlserver"
    };
    bool valid_scheme = false;
    for (const auto& ds : db_schemes) {
        if (scheme == ds) { valid_scheme = true; break; }
    }
    if (!valid_scheme && scheme_sv.size() >= 7) {
        if (scheme_start + 11 <= pos && s.substr(scheme_start, 11) == "mongodb+srv") {
            valid_scheme = true;
        }
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
        "token", "bearer", "credential"
    };
    if (!has_context_word(s, pos, kv_keywords, 13)) return 0;
    
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

} // namespace secrets
} // namespace fastscrub
