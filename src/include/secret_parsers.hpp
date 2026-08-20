#pragma once
#include <cstddef>
#include <string_view>

namespace fastscrub {
namespace secrets {

struct JwtMatch {
    std::size_t total_len;
    std::size_t header_len; // segment 1 length (preserved in Mode B)
};

std::size_t parse_aws_key(std::string_view s, std::size_t pos) noexcept;
std::size_t parse_github_token(std::string_view s, std::size_t pos, std::size_t& match_start) noexcept;
std::size_t parse_gcp_key(std::string_view s, std::size_t pos) noexcept;
std::size_t parse_slack_token(std::string_view s, std::size_t pos, std::size_t& match_start) noexcept;
std::size_t parse_stripe_key(std::string_view s, std::size_t pos, std::size_t& match_start) noexcept;
std::size_t parse_private_key(std::string_view s, std::size_t pos) noexcept;
JwtMatch parse_jwt(std::string_view s, std::size_t pos, std::size_t& match_start) noexcept;
std::size_t parse_connection_string(std::string_view s, std::size_t pos, std::size_t& password_start, std::size_t& password_len) noexcept;
std::size_t parse_kv_secret(std::string_view s, std::size_t pos, std::size_t& value_start, std::size_t& value_len) noexcept;

// Modern AI, DevOps & Security Token Parsers
std::size_t parse_openai_key(std::string_view s, std::size_t pos, std::size_t& match_start) noexcept;
std::size_t parse_anthropic_key(std::string_view s, std::size_t pos, std::size_t& match_start) noexcept;
std::size_t parse_gitlab_token(std::string_view s, std::size_t pos, std::size_t& match_start) noexcept;
std::size_t parse_pypi_token(std::string_view s, std::size_t pos, std::size_t& match_start) noexcept;
std::size_t parse_vault_token(std::string_view s, std::size_t pos, std::size_t& match_start) noexcept;
std::size_t parse_huggingface_token(std::string_view s, std::size_t pos, std::size_t& match_start) noexcept;

bool has_context_word(std::string_view input, std::size_t pos, const std::string_view* keywords, std::size_t num_keywords) noexcept;

} // namespace secrets
} // namespace fastscrub
