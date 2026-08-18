"""
test_core.py

Comprehensive TDD test suite for the fastscrub PII-scrubbing engine.

Tests are written BEFORE any implementation code exists, following strict
Test-Driven Development methodology. They define the correctness contract
the C++ engine (and its Python bindings) must satisfy.

Run with:
    pytest tests/test_core.py -v
"""

import re
import time
from pathlib import Path

import pytest

from fastscrub import scrub

# ---------------------------------------------------------------------------
# Paths (OS-agnostic via pathlib)
# ---------------------------------------------------------------------------
TESTS_DIR = Path(__file__).resolve().parent
DATA_DIR = TESTS_DIR / "data"
MESSY_LOGS_PATH = DATA_DIR / "messy_production_logs.txt"


# ======================================================================
# 1. Functional redaction of every supported PII category
# ======================================================================
class TestFunctionalRedaction:
    """Verify that each supported PII type is replaced by its specific
    uppercase mask token."""

    def test_email_redaction(self):
        text = "Contact us at john.doe@example.com for details."
        result = scrub(text)
        assert "john.doe@example.com" not in result
        assert "[REDACTED_EMAIL]" in result

    def test_email_with_subdomain(self):
        text = "Send to admin@mail.corp.example.co.uk please."
        result = scrub(text)
        assert "admin@mail.corp.example.co.uk" not in result
        assert "[REDACTED_EMAIL]" in result

    def test_ipv4_redaction(self):
        text = "Server at 192.168.1.100 is unreachable."
        result = scrub(text)
        assert "192.168.1.100" not in result
        assert "[REDACTED_IP]" in result

    def test_ipv4_edge_values(self):
        text = "Range from 0.0.0.0 to 255.255.255.255 is wide."
        result = scrub(text)
        assert "0.0.0.0" not in result
        assert "255.255.255.255" not in result
        assert result.count("[REDACTED_IP]") == 2

    def test_ipv6_full_redaction(self):
        text = "IPv6 host: 2001:0db8:85a3:0000:0000:8a2e:0370:7334 online."
        result = scrub(text)
        assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" not in result
        assert "[REDACTED_IP]" in result

    def test_ipv6_compressed_redaction(self):
        text = "Loopback is ::1 and unspecified is :: in IPv6."
        result = scrub(text)
        assert "[REDACTED_IP]" in result

    def test_mac_address_colon_format(self):
        text = "NIC MAC: 00:1A:2B:3C:4D:5E registered."
        result = scrub(text)
        assert "00:1A:2B:3C:4D:5E" not in result
        assert "[REDACTED_MAC]" in result

    def test_mac_address_hyphen_format(self):
        text = "Device 00-1A-2B-3C-4D-5E connected."
        result = scrub(text)
        assert "00-1A-2B-3C-4D-5E" not in result
        assert "[REDACTED_MAC]" in result

    def test_phone_us_format(self):
        text = "Call me at +1-555-867-5309 anytime."
        result = scrub(text)
        assert "555-867-5309" not in result
        assert "[REDACTED_PHONE]" in result

    def test_phone_international_format(self):
        text = "UK office: +44 20 7946 0958 is available."
        result = scrub(text)
        assert "20 7946 0958" not in result
        assert "[REDACTED_PHONE]" in result

    def test_phone_parenthesized_area_code(self):
        text = "Reach us at (555) 867-5309 during hours."
        result = scrub(text)
        assert "(555) 867-5309" not in result
        assert "[REDACTED_PHONE]" in result

    def test_us_ssn_redaction(self):
        text = "SSN on file: 123-45-6789 for the applicant."
        result = scrub(text)
        assert "123-45-6789" not in result
        assert "[REDACTED_SSN]" in result

    def test_us_ssn_without_dashes(self):
        text = "SSN: 123456789 submitted."
        result = scrub(text)
        assert "123456789" not in result
        assert "[REDACTED_SSN]" in result

    def test_uuid_v4_redaction(self):
        text = "Trace ID: 550e8400-e29b-41d4-a716-446655440000 logged."
        result = scrub(text)
        assert "550e8400-e29b-41d4-a716-446655440000" not in result
        assert "[REDACTED_UUID]" in result

    def test_uuid_uppercase_redaction(self):
        text = "Request 550E8400-E29B-41D4-A716-446655440000 received."
        result = scrub(text)
        assert "550E8400-E29B-41D4-A716-446655440000" not in result
        assert "[REDACTED_UUID]" in result

    def test_multiple_pii_types_in_one_string(self):
        text = (
            "User john@example.com on 10.0.0.1 "
            "with SSN 999-88-7777 and phone +1-800-555-0199."
        )
        result = scrub(text)
        assert "[REDACTED_EMAIL]" in result
        assert "[REDACTED_IP]" in result
        assert "[REDACTED_SSN]" in result
        assert "[REDACTED_PHONE]" in result
        assert "john@example.com" not in result
        assert "10.0.0.1" not in result
        assert "999-88-7777" not in result
        assert "800-555-0199" not in result

    def test_clean_text_unchanged(self):
        text = "This is a perfectly normal sentence with no PII at all."
        result = scrub(text)
        assert result == text


# ======================================================================
# 2. Luhn / Modulo-10 validated credit card detection
# ======================================================================
class TestLuhnCreditCard:
    """Credit cards that pass the Luhn checksum must be redacted.
    Numbers that look like credit cards but fail Luhn must be left alone."""

    def test_valid_visa_redacted(self):
        # 4111111111111111 is the standard Visa test number (passes Luhn)
        text = "Payment card: 4111111111111111 on file."
        result = scrub(text)
        assert "4111111111111111" not in result
        assert "[REDACTED_CREDIT_CARD]" in result

    def test_valid_mastercard_redacted(self):
        # 5500000000000004 is a standard MasterCard test number (passes Luhn)
        text = "Charged to 5500000000000004 successfully."
        result = scrub(text)
        assert "5500000000000004" not in result
        assert "[REDACTED_CREDIT_CARD]" in result

    def test_valid_amex_redacted(self):
        # 378282246310005 is a standard AmEx test number (passes Luhn, 15 digits)
        text = "AmEx card 378282246310005 registered."
        result = scrub(text)
        assert "378282246310005" not in result
        assert "[REDACTED_CREDIT_CARD]" in result

    def test_invalid_luhn_untouched(self):
        # 4111111111111112 fails Luhn (last digit wrong)
        text = "Not a real card: 4111111111111112 stored."
        result = scrub(text)
        assert "4111111111111112" in result
        assert "[REDACTED_CREDIT_CARD]" not in result

    def test_valid_card_with_spaces(self):
        # 4111 1111 1111 1111 — spaced format, still valid Luhn
        text = "Card: 4111 1111 1111 1111 submitted."
        result = scrub(text)
        assert "4111 1111 1111 1111" not in result
        assert "[REDACTED_CREDIT_CARD]" in result

    def test_valid_card_with_dashes(self):
        # 4111-1111-1111-1111 — dashed format, still valid Luhn
        text = "Card: 4111-1111-1111-1111 saved."
        result = scrub(text)
        assert "4111-1111-1111-1111" not in result
        assert "[REDACTED_CREDIT_CARD]" in result


# ======================================================================
# 3. Null byte poisoning resilience
# ======================================================================
class TestNullBytePoisoning:
    """The engine must handle embedded null bytes without truncation or crash."""

    def test_null_byte_after_email(self):
        text = "valid_email@test.com\x00poison_payload"
        result = scrub(text)
        # The email before the null must still be redacted
        assert "valid_email@test.com" not in result
        assert "[REDACTED_EMAIL]" in result
        # The text after the null byte must survive (no C-string truncation)
        assert "poison_payload" in result

    def test_null_byte_before_pii(self):
        text = "prefix\x00user@domain.org suffix"
        result = scrub(text)
        assert "user@domain.org" not in result
        assert "[REDACTED_EMAIL]" in result
        assert "prefix" in result
        assert "suffix" in result

    def test_multiple_null_bytes(self):
        text = "a\x00b\x00c\x00user@evil.com\x00d"
        result = scrub(text)
        assert "user@evil.com" not in result
        assert "[REDACTED_EMAIL]" in result

    def test_null_byte_only_string(self):
        text = "\x00\x00\x00"
        # Must not crash; output can be anything but must return
        result = scrub(text)
        assert isinstance(result, str)

    def test_null_byte_inside_ssn(self):
        text = "SSN: 123-45\x00-6789 might break parsers."
        result = scrub(text)
        # Engine must not crash regardless of whether it detects the split SSN
        assert isinstance(result, str)


# ======================================================================
# 4. Catastrophic backtracking / ReDoS resistance
# ======================================================================
class TestCatastrophicBacktracking:
    """The engine must evaluate pathological inputs without freezing.
    A naive regex like (a+)+ would hang on these inputs."""

    def test_repeated_a_with_bang(self):
        # Classic ReDoS payload for (a+)+$ patterns
        malicious = "a" * 50_000 + "!"
        start = time.monotonic()
        result = scrub(malicious)
        elapsed = time.monotonic() - start
        assert isinstance(result, str)
        assert elapsed < 5.0, (
            f"Engine took {elapsed:.2f}s on ReDoS payload — likely backtracking"
        )

    def test_repeated_email_like_noise(self):
        # Thousands of @-signs that look like partial emails
        malicious = ("x@" * 20_000) + ".com"
        start = time.monotonic()
        result = scrub(malicious)
        elapsed = time.monotonic() - start
        assert isinstance(result, str)
        assert elapsed < 5.0, (
            f"Engine took {elapsed:.2f}s on partial-email flood"
        )

    def test_nested_dot_sequences(self):
        # Deeply nested dots mimicking IP-like structure
        malicious = ".".join(["999"] * 10_000)
        start = time.monotonic()
        result = scrub(malicious)
        elapsed = time.monotonic() - start
        assert isinstance(result, str)
        assert elapsed < 5.0, (
            f"Engine took {elapsed:.2f}s on nested dot payload"
        )

    def test_large_clean_text(self):
        # 1 MB of normal text — should not degrade performance
        clean = "The quick brown fox jumps over the lazy dog. " * 25_000
        start = time.monotonic()
        result = scrub(clean)
        elapsed = time.monotonic() - start
        assert result == clean
        assert elapsed < 5.0, (
            f"Engine took {elapsed:.2f}s on 1MB clean text"
        )


# ======================================================================
# 5. Token boundary isolation
# ======================================================================
class TestTokenBoundaryIsolation:
    """PII patterns embedded inside longer tokens (no whitespace boundaries)
    should NOT be redacted — only standalone PII at proper word boundaries."""

    def test_email_embedded_in_word(self):
        text = "abcjohn.doe@email.comxyz"
        result = scrub(text)
        # Embedded email should not be detected
        assert "[REDACTED_EMAIL]" not in result
        assert result == text

    def test_email_standalone_detected(self):
        text = "contact john.doe@email.com now"
        result = scrub(text)
        assert "[REDACTED_EMAIL]" in result
        assert "john.doe@email.com" not in result

    def test_ssn_embedded_in_digits(self):
        text = "REF0001234567890000"
        result = scrub(text)
        # Should NOT extract 123-45-6789 from the middle
        assert "[REDACTED_SSN]" not in result
        assert result == text

    def test_ssn_standalone_detected(self):
        text = "SSN is 123-45-6789 on record."
        result = scrub(text)
        assert "[REDACTED_SSN]" in result

    def test_ip_embedded_in_version_string(self):
        text = "version10.0.0.1release"
        result = scrub(text)
        # Should NOT extract the IP from inside a version slug
        assert "[REDACTED_IP]" not in result
        assert result == text

    def test_ip_standalone_detected(self):
        text = "host at 10.0.0.1 responded"
        result = scrub(text)
        assert "[REDACTED_IP]" in result

    def test_phone_embedded_in_long_number(self):
        text = "ORDER88005550199421"
        result = scrub(text)
        assert "[REDACTED_PHONE]" not in result
        assert result == text

    def test_uuid_embedded_in_hex_blob(self):
        text = "ff550e8400e29b41d4a716446655440000aa"
        result = scrub(text)
        assert "[REDACTED_UUID]" not in result
        assert result == text


# ======================================================================
# 6. Line ending normalization
# ======================================================================
class TestLineEndings:
    """Mixed CRLF and LF must not break pattern detection across lines."""

    def test_crlf_logs(self):
        text = (
            "User: admin@corp.com\r\n"
            "IP: 172.16.0.1\r\n"
            "SSN: 321-54-9876\r\n"
        )
        result = scrub(text)
        assert "admin@corp.com" not in result
        assert "172.16.0.1" not in result
        assert "321-54-9876" not in result
        assert "[REDACTED_EMAIL]" in result
        assert "[REDACTED_IP]" in result
        assert "[REDACTED_SSN]" in result

    def test_lf_logs(self):
        text = (
            "User: admin@corp.com\n"
            "IP: 172.16.0.1\n"
            "SSN: 321-54-9876\n"
        )
        result = scrub(text)
        assert "admin@corp.com" not in result
        assert "172.16.0.1" not in result
        assert "321-54-9876" not in result

    def test_mixed_endings(self):
        text = (
            "Email: qa@test.io\r\n"
            "Phone: +1-555-123-4567\n"
            "UUID: a1b2c3d4-e5f6-7890-abcd-ef1234567890\r\n"
            "MAC: AA:BB:CC:DD:EE:FF\n"
        )
        result = scrub(text)
        assert "qa@test.io" not in result
        assert "555-123-4567" not in result
        assert "a1b2c3d4-e5f6-7890-abcd-ef1234567890" not in result
        assert "AA:BB:CC:DD:EE:FF" not in result

    def test_line_endings_preserved(self):
        text = "clean line\r\nanother clean line\nfinal line\r\n"
        result = scrub(text)
        # Line endings must pass through unchanged
        assert result == text

    def test_pii_spanning_line_boundary_not_detected(self):
        # A PII pattern split across two lines should NOT be detected
        text = "prefix 123-45\n-6789 suffix"
        result = scrub(text)
        assert "[REDACTED_SSN]" not in result


# ======================================================================
# 7. Messy production log scrubbing (real-world benchmark data)
# ======================================================================
class TestMessyProductionLogs:
    """Run the scrubber over the entire downloaded benchmark file and verify
    that no common raw PII patterns survive in the output."""

    # Regex patterns for detecting raw (unmasked) PII in scrubbed output.
    # These are intentionally broad to catch anything the engine should mask.
    PII_PATTERNS = {
        "email": re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
        ),
        "ipv4": re.compile(
            r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
            r"(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b"
        ),
        "ssn": re.compile(
            r"\b\d{3}-\d{2}-\d{4}\b"
        ),
        "credit_card_16": re.compile(
            r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"
        ),
        "uuid": re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
            r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        "mac_colon": re.compile(
            r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b"
        ),
    }

    @pytest.fixture()
    def scrubbed_logs(self):
        """Read the benchmark file and return the fully scrubbed text."""
        assert MESSY_LOGS_PATH.exists(), (
            f"Benchmark data not found at {MESSY_LOGS_PATH}. "
            "Run 'python tests/download_benchmarks.py' first."
        )
        raw = MESSY_LOGS_PATH.read_text(encoding="utf-8")
        assert len(raw) > 0, "Benchmark file is empty."
        return scrub(raw)

    def test_no_raw_emails_remain(self, scrubbed_logs):
        matches = self.PII_PATTERNS["email"].findall(scrubbed_logs)
        # Filter out mask tokens themselves (they don't contain @)
        real_matches = [m for m in matches if "@" in m]
        assert len(real_matches) == 0, (
            f"Found {len(real_matches)} un-redacted email(s): "
            f"{real_matches[:5]}"
        )

    def test_no_raw_ipv4_remain(self, scrubbed_logs):
        matches = self.PII_PATTERNS["ipv4"].findall(scrubbed_logs)
        assert len(matches) == 0, (
            f"Found {len(matches)} un-redacted IPv4 address(es): "
            f"{matches[:5]}"
        )

    def test_no_raw_ssns_remain(self, scrubbed_logs):
        matches = self.PII_PATTERNS["ssn"].findall(scrubbed_logs)
        assert len(matches) == 0, (
            f"Found {len(matches)} un-redacted SSN(s): "
            f"{matches[:5]}"
        )

    def test_no_raw_credit_cards_remain(self, scrubbed_logs):
        def luhn_validate(s: str) -> bool:
            digits = [int(c) for c in s if c.isdigit()]
            if not (13 <= len(digits) <= 19): return False
            total = 0
            double = False
            for d in reversed(digits):
                if double:
                    d *= 2
                    if d > 9: d -= 9
                total += d
                double = not double
            return (total % 10) == 0

        matches = self.PII_PATTERNS["credit_card_16"].findall(scrubbed_logs)
        valid_matches = [m for m in matches if luhn_validate(m)]
        assert len(valid_matches) == 0, (
            f"Found {len(valid_matches)} un-redacted valid credit card(s): "
            f"{valid_matches[:5]}"
        )

    def test_no_raw_uuids_remain(self, scrubbed_logs):
        matches = self.PII_PATTERNS["uuid"].findall(scrubbed_logs)
        assert len(matches) == 0, (
            f"Found {len(matches)} un-redacted UUID(s): "
            f"{matches[:5]}"
        )

    def test_no_raw_macs_remain(self, scrubbed_logs):
        matches = self.PII_PATTERNS["mac_colon"].findall(scrubbed_logs)
        assert len(matches) == 0, (
            f"Found {len(matches)} un-redacted MAC address(es): "
            f"{matches[:5]}"
        )

    def test_output_is_not_empty(self, scrubbed_logs):
        assert len(scrubbed_logs) > 100, (
            "Scrubbed output is suspiciously short — engine may have "
            "dropped content."
        )

    def test_scrubbing_completes_in_reasonable_time(self):
        raw = MESSY_LOGS_PATH.read_text(encoding="utf-8")
        start = time.monotonic()
        scrub(raw)
        elapsed = time.monotonic() - start
        assert elapsed < 10.0, (
            f"Scrubbing {len(raw)} bytes took {elapsed:.2f}s — "
            "expected under 10s for production logs."
        )
