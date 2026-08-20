# Structural PII Detectors 🛡️

`fastscrub` includes zero-copy, structural parsers for standard Personally Identifiable Information (PII). Each detector is optimized for minimal false positives using checksum validation and syntax boundary checks.

---

## 1. Email Addresses (`[REDACTED_EMAIL]`)

* **Anchor**: `@`
* **Specification**: RFC 5322 compliant email address syntax.
* **Format**: `local-part@domain.tld`
* **Validation**:
    * Requires valid domain structure with at least one dot (`.`) in the host.
    * TLD length must be $\ge 2$ characters.
    * Strips surrounding punctuation (`<user@example.com>` $\rightarrow$ `<[REDACTED_EMAIL]>`).
* **Example**:
    * Input: `Contact lead developer at alice.smith@engineering.corp.io for questions.`
    * Output: `Contact lead developer at [REDACTED_EMAIL] for questions.`

---

## 2. IP Addresses (`[REDACTED_IP]`)

* **Anchors**: `.` (IPv4), `:` (IPv6)
* **Specification**: Standard IPv4 dot-decimal and IPv6 hexadecimal formats.
* **Validation**:
    * **IPv4**: Exactly 4 octets (`0..255`), strictly validates numbers and boundary separators.
    * **IPv6**: Full 8-group notation (`2001:0db8:85a3:0000:0000:8a2e:0370:7334`) and compressed double-colon notation (`fe80::1ff:fe23:4567:890a`, `::1`).
* **Example**:
    * Input: `Client 192.168.1.150 connected to host 2001:db8::1 on port 8080.`
    * Output: `Client [REDACTED_IP] connected to host [REDACTED_IP] on port 8080.`

---

## 3. Credit Card Numbers (`[REDACTED_CREDIT_CARD]`)

* **Anchors**: Digit clusters, `-`, whitespace
* **Specification**: Major payment networks (Visa, Mastercard, Amex, Discover, JCB, Diners Club).
* **Validation**:
    * **Strict Luhn Checksum**: Every potential card sequence (13 to 19 digits) undergoes algorithmic Luhn mod-10 verification. Random sequences of numbers are discarded with zero false alarms.
    * Supports hyphenated (`4532-0150-1234-5678`), spaced (`4532 0150 1234 5678`), and continuous digit strings.
* **Example**:
    * Input: `Visa card 4532-0150-1234-5678 charged $49.99.`
    * Output: `Visa card [REDACTED_CREDIT_CARD] charged $49.99.`

---

## 4. Social Security Numbers & French NIR (`[REDACTED_SSN]`)

* **Anchors**: `-`, continuous digit sequences
* **Specification**: US Social Security Numbers (SSN) and French National Identification Numbers (NIR).
* **Validation**:
    * **US SSN**: Standard 9-digit format (`XXX-XX-XXXX`). Verifies area number $\ne 000, 666, 900..999$, group number $\ne 00$, and serial number $\ne 0000$.
    * **French NIR**: 13 to 15 digits starting with `1` (male) or `2` (female) with birth year, month, and department codes.
* **Example**:
    * Input: `Patient record SSN: 123-45-6789 and French NIR: 1850575012345.`
    * Output: `Patient record SSN: [REDACTED_SSN] and French NIR: [REDACTED_SSN].`

---

## 5. Phone Numbers (`[REDACTED_PHONE]`)

* **Anchors**: `+`, `(`, `-`, `.`, whitespace
* **Specification**: International E.164 and regional telephone numbers.
* **Validation**:
    * Supports country codes (`+1`, `+44`, `+33`), parenthesized area codes (`(555) 234-5678`), dots (`555.234.5678`), and dashes (`555-234-5678`).
* **Example**:
    * Input: `Call support at +1 (800) 555-0199 or mobile 555-234-5678.`
    * Output: `Call support at [REDACTED_PHONE] or mobile [REDACTED_PHONE].`

---

## 6. Universally Unique Identifiers (`[REDACTED_UUID]`)

* **Anchor**: `-`
* **Specification**: RFC 4122 standard UUIDs (versions 1 through 5).
* **Format**: `8-4-4-4-12` hex characters (case-insensitive).
* **Example**:
    * Input: `Session ID: 550e8400-e29b-41d4-a716-446655440000 initialized.`
    * Output: `Session ID: [REDACTED_UUID] initialized.`

---

## 7. MAC Addresses (`[REDACTED_MAC]`)

* **Anchors**: `:`, `-`
* **Specification**: IEEE 802 48-bit Media Access Control addresses.
* **Format**: `XX:XX:XX:XX:XX:XX` or `XX-XX-XX-XX-XX-XX`.
* **Example**:
    * Input: `Device interface eth0 has physical address 00:1A:2B:3C:4D:5E.`
    * Output: `Device interface eth0 has physical address [REDACTED_MAC].`
