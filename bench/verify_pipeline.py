import os
import sys
import json
import re
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import fastscrub

def check_span_redacted(source_text: str, start: int, end: int) -> bool:
    """Check if the exact span was redacted using in-place bytearray mutation."""
    raw_bytes = source_text.encode("utf-8", errors="replace")
    buf = bytearray(raw_bytes)
    fastscrub.scrub_inplace(buf)
    
    # Check if any byte in the target slice was replaced with '*'
    # Map char offsets to byte offsets safely
    prefix_bytes = len(source_text[:start].encode("utf-8", errors="replace"))
    span_bytes = len(source_text[start:end].encode("utf-8", errors="replace"))
    byte_slice = buf[prefix_bytes : prefix_bytes + span_bytes]
    return (ord('*') in byte_slice)

DATA_DIR = Path(r"d:\fastscrub\tests\data")

IN_SCOPE_MAP = {
    # Email
    "EMAIL": "EMAIL",
    "EMAIL_ADDRESS": "EMAIL",
    "B-EMAIL": "EMAIL",
    "I-EMAIL": "EMAIL",
    
    # Phone
    "PHONE": "PHONE",
    "PHONENUMBER": "PHONE",
    "PHONE_NUMBER": "PHONE",
    "PHONEIMEI": "PHONE",
    "TELEPHONE": "PHONE",
    "B-PHONE_NUM": "PHONE",
    "I-PHONE_NUM": "PHONE",
    
    # IP Address
    "IP": "IP_ADDRESS",
    "IP_ADDRESS": "IP_ADDRESS",
    "IPV4": "IP_ADDRESS",
    "IPV6": "IP_ADDRESS",
    "B-IP_ADDRESS": "IP_ADDRESS",
    "I-IP_ADDRESS": "IP_ADDRESS",
    
    # SSN / Social Number
    "SOCIALNUMBER": "SSN",
    "SSN": "SSN",
    "US_SSN": "SSN",
    "B-SSN": "SSN",
    
    # Credit Card
    "CREDITCARD": "CREDIT_CARD",
    "CREDIT_CARD": "CREDIT_CARD",
    "MASKEDNUMBER": "CREDIT_CARD",
    "IBAN_CODE": "CREDIT_CARD",
    "B-CREDIT_CARD": "CREDIT_CARD",
    
    # Secrets
    "PASSWORD": "INFRA_SECRET",
    "API_KEY": "INFRA_SECRET",
    "SECRET_KEY": "INFRA_SECRET",
}

def test_jsonl_dataset(filename: str, sample_size: int = 5):
    filepath = DATA_DIR / filename
    print("\n" + "=" * 90)
    print(f"[+] AUDIT 1: Testing Dataset -> {filename}")
    print("=" * 90)
    
    if not filepath.exists():
        print(f"[-] File not found: {filepath}")
        return

    verified_slices = 0
    total_spans = 0
    in_scope_spans = 0
    detected_spans = 0

    with open(filepath, "r", encoding="utf-8") as f:
        for line_idx, line in enumerate(f):
            if line_idx >= sample_size:
                break
            data = json.loads(line)
            source_text = data["source_text"]
            privacy_mask = data.get("privacy_mask", [])

            print(f"\n--- [Doc #{line_idx + 1}] Length: {len(source_text)} chars ---")
            print(f"Text Snippet: {source_text[:120]}...")

            for span in privacy_mask:
                total_spans += 1
                val = span.get("value", "")
                s = span["start"]
                e = span["end"]
                raw_label = span.get("label", "UNKNOWN")
                
                # 1. Verify exact slicing
                sliced = source_text[s:e]
                slice_ok = (sliced == val)
                if slice_ok:
                    verified_slices += 1

                # 2. Check in-scope vs out-of-scope
                norm_label = IN_SCOPE_MAP.get(raw_label, None)
                is_in_scope = (norm_label is not None)
                if is_in_scope:
                    in_scope_spans += 1

                # 3. Check if FastScrub redacted this span in-place
                was_redacted = check_span_redacted(source_text, s, e)
                if is_in_scope and was_redacted:
                    detected_spans += 1

                status_tag = "✅ TP" if (is_in_scope and was_redacted) else ("❌ FN" if is_in_scope else "ℹ️ OUT-OF-SCOPE")
                print(f"  Span [{s:3d}..{e:3d}] | Label: {raw_label:<14} -> {str(norm_label):<12} | Slice Valid: {slice_ok!s:<5} | Redacted: {was_redacted!s:<5} | {status_tag}")
                print(f"    Target Value : {val!r}")

    print(f"\n[+] Summary for {filename}:")
    print(f"    - Slice Offsets Verified: {verified_slices}/{total_spans} ({verified_slices/max(1, total_spans)*100:.1f}%)")
    print(f"    - In-Scope PII Tested   : {in_scope_spans}")
    print(f"    - Correctly Detected    : {detected_spans}/{in_scope_spans}")

def test_presidio_dataset(filename: str = "synth_dataset_v2.json", sample_size: int = 5):
    filepath = DATA_DIR / filename
    print("\n" + "=" * 90)
    print(f"[+] AUDIT 2: Testing Microsoft Presidio Dataset -> {filename}")
    print("=" * 90)

    if not filepath.exists():
        print(f"[-] File not found: {filepath}")
        return

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    samples = data[:sample_size]
    for idx, doc in enumerate(samples):
        text = doc.get("full_text", "")
        spans = doc.get("spans", [])
        print(f"\n--- [Presidio Doc #{idx + 1}] Length: {len(text)} chars ---")
        print(f"Text Snippet: {text[:120]}...")

        for span in spans:
            val = span.get("entity_value", "")
            s = span["start_position"]
            e = span["end_position"]
            raw_label = span.get("entity_type", "")
            norm_label = IN_SCOPE_MAP.get(raw_label, None)
            is_in_scope = (norm_label is not None)

            sliced = text[s:e]
            slice_ok = (sliced == val)
            was_redacted = check_span_redacted(text, s, e)
            status_tag = "✅ TP" if (is_in_scope and was_redacted) else ("❌ FN" if is_in_scope else "ℹ️ OUT-OF-SCOPE")

            print(f"  Span [{s:3d}..{e:3d}] | Label: {raw_label:<16} -> {str(norm_label):<12} | Slice Valid: {slice_ok!s:<5} | Redacted: {was_redacted!s:<5} | {status_tag}")
            print(f"    Target Value : {val!r}")

def test_trufflehog_ground_truth(filename: str = "secrets/trufflehog_ground_truth.json"):
    filepath = DATA_DIR / filename
    print("\n" + "=" * 90)
    print(f"[+] AUDIT 3: Testing TruffleHog Secrets & Traps Ground Truth -> {filename}")
    print("=" * 90)

    if not filepath.exists():
        print(f"[-] File not found: {filepath}")
        return

    with open(filepath, "r", encoding="utf-8") as f:
        gt = json.load(f)

    test_cases = gt.get("test_cases", [])
    valid_cases = [c for c in test_cases if c["is_secret"]][:5]
    trap_cases = [c for c in test_cases if not c["is_secret"]][:5]

    print("\n--- 1. Testing Valid True Secrets (Must be Redacted) ---")
    for idx, tc in enumerate(valid_cases):
        inp = tc["input"]
        scrubbed = fastscrub.scrub(inp)
        redacted = (scrubbed != inp) or ("[REDACTED_" in scrubbed) or ("*" in scrubbed)
        status = "✅ TP (Caught Secret)" if redacted else "❌ FN (Missed Secret)"
        print(f"  [Secret #{idx + 1}] Detector: {tc['detector']:<12} | Name: {tc['name'][:30]:<30} | Redacted: {redacted!s:<5} | {status}")
        print(f"    Input Snippet: {inp[:80].strip()!r}")

    print("\n--- 2. Testing Negative Traps (Must NOT be Redacted) ---")
    for idx, tc in enumerate(trap_cases):
        inp = tc["input"]
        scrubbed = fastscrub.scrub(inp)
        redacted = (scrubbed != inp) or ("[REDACTED_" in scrubbed) or ("*" in scrubbed)
        status = "✅ TN (Ignored Trap)" if not redacted else "❌ FP (False Positive Triggered)"
        print(f"  [Trap #{idx + 1}]   Detector: {tc['detector']:<12} | Name: {tc['name'][:30]:<30} | Redacted: {redacted!s:<5} | {status}")
        print(f"    Input Snippet: {inp[:80].strip()!r}")

def main():
    print("==========================================================================================")
    print("                 FASTSCRUB GROUND-TRUTH INTEGRITY & MAPPING AUDIT")
    print("==========================================================================================")
    
    test_jsonl_dataset("english_pii_43k.jsonl", sample_size=3)
    test_jsonl_dataset("french_pii_62k.jsonl", sample_size=3)
    test_presidio_dataset("synth_dataset_v2.json", sample_size=3)
    test_trufflehog_ground_truth("secrets/trufflehog_ground_truth.json")
    
    print("\n" + "=" * 90)
    print("[+] ALL AUDITS COMPLETED SUCCESSFULLY")
    print("==========================================================================================")

if __name__ == "__main__":
    main()
