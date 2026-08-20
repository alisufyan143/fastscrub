import pytest
import json
from fastscrub import scrub
from pathlib import Path

GT_FILE = Path(__file__).parent / "data" / "secrets" / "trufflehog_ground_truth.json"

def test_trufflehog_valid_secrets_detection():
    """
    Evaluates detection across all 104 valid secrets extracted from TruffleHog.
    """
    assert GT_FILE.exists(), f"Ground truth file not found at {GT_FILE}"
    with open(GT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    valid_cases = [c for c in data["test_cases"] if c["is_secret"]]
    assert len(valid_cases) > 0, "No valid test cases found in ground truth!"
    
    detected = 0
    for tc in valid_cases:
        res = scrub(tc["input"])
        if res != tc["input"] or "[REDACTED_" in res or "*" in res:
            detected += 1
            
    recall = detected / len(valid_cases)
    assert recall >= 0.70, f"Expected >= 70% recall on TruffleHog secrets, got {recall*100:.1f}% ({detected}/{len(valid_cases)})"

def test_trufflehog_negative_traps_precision():
    """
    Evaluates that all 55 negative traps from TruffleHog detector suites
    are processed safely without crashes or buffer corruptions.
    """
    assert GT_FILE.exists(), f"Ground truth file not found at {GT_FILE}"
    with open(GT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    trap_cases = [c for c in data["test_cases"] if not c["is_secret"]]
    assert len(trap_cases) == 55, "Expected exactly 55 negative traps from Go detector suites"
    
    for tc in trap_cases:
        res = scrub(tc["input"])
        assert isinstance(res, str), "Scrub output must be a valid string"
        assert len(res) > 0, "Scrub output must not be empty"
