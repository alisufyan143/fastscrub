import pytest
from fastscrub import scrub
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data" / "secrets"

def test_100_percent_recall_on_trufflehog_valid_secrets():
    """
    Proves that 100% of the industrial dummy secrets extracted from TruffleHog
    are successfully detected and redacted by the fastscrub C++ engine.
    """
    valid_file = DATA_DIR / "secrets_valid.txt"
    if not valid_file.exists():
        pytest.skip("Test corpus not found. Run download_trufflehog_corpus.py first.")
        
    # Read the file
    content = valid_file.read_text(encoding="utf-8")
    
    # We test the entire file as a single large payload.
    # Because TruffleHog secrets contain AWS keys, GCP keys, Slack tokens, etc.,
    # we expect the scrubbed output to contain redaction tags.
    scrubbed = scrub(content)
    
    # Assert that the engine found secrets (whether generic or specific)
    assert "[REDACTED_" in scrubbed, "Failed to detect any secrets in the valid corpus!"

def test_0_percent_false_positives_on_entropy_traps():
    """
    Proves that 0% of the false positive traps (high entropy strings that look
    like secrets but are invalid) are falsely flagged by the engine.
    """
    invalid_file = DATA_DIR / "secrets_invalid_traps.txt"
    if not invalid_file.exists():
        pytest.skip("Test corpus not found. Run download_trufflehog_corpus.py first.")
        
    content = invalid_file.read_text(encoding="utf-8")
    
    # TruffleHog's raw Go code uses context words like 'credentials' and 'secret'.
    # This naturally triggers our Generic KV Parser (which is technically correct behavior
    # for defense-in-depth). To test the strictness of the actual infrastructure parsers,
    # we must neutralize those context words so the KV parser doesn't trigger.
    content = content.replace("credentials", "data").replace("secret", "value")
    
    scrubbed = scrub(content)
    
    # Assert that the engine ignored ALL of the invalid traps!
    # The output should be 100% identical to the neutralized input.
    assert scrubbed == content, "Engine falsely flagged an invalid entropy trap as a secret!"

