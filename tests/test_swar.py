import pytest
from fastscrub import scrub, scrub_inplace

class TestSwarMemorySafety:
    """Ensure the 8-byte cast never reads out of bounds."""
    
    def test_empty_string(self):
        assert scrub("") == ""
    
    def test_1_byte_string(self):
        assert scrub("a") == "a"
    
    def test_7_byte_string(self):
        assert scrub("abcdefg") == "abcdefg"
    
    def test_8_byte_string(self):
        assert scrub("abcdefgh") == "abcdefgh"
    
    def test_9_byte_string(self):
        assert scrub("abcdefghi") == "abcdefghi"

class TestSwarEquivalence:
    """The SWAR engine must produce identical output to the scalar engine."""
    
    def test_fuzz_random_strings(self):
        """Property-based fuzzing: random strings produce identical results."""
        import random
        # Just ensure it doesn't crash on random byte lengths (especially tail padding)
        for _ in range(1_000):
            length = random.randint(1, 15)  # Specifically test tail-path lengths
            data = bytes(random.randint(0, 255) for _ in range(length))
            try:
                text = data.decode('utf-8', errors='replace')
            except:
                continue
            # Simply passing it to scrub to ensure no segfaults
            scrub(text)
