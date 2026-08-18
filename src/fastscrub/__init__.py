"""
fastscrub: High-performance PII scrubbing engine.
"""

from .fastscrub_backend import Engine, scrub_batch

# Global Engine instance automatically scales to available CPU hardware cores.
_ENGINE = Engine(worker_count=0)

def scrub(data: str) -> str:
    """
    Scrub PII from the provided string data.
    
    Automatically routes large text payloads to the concurrent bulk processing
    engine, dropping the GIL to leverage full CPU throughput.
    """
    if not isinstance(data, str):
        raise TypeError(f"fastscrub.scrub expected a string, got {type(data).__name__}")
    
    # Threshold for invoking the multi-threaded backend overhead
    if len(data) >= 16384:
        return _ENGINE.scrub_bulk(data)
    else:
        return _ENGINE.scrub(data)

def scrub_list(text_list: list[str]) -> list[str]:
    """
    Scrub a list of strings in parallel across all CPU cores with zero GIL contention.
    """
    if not isinstance(text_list, list):
        raise TypeError("Input must be a list of strings.")
    return scrub_batch(text_list, 0)
