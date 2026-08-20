import urllib.request
import re
from pathlib import Path

BASE_DIR = Path(r"d:\fastscrub\tests\data\secrets")
BASE_DIR.mkdir(parents=True, exist_ok=True)

URLS = {
    "aws": "https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/pkg/detectors/aws/access_keys/accesskey_test.go",
    "gcp": "https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/pkg/detectors/gcp/gcp_test.go",
    "github": "https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/pkg/detectors/github/v2/github_test.go",
    "slack": "https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/pkg/detectors/slack/slack_test.go",
    "stripe": "https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/pkg/detectors/stripe/stripe_test.go",
}

def extract_secrets(url):
    print(f"Fetching {url}")
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as response:
        content = response.read().decode('utf-8')
        
    valid = []
    invalid = []
    
    parts = content.split('name:')[1:]
    for p in parts:
        idx_input = p.find('input:')
        if idx_input == -1: continue
        
        idx_want = p.find('want:', idx_input)
        if idx_want == -1: continue
        
        input_str = p[idx_input+6:idx_want].strip()
        if input_str.startswith('`') and input_str.endswith('`'):
            input_str = input_str[1:-1]
        elif input_str.startswith('"') and input_str.endswith('"'):
            input_str = input_str[1:-1]
            
        idx_end = p.find('\n', idx_want)
        if idx_end == -1: idx_end = len(p)
        want_val = p[idx_want+5:idx_end].strip()
        
        if "nil" in want_val or "false" in want_val or "[]string{}" in want_val or len(want_val) == 0:
            invalid.append(input_str.strip())
        else:
            valid.append(input_str.strip())
            
    return valid, invalid

def main():
    all_valid = []
    all_invalid = []
    for name, url in URLS.items():
        v, iv = extract_secrets(url)
        print(f"[{name}] Valid: {len(v)}, Invalid: {len(iv)}")
        all_valid.extend(v)
        all_invalid.extend(iv)
        
    valid_file = BASE_DIR / "secrets_valid.txt"
    valid_file.write_text("\n".join(all_valid), encoding='utf-8')
    invalid_file = BASE_DIR / "secrets_invalid_traps.txt"
    invalid_file.write_text("\n".join(all_invalid), encoding='utf-8')
    print("Done!")

if __name__ == "__main__":
    main()
