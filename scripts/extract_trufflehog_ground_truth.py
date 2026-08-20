import os
import re
import json
from pathlib import Path

SECRETS_DIR = Path(r"d:\fastscrub\tests\data\secrets")

def extract_variables(content: str):
    vars_dict = {}
    
    # Multi-line var ( ... )
    var_block_match = re.search(r'var\s*\((.*?)\)', content, re.DOTALL)
    if var_block_match:
        block = var_block_match.group(1)
        var_defs = re.findall(r'([a-zA-Z0-9_]+)\s*=\s*(`[^`]*`|"(?:\\.|[^"\\])*")', block)
        for name, val in var_defs:
            if val.startswith('`') and val.endswith('`'):
                vars_dict[name] = val[1:-1]
            elif val.startswith('"') and val.endswith('"'):
                try:
                    vars_dict[name] = bytes(val[1:-1], "utf-8").decode("unicode_escape", errors="replace")
                except:
                    vars_dict[name] = val[1:-1]

    # Single-line var name = ...
    single_vars = re.findall(r'var\s+([a-zA-Z0-9_]+)\s*=\s*(`[^`]*`|"(?:\\.|[^"\\])*")', content)
    for name, val in single_vars:
        if name not in vars_dict:
            if val.startswith('`') and val.endswith('`'):
                vars_dict[name] = val[1:-1]
            elif val.startswith('"') and val.endswith('"'):
                try:
                    vars_dict[name] = bytes(val[1:-1], "utf-8").decode("unicode_escape", errors="replace")
                except:
                    vars_dict[name] = val[1:-1]

    return vars_dict

def resolve_str(raw_val: str, vars_dict: dict):
    raw_val = raw_val.strip()
    if raw_val in vars_dict:
        return vars_dict[raw_val]
    
    if '+' in raw_val:
        parts = raw_val.split('+')
        res = ""
        for p in parts:
            p = p.strip()
            if p.startswith('`') and p.endswith('`'):
                res += p[1:-1]
            elif p.startswith('"') and p.endswith('"'):
                res += p[1:-1]
            elif p in vars_dict:
                res += vars_dict[p]
        if res:
            return res

    if raw_val.startswith('`') and raw_val.endswith('`'):
        return raw_val[1:-1]
    if raw_val.startswith('"') and raw_val.endswith('"'):
        try:
            return bytes(raw_val[1:-1], "utf-8").decode("unicode_escape", errors="replace")
        except:
            return raw_val[1:-1]
            
    fmt_match = re.match(r'fmt\.Sprintf\(\s*(".*?"|`.*?`)\s*,\s*(.*)\)', raw_val, re.DOTALL)
    if fmt_match:
        fmt_str = fmt_match.group(1)[1:-1]
        args_raw = fmt_match.group(2).split(',')
        args = []
        for a in args_raw:
            a = a.strip()
            if a in vars_dict:
                args.append(vars_dict[a])
            elif (a.startswith('"') and a.endswith('"')) or (a.startswith('`') and a.endswith('`')):
                args.append(a[1:-1])
            else:
                args.append(a)
        try:
            parts = fmt_str.split('%s')
            res = parts[0]
            for i, arg in enumerate(args):
                if i < len(parts) - 1:
                    res += str(arg) + parts[i+1]
            return res
        except:
            pass

    return raw_val

def extract_struct_entries(content: str):
    entries = []
    # Find all struct slice definitions: tests := []struct { ... } { ... }
    for match in re.finditer(r'tests\s*:?=\s*\[\s*\]struct\s*\{', content):
        start_struct_def = match.end() - 1
        # 1. Match closing brace of struct type definition
        depth = 0
        pos = start_struct_def
        struct_def_end = -1
        while pos < len(content):
            if content[pos] == '{':
                depth += 1
            elif content[pos] == '}':
                depth -= 1
                if depth == 0:
                    struct_def_end = pos
                    break
            pos += 1
            
        if struct_def_end == -1:
            continue
            
        # 2. Find opening brace of slice literal
        slice_literal_start = content.find('{', struct_def_end)
        if slice_literal_start == -1:
            continue
            
        # 3. Parse entries inside slice literal
        pos = slice_literal_start + 1
        depth = 1
        in_backtick = False
        in_dquote = False
        entry_start = -1
        
        while pos < len(content) and depth > 0:
            c = content[pos]
            if c == '`':
                in_backtick = not in_backtick
            elif c == '"' and not in_backtick and (pos == 0 or content[pos-1] != '\\'):
                in_dquote = not in_dquote
            elif not in_backtick and not in_dquote:
                if c == '{':
                    if depth == 1:
                        entry_start = pos
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 1 and entry_start != -1:
                        entries.append(content[entry_start+1:pos])
                        entry_start = -1
            pos += 1
            
    return entries

def parse_go_test_file(file_path: Path):
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    detector_name = file_path.stem.replace("_test", "").replace("_v2", "").replace("_v3", "")
    vars_dict = extract_variables(content)
    cases = []

    # 1. Parse struct slice entries
    entries = extract_struct_entries(content)
    for entry in entries:
        name_m = re.search(r'name:\s*"([^"]*)"', entry)
        name = name_m.group(1) if name_m else ""
        
        inp_m = re.search(r'(?:input|data):\s*(`[^`]*`|"(?:\\.|[^"\\])*"|fmt\.Sprintf\(.*?\)|[a-zA-Z0-9_]+(?:\s*\+\s*[a-zA-Z0-9_`"]+)*)', entry, re.DOTALL)
        if not inp_m:
            continue
        input_val = resolve_str(inp_m.group(1), vars_dict).strip()
        
        is_secret = True
        want_m = re.search(r'(?:want|shouldMatch|expectedPairs):\s*([^,\n]+)', entry)
        if want_m:
            w = want_m.group(1).strip()
            if w == "false" or "nil" in w or "[]string{}" in w or w == "nil":
                is_secret = False
            elif w == "true":
                is_secret = True
        
        if "invalid" in name.lower() or "not match" in name.lower() or "too short" in name.lower() or "placeholders" in name.lower():
            is_secret = False

        if input_val:
            cases.append({
                "detector": detector_name,
                "name": name,
                "input": input_val,
                "is_secret": is_secret
            })

    # 2. Standalone test functions
    func_pattern = re.compile(r'func\s+(Test[a-zA-Z0-9_]+)\(t\s*\*testing\.T\)\s*\{(.*?)\n\}', re.DOTALL)
    for fm in func_pattern.finditer(content):
        func_name = fm.group(1)
        func_body = fm.group(2)
        
        inp_m = re.search(r'input\s*:=\s*(`[^`]*`|"(?:\\.|[^"\\])*"|fmt\.Sprintf\(.*?\))', func_body, re.DOTALL)
        if inp_m:
            inp = resolve_str(inp_m.group(1), vars_dict).strip()
            is_sec = True
            if "invalid" in func_name.lower() or "nosecrets" in func_name.lower() or "notmatch" in func_name.lower():
                is_sec = False
            if inp:
                cases.append({
                    "detector": detector_name,
                    "name": func_name,
                    "input": inp,
                    "is_secret": is_sec
                })

    # 3. Standalone variables
    for var_name, var_val in vars_dict.items():
        var_lower = var_name.lower()
        if "valid" in var_lower and ("pattern" in var_lower or "token" in var_lower or "key" in var_lower):
            cases.append({"detector": detector_name, "name": f"var:{var_name}", "input": var_val, "is_secret": True})
        elif "invalid" in var_lower and ("pattern" in var_lower or "token" in var_lower or "key" in var_lower):
            cases.append({"detector": detector_name, "name": f"var:{var_name}", "input": var_val, "is_secret": False})

    return cases

def main():
    all_cases = []
    go_files = list(SECRETS_DIR.glob("*.go"))
    print(f"[*] Parsing {len(go_files)} TruffleHog Go detector files...")

    for go_file in go_files:
        cases = parse_go_test_file(go_file)
        print(f"  [+] {go_file.name:<32}: {len(cases):2d} test cases extracted")
        all_cases.extend(cases)

    # Deduplicate by (detector, input)
    seen = set()
    unique_cases = []
    for c in all_cases:
        key = (c["detector"], c["input"])
        if key not in seen:
            seen.add(key)
            unique_cases.append(c)

    valid_count = sum(1 for c in unique_cases if c["is_secret"])
    invalid_count = sum(1 for c in unique_cases if not c["is_secret"])

    output_path = SECRETS_DIR / "trufflehog_ground_truth.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({
            "metadata": {
                "source": "TruffleHog Official Go Detector Test Suites",
                "total_cases": len(unique_cases),
                "total_valid_secrets": valid_count,
                "total_invalid_traps": invalid_count,
                "detectors_count": len(set(c["detector"] for c in unique_cases))
            },
            "test_cases": unique_cases
        }, f, indent=2)

    print("\n" + "=" * 70)
    print(f"[+] COMPLETE: Extracted {len(unique_cases)} Unique Test Cases")
    print(f"    - True Valid Secrets : {valid_count}")
    print(f"    - Negative Traps     : {invalid_count}")
    print(f"[+] Saved to: {output_path}")
    print("=" * 70)

if __name__ == "__main__":
    main()
