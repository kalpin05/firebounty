"""
FireBounty v2 - Static JS Regex Analyzer
Analyzes script files using defined signature patterns.
"""

import os
from core.js.regex_patterns import PATTERNS

def analyze_js_file(filepath: str) -> dict:
    """
    Scan the content of a local file against all compiled regex patterns.
    """
    findings = {}
    if not os.path.exists(filepath):
        return findings
        
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            
        for category, regex in PATTERNS.items():
            matches = regex.findall(content)
            if matches:
                # Handle regex tuples/tuples list returned by findall matches (like in aws_secret)
                cleaned_matches = []
                for m in matches:
                    if isinstance(m, tuple):
                        # Join tuples elements or get the longest non-empty part
                        flat = " ".join([x.strip() for x in m if x.strip()])
                        if flat:
                            cleaned_matches.append(flat)
                    else:
                        cleaned_matches.append(m.strip())
                        
                cleaned_matches = sorted(list(set(filter(None, cleaned_matches))))
                if cleaned_matches:
                    findings[category] = cleaned_matches
    except Exception:
        pass
        
    return findings
