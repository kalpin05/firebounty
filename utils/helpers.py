"""
FireBounty v2 - Central Helper Utilities
"""

import urllib.parse
from typing import Tuple

def sanitize_target(target_raw: str) -> Tuple[str, str]:
    """
    Parse raw target input (URL or domain) into a clean domain and a base URL.
    
    Example:
        "https://example.com/api" -> ("example.com", "https://example.com")
        "example.com"             -> ("example.com", "https://example.com")
        "www.example.com"         -> ("www.example.com", "https://www.example.com")
    """
    target = target_raw.strip()
    if not target.startswith(("http://", "https://")):
        # Default to https for scanning
        parsed_target = "https://" + target
    else:
        parsed_target = target

    parsed = urllib.parse.urlparse(parsed_target)
    domain = parsed.netloc or parsed.path.split('/')[0]
    
    # Strip port if present
    if ":" in domain:
        domain = domain.split(":")[0]
        
    base_url = f"{parsed.scheme or 'https'}://{domain}"
    return domain, base_url
