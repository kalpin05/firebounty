"""
FireBounty v2 - Parameter Classifier
Categorizes parameter names into taxonomy types (GET, POST/JSON, GraphQL, Multipart).
"""

POST_JSON_KEYWORDS = [
    "password", "passwd", "username", "email", "session", "token", 
    "auth", "key", "secret", "payload", "json", "data", "body",
    "csrf", "xsrf", "access", "role", "admin", "config", "setting"
]

GRAPHQL_KEYWORDS = [
    "query", "mutation", "variables", "operationname", "graphql"
]

MULTIPART_KEYWORDS = [
    "file", "image", "upload", "avatar", "attachment", "doc", "pdf",
    "media", "photo", "filename"
]

def classify_param(name: str) -> str:
    """
    Classify a parameter name based on matching common security keywords.
    """
    name_lower = name.lower()
    
    for kw in GRAPHQL_KEYWORDS:
        if kw in name_lower:
            return "GraphQL"
            
    for kw in MULTIPART_KEYWORDS:
        if kw in name_lower:
            return "Multipart"
            
    for kw in POST_JSON_KEYWORDS:
        if kw in name_lower:
            return "POST/JSON"
            
    return "GET"
