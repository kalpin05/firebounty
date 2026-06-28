"""
FireBounty v2 - JS Risk Scorer
Assigns severity scores to files based on regex matched categories.
"""

# Risk categories mappings
SEVERITY_SCORES = {
    # High Risk Secrets
    "aws_access_key": 10,
    "aws_secret": 10,
    "stripe_live": 10,
    "github_token": 10,
    "slack": 10,
    
    # Medium Risk tokens & configs
    "jwt": 5,
    "bearer": 5,
    "basic_auth": 5,
    "google_api": 5,
    "firebase": 5,
    
    # Low Risk paths & APIs
    "url": 2,
    "api_path": 2,
    "swagger": 2,
    "graphql": 2
}

def calculate_risk(findings: dict) -> int:
    """
    Calculate maximum severity score based on matched findings.
    """
    max_score = 0
    for category in findings.keys():
        score = SEVERITY_SCORES.get(category, 0)
        if score > max_score:
            max_score = score
    return max_score

def get_risk_label(score: int) -> str:
    if score >= 10:
        return "HIGH"
    elif score >= 5:
        return "MEDIUM"
    elif score >= 2:
        return "LOW"
    return "INFO"
