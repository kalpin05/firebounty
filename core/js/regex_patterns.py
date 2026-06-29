"""
FireBounty v2
Regex Pattern Library

Every JS analyzer imports this file.
Keep ALL regexes here.
"""

import re

PATTERNS = {

    # ============================
    # Authentication
    # ============================

    "jwt": re.compile(
        r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+"
    ),

    "bearer": re.compile(
        r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
        re.IGNORECASE
    ),

    "basic_auth": re.compile(
        r"Basic\s+[A-Za-z0-9+/=]+",
        re.IGNORECASE
    ),

    # ============================
    # AWS
    # ============================

    "aws_access_key": re.compile(
        r"AKIA[0-9A-Z]{16}"
    ),

    "aws_secret": re.compile(
        r"(?i)aws(.{0,20})?(secret|access).{0,20}[A-Za-z0-9/+=]{40}"
    ),

    # ============================
    # Google
    # ============================

    "google_api": re.compile(
        r"AIza[0-9A-Za-z\-_]{35}"
    ),

    "firebase": re.compile(
        r"firebaseio\.com|firebaseapp\.com",
        re.IGNORECASE
    ),

    # ============================
    # Stripe
    # ============================

    "stripe_live": re.compile(
        r"sk_live_[0-9a-zA-Z]{24,}"
    ),

    # ============================
    # GitHub
    # ============================

    "github_token": re.compile(
        r"gh[pousr]_[A-Za-z0-9]{36,}"
    ),

    # ============================
    # Slack
    # ============================

    "slack": re.compile(
        r"xox[baprs]-[A-Za-z0-9-]+"
    ),

    # ============================
    # URLs
    # ============================

    "url": re.compile(
        r"https?://[^\s\"'<>]+"
    ),

    # ============================
    # API Paths
    # ============================

    "api_path": re.compile(
        r"/(api|v1|v2|v3|admin|graphql|internal|private)[^\"' ]*",
        re.IGNORECASE
    ),

    # ============================
    # Swagger
    # ============================

    "swagger": re.compile(
        r"swagger|openapi",
        re.IGNORECASE
    ),

    # ============================
    # GraphQL
    # ============================

    "graphql": re.compile(
        r"graphql",
        re.IGNORECASE
    )

}