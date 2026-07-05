"""
FireBounty v2 - Subdomain Takeover Signatures Database
"""

SIGNATURES = {
    "github": {
        "cname": ["github.io"],
        "response": ["There's not a GitHub Pages site here", "404 Not Found"]
    },
    "s3": {
        "cname": ["amazonaws.com"],
        "response": ["NoSuchBucket", "The specified bucket does not exist"]
    },
    "heroku": {
        "cname": ["herokudns.com", "herokussl.com"],
        "response": ["There's nothing here", "no-such-app.html"]
    },
    "shopify": {
        "cname": ["myshopify.com"],
        "response": ["Sorry, this shop is currently unavailable"]
    },
    "zendesk": {
        "cname": ["zendesk.com"],
        "response": ["Help Center Closed", "No such app"]
    },
    "fastly": {
        "cname": ["fastly.net"],
        "response": ["Fastly error: unknown domain"]
    },
    "tumblr": {
        "cname": ["tumblr.com"],
        "response": ["Whatever you were looking for is not here", "404 Not Found"]
    },
    "azure": {
        "cname": ["azurewebsites.net", "cloudapp.net"],
        "response": ["404 Web Site not found", "Page not found"]
    }
}
