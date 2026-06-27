"""
FireBounty v2
Technology Fingerprint Database

Every technology detector imports this file.
"""

TECH_FINGERPRINTS = {

    # =========================
    # Web Servers
    # =========================

    "servers": {

        "nginx": [
            "server: nginx"
        ],

        "apache": [
            "server: apache"
        ],

        "iis": [
            "server: microsoft-iis"
        ],

        "caddy": [
            "server: caddy"
        ],

        "openresty": [
            "server: openresty"
        ]

    },

    # =========================
    # Frameworks
    # =========================

    "frameworks": {

        "laravel": [
            "laravel_session",
            "x-powered-by: laravel",
            "/vendor/laravel"
        ],

        "django": [
            "csrftoken",
            "sessionid"
        ],

        "flask": [
            "werkzeug",
            "flask"
        ],

        "spring": [
            "jsessionid",
            "spring"
        ],

        "express": [
            "x-powered-by: express"
        ],

        "nextjs": [
            "__next",
            "_next/static"
        ],

        "nuxt": [
            "__nuxt"
        ],

        "rails": [
            "_rails_session"
        ]

    },

    # =========================
    # JavaScript Libraries
    # =========================

    "javascript": {

        "react": [
            "react",
            "__react"
        ],

        "vue": [
            "__vue__",
            "vue.js"
        ],

        "angular": [
            "ng-version",
            "angular"
        ],

        "jquery": [
            "jquery"
        ],

        "axios": [
            "axios"
        ],

        "bootstrap": [
            "bootstrap"
        ],

        "tailwind": [
            "tailwind"
        ]

    },

    # =========================
    # Cloud Providers
    # =========================

    "cloud": {

        "aws": [
            "amazonaws.com",
            "cloudfront"
        ],

        "firebase": [
            "firebase",
            "firebaseapp.com",
            "firebaseio.com"
        ],

        "azure": [
            "azurewebsites.net"
        ],

        "gcp": [
            "googleapis.com"
        ],

        "cloudflare": [
            "cloudflare",
            "__cf_bm",
            "cf-ray"
        ]

    },

    # =========================
    # CMS
    # =========================

    "cms": {

        "wordpress": [
            "wp-content",
            "wp-json",
            "wordpress"
        ],

        "drupal": [
            "drupal"
        ],

        "joomla": [
            "joomla"
        ],

        "ghost": [
            "ghost"
        ]

    },

    # =========================
    # Security Products
    # =========================

    "security": {

        "cloudflare": [
            "cf-ray",
            "__cf_bm"
        ],

        "akamai": [
            "akamai"
        ],

        "imperva": [
            "incapsula",
            "imperva"
        ],

        "fastly": [
            "fastly"
        ]

    }

}