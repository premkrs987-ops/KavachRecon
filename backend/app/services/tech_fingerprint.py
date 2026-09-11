import re
from typing import List, Dict, Any

class TechnologyFingerprinter:
    SIGNATURES = [
        # Cloud & CDN Edge Infrastructure
        {"name": "Cloudflare Edge", "category": "CDN / Reverse Proxy", "type": "header", "key": "server", "regex": r"cloudflare"},
        {"name": "Cloudflare Ray ID", "category": "WAF / CDN", "type": "header", "key": "cf-ray", "regex": r".+"},
        {"name": "Google Frontend (GFE)", "category": "Web Server", "type": "header", "key": "server", "regex": r"^gfe|gws|esf"},
        {"name": "Amazon CloudFront", "category": "CDN / Reverse Proxy", "type": "header", "key": "via", "regex": r"cloudfront"},
        {"name": "Amazon CloudFront ID", "category": "CDN", "type": "header", "key": "x-amz-cf-id", "regex": r".+"},
        {"name": "AWS Elastic Load Balancer", "category": "Load Balancer", "type": "header", "key": "awselb", "regex": r".+"},
        {"name": "Fastly", "category": "CDN / Reverse Proxy", "type": "header", "key": "x-fastly-request-id", "regex": r".+"},
        {"name": "Akamai GHost", "category": "CDN / WAF", "type": "header", "key": "server", "regex": r"AkamaiGHost"},
        {"name": "Varnish Cache", "category": "HTTP Accelerator", "type": "header", "key": "via", "regex": r"varnish"},

        # Web Servers
        {"name": "Nginx", "category": "Web Server", "type": "header", "key": "server", "regex": r"nginx(?:/([0-9.]+))?"},
        {"name": "Apache HTTP Server", "category": "Web Server", "type": "header", "key": "server", "regex": r"Apache(?:/([0-9.]+))?"},
        {"name": "Microsoft IIS", "category": "Web Server", "type": "header", "key": "server", "regex": r"Microsoft-IIS(?:/([0-9.]+))?"},
        {"name": "LiteSpeed", "category": "Web Server", "type": "header", "key": "server", "regex": r"LiteSpeed"},
        {"name": "Caddy", "category": "Web Server", "type": "header", "key": "server", "regex": r"Caddy"},
        {"name": "OpenResty", "category": "Web Server", "type": "header", "key": "server", "regex": r"openresty"},

        # Backend Frameworks & Platforms
        {"name": "PHP", "category": "Programming Language", "type": "header", "key": "x-powered-by", "regex": r"PHP(?:/([0-9.]+))?"},
        {"name": "Express.js", "category": "Backend Framework", "type": "header", "key": "x-powered-by", "regex": r"^Express"},
        {"name": "ASP.NET", "category": "Backend Framework", "type": "header", "key": "x-powered-by", "regex": r"ASP\.NET"},
        {"name": "Next.js", "category": "Web Framework", "type": "header", "key": "x-powered-by", "regex": r"Next\.js"},

        # HTML DOM & Frontend Frameworks
        {"name": "Next.js", "category": "Web Framework", "type": "html", "regex": r'<div id="__next">|__NEXT_DATA__|_next/static'},
        {"name": "React", "category": "JavaScript Framework", "type": "html", "regex": r'data-reactroot|react-dom|_reactRoot|react\.production'},
        {"name": "Vue.js", "category": "JavaScript Framework", "type": "html", "regex": r'data-v-[a-z0-9]+|vue\.runtime|__vue__'},
        {"name": "Angular", "category": "JavaScript Framework", "type": "html", "regex": r'ng-version=|ng-app'},
        {"name": "jQuery", "category": "JavaScript Library", "type": "html", "regex": r'jquery(?:-([0-9.]+))?(?:\.min)?\.js'},
        {"name": "Tailwind CSS", "category": "UI Framework", "type": "html", "regex": r'class="[^"]*(?:flex|grid|hidden|text-sm|bg-zinc-|p-[0-9])[^"]*"'},
        {"name": "Bootstrap", "category": "UI Framework", "type": "html", "regex": r'bootstrap(?:\.min)?\.(?:css|js)|class="[^"]*(?:container|row|col-md-)'},
        {"name": "WordPress", "category": "CMS", "type": "html", "regex": r'/wp-content/|/wp-includes/|name="generator" content="WordPress'},
        {"name": "Google Tag Manager", "category": "Analytics", "type": "html", "regex": r'googletagmanager\.com/gtm\.js|googletagmanager\.com/gtag'},
        {"name": "Google Analytics", "category": "Analytics", "type": "html", "regex": r'google-analytics\.com/analytics\.js'},
        {"name": "Webpack", "category": "Module Bundler", "type": "html", "regex": r'webpackChunk|webpack-'}
    ]

    @classmethod
    def analyze(cls, headers: Dict[str, str], body: str, url: str) -> List[Dict[str, Any]]:
        results = []
        seen = set()
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        # 1. Signature-based Match
        for sig in cls.SIGNATURES:
            if sig["type"] == "header":
                val = headers_lower.get(sig["key"].lower())
                if val:
                    m = re.search(sig["regex"], val, re.IGNORECASE)
                    if m:
                        version = m.group(1) if m.groups() and m.group(1) else None
                        key = f"{sig['name']}_{sig['category']}"
                        if key not in seen:
                            seen.add(key)
                            results.append({
                                "name": sig["name"],
                                "category": sig["category"],
                                "version": version,
                                "confidence": 1.0,
                                "evidence": f"Header '{sig['key']}: {val}' matched '{sig['regex']}'"
                            })

            elif sig["type"] == "html" and body:
                m = re.search(sig["regex"], body, re.IGNORECASE)
                if m:
                    key = f"{sig['name']}_{sig['category']}"
                    if key not in seen:
                        seen.add(key)
                        results.append({
                            "name": sig["name"],
                            "category": sig["category"],
                            "version": None,
                            "confidence": 0.90,
                            "evidence": f"DOM pattern match on {url}"
                        })

        # 2. Dynamic Server Header Fallback (Ensures server is ALWAYS captured even if not in signatures)
        server_header = headers_lower.get("server")
        if server_header and not any(r["category"] == "Web Server" for r in results):
            results.append({
                "name": server_header.strip(),
                "category": "Web Server",
                "version": None,
                "confidence": 1.0,
                "evidence": f"Raw Server Header: '{server_header}'"
            })

        # 3. Dynamic Protocol & Security Features
        if url.startswith("https://"):
            if "Strict-Transport-Security (HTTPS)" not in seen:
                seen.add("Strict-Transport-Security (HTTPS)")
                results.append({
                    "name": "TLS / HTTPS Encryption",
                    "category": "Security Protocol",
                    "version": None,
                    "confidence": 1.0,
                    "evidence": f"Reachable over secure TLS endpoint: {url}"
                })

        return results