import re
from urllib.parse import urlparse
from typing import Dict, Any

class CanonicalNormalizer:
    @staticmethod
    def normalize_domain(domain: str) -> str:
        domain = domain.strip().lower()
        domain = re.sub(r'^\*\.', '', domain)
        domain = re.sub(r':\d+$', '', domain)
        return domain.rstrip('.')

    @staticmethod
    def normalize_url(raw_url: str) -> Dict[str, Any]:
        raw_url = raw_url.strip()
        if not re.match(r'^https?://', raw_url, re.IGNORECASE):
            raw_url = f"https://{raw_url}"
        
        parsed = urlparse(raw_url)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or '').lower()
        port = parsed.port or (443 if scheme == 'https' else 80)
        path = parsed.path or "/"
        
        while "//" in path:
            path = path.replace("//", "/")
            
        canonical_url = f"{scheme}://{hostname}"
        if (scheme == 'http' and port != 80) or (scheme == 'https' and port != 443):
            canonical_url += f":{port}"
        canonical_url += path
        
        return {
            "canonical_url": canonical_url,
            "scheme": scheme,
            "hostname": hostname,
            "port": port,
            "path": path,
            "query": parsed.query
        }
