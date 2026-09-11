import re
import aiohttp
from urllib.parse import urljoin
from typing import Dict, Any

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5"
}

class JavaScriptAnalyzer:
    SECRET_PATTERNS = [
        {"name": "AWS Access Key ID", "regex": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", "severity": "HIGH"},
        {"name": "Generic API Key Assignment", "regex": r"""(?i)(?:api_key|apikey|secret|token|auth_token|client_secret)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]""", "severity": "MEDIUM"},
        {"name": "JSON Web Token (JWT)", "regex": r"eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+", "severity": "MEDIUM"},
        {"name": "Google API Key", "regex": r"AIza[0-9A-Za-z\-_]{35}", "severity": "MEDIUM"},
        {"name": "Slack Webhook / Token", "regex": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", "severity": "HIGH"}
    ]

    ENDPOINT_PATTERNS = [
        r"""(?:['"])(/(?:api|v1|v2|v3|graphql|auth|admin|user|users|orders|internal)/[a-zA-Z0-9_\-/\.]+)(?:['"])""",
        r"""(?:fetch|axios\.(?:get|post|put|delete)|open)\s*\(\s*['"]([^'"]+)['"]"""
    ]

    @classmethod
    def analyze_raw_content(cls, content: str, source_url: str) -> Dict[str, Any]:
        report = {
            "url": f"Inline Script [{source_url}]",
            "source_map_detected": False,
            "source_map_url": None,
            "extracted_endpoints": [],
            "potential_secrets": [],
            "script_size_kb": round(len(content.encode('utf-8')) / 1024, 2) if content else 0,
            "status": "ANALYZED"
        }

        if not content:
            return report

        discovered_routes = set()
        for pattern in cls.ENDPOINT_PATTERNS:
            for m in re.finditer(pattern, content):
                route = m.group(1).strip()
                if len(route) > 2 and not route.endswith((".png", ".jpg", ".svg", ".css")):
                    discovered_routes.add(route)
        report["extracted_endpoints"] = list(discovered_routes)[:30]

        for rule in cls.SECRET_PATTERNS:
            for m in re.finditer(rule["regex"], content):
                matched_str = m.group(0)
                masked = matched_str[:8] + "..." + matched_str[-4:] if len(matched_str) > 12 else matched_str
                report["potential_secrets"].append({
                    "pattern_name": rule["name"],
                    "severity": rule["severity"],
                    "evidence_masked": masked,
                    "classification": "RECOMMENDED_FOR_MANUAL_REVIEW"
                })

        return report

    @classmethod
    async def analyze_script(cls, session: aiohttp.ClientSession, script_url: str, base_url: str) -> Dict[str, Any]:
        full_url = urljoin(base_url, script_url)
        report = {
            "url": full_url,
            "source_map_detected": False,
            "source_map_url": None,
            "extracted_endpoints": [],
            "potential_secrets": [],
            "script_size_kb": 0,
            "status": "ANALYZED"
        }

        try:
            async with session.get(full_url, headers=BROWSER_HEADERS, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                if resp.status != 200:
                    report["status"] = f"HTTP_{resp.status}"
                    return report

                content = await resp.text(errors="ignore")
                report["script_size_kb"] = round(len(content.encode('utf-8')) / 1024, 2)

                map_match = re.search(r"//#\s*sourceMappingURL=([^\s]+)", content)
                if map_match:
                    report["source_map_detected"] = True
                    report["source_map_url"] = urljoin(full_url, map_match.group(1))

                discovered_routes = set()
                for pattern in cls.ENDPOINT_PATTERNS:
                    for m in re.finditer(pattern, content):
                        route = m.group(1).strip()
                        if len(route) > 2 and not route.endswith((".png", ".jpg", ".svg", ".css")):
                            discovered_routes.add(route)
                report["extracted_endpoints"] = list(discovered_routes)[:30]

                for rule in cls.SECRET_PATTERNS:
                    for m in re.finditer(rule["regex"], content):
                        matched_str = m.group(0)
                        masked = matched_str[:8] + "..." + matched_str[-4:] if len(matched_str) > 12 else matched_str
                        report["potential_secrets"].append({
                            "pattern_name": rule["name"],
                            "severity": rule["severity"],
                            "evidence_masked": masked,
                            "classification": "RECOMMENDED_FOR_MANUAL_REVIEW"
                        })

        except Exception as e:
            report["status"] = f"FAILED"

        return report