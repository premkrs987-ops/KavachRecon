import re
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Set

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5"
}

class EndpointCrawler:
    @classmethod
    def classify_endpoint(cls, path: str) -> str:
        p = path.lower()
        if any(x in p for x in ["/admin", "/dashboard", "/manage", "/cpanel"]):
            return "ADMIN"
        elif any(x in p for x in ["/login", "/signin", "/auth", "/oauth", "/sso", "/register"]):
            return "AUTHENTICATION"
        elif any(x in p for x in ["/api/", "/v1/", "/v2/", "/graphql", "/swagger", "/openapi"]):
            return "API"
        elif any(x in p for x in ["/upload", "/file", "/import", "/attachment"]):
            return "UPLOAD"
        elif any(x in p for x in [".env", ".git", "config.", "backup", ".sql", "database"]):
            return "SENSITIVE"
        elif any(x in p for x in [".js", ".css", ".png", ".jpg", ".svg", ".woff"]):
            return "STATIC"
        return "PUBLIC"

    @classmethod
    async def crawl_target(cls, session: aiohttp.ClientSession, base_url: str, html_body: str) -> Dict[str, Any]:
        endpoints: Dict[str, Dict[str, Any]] = {}
        scripts: Set[str] = set()

        if html_body:
            try:
                soup = BeautifulSoup(html_body, "html.parser")
                
                # Extract all <script src="...">
                for s in soup.find_all("script"):
                    src = s.get("src")
                    if src:
                        full_script = urljoin(base_url, src.strip())
                        scripts.add(full_script)

                # Extract <link rel="preload" as="script">
                for link in soup.find_all("link", href=True):
                    href = link.get("href", "").strip()
                    if href.endswith(".js") or link.get("as") == "script":
                        scripts.add(urljoin(base_url, href))

                # Extract anchors
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                        full_u = urljoin(base_url, href)
                        endpoints[full_u] = {
                            "url": full_u,
                            "method": "GET",
                            "classification": cls.classify_endpoint(urlparse(full_u).path or "/"),
                            "source": "HTML_ANCHOR_DISCOVERY"
                        }

                # Extract forms
                for form in soup.find_all("form", action=True):
                    action = form["action"].strip()
                    full_u = urljoin(base_url, action)
                    endpoints[full_u] = {
                        "url": full_u,
                        "method": form.get("method", "GET").upper(),
                        "classification": cls.classify_endpoint(urlparse(full_u).path or "/"),
                        "source": "HTML_FORM_ACTION"
                    }
            except Exception:
                pass

            # Regex Fallback to catch JavaScript paths in minified HTML
            js_regex = r"""(?:src|href)=['"]([^'"]+?\.js(?:\?[^'"]*)?)['"]"""
            for m in re.finditer(js_regex, html_body, re.IGNORECASE):
                scripts.add(urljoin(base_url, m.group(1)))

        # Parse robots.txt
        robots_url = urljoin(base_url, "/robots.txt")
        try:
            async with session.get(robots_url, headers=BROWSER_HEADERS, timeout=aiohttp.ClientTimeout(total=4), ssl=False) as r_resp:
                if r_resp.status == 200:
                    r_text = await r_resp.text(errors="ignore")
                    for line in r_text.splitlines():
                        line = line.strip()
                        if line.lower().startswith(("disallow:", "allow:")):
                            parts = line.split(":", 1)
                            if len(parts) == 2:
                                dis_path = parts[1].strip()
                                if dis_path and not dis_path.startswith("*"):
                                    full_u = urljoin(base_url, dis_path)
                                    endpoints[full_u] = {
                                        "url": full_u,
                                        "method": "GET",
                                        "classification": cls.classify_endpoint(dis_path),
                                        "source": "ROBOTS_TXT_POLICY"
                                    }
        except Exception:
            pass

        return {
            "endpoints": list(endpoints.values()),
            "scripts": list(scripts)
        }