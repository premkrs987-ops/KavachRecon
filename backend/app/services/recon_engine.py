import asyncio
import aiohttp
import dns.asyncresolver
import re
import datetime
from typing import Dict, Any, List

from app.core.scope_guard import ScopeGuard, ScopeDefinition
from app.services.normalizer import CanonicalNormalizer
from app.services.risk_engine import DeterministicRiskEngine
from app.services.tech_fingerprint import TechnologyFingerprinter
from app.services.endpoint_crawler import EndpointCrawler, BROWSER_HEADERS
from app.services.js_analyzer import JavaScriptAnalyzer

COMMON_SUBDOMAIN_WORDLIST = [
    "www", "api", "dev", "app", "admin", "staging", "auth", "login", 
    "portal", "mail", "cdn", "vpn", "docs", "status", "test", "beta"
]

class LiveReconRunner:
    def __init__(self, target_domain: str, scan_id: str, scan_mode: str = "PASSIVE_ONLY"):
        self.target_domain = CanonicalNormalizer.normalize_domain(target_domain)
        self.scan_id = scan_id
        self.scan_mode = scan_mode
        self.scope_guard = ScopeGuard([
            ScopeDefinition(pattern=f"*.{self.target_domain}", scope_type="DOMAIN_REGEX", authorization_confirmed=True),
            ScopeDefinition(pattern=self.target_domain, scope_type="EXACT_HOST", authorization_confirmed=True)
        ])
        
        self.state = {
            "scan_id": self.scan_id,
            "target": self.target_domain,
            "status": "RUNNING",
            "started_at": datetime.datetime.utcnow().isoformat(),
            "completed_at": None,
            "modules": [
                {"name": "SUBDOMAIN_DISCOVERY", "status": "PENDING", "items_discovered": 0, "error": None},
                {"name": "DNS_ENUMERATION", "status": "PENDING", "items_discovered": 0, "error": None},
                {"name": "HTTP_SERVICE_PROBE", "status": "PENDING", "items_discovered": 0, "error": None},
                {"name": "TECHNOLOGY_FINGERPRINT", "status": "PENDING", "items_discovered": 0, "error": None},
                {"name": "ENDPOINT_CRAWLER", "status": "PENDING", "items_discovered": 0, "error": None},
                {"name": "JAVASCRIPT_INTELLIGENCE", "status": "PENDING", "items_discovered": 0, "error": None},
                {"name": "SECURITY_POSTURE", "status": "PENDING", "items_discovered": 0, "error": None}
            ],
            "subdomains": [],
            "assets": [],
            "technologies": [],
            "endpoints": [],
            "javascript_findings": [],
            "findings": [],
            "graph": {"nodes": [], "edges": []}
        }

    def _set_module_state(self, mod_name: str, status: str, items: int = 0, error: str = None):
        for mod in self.state["modules"]:
            if mod["name"] == mod_name:
                mod["status"] = status
                mod["items_discovered"] = items
                mod["error"] = error
                break

    async def execute_all(self):
        discovered_subdomain_map: Dict[str, Dict[str, Any]] = {}
        
        root_id = f"domain_{self.target_domain}"
        self.state["graph"]["nodes"].append({
            "id": root_id, "label": self.target_domain, "type": "ROOT_DOMAIN", "group": "domain"
        })

        discovered_subdomain_map[self.target_domain] = {
            "subdomain": self.target_domain,
            "source": "TARGET_ROOT",
            "confidence": 1.0,
            "resolved_ips": []
        }

        live_services = []
        discovered_scripts = set()

        # 1. Multi-Feed Subdomains
        self._set_module_state("SUBDOMAIN_DISCOVERY", "RUNNING")
        try:
            passive_subs = await self._run_multi_source_passive_discovery()
            for host in passive_subs:
                auth, _ = self.scope_guard.is_authorized(host)
                if auth and host not in discovered_subdomain_map:
                    discovered_subdomain_map[host] = {
                        "subdomain": host,
                        "source": "PASSIVE_MULTI_FEED",
                        "confidence": 0.90,
                        "resolved_ips": []
                    }

            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
            resolver.timeout = 1.2
            resolver.lifetime = 1.2
            sem = asyncio.Semaphore(20)

            async def probe_wordlist(prefix: str):
                sub = f"{prefix}.{self.target_domain}"
                async with sem:
                    try:
                        ans = await resolver.resolve(sub, "A")
                        ips = [r.to_text() for r in ans]
                        if ips:
                            return sub, ips
                    except Exception:
                        pass
                return None, []

            wordlist_tasks = [probe_wordlist(w) for w in COMMON_SUBDOMAIN_WORDLIST]
            wordlist_results = await asyncio.gather(*wordlist_tasks)

            for sub, ips in wordlist_results:
                if sub:
                    if sub in discovered_subdomain_map:
                        discovered_subdomain_map[sub]["resolved_ips"].extend(ips)
                    else:
                        discovered_subdomain_map[sub] = {
                            "subdomain": sub,
                            "source": "DNS_WORDLIST_PROBE",
                            "confidence": 1.0,
                            "resolved_ips": ips
                        }

            self.state["subdomains"] = list(discovered_subdomain_map.values())
            
            for s_info in self.state["subdomains"]:
                sub_val = s_info["subdomain"]
                sub_id = f"sub_{sub_val}"
                if sub_val != self.target_domain:
                    self.state["graph"]["nodes"].append({
                        "id": sub_id, "label": sub_val, "type": "SUBDOMAIN", "group": "subdomain"
                    })
                    self.state["graph"]["edges"].append({
                        "source": root_id, "target": sub_id, "relationship": "PARENT_OF"
                    })
                
                self.state["assets"].append({
                    "type": "SUBDOMAIN" if sub_val != self.target_domain else "DOMAIN",
                    "value": sub_val,
                    "source": s_info["source"],
                    "confidence": s_info["confidence"]
                })

            sub_count = len(self.state["subdomains"])
            self._set_module_state("SUBDOMAIN_DISCOVERY", "COMPLETED" if sub_count else "COMPLETED_NO_RESULTS", sub_count)
        except Exception as e:
            self._set_module_state("SUBDOMAIN_DISCOVERY", "FAILED", error=str(e))

        # 2. Parallel DNS Resolution
        self._set_module_state("DNS_ENUMERATION", "RUNNING")
        resolved_ips = set()
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
            resolver.timeout = 1.5
            resolver.lifetime = 1.5
            dns_sem = asyncio.Semaphore(25)

            async def resolve_sub_records(host: str, rtype: str):
                async with dns_sem:
                    try:
                        ans = await asyncio.wait_for(resolver.resolve(host, rtype), timeout=2.0)
                        return host, rtype, [rdata.to_text() for rdata in ans]
                    except Exception:
                        return host, rtype, []

            all_hosts = list(discovered_subdomain_map.keys())[:50]
            dns_tasks = []
            for host in all_hosts:
                for rtype in ["A", "MX", "TXT"]:
                    dns_tasks.append(resolve_sub_records(host, rtype))

            dns_results = await asyncio.gather(*dns_tasks)

            for host, rtype, values in dns_results:
                sub_id = f"sub_{host}" if host != self.target_domain else root_id
                for val in values:
                    if rtype == "A":
                        resolved_ips.add(val)
                        if host in discovered_subdomain_map and val not in discovered_subdomain_map[host]["resolved_ips"]:
                            discovered_subdomain_map[host]["resolved_ips"].append(val)
                        
                        ip_id = f"ip_{val}"
                        if not any(n["id"] == ip_id for n in self.state["graph"]["nodes"]):
                            self.state["graph"]["nodes"].append({
                                "id": ip_id, "label": val, "type": "IP_ADDRESS", "group": "network"
                            })
                        self.state["graph"]["edges"].append({
                            "source": sub_id, "target": ip_id, "relationship": "RESOLVES_TO"
                        })

                    self.state["assets"].append({
                        "type": "IP_ADDRESS" if rtype == "A" else "DOMAIN",
                        "value": val,
                        "source": f"DNS_{rtype}_{host}",
                        "confidence": 1.0
                    })

            self.state["subdomains"] = list(discovered_subdomain_map.values())
            self._set_module_state("DNS_ENUMERATION", "COMPLETED" if resolved_ips else "COMPLETED_NO_RESULTS", len(resolved_ips))
        except Exception as e:
            self._set_module_state("DNS_ENUMERATION", "FAILED", error=str(e))

        # 3. HTTP Probing with Content Negotiation
        self._set_module_state("HTTP_SERVICE_PROBE", "RUNNING")
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=30)
            timeout = aiohttp.ClientTimeout(total=6)
            probe_sem = asyncio.Semaphore(15)

            async def probe_service(session: aiohttp.ClientSession, host: str):
                async with probe_sem:
                    for proto in ["https", "http"]:
                        url = f"{proto}://{host}"
                        try:
                            async with session.get(url, headers=BROWSER_HEADERS, allow_redirects=True, ssl=False) as resp:
                                body = ""
                                try:
                                    body = await resp.text(errors="ignore")
                                except Exception:
                                    pass

                                title_m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                                title = title_m.group(1).strip() if title_m else "No Title"
                                
                                return {
                                    "url": str(resp.url),
                                    "host": host,
                                    "status": resp.status,
                                    "server": resp.headers.get("Server") or resp.headers.get("server") or "Undisclosed",
                                    "title": title[:60],
                                    "headers": dict(resp.headers),
                                    "body": body
                                }
                        except Exception:
                            continue
                    return None

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                hosts_to_probe = [self.target_domain] + [h for h in discovered_subdomain_map.keys() if h != self.target_domain][:20]
                probe_tasks = [probe_service(session, h) for h in hosts_to_probe]
                probe_results = await asyncio.gather(*probe_tasks)
                
                for s in probe_results:
                    if s:
                        live_services.append(s)
                        svc_id = f"svc_{s['url']}"
                        sub_id = f"sub_{s['host']}" if s['host'] != self.target_domain else root_id
                        
                        self.state["graph"]["nodes"].append({
                            "id": svc_id, "label": f"{s['status']} | {s['url']}", "type": "WEB_SERVICE", "group": "service"
                        })
                        self.state["graph"]["edges"].append({
                            "source": sub_id, "target": svc_id, "relationship": "SERVES_HTTP"
                        })

                        self.state["assets"].append({
                            "type": "WEB_SERVICE",
                            "value": s["url"],
                            "source": "HTTP_LIVE_PROBE",
                            "confidence": 1.0,
                            "metadata": {"status": s["status"], "server": s["server"], "title": s["title"]}
                        })

            self._set_module_state("HTTP_SERVICE_PROBE", "COMPLETED" if live_services else "COMPLETED_NO_RESULTS", len(live_services))
        except Exception as e:
            self._set_module_state("HTTP_SERVICE_PROBE", "FAILED", error=str(e))

        # 4. Comprehensive Technology Fingerprinting
        self._set_module_state("TECHNOLOGY_FINGERPRINT", "RUNNING")
        tech_count = 0
        try:
            for s in live_services:
                detected = TechnologyFingerprinter.analyze(s["headers"], s["body"], s["url"])
                svc_id = f"svc_{s['url']}"
                for t in detected:
                    t["target_url"] = s["url"]
                    self.state["technologies"].append(t)
                    tech_count += 1
                    
                    tech_id = f"tech_{t['name']}"
                    if not any(n["id"] == tech_id for n in self.state["graph"]["nodes"]):
                        self.state["graph"]["nodes"].append({
                            "id": tech_id, "label": t["name"], "type": "TECHNOLOGY", "group": "tech"
                        })
                    self.state["graph"]["edges"].append({
                        "source": svc_id, "target": tech_id, "relationship": "RUNS_TECH"
                    })

            self._set_module_state("TECHNOLOGY_FINGERPRINT", "COMPLETED" if tech_count else "COMPLETED_NO_RESULTS", tech_count)
        except Exception as e:
            self._set_module_state("TECHNOLOGY_FINGERPRINT", "FAILED", error=str(e))

        # 5. Endpoint Crawling & Script Collection
        self._set_module_state("ENDPOINT_CRAWLER", "RUNNING")
        endpoint_count = 0
        try:
            crawler_conn = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(connector=crawler_conn, timeout=timeout) as session:
                for s in live_services:
                    crawl_res = await EndpointCrawler.crawl_target(session, s["url"], s["body"])
                    for ep in crawl_res["endpoints"]:
                        self.state["endpoints"].append(ep)
                        endpoint_count += 1
                    for scr in crawl_res["scripts"]:
                        discovered_scripts.add(scr)

            self._set_module_state("ENDPOINT_CRAWLER", "COMPLETED" if endpoint_count else "COMPLETED_NO_RESULTS", endpoint_count)
        except Exception as e:
            self._set_module_state("ENDPOINT_CRAWLER", "FAILED", error=str(e))

        # 6. JavaScript Intelligence (Logging All Analyzed Scripts)
        self._set_module_state("JAVASCRIPT_INTELLIGENCE", "RUNNING")
        js_finding_count = 0
        try:
            js_conn = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=5)
            js_sem = asyncio.Semaphore(10)

            async def analyze_single_script(session: aiohttp.ClientSession, script_url: str):
                async with js_sem:
                    return await JavaScriptAnalyzer.analyze_script(session, script_url, f"https://{self.target_domain}")

            async with aiohttp.ClientSession(connector=js_conn, timeout=timeout) as session:
                # Include inline script analyses
                for s in live_services:
                    if s["body"]:
                        inline_analysis = JavaScriptAnalyzer.analyze_raw_content(s["body"], s["url"])
                        self.state["javascript_findings"].append(inline_analysis)

                # Fetch and analyze external script bundles
                js_tasks = [analyze_single_script(session, s) for s in list(discovered_scripts)[:15]]
                js_results = await asyncio.gather(*js_tasks)

                for analysis in js_results:
                    if analysis and analysis["status"] == "ANALYZED":
                        self.state["javascript_findings"].append(analysis)
                        
                        if analysis["source_map_detected"]:
                            score = DeterministicRiskEngine.calculate("LOW", "VERIFIED", True)
                            self.state["findings"].append({
                                "title": "Client-Side Source Map Exposed",
                                "description": "Production JavaScript references an accessible .map file, exposing source code.",
                                "severity": "LOW",
                                "classification": "VERIFIED",
                                "risk_score": score,
                                "evidence": f"Script: {analysis['url']} -> Map: {analysis['source_map_url']}",
                                "remediation": "Disable source map generation in production build configurations."
                            })

                        for sec in analysis["potential_secrets"]:
                            score = DeterministicRiskEngine.calculate(sec["severity"], sec["classification"], True)
                            self.state["findings"].append({
                                "title": f"Potential Credential Pattern: {sec['pattern_name']}",
                                "description": "Matched static token regex pattern inside public JavaScript bundle.",
                                "severity": sec["severity"],
                                "classification": sec["classification"],
                                "risk_score": score,
                                "evidence": f"File: {analysis['url']} | Matched: {sec['evidence_masked']}",
                                "remediation": "Verify whether token is active; rotate credentials immediately and remove from client bundles."
                            })

            total_js_items = len(self.state["javascript_findings"])
            self._set_module_state("JAVASCRIPT_INTELLIGENCE", "COMPLETED" if total_js_items else "COMPLETED_NO_RESULTS", total_js_items)
        except Exception as e:
            self._set_module_state("JAVASCRIPT_INTELLIGENCE", "FAILED", error=str(e))

        # 7. Security Posture Checks
        self._set_module_state("SECURITY_POSTURE", "RUNNING")
        try:
            sec_checks = [
                ("Strict-Transport-Security", "HIGH", "Missing HTTP Strict Transport Security (HSTS) enforcement."),
                ("X-Content-Type-Options", "LOW", "Missing X-Content-Type-Options (nosniff) header."),
                ("X-Frame-Options", "MEDIUM", "Missing anti-clickjacking frame protection (X-Frame-Options/CSP frame-ancestors).")
            ]

            findings_count = 0
            for s in live_services:
                headers = s.get("headers", {})
                hkeys_lower = [k.lower() for k in headers.keys()]
                
                for hname, sev, desc in sec_checks:
                    if hname.lower() not in hkeys_lower:
                        score = DeterministicRiskEngine.calculate(sev, "VERIFIED", True)
                        self.state["findings"].append({
                            "title": f"Missing Security Header: {hname}",
                            "description": desc,
                            "severity": sev,
                            "classification": "VERIFIED",
                            "risk_score": score,
                            "evidence": f"Live URL: {s['url']}. Returned headers: {', '.join(headers.keys())}",
                            "remediation": f"Configure web server to return the standard '{hname}' header."
                        })
                        findings_count += 1
            
            self._set_module_state("SECURITY_POSTURE", "COMPLETED" if findings_count else "COMPLETED_NO_RESULTS", findings_count)
        except Exception as e:
            self._set_module_state("SECURITY_POSTURE", "FAILED", error=str(e))

        self.state["status"] = "COMPLETED"
        self.state["completed_at"] = datetime.datetime.utcnow().isoformat()
        return self.state

    async def _run_multi_source_passive_discovery(self) -> List[str]:
        hosts = set()
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=6)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            try:
                otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.target_domain}/passive_dns"
                async with session.get(otx_url, headers=BROWSER_HEADERS, ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data.get("passive_dns", []):
                            hostname = CanonicalNormalizer.normalize_domain(entry.get("hostname", ""))
                            if hostname and hostname.endswith(self.target_domain) and "*" not in hostname:
                                hosts.add(hostname)
            except Exception:
                pass

            try:
                ht_url = f"https://api.hackertarget.com/hostsearch/?q={self.target_domain}"
                async with session.get(ht_url, headers=BROWSER_HEADERS, ssl=False) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.splitlines():
                            parts = line.split(",")
                            if parts:
                                sub = CanonicalNormalizer.normalize_domain(parts[0])
                                if sub and sub.endswith(self.target_domain):
                                    hosts.add(sub)
            except Exception:
                pass

            try:
                crt_url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
                async with session.get(crt_url, headers=BROWSER_HEADERS, ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data:
                            name_val = entry.get("name_value", "")
                            for line in name_val.split("\n"):
                                clean_line = CanonicalNormalizer.normalize_domain(line)
                                if clean_line and clean_line.endswith(self.target_domain) and "*" not in clean_line:
                                    hosts.add(clean_line)
            except Exception:
                pass

        return list(hosts)