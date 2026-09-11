import json
import os
import aiohttp
from typing import Dict, Any, List, Optional, Tuple

_RESOLVED_MODEL_CACHE: Dict[str, str] = {}

class GeminiAnalyzer:
    """
    Zero-guesswork Gemini Engine prioritizing gemini-3.6-flash
    with dynamic failover across active generation models.
    """

    SYSTEM_PROMPT = """
You are the Lead Cybersecurity AI Architect for KavachRecon (@premkrs).
You are analyzing verified attack-surface reconnaissance data for target: {target}.

STRICT OPERATIONAL RULES:
1. STRICT GROUNDING: ONLY make claims supported by the provided JSON reconnaissance dataset.
2. NO EVIDENCE = NO CLAIM: Never invent or assume CVEs, ports, exposed databases, or credentials not in the data.
3. CLEAR ATTRIBUTION: Whenever citing a risk or technology, mention the exact evidence (e.g., header, URL, or DNS record).
4. ACTIONABLE REMEDIATION: Tailor all defense instructions specifically to the detected web servers, proxies, and frameworks.
5. PROFESSIONAL TONE: Provide concise, high-density, executive-level technical analysis.
"""

    @classmethod
    async def _fetch_available_models(cls, session: aiohttp.ClientSession, api_key: str) -> Tuple[List[str], Optional[str]]:
        url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    valid = [
                        m["name"] for m in data.get("models", [])
                        if "generateContent" in m.get("supportedGenerationMethods", [])
                    ]
                    return valid, None
                else:
                    err_text = await resp.text()
                    return [], f"Google API Error during Model Discovery (HTTP {resp.status}): {err_text[:200]}"
        except Exception as e:
            return [], f"Network/SSL Failure: {str(e)}"

    @classmethod
    async def generate_summary(cls, scan_data: Dict[str, Any], api_key: Optional[str] = None) -> str:
        key = (api_key or os.environ.get("GEMINI_API_KEY", "")).strip()
        if not key:
            return "Error: No Gemini API Key provided. Please paste your API Key in the top control bar."

        subs = [s.get("subdomain") for s in scan_data.get("subdomains", [])[:20]]
        techs = list(set([t.get("name") for t in scan_data.get("technologies", [])]))[:15]
        endpoints = [e.get("url") for e in scan_data.get("endpoints", [])[:12]]
        findings = [f.get("title") for f in scan_data.get("findings", [])[:10]]

        prompt = f"""
{cls.SYSTEM_PROMPT.format(target=scan_data.get('target', 'Target'))}

RECONNAISSANCE SUMMARY DATASET:
- Target Domain: {scan_data.get('target')}
- Total Subdomains Discovered: {len(scan_data.get('subdomains', []))} (Sample: {subs})
- Technologies Detected ({len(techs)}): {techs}
- Public Endpoints Sample ({len(endpoints)}): {endpoints}
- JavaScript Files Inspected: {len(scan_data.get('javascript_findings', []))}
- Verified Security Posture Deficits: {findings}

Please produce a concise, structured intelligence report:
1. **Executive Attack-Surface Overview** (Perimeter scope & observed edge architecture)
2. **Key Security Observations** (Evidence-backed analysis of headers, exposed routes, or technologies)
3. **Prioritized Remediation Roadmap** (Actionable hardening instructions for detected stack)
"""
        return await cls._execute_request(prompt, key)

    @classmethod
    async def chat_query(cls, scan_data: Dict[str, Any], user_message: str, api_key: Optional[str] = None) -> str:
        key = (api_key or os.environ.get("GEMINI_API_KEY", "")).strip()
        if not key:
            return "Error: No Gemini API Key provided. Please paste your API Key in the top control bar."

        context_summary = {
            "target": scan_data.get("target"),
            "subdomains_count": len(scan_data.get("subdomains", [])),
            "subdomains_sample": [s.get("subdomain") for s in scan_data.get("subdomains", [])[:15]],
            "technologies": [f"{t.get('name')} ({t.get('category')})" for t in scan_data.get("technologies", [])[:10]],
            "endpoints_sample": [f"{e.get('method')} {e.get('url')}" for e in scan_data.get("endpoints", [])[:12]],
            "findings": [{"title": f.get("title"), "severity": f.get("severity")} for f in scan_data.get("findings", [])[:8]]
        }

        prompt = f"""
{cls.SYSTEM_PROMPT.format(target=scan_data.get('target', 'Target'))}

RECONNAISSANCE CONTEXT:
{json.dumps(context_summary, indent=2)}

USER QUESTION:
{user_message}

Provide a concise, direct, evidence-backed answer based solely on this reconnaissance data.
"""
        return await cls._execute_request(prompt, key)

    @classmethod
    async def _execute_request(cls, prompt: str, api_key: str) -> str:
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=25)
        cache_id = api_key[:12]

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            candidates: List[str] = []

            # 1. Check working cache
            if cache_id in _RESOLVED_MODEL_CACHE:
                candidates.append(_RESOLVED_MODEL_CACHE[cache_id])

            # 2. Discover models from live account
            available, _ = await cls._fetch_available_models(session, api_key)

            def model_rank(name: str) -> int:
                n = name.lower()
                if "3.6-flash" in n:
                    return 0
                if "3.6" in n:
                    return 1
                if "3.5-flash" in n:
                    return 2
                if "flash" in n and not any(d in n for d in ["2.5", "1.5", "2.0"]):
                    return 3
                if any(d in n for d in ["2.5", "1.5", "2.0"]):
                    return 10  # Deprecated
                return 5

            available.sort(key=model_rank)

            for m in available:
                if m not in candidates:
                    candidates.append(m)

            # Fallback guarantee
            if "models/gemini-3.6-flash" not in candidates:
                candidates.insert(0, "models/gemini-3.6-flash")

            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.2,
                    "maxOutputTokens": 1000
                }
            }

            last_error = ""
            for target_model in candidates:
                url = f"https://generativelanguage.googleapis.com/v1beta/{target_model}:generateContent?key={api_key}"
                try:
                    async with session.post(url, json=payload) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            candidates_resp = data.get("candidates", [])
                            if candidates_resp and "content" in candidates_resp[0]:
                                parts = candidates_resp[0]["content"].get("parts", [])
                                if parts and "text" in parts[0]:
                                    _RESOLVED_MODEL_CACHE[cache_id] = target_model
                                    return parts[0]["text"]
                            return "Model returned an empty response."

                        elif resp.status == 404:
                            last_error = f"{target_model} returned 404"
                            continue

                        elif resp.status == 400:
                            err_data = await resp.json()
                            msg = err_data.get("error", {}).get("message", "Invalid request")
                            return f"Gemini API Error (HTTP 400): {msg}"

                        elif resp.status == 403:
                            return "Gemini API Error (HTTP 403): Invalid API Key or access not enabled in Google AI Studio."

                        else:
                            last_error = f"{target_model} HTTP {resp.status}"

                except Exception as e:
                    last_error = f"{target_model}: {str(e)}"
                    continue

            return f"Gemini API Error: {last_error}"