"""Web search tool for CVE vulnerability assessment using Tavily API."""
import os
import json
import hashlib
from pathlib import Path
from typing import List, Optional
import logging
from tavily import TavilyClient

# Cache directory configuration
CACHE_DIR = Path("vul_analysis") / ".cache" / "web_search"
CACHE_DIR.mkdir(parents=True, exist_ok=True)


class CVEWebSearchTool:
    """Search web for CVE vulnerability information, exploits, and patches."""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize Tavily web search client.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        self.api_key = os.environ.get('TAVILY_API_KEY')
        
        if not self.api_key:
            self.logger.warning("TAVILY_API_KEY not found. Web search disabled.")
            self.client = None
        else:
            try:
                self.client = TavilyClient(api_key=self.api_key)
                self.logger.info("Tavily web search initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize Tavily: {e}")
                self.client = None
    
    def _get_cache_path(self, query: str) -> Path:
        """Generate a secure cache path for the query."""
        hash_obj = hashlib.md5(query.encode("utf-8"))
        return CACHE_DIR / f"{hash_obj.hexdigest()}.json"

    def __call__(self, cve_id: str, max_results: int = 2) -> str:
        """
        Search for CVE vulnerability information.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
            max_results: Max results (default: 2)
            
        Returns:
            Formatted vulnerability intelligence
        """
        if not self.client:
            return "Web search unavailable: Tavily API key not configured"
        
        # Build search query
        query = f"'{cve_id}' vulnerability exploit code, exploit version, fixed version"
        
        # Check cache
        cache_path = self._get_cache_path(query)
        if cache_path.exists():
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    cached_data = json.load(f)
                
                # Validate cache has results - if empty, delete and re-search
                if not cached_data.get("results"):
                    self.logger.info(f"Cache empty for {cve_id}, re-searching...")
                    cache_path.unlink()  # Delete empty cache
                else:
                    results = self._format_results(cached_data, cve_id)
                    self.logger.info(f"Web search cache hit for {cve_id}")
                    self.logger.info(f"\n{'='*40} [TOOL OUTPUT: CVEWebSearch] {'='*40}\n{results}\n{'='*95}")
                    return results
            except Exception as e:
                self.logger.warning(f"Failed to read cache for {cve_id}: {e}")

        # Curated authoritative security domains for CVE research
        # All domains are maintained, authentic, and widely trusted in security community
        # Note: Tavily include_domains expects clean domain names (no protocol, paths ok)
        curated_domains = [
            # Primary CVE & Global Registries
            # "nvd.nist.gov",              # NIST National Vulnerability Database (Official US)
            "cve.org",                   # Modern official CVE Program site
            "cve.mitre.org",             # Legacy MITRE registry (historical data)
            "cvedetails.com",            # CVE aggregation with CVSS and trends
            "cisa.gov",                  # Known Exploited Vulnerabilities (KEV) list

            # Developer & Open Source Intelligence
            "github.com",                # GitHub Security Advisories (GHSA)
            "osv.dev",                   # Google's Open Source Vulnerability database
            "security.snyk.io",          # Snyk database (remediation info)
            "vuldb.com",                 # Vulnerability database with risk analysis

            # Operating System & Distro Security
            "ubuntu.com",                # Ubuntu Security Notices (USN)
            "access.redhat.com",         # Red Hat Security Data (RHEL/CentOS)
            "security.debian.org",       # Debian Security Tracker
            "security.alpinelinux.org",  # Alpine Linux (container security)
            "archlinux.org",             # Arch Linux Security Advisory

            # Enterprise & Cloud Vendor Advisories
            "msrc.microsoft.com",        # Microsoft Security Response Center
            "security.apache.org",       # Apache Software Foundation
            "aws.amazon.com",            # AWS Security Bulletins
            "cloud.google.com",          # Google Cloud Security
            "oracle.com",                # Oracle Critical Patch Updates

            # Exploit, PoC, & Deep Research
            "exploit-db.com",            # Offensive Security's Exploit Database
            "packetstormsecurity.com",   # Exploit and security tool repository
            "attackerkb.com",            # Exploitability assessments (Rapid7)
            "zerodayinitiative.com",     # Zero Day Initiative (ZDI) advisories
            "vulncheck.com",             # Modern exploit intelligence
        ]

        try:
            self.logger.info(f"Web search: {query}")
            
            # Search with curated security sources
            # Using search_depth="basic" for cost optimization (1 credit vs 2)
            response = self.client.search(
                query=query,
                max_results=2,
                auto_parameters=True,
                # search_depth="basic",
                include_domains=curated_domains, # When enabled strict the search to this domain only, No results found for some case.
            )
            
            # Save to cache
            try:
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(response, f, indent=2)
            except Exception as e:
                self.logger.warning(f"Failed to write cache for {cve_id}: {e}")
            
            # Format results
            output = self._format_results(response, cve_id)
            
            # Log truncated output
            log_output =  output
            self.logger.info(f"\n{'='*40} [TOOL OUTPUT: CVEWebSearch] {'='*40}\n{log_output}\n{'='*95}")
            
            return output
            
        except Exception as e:
            self.logger.error(f"Web search failed for {cve_id}: {e}")
            return f"Web search error: {str(e)}"
    
    def _format_results(self, response: dict, cve_id: str) -> str:
        """Format Tavily search results with relevance filtering."""
        results = response.get("results", [])
        
        if not results:
            return f"No web results found for {cve_id}"
        
        # Noise phrases that indicate low-quality/error content
        noise_phrases = [
            "please reload this page",
            "error while loading",
            "can't perform that action",
            "you can't perform",
            "there was an error",
        ]
        
        # Filter results: relevance >= 0.45 OR exact CVE ID in content
        # Also exclude results with noise/error content
        filtered_results = [
            r for r in results 
            if (r.get("score", 0) >= 0.5 or cve_id.upper() in r.get("content", "").upper())
            and not any(noise in r.get("content", "").lower() for noise in noise_phrases)
        ]
        
        # Fallback: if no results pass filter, take highest relevance result
        if not filtered_results and results:
            filtered_results = [max(results, key=lambda x: x.get("score", 0))]
        
        if not filtered_results:
            return f"No relevant web results found for {cve_id}"
        
        # Build summary
        lines = [f"=== Web Intelligence: {cve_id} ===\n"]
        
        # Add AI summary if available
        if response.get("answer"):
            lines.append(f"Summary: {response['answer']}\n")
        
        # Add top 2 relevant results (reduces token usage for LLM)
        for idx, result in enumerate(filtered_results[:1], 1):
            title = result.get("title", "No title")
            url = result.get("url", "")
            content = result.get("content", "")#[:800]  # Truncate long content
            score = result.get("score", 0.0)
            
            lines.append(
                f"\n[{idx}] {title}\n"
                f"URL: {url}\n"
                f"Relevance: {score:.2f}\n"
                f"{content}\n"
            )
        
        return "".join(lines)
