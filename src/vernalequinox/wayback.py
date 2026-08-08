"""Wayback Machine 历史 URL 发现"""
import httpx
from dataclasses import dataclass, field


@dataclass
class WaybackResult:
    domain: str = ""
    urls: list = field(default_factory=list)
    unique_urls: list = field(default_factory=list)
    error: str = ""
    source: str = "wayback"

    def to_dict(self):
        return {
            "domain": self.domain,
            "total_urls": len(self.urls),
            "unique_urls": len(self.unique_urls),
            "interesting_urls": self.unique_urls[:50],
            "error": self.error,
            "source": self.source,
        }


class WaybackQuery:
    """Internet Archive Wayback Machine integration"""

    API_BASE = "https://web.archive.org/cdx/search/cdx"

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout

    async def search(self, domain: str, limit: int = 500,
                     filter_mimetype: str = "text/html",
                     collapse: str = "urlkey") -> WaybackResult:
        """Search Wayback Machine for historical URLs of a domain"""
        result = WaybackResult(domain=domain)
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                params = {
                    "url": f"*.{domain}/*",
                    "output": "json",
                    "fl": "original,mimetype,statuscode,timestamp",
                    "limit": limit,
                    "collapse": collapse,
                }
                if filter_mimetype:
                    params["filter"] = f"mimetype:{filter_mimetype}"

                resp = await client.get(self.API_BASE, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    if len(data) > 1:  # First row is header
                        for row in data[1:]:
                            url = row[0] if row else ""
                            if url:
                                result.urls.append({
                                    "url": url,
                                    "mimetype": row[1] if len(row) > 1 else "",
                                    "status": row[2] if len(row) > 2 else "",
                                    "timestamp": row[3] if len(row) > 3 else "",
                                })
                    # Deduplicate by URL path
                    seen = set()
                    for entry in result.urls:
                        path = entry["url"].split("?")[0]  # Remove query params
                        if path not in seen:
                            seen.add(path)
                            result.unique_urls.append(entry)
                else:
                    result.error = f"HTTP {resp.status_code}"
        except Exception as e:
            result.error = str(e)[:100]
        return result

    async def find_interesting_urls(self, domain: str) -> list:
        """Find potentially interesting URLs (admin panels, APIs, config files)"""
        result = await self.search(domain, limit=1000, collapse="urlkey")
        interesting = []
        keywords = [
            "admin", "login", "api", "swagger", "graphql", "debug", "config",
            "backup", "dump", "test", "dev", "staging", "internal", "secret",
            ".env", ".git", ".svn", "wp-admin", "phpmyadmin", "manager",
        ]
        for entry in result.unique_urls:
            url_lower = entry["url"].lower()
            if any(kw in url_lower for kw in keywords):
                interesting.append(entry)
        return interesting

    @staticmethod
    def print_result(r: WaybackResult):
        """Format and print Wayback results"""
        print("  Wayback Machine")
        print(f"  {'─' * 50}")

        if r.error:
            print(f"  Error: {r.error}")
            return

        print(f"  Total URLs:    {len(r.urls)}")
        print(f"  Unique paths:  {len(r.unique_urls)}")

        if r.unique_urls:
            for entry in r.unique_urls[:10]:
                print(f"    {entry['url']}")
            if len(r.unique_urls) > 10:
                print(f"    ... {len(r.unique_urls)} total")
