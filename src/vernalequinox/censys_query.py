"""Censys 主机/证书搜索集成"""
import os
import httpx
from dataclasses import dataclass, field


@dataclass
class CensysResult:
    domain: str = ""
    hosts: list = field(default_factory=list)
    certificates: list = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)
    error: str = ""
    source: str = "censys"

    def to_dict(self):
        return {
            "domain": self.domain,
            "hosts": self.hosts,
            "certificates": self.certificates,
            "error": self.error,
            "source": self.source,
        }


class CensysQuery:
    """Censys Search API integration"""

    API_BASE = "https://search.censys.io/api/v2"

    def __init__(self, api_id: str = "", api_secret: str = "", timeout: float = 10.0):
        self.api_id = api_id or os.environ.get("CENSYS_API_ID", "")
        self.api_secret = api_secret or os.environ.get("CENSYS_API_SECRET", "")
        self.timeout = timeout

    @property
    def has_credentials(self) -> bool:
        return bool(self.api_id and self.api_secret)

    async def search_hosts(self, query: str, limit: int = 50) -> CensysResult:
        """Search for hosts matching a query"""
        result = CensysResult(domain=query)
        if not self.api_id or not self.api_secret:
            result.error = "No Censys API credentials"
            return result

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"{self.API_BASE}/search/hosts",
                    params={"q": query, "per_page": min(limit, 100)},
                    auth=(self.api_id, self.api_secret),
                )
                if resp.status_code == 200:
                    data = resp.json()
                    result.raw_data = data
                    for hit in data.get("result", {}).get("hits", []):
                        result.hosts.append({
                            "ip": hit.get("ip", ""),
                            "services": [s.get("service_name", "") for s in hit.get("services", [])],
                            "os": hit.get("operating_system", {}).get("product", ""),
                            "location": hit.get("location", {}).get("country", ""),
                        })
                else:
                    result.error = f"HTTP {resp.status_code}"
        except Exception as e:
            result.error = str(e)[:100]
        return result

    async def search_certificates(self, query: str, limit: int = 50) -> CensysResult:
        """Search certificates (alternative to crt.sh)"""
        result = CensysResult(domain=query)
        if not self.api_id or not self.api_secret:
            result.error = "No Censys API credentials"
            return result

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"{self.API_BASE}/search/certificates",
                    params={"q": query, "per_page": min(limit, 100)},
                    auth=(self.api_id, self.api_secret),
                )
                if resp.status_code == 200:
                    data = resp.json()
                    result.raw_data = data
                    for hit in data.get("result", {}).get("hits", []):
                        result.certificates.append({
                            "fingerprint": hit.get("fingerprint_sha256", ""),
                            "names": hit.get("names", []),
                            "issuer": hit.get("issuer", {}).get("organization", []),
                            "validity": hit.get("validity", {}),
                        })
                else:
                    result.error = f"HTTP {resp.status_code}"
        except Exception as e:
            result.error = str(e)[:100]
        return result

    @staticmethod
    def print_result(r: CensysResult):
        """Format and print Censys results"""
        print(f"  Censys Search")
        print(f"  {'─' * 50}")

        if r.error:
            print(f"  Error: {r.error}")
            return

        if r.hosts:
            print(f"  Hosts: {len(r.hosts)} found")
            for h in r.hosts[:10]:
                services = ", ".join(h.get("services", [])) if h.get("services") else "N/A"
                print(f"    {h['ip']}  services=[{services}]  os={h.get('os', '')}  loc={h.get('location', '')}")
            if len(r.hosts) > 10:
                print(f"    ... {len(r.hosts)} total")

        if r.certificates:
            print(f"  Certificates: {len(r.certificates)} found")
            for c in r.certificates[:10]:
                names = ", ".join(c.get("names", [])[:3]) if c.get("names") else "N/A"
                print(f"    {c.get('fingerprint', '')[:16]}...  names=[{names}]")
            if len(r.certificates) > 10:
                print(f"    ... {len(r.certificates)} total")
