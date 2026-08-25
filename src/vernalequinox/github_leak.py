"""GitHub 代码泄露扫描"""
import os
import httpx
from dataclasses import dataclass, field


@dataclass
class GitHubLeakResult:
    """GitHub 代码泄露扫描结果"""

    domain: str = ""
    leaks: list = field(default_factory=list)
    error: str = ""
    source: str = "github"

    def to_dict(self):
        """GitHub 泄露扫描结果序列化"""
        return {
            "domain": self.domain,
            "leaks": self.leaks,
            "error": self.error,
            "source": self.source,
        }


class GitHubLeakScanner:
    """Search GitHub for leaked credentials and sensitive files"""

    API_BASE = "https://api.github.com"

    def __init__(self, token: str = "", timeout: float = 10.0):
        """初始化 GitHub 泄露扫描器（Token/超时）"""
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        self.timeout = timeout

    @property
    def has_token(self) -> bool:
        """是否已配置 GitHub Token"""
        return bool(self.token)

    async def search(self, domain: str) -> GitHubLeakResult:
        """Search GitHub for code related to a domain"""
        result = GitHubLeakResult(domain=domain)

        queries = [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
            f'"{domain}" token',
            f'"{domain}" credentials',
            f'"{domain}" .env',
            f'"{domain}" database',
            f'"{domain}" mysql',
            f'"{domain}" redis',
        ]

        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.token:
            headers["Authorization"] = f"token {self.token}"

        async with httpx.AsyncClient(timeout=self.timeout, headers=headers) as client:
            for query in queries:
                try:
                    resp = await client.get(
                        f"{self.API_BASE}/search/code",
                        params={"q": query, "per_page": 10},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        for item in data.get("items", []):
                            result.leaks.append({
                                "repo": item.get("repository", {}).get("full_name", ""),
                                "path": item.get("path", ""),
                                "url": item.get("html_url", ""),
                                "query": query,
                            })
                    elif resp.status_code == 403:
                        result.error = "GitHub API rate limited"
                        break
                    elif resp.status_code == 401:
                        result.error = "Invalid GitHub token"
                        break
                except Exception:
                    continue

        return result

    @staticmethod
    def print_result(r: GitHubLeakResult):
        """Format and print GitHub leak results"""
        print("  GitHub Leak Scan")
        print(f"  {'─' * 50}")

        if r.error:
            print(f"  Error: {r.error}")
            return

        if not r.leaks:
            print("  No leaks found")
            return

        print(f"  Potential leaks: {len(r.leaks)}")
        seen_repos = set()
        for leak in r.leaks[:15]:
            repo = leak.get("repo", "")
            path = leak.get("path", "")
            url = leak.get("url", "")
            print(f"    {repo} / {path}")
            if url:
                print(f"      {url}")
            seen_repos.add(repo)

        if len(r.leaks) > 15:
            print(f"    ... {len(r.leaks)} total")

        print(f"  Affected repos: {len(seen_repos)}")
