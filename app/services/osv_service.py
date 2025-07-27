import httpx
import asyncio
import time
from typing import Dict, List

CACHE: Dict[str, dict] = {}
CACHE_TTL = 3600  # 1 hour


async def fetch_vulnerability(dep: str) -> dict:
    """Fetch vulnerability data for a single dependency with caching."""
    now = time.time()

    if dep in CACHE and now - CACHE[dep]["time"] < CACHE_TTL:
        return CACHE[dep]["data"]

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                "https://api.osv.dev/v1/query",
                json={"package": {"name": dep, "ecosystem": "PyPI"}}
            )
            if response.status_code == 200:
                data = response.json()  # NO `await` (httpx uses sync JSON)
            else:
                data = {"vulns": []}
    except httpx.RequestError:
        data = {"vulns": []}

    # Normalize scores to floats
    for vuln in data.get("vulns", []):
        if "score" in vuln:
            try:
                vuln["score"] = float(vuln["score"])
            except (ValueError, TypeError):
                vuln["score"] = 0.0

    CACHE[dep] = {"data": data, "time": now}
    return data


async def batch_fetch_vulnerabilities(dependencies: List[str]) -> Dict[str, dict]:
    """Fetch vulnerabilities for multiple dependencies concurrently."""
    tasks = [fetch_vulnerability(dep) for dep in dependencies]
    results = await asyncio.gather(*tasks)
    return {dep: res for dep, res in zip(dependencies, results)}
