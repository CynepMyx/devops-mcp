import os
import httpx

SERPAPI_KEY = os.environ.get("SERPAPI_KEY", "")
EXA_API_KEY = os.environ.get("EXA_API_KEY", "")


async def search_web(args: dict) -> dict:
    query = args.get("query", "")
    limit = min(int(args.get("limit", 5)), 10)
    if not query:
        return {"error": "query is required"}
    if not SERPAPI_KEY:
        return {"error": "SERPAPI_KEY not configured"}

    params = {
        "engine": "google",
        "q": query,
        "num": limit,
        "api_key": SERPAPI_KEY,
    }
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get("https://serpapi.com/search", params=params)
        r.raise_for_status()
        data = r.json()

    results = []
    for item in data.get("organic_results", [])[:limit]:
        results.append({
            "title": item.get("title"),
            "url": item.get("link"),
            "snippet": item.get("snippet"),
        })
    return {"query": query, "results": results}


async def search_ai(args: dict) -> dict:
    query = args.get("query", "")
    limit = min(int(args.get("limit", 5)), 10)
    if not query:
        return {"error": "query is required"}
    if not EXA_API_KEY:
        return {"error": "EXA_API_KEY not configured"}

    payload = {
        "query": query,
        "numResults": limit,
        "useAutoprompt": True,
        "contents": {"text": {"maxCharacters": 500}},
    }
    headers = {"x-api-key": EXA_API_KEY, "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post("https://api.exa.ai/search", json=payload, headers=headers)
        r.raise_for_status()
        data = r.json()

    results = []
    for item in data.get("results", [])[:limit]:
        results.append({
            "title": item.get("title"),
            "url": item.get("url"),
            "snippet": (item.get("text") or "")[:300],
        })
    return {"query": query, "results": results}
