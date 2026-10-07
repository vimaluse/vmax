import os
from dotenv import load_dotenv
from firecrawl import FirecrawlApp

load_dotenv()

FIRECRAWL_API_KEY = os.getenv("FIRECRAWL_API_KEY")

if not FIRECRAWL_API_KEY:
    raise RuntimeError(
        "FIRECRAWL_API_KEY is missing from .env"
    )

app = FirecrawlApp(api_key=FIRECRAWL_API_KEY)


def web_search(query: str, limit: int = 5) -> str:
    """
    Search the web using Firecrawl and return
    compact text suitable for an LLM context.
    """

    try:
        result = app.search(
            query,
            limit=limit,
        )

        results = []

        # Firecrawl response format can vary by SDK version.
        if hasattr(result, "web"):
            items = result.web or []
        elif isinstance(result, dict):
            items = result.get("web", result.get("data", []))
        else:
            items = []

        for item in items[:limit]:

            if hasattr(item, "model_dump"):
                item = item.model_dump()

            if not isinstance(item, dict):
                continue

            title = item.get("title", "Untitled")
            url = item.get("url", "")
            description = (
                item.get("description")
                or item.get("snippet")
                or item.get("markdown")
                or ""
            )

            text = (
                f"Title: {title}\n"
                f"URL: {url}\n"
                f"Content: {description}"
            )

            results.append(text)

        return "\n\n---\n\n".join(results)

    except Exception as exc:
        print(f"Firecrawl search failed: {exc}")
        return ""