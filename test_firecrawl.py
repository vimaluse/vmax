import os

from dotenv import load_dotenv
from firecrawl import FirecrawlApp

load_dotenv()

api_key = os.getenv("FIRECRAWL_API_KEY")

if not api_key:
    raise RuntimeError(
        "FIRECRAWL_API_KEY is missing from .env"
    )

print("Firecrawl package imported successfully")
print("API key found")

app = FirecrawlApp(api_key=api_key)

url = "https://example.com"

result = app.scrape(
    url,
    formats=["markdown"]
)

print("\n========== FIRECRAWL RESULT ==========\n")

print(result.markdown)

print("\n======================================")