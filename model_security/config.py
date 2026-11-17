import os


DEFAULT_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "gemma4:latest"
)

# Must match QWEN_OLLAMA_MODEL in main.py
QWEN_MODEL = os.getenv("OLLAMA_QWEN_MODEL", "qwen3.5:9b")
GEMINI_MODEL = "gemini-3.6-flash"

ALLOWED_MODELS = {
    "gemma4:latest",
    QWEN_MODEL,
    GEMINI_MODEL,
}

MAX_REQUEST_CHARS = 20_000
MAX_HISTORY_MESSAGES = 12
MAX_FILE_SIZE_MB = 50

MODEL_POLICIES = {
    "gemma4:latest": {
        "allowed_roles": {"admin", "supervisor", "user"},
        "rag_enabled": True,
        "web_enabled": True,
        "max_output_tokens": 2048,
    },
    QWEN_MODEL: {
        "allowed_roles": {"admin", "supervisor", "user"},
        "rag_enabled": True,
        "web_enabled": True,
        "max_output_tokens": 2048,
    },
    GEMINI_MODEL: {
        "allowed_roles": {"admin", "supervisor"},
        "rag_enabled": True,
        "web_enabled": True,
        "max_output_tokens": 2048,
    },
}


ROLE_PERMISSIONS = {
    "admin": {
        "chat",
        "upload",
        "delete",
        "web_search",
        "advanced_model",
        "redteam",
    },

    "supervisor": {
        "chat",
        "upload",
        "delete",
        "web_search",
    },

    "user": {
        "chat",
    },
}