import os


DEFAULT_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "gemma4:latest"
)

ALLOWED_MODELS = {
    "gemma4:latest",
}

MAX_REQUEST_CHARS = 20_000
MAX_HISTORY_MESSAGES = 12
MAX_FILE_SIZE_MB = 50

MODEL_POLICIES = {
    "gemma4:latest": {
        "allowed_roles": {
            "admin",
            "supervisor",
            "user",
        },
        "rag_enabled": True,
        "web_enabled": True,
        "max_output_tokens": 2048,
    }
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