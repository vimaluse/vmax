import os
from dotenv import load_dotenv

load_dotenv()
from functools import lru_cache
import numpy as np
from sentence_transformers import SentenceTransformer

from langchain_huggingface import HuggingFaceEmbeddings

embeddings = HuggingFaceEmbeddings(
    model_name="BAAI/bge-base-en-v1.5",
    model_kwargs={
        "device": "cpu"
    },
    encode_kwargs={
        "normalize_embeddings": True
    }
)

MODEL_NAME = os.getenv("EMBEDDING_MODEL", "BAAI/bge-base-en-v1.5")

@lru_cache(maxsize=1)
def get_model():
    return SentenceTransformer(MODEL_NAME)

def embed_documents(texts):
    x = get_model().encode(texts, normalize_embeddings=True, batch_size=16, show_progress_bar=False)
    return np.asarray(x, dtype=np.float32).tolist()

def embed_query(text):
    x = get_model().encode([text], normalize_embeddings=True, show_progress_bar=False)[0]
    return np.asarray(x, dtype=np.float32).tolist()
