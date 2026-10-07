import os
from dotenv import load_dotenv

load_dotenv()
from functools import lru_cache
import whisper

MODEL_NAME = os.getenv("WHISPER_MODEL", "small")

@lru_cache(maxsize=1)
def get_model():
    return whisper.load_model(MODEL_NAME)

def transcribe_audio(path):
    result = get_model().transcribe(path, fp16=False)
    return result.get("text", "").strip()
