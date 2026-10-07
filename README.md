# Local Multimodal RAG Chatbot

FastAPI + Ollama gemma4:latest + ChromaDB + BAAI/bge-base-en-v1.5 +
Whisper STT + Tesseract OCR + Windows pyttsx3 TTS.

Supported uploads: PDF, DOCX, PPTX, XLSX, CSV, TXT, Markdown, common
images, and common audio formats.

Prerequisites:
1. Ollama: `ollama pull gemma4:latest`
2. Tesseract OCR installed on Windows
3. FFmpeg installed and available on PATH for Whisper audio
4. Python 3.12 recommended

Install:
```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Copy `.env.example` to `.env`.

Run:
```powershell
.\.venv\Scripts\python.exe main.py
```

Open http://127.0.0.1:8000

Pipeline:
Text -> BGE -> ChromaDB -> retrieval -> Gemma 4
Document -> extraction -> chunking -> BGE -> ChromaDB
Image -> Tesseract OCR -> ChromaDB + original image -> Gemma 4 vision
Mic -> browser MediaRecorder -> Whisper -> transcript -> chat
Answer -> pyttsx3 -> WAV -> browser

The BGE model is downloaded and cached on first use. It produces 768-dimensional
embeddings. This project is intended for local development; add authentication,
rate limiting, antivirus scanning and stronger upload isolation before public
deployment.
