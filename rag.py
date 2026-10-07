
import hashlib
import os
import re
import uuid
from pathlib import Path
from typing import Optional

from guardrails.document_guard import guard_document_text
from guardrails.retrieval_guard import guard_retrieval_hits
from guardrails.audit_logger import audit

from embeddings import embed_documents, embed_query
from extractors import extract_file

from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    VectorParams,
    PointStruct,
    Filter,
    FieldCondition,
    MatchValue,
    MatchAny,
)


# ============================================================
# QDRANT CONFIGURATION
# ============================================================

QDRANT_URL = os.getenv(
    "QDRANT_URL",
    "http://localhost:6333",
)

QDRANT_COLLECTION = os.getenv(
    "QDRANT_COLLECTION",
    "knowledge_base",
)

EMBEDDING_DIMENSION = 768


# ============================================================
# RAG CONFIGURATION
# ============================================================

RAG_SIMILARITY_THRESHOLD = float(
    os.getenv(
        "RAG_SIMILARITY_THRESHOLD",
        "0.55",
    )
)

RAG_TOP_K = int(
    os.getenv(
        "RAG_TOP_K",
        "4",
    )
)

MAX_CONTEXT_CHARS = int(
    os.getenv(
        "MAX_CONTEXT_CHARS",
        "14000",
    )
)


# ============================================================
# SUPPORTED FILE TYPES
# ============================================================

SUPPORTED_EXTENSIONS = {
    ".pdf",
    ".docx",
    ".pptx",
    ".xlsx",
    ".csv",
    ".txt",
    ".md",

    # Images
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".bmp",
    ".tiff",

    # Audio
    ".wav",
    ".mp3",
    ".m4a",
    ".webm",
    ".ogg",
    ".flac",
}


# ============================================================
# QDRANT CLIENT
# ============================================================

client = QdrantClient(
    url=QDRANT_URL
)


# ============================================================
# CREATE COLLECTION IF IT DOES NOT EXIST
# ============================================================

if not client.collection_exists(
    QDRANT_COLLECTION
):
    client.create_collection(
        collection_name=QDRANT_COLLECTION,
        vectors_config=VectorParams(
            size=EMBEDDING_DIMENSION,
            distance=Distance.COSINE,
        ),
    )


# ============================================================
# FILE ID
# ============================================================

def make_file_id(path):
    """
    Create a stable file ID from the file contents.

    The same file content produces the same file_id.
    """

    path = Path(path)

    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


# ============================================================
# CLEAN TEXT
# ============================================================

def clean_text(text):
    """
    Clean extracted text before chunking.
    """

    if not text:
        return ""

    # Remove NULL characters
    text = text.replace(
        "\x00",
        " ",
    )

    # Normalize Windows line endings
    text = text.replace(
        "\r\n",
        "\n",
    )

    text = text.replace(
        "\r",
        "\n",
    )

    # Collapse spaces and tabs
    text = re.sub(
        r"[ \t]+",
        " ",
        text,
    )

    # Reduce excessive blank lines
    text = re.sub(
        r"\n\s*\n\s*\n+",
        "\n\n",
        text,
    )

    # Remove spaces around paragraph breaks
    text = re.sub(
        r"[ \t]*\n[ \t]*\n[ \t]*",
        "\n\n",
        text,
    )

    return text.strip()


# ============================================================
# TEXT CHUNKING
# ============================================================

def chunk_text(
    text,
    chunk_size=600,
    overlap=100,
):
    """
    Split text into overlapping chunks.

    chunk_size = maximum characters per chunk
    overlap    = characters shared between chunks
    """

    if not text:
        return []

    if overlap >= chunk_size:
        raise ValueError(
            "overlap must be smaller than chunk_size"
        )

    # Split paragraphs
    paragraphs = re.split(
        r"\n\s*\n",
        text,
    )

    paragraphs = [
        paragraph.strip()
        for paragraph in paragraphs
        if paragraph.strip()
    ]

    chunks = []
    current = ""

    for paragraph in paragraphs:

        # ----------------------------------------------------
        # Paragraph itself is larger than chunk size
        # ----------------------------------------------------

        if len(paragraph) > chunk_size:

            if current:
                if len(current) >= 20:
                    chunks.append(current)

                current = ""

            start = 0

            while start < len(paragraph):

                end = start + chunk_size

                chunk = paragraph[
                    start:end
                ].strip()

                if len(chunk) >= 20:
                    chunks.append(chunk)

                start += (
                    chunk_size - overlap
                )

            continue

        # ----------------------------------------------------
        # Start first chunk
        # ----------------------------------------------------

        if not current:
            current = paragraph
            continue

        # ----------------------------------------------------
        # Try adding paragraph
        # ----------------------------------------------------

        candidate = (
            current
            + "\n\n"
            + paragraph
        )

        if len(candidate) <= chunk_size:

            current = candidate

        else:

            # Save current chunk
            if len(current) >= 20:
                chunks.append(current)

            # Keep overlap
            overlap_text = (
                current[-overlap:]
                if overlap > 0
                else ""
            )

            current = (
                overlap_text
                + "\n\n"
                + paragraph
            )

            # ------------------------------------------------
            # If overlap + paragraph is still too large
            # ------------------------------------------------

            if len(current) > chunk_size:

                start = 0

                while start < len(current):

                    end = start + chunk_size

                    chunk = current[
                        start:end
                    ].strip()

                    if len(chunk) >= 20:
                        chunks.append(chunk)

                    start += (
                        chunk_size - overlap
                    )

                current = ""

    # --------------------------------------------------------
    # Save final chunk
    # --------------------------------------------------------

    if current and len(current) >= 20:
        chunks.append(
            current.strip()
        )

    return chunks


# ============================================================
# DELETE FILE CHUNKS FROM QDRANT
# ============================================================

def _delete_file_id(file_id):
    """
    Delete all Qdrant points belonging to a file.
    """

    result = client.delete(
        collection_name=QDRANT_COLLECTION,
        points_selector=Filter(
            must=[
                FieldCondition(
                    key="file_id",
                    match=MatchValue(
                        value=file_id
                    ),
                )
            ]
        ),
    )

    return result


# ============================================================
# INDEX FILE
# ============================================================

def index_file(
    path,
    user_id=None,
):
    """
    Extract, guard, chunk, embed and index a document.

    user_id is stored as owner_user_id and is required
    for authenticated RAG ownership filtering.
    """

    path = Path(path)

    audit(
        event_type="document_index_started",
        action="start",
        allowed=True,
        metadata={
            "filename": path.name,
            "file_type": path.suffix.lower(),
            "user_id": user_id,
        },
    )

    # --------------------------------------------------------
    # Validate file
    # --------------------------------------------------------

    if not path.exists():

        audit(
            event_type="document_index_error",
            action="error",
            allowed=False,
            reasons=[
                "Document does not exist"
            ],
            metadata={
                "path": str(path),
                "user_id": user_id,
            },
        )

        raise FileNotFoundError(
            f"File does not exist: {path}"
        )

    # --------------------------------------------------------
    # Create file ID
    # --------------------------------------------------------

    file_id = make_file_id(path)

    # --------------------------------------------------------
    # Remove previous version
    # --------------------------------------------------------

    _delete_file_id(file_id)

    # --------------------------------------------------------
    # Extract content
    # --------------------------------------------------------

    result = extract_file(path)

    original_text = result.get(
        "text",
        "",
    ) or ""

    audit(
        event_type="document_extraction",
        action="extract",
        allowed=True,
        metadata={
            "filename": path.name,
            "text_chars": len(original_text),
            "ocr": bool(
                result.get(
                    "ocr",
                    False,
                )
            ),
            "user_id": user_id,
        },
    )

    # --------------------------------------------------------
    # Document guardrails
    # --------------------------------------------------------

    guarded = guard_document_text(
        original_text,
        filename=path.name,
    )

    if not guarded.allowed:

        audit(
            event_type="document_guard_blocked",
            action="index_document",
            allowed=False,
            reasons=guarded.reasons,
            metadata={
                "filename": path.name,
                "file_id": file_id,
                "user_id": user_id,
            },
        )

        raise ValueError(
            "Document blocked by guardrails: "
            + ", ".join(
                guarded.reasons
            )
        )

    # --------------------------------------------------------
    # Use safe / masked text
    # --------------------------------------------------------

    text = clean_text(
        guarded.text
    )

    audit(
        event_type="document_guard",
        action="index_document",
        allowed=True,
        metadata={
            "filename": path.name,
            "file_id": file_id,
            "action_taken": guarded.action,
            "reason": guarded.reasons,
            "user_id": user_id,
        },
    )

    # --------------------------------------------------------
    # Create chunks
    # --------------------------------------------------------

    chunks = chunk_text(
        text,
        chunk_size=600,
        overlap=100,
    )

    # --------------------------------------------------------
    # Image fallback
    # --------------------------------------------------------

    image_extensions = {
        ".png",
        ".jpg",
        ".jpeg",
        ".webp",
        ".bmp",
        ".tiff",
    }

    if not chunks:

        if path.suffix.lower() in image_extensions:

            chunks = [
                (
                    f"Image file: {path.name}. "
                    "No readable text was detected by OCR."
                )
            ]

        else:

            raise ValueError(
                "No searchable text extracted. "
                "Check Tesseract/FFmpeg/Whisper."
            )

    # --------------------------------------------------------
    # Generate embeddings
    # --------------------------------------------------------

    vectors = embed_documents(
        chunks
    )

    audit(
        event_type="document_embedding",
        action="embed",
        allowed=True,
        metadata={
            "filename": path.name,
            "chunk_count": len(chunks),
            "embedding_count": len(vectors),
            "user_id": user_id,
        },
    )

    if len(vectors) != len(chunks):

        raise ValueError(
            "Number of embeddings does not match "
            "number of chunks."
        )

    # --------------------------------------------------------
    # Create Qdrant points
    # --------------------------------------------------------

    points = []

    for i, (chunk, vector) in enumerate(
        zip(
            chunks,
            vectors,
        )
    ):

        point_id = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{file_id}-{i}",
            )
        )

        points.append(
            PointStruct(
                id=point_id,
                vector=vector,
                payload={
                    "text": chunk,
                    "file_id": file_id,
                    "filename": path.name,
                    "path": str(
                        path.resolve()
                    ),
                    "chunk_index": i,
                    "type": path.suffix.lower(),
                    "ocr": bool(
                        result.get(
                            "ocr",
                            False,
                        )
                    ),

                    # IMPORTANT:
                    # This must contain the authenticated
                    # user's ID when indexing.
                    "owner_user_id": user_id,
                },
            )
        )

    # --------------------------------------------------------
    # Store vectors in Qdrant
    # --------------------------------------------------------

    client.upsert(
        collection_name=QDRANT_COLLECTION,
        points=points,
    )

    audit(
        event_type="qdrant_indexing",
        action="upsert",
        allowed=True,
        metadata={
            "filename": path.name,
            "file_id": file_id,
            "points": len(points),
            "collection": QDRANT_COLLECTION,
            "user_id": user_id,
        },
    )

    # --------------------------------------------------------
    # Completed
    # --------------------------------------------------------

    audit(
        event_type="document_index_completed",
        action="complete",
        allowed=True,
        metadata={
            "filename": path.name,
            "file_id": file_id,
            "chunks": len(chunks),
            "text_chars": len(text),
            "ocr": bool(
                result.get(
                    "ocr",
                    False,
                )
            ),
            "user_id": user_id,
        },
    )

    return {
        "file_id": file_id,
        "chunks": len(chunks),
        "text_chars": len(text),
        "ocr": bool(
            result.get(
                "ocr",
                False,
            )
        ),
    }


# ============================================================
# RETRIEVAL
# ============================================================

def retrieve(
    query,
    file_ids: Optional[list[str]] = None,
    top_k=None,
    user_id=None,
):
    """
    Retrieve knowledge-base chunks from Qdrant.

    Qdrant uses COSINE distance, therefore point.score
    represents cosine similarity.

    Higher score = more semantically similar.

    Retrieval is restricted by:
        1. authenticated user ownership
        2. requested file_ids, when supplied
    """

    audit(
        event_type="rag_retrieval_started",
        action="retrieve",
        allowed=True,
        metadata={
            "query_length": len(
                str(query)
            ),
            "file_count": len(
                file_ids or []
            ),
            "top_k": top_k,
            "user_id": user_id,
        },
    )

    # --------------------------------------------------------
    # TOP K
    # --------------------------------------------------------

    top_k = (
        top_k
        or RAG_TOP_K
    )

    # --------------------------------------------------------
    # Validate collection
    # --------------------------------------------------------

    collection_info = client.get_collection(
        QDRANT_COLLECTION
    )

    if not collection_info.points_count:

        audit(
            event_type="rag_retrieval_completed",
            action="empty",
            allowed=True,
            metadata={
                "reason": "empty_collection",
                "user_id": user_id,
            },
        )

        return []

    # --------------------------------------------------------
    # Create query embedding
    # --------------------------------------------------------

    query_vector = embed_query(
        query
    )

    # --------------------------------------------------------
    # Build Qdrant filters
    # --------------------------------------------------------

    must_conditions = []

    # --------------------------------------------------------
    # USER OWNERSHIP FILTER
    # --------------------------------------------------------

    if user_id:

        must_conditions.append(
            FieldCondition(
                key="owner_user_id",
                match=MatchValue(
                    value=user_id
                ),
            )
        )

    # --------------------------------------------------------
    # FILE ID FILTER
    # --------------------------------------------------------

    if file_ids:

        clean_file_ids = [
            str(file_id)
            for file_id in file_ids
            if file_id
        ]

        if clean_file_ids:

            must_conditions.append(
                FieldCondition(
                    key="file_id",
                    match=MatchAny(
                        any=clean_file_ids
                    ),
                )
            )

    # --------------------------------------------------------
    # FINAL FILTER
    # --------------------------------------------------------

    query_filter = None

    if must_conditions:

        query_filter = Filter(
            must=must_conditions
        )

    # --------------------------------------------------------
    # Retrieve extra candidates
    # --------------------------------------------------------

    candidate_limit = min(
        max(
            top_k * 3,
            top_k,
        ),
        collection_info.points_count,
    )

    # --------------------------------------------------------
    # Query Qdrant
    # --------------------------------------------------------

    response = client.query_points(
        collection_name=QDRANT_COLLECTION,
        query=query_vector,
        query_filter=query_filter,
        limit=candidate_limit,
        with_payload=True,
    )

    results = response.points

    # --------------------------------------------------------
    # Build result list
    # --------------------------------------------------------

    hits = []

    used = 0

    for point in results:

        payload = (
            point.payload
            or {}
        )

        text = payload.get(
            "text",
            "",
        )

        if not text:
            continue

        # ----------------------------------------------------
        # Context protection
        # ----------------------------------------------------

        if (
            used + len(text)
            > MAX_CONTEXT_CHARS
        ):
            break

        # ----------------------------------------------------
        # COSINE SIMILARITY
        # ----------------------------------------------------

        score = float(
            point.score
        )

        hits.append(
            {
                "text": text,

                "filename": payload.get(
                    "filename",
                    "unknown",
                ),

                "file_id": payload.get(
                    "file_id",
                    "",
                ),

                "path": payload.get(
                    "path",
                    "",
                ),

                "chunk_index": payload.get(
                    "chunk_index",
                    0,
                ),

                # IMPORTANT:
                # Use "score", not "distance".
                "score": score,
            }
        )

        used += len(text)

    # --------------------------------------------------------
    # RETRIEVAL GUARD
    # --------------------------------------------------------

    safe_hits, findings = guard_retrieval_hits(
        hits
    )

    if findings:

        audit(
            event_type="retrieval_guard",
            action="sanitize_retrieved_content",
            allowed=True,
            metadata={
                "findings": findings,
                "hit_count": len(
                    safe_hits
                ),
                "user_id": user_id,
            },
        )

    # --------------------------------------------------------
    # AUDIT SCORES
    # --------------------------------------------------------

    scores = [
        hit.get("score")
        for hit in safe_hits
        if hit.get("score") is not None
    ]

    audit(
        event_type="rag_retrieval_completed",
        action="complete",
        allowed=True,
        metadata={
            "query_length": len(
                str(query)
            ),

            "candidate_hits": len(
                hits
            ),

            "safe_hits": len(
                safe_hits
            ),

            "file_count": len(
                file_ids or []
            ),

            "similarity_threshold": (
                RAG_SIMILARITY_THRESHOLD
            ),

            "scores": scores,

            "user_id": user_id,
        },
    )

    return safe_hits


# ============================================================
# DELETE FILE
# ============================================================

def delete_file_from_index(
    file_id,
    user_id=None,
):
    """
    Delete a file only when it belongs to the
    authenticated user.
    """

    audit(
        event_type="file_index_delete_started",
        action="delete",
        allowed=True,
        metadata={
            "file_id": file_id,
            "user_id": user_id,
        },
    )

    # --------------------------------------------------------
    # OWNERSHIP CHECK
    # --------------------------------------------------------

    if user_id:

        ownership_check = client.scroll(
            collection_name=QDRANT_COLLECTION,

            scroll_filter=Filter(
                must=[
                    FieldCondition(
                        key="file_id",
                        match=MatchValue(
                            value=file_id,
                        ),
                    ),

                    FieldCondition(
                        key="owner_user_id",
                        match=MatchValue(
                            value=user_id,
                        ),
                    ),
                ]
            ),

            with_payload=False,
            limit=1,
        )

        points = ownership_check[0]

        if not points:

            audit(
                event_type="file_access_denied",
                action="delete",
                allowed=False,
                reasons=[
                    "File does not belong to authenticated user"
                ],
                metadata={
                    "file_id": file_id,
                    "user_id": user_id,
                },
            )

            return False

    # --------------------------------------------------------
    # DELETE
    # --------------------------------------------------------

    _delete_file_id(
        file_id
    )

    audit(
        event_type="file_index_delete_completed",
        action="delete",
        allowed=True,
        metadata={
            "file_id": file_id,
            "user_id": user_id,
        },
    )

    return True


# ============================================================
# GET FILE PATHS
# ============================================================

def get_file_paths(
    file_ids,
    user_id=None,
):
    """
    Return filesystem paths for files owned by user_id.
    """

    if not file_ids:
        return []

    if not user_id:
        return []

    clean_file_ids = [
        str(file_id)
        for file_id in file_ids
        if file_id
    ]

    if not clean_file_ids:
        return []

    result = client.scroll(
        collection_name=QDRANT_COLLECTION,

        scroll_filter=Filter(
            must=[
                FieldCondition(
                    key="owner_user_id",
                    match=MatchValue(
                        value=user_id
                    ),
                ),

                FieldCondition(
                    key="file_id",
                    match=MatchAny(
                        any=clean_file_ids
                    ),
                ),
            ]
        ),

        with_payload=True,
        limit=1000,
    )

    points = result[0]

    paths = []

    for point in points:

        payload = (
            point.payload
            or {}
        )

        path = payload.get(
            "path"
        )

        if path and path not in paths:
            paths.append(path)

    return paths

