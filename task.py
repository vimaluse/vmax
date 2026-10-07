from pathlib import Path

from celery_app import celery_app
from rag import index_file, retrieve

from guardrails.document_guard import guard_document_text
from guardrails.retrieval_guard import guard_retrieval_hits
from guardrails.audit_logger import audit


# ============================================================
# DOCUMENT PROCESSING
# ============================================================

@celery_app.task(
    name="process_document"
)
def process_document(
    path,
    user_id=None
):

    path = Path(path)

    audit(
        "document_processing_started",
        action="start",
        allowed=True,
        metadata={
            "filename": path.name,
            "path": str(path),
            "user_id": user_id,
        },
    )

    print(
        "\n========================================"
    )
    print(
        "[Celery] Document processing started"
    )
    print(
        "File:",
        path.name
    )
    print(
        "User:",
        user_id
    )
    print(
        "========================================\n"
    )

    # --------------------------------------------------------
    # 1. CHECK FILE
    # --------------------------------------------------------

    if not path.exists():

        audit(
            "document_processing",
            action="block",
            allowed=False,
            reasons=[
                "Document does not exist"
            ],
            metadata={
                "path": str(path),
                "user_id": user_id,
            }
        )

        raise FileNotFoundError(
            f"File does not exist: {path}"
        )

    # --------------------------------------------------------
    # 2. PRE-SCAN DOCUMENT
    # --------------------------------------------------------
    #
    # This extracts the document once and checks:
    #
    # - PII
    # - DLP / secrets
    # - Prompt injection
    #
    # The document is NOT deleted because of
    # instruction-like content.
    #
    # --------------------------------------------------------

    guard_findings = []

    try:

        from extractors import extract_file

        extracted = extract_file(
            path
        )

        extracted_text = extracted.get(
            "text",
            ""
        )

        document_guard = guard_document_text(
            extracted_text
        )

        guard_findings.extend(
            document_guard.reasons
        )

        print(
            "[Document Guard] "
            f"Action: {document_guard.action}"
        )

        if document_guard.reasons:

            print(
                "[Document Guard] "
                f"Findings: {document_guard.reasons}"
            )

        # ----------------------------------------------------
        # AUDIT DOCUMENT GUARD
        # ----------------------------------------------------

        audit(
            "document_guard",
            action=document_guard.action,
            allowed=document_guard.allowed,
            reasons=document_guard.reasons,
            metadata={
                "filename": path.name,
                "file_type": path.suffix.lower(),
                "user_id": user_id,
                "prompt_injection": (
                    document_guard.metadata
                    .get(
                        "prompt_injection",
                        {}
                    )
                ),
                "untrusted_content": (
                    document_guard.metadata
                    .get(
                        "untrusted_content",
                        False
                    )
                )
            }
        )

    except Exception as exc:

        print(
            "[Document Guard] "
            f"Pre-scan failed: {exc}"
        )

        audit(
            "document_guard",
            action="error",
            allowed=False,
            reasons=[
                f"Document guard failed: {exc}"
            ],
            metadata={
                "filename": path.name,
                "user_id": user_id,
            }
        )

        raise

    # --------------------------------------------------------
    # 3. INDEX DOCUMENT
    # --------------------------------------------------------
    #
    # Existing rag.index_file() performs:
    #
    # extract
    #    ↓
    # clean
    #    ↓
    # chunk
    #    ↓
    # embedding
    #    ↓
    # Qdrant
    #
    # user_id is passed so rag.py can store
    # owner_user_id in the Qdrant payload.
    #
    # --------------------------------------------------------

    try:

        result = index_file(
            path,
            user_id=user_id,
        )

    except Exception as exc:

        audit(
            "document_indexing",
            action="error",
            allowed=False,
            reasons=[
                f"Document indexing failed: {exc}"
            ],
            metadata={
                "filename": path.name,
                "path": str(path),
                "user_id": user_id,
            }
        )

        raise

    # --------------------------------------------------------
    # 4. AUDIT SUCCESS
    # --------------------------------------------------------

    audit(
        "document_indexing",
        action="allow",
        allowed=True,
        reasons=guard_findings,
        metadata={
            "filename": path.name,
            "file_id": result.get(
                "file_id"
            ),
            "chunks": result.get(
                "chunks",
                0
            ),
            "text_chars": result.get(
                "text_chars",
                0
            ),
            "ocr": result.get(
                "ocr",
                False
            ),
            "user_id": user_id,
        }
    )

    print(
        "\n========================================"
    )
    print(
        "[Celery] Document processing completed"
    )
    print(
        "File:",
        path.name
    )
    print(
        "User:",
        user_id
    )
    print(
        "Chunks:",
        result.get(
            "chunks",
            0
        )
    )
    print(
        "Text chars:",
        result.get(
            "text_chars",
            0
        )
    )
    print(
        "OCR:",
        result.get(
            "ocr",
            False
        )
    )
    print(
        "========================================\n"
    )

    return {
        "status": "completed",

        "file_id": result.get(
            "file_id"
        ),

        "filename": result.get(
            "filename",
            path.name
        ),

        "chunks": result.get(
            "chunks",
            0
        ),

        "text_chars": result.get(
            "text_chars",
            0
        ),

        "ocr": result.get(
            "ocr",
            False
        ),

        "guardrails": {
            "checked": True,
            "findings": guard_findings
        }
    }


# ============================================================
# CHAT / RAG RETRIEVAL TASK
# ============================================================

@celery_app.task(
    name="process_chat"
)
def process_chat(
    question,
    file_ids=None,
    user_id=None
):

    audit(
        "chat_retrieval_task_started",
        action="start",
        allowed=True,
        metadata={
            "question_length": len(str(question)),
            "file_count": len(file_ids or []),
            "user_id": user_id,
        },
    )

    print(
        "\n========================================"
    )
    print(
        "[Celery] RAG retrieval started"
    )
    print(
        "Question:",
        question
    )
    print(
        "User:",
        user_id
    )
    print(
        "========================================\n"
    )

    # --------------------------------------------------------
    # 1. RETRIEVE FROM QDRANT
    # --------------------------------------------------------

    try:

        hits = retrieve(
            question,
            file_ids or None,
            user_id=user_id,
        )

    except Exception as exc:

        audit(
            "chat_retrieval_task_error",
            action="error",
            allowed=False,
            reasons=[str(exc)],
            metadata={
                "question_length": len(
                    str(question)
                ),
                "file_count": len(
                    file_ids or []
                ),
                "user_id": user_id,
            },
        )

        raise

    # --------------------------------------------------------
    # 2. GUARD RETRIEVED CONTENT
    # --------------------------------------------------------
    #
    # Important:
    #
    # Qdrant content is DATA.
    #
    # It must never be treated as an instruction
    # to the LLM.
    #
    # --------------------------------------------------------

    safe_hits, findings = guard_retrieval_hits(
        hits
    )

    # --------------------------------------------------------
    # 3. AUDIT RETRIEVAL GUARD
    # --------------------------------------------------------

    audit(
        "retrieval_guard",
        action=(
            "sanitize"
            if findings
            else
            "allow"
        ),
        allowed=True,
        reasons=findings,
        metadata={
            "question_length": len(
                question
            ),
            "retrieved_chunks": len(
                hits
            ),
            "safe_chunks": len(
                safe_hits
            ),
            "file_ids": file_ids or [],
            "user_id": user_id,
        }
    )

    print(
        "[Retrieval Guard] "
        f"Retrieved: {len(hits)}"
    )

    print(
        "[Retrieval Guard] "
        f"Safe: {len(safe_hits)}"
    )

    if findings:

        print(
            "[Retrieval Guard] "
            f"Findings: {findings}"
        )

    # --------------------------------------------------------
    # 4. RETURN SAFE DOCUMENTS
    # --------------------------------------------------------

    audit(
        "chat_retrieval_task_completed",
        action="complete",
        allowed=True,
        metadata={
            "question_length": len(
                str(question)
            ),
            "retrieved_chunks": len(
                hits
            ),
            "safe_chunks": len(
                safe_hits
            ),
            "file_count": len(
                file_ids or []
            ),
            "user_id": user_id,
        },
    )

    return {
        "status": "completed",

        "question": question,

        "documents": safe_hits,

        "guardrails": {
            "checked": True,
            "findings": findings
        }
    }