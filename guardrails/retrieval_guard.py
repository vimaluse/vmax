from .document_guard import guard_document_text


def guard_retrieval_hits(hits):
    """
    Sanitize retrieved RAG content and mark instruction-like
    content as untrusted.
    """

    safe_hits = []
    findings = []

    for hit in hits or []:
        item = dict(hit)

        # Guard the retrieved text
        guarded = guard_document_text(
            item.get("text", "")
        )

        # Store sanitized/masked text
        item["text"] = guarded.text

        # Mark only when the document guard detected
        # instruction-like/untrusted content
        item["untrusted_content"] = bool(
            guarded.metadata.get(
                "untrusted_content",
                False
            )
        )

        # Collect guardrail findings
        if guarded.reasons:
            findings.extend(
                guarded.reasons
            )

        safe_hits.append(item)

    return safe_hits, findings