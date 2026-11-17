---
type: procedure
title: Troubleshoot Retrieval
description: Checklist for investigating missing or irrelevant chatbot context
category: operations
status: draft
tags:
  - troubleshooting
  - qdrant
  - retrieval
  - embeddings
---

# Troubleshoot Retrieval

1. Confirm the document was uploaded successfully.
2. Confirm the background indexing task completed successfully.
3. Confirm Qdrant is reachable and the expected collection exists.
4. Confirm the query embedding model matches the indexed vector dimension.
5. Check similarity scores and the configured relevance threshold.
6. For OKF, call the administrator-only validation endpoint and fix missing frontmatter or broken local links.
7. Check whether the OKF document's title, description, tags, category, and status help retrieval.
8. If Jev is unavailable or no API key is configured, confirm local keyword fallback still returns results.
9. Review audit logs without logging secrets or full sensitive prompts.
10. Compare retrieval results against a fixed evaluation set before changing thresholds.
