---
type: concept
title: Qdrant Setup
description: Vector database configuration used by the chatbot
category: infrastructure
status: draft
tags:
  - qdrant
  - vector-database
  - embeddings
  - rag
---

# Qdrant Setup

The chatbot uses Qdrant for vector-based retrieval. Confirm the actual deployed configuration before treating these notes as authoritative.

## Known project configuration

- Collection name: `knowledge_base`
- Embedding model previously configured: `BAAI/bge-base-en-v1.5`
- Embedding dimension previously configured: `768`
- Default Qdrant HTTP port in local development: `6333`

## Troubleshooting

1. Confirm the Qdrant service is running.
2. Confirm the configured URL and collection name.
3. Confirm the embedding model and vector dimension match the collection.
4. Confirm the file has completed indexing and that payload filters match the authenticated user.
5. Inspect the application and worker logs for indexing or retrieval errors.

## Related knowledge

- [RAG architecture](./rag-architecture.md)
- [Troubleshoot retrieval](../procedures/troubleshoot-retrieval.md)
