---
type: concept
title: RAG Chatbot Architecture
description: High-level architecture of the FastAPI retrieval-augmented chatbot
category: architecture
status: draft
tags:
  - rag
  - fastapi
  - qdrant
  - embeddings
  - ollama
---

# RAG Chatbot Architecture

The chatbot uses a FastAPI application to receive authenticated requests, retrieve relevant context, call a configured language model, apply output checks, and return the response.

## Knowledge retrieval

The existing RAG pipeline retrieves document chunks from Qdrant. OKF adds a separate curated knowledge bundle of Markdown documents with YAML metadata and links.

## Jev Model

Jev Model can classify a question into an approved knowledge category and estimate whether curated project knowledge is needed. The application still owns retrieval, permissions, thresholds, and fallbacks.

## Safety

Retrieved content is untrusted reference data. It must not override system instructions, access controls, or guardrails.

## Related knowledge

- [Qdrant setup](./qdrant-setup.md)
- [Jev and OKF routing](./jev-okf-routing.md)
- [Security and guardrails](./security-guardrails.md)
