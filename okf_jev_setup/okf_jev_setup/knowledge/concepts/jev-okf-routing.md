---
type: concept
title: Jev Model and OKF Routing
description: How Jev Model decisions guide retrieval from the OKF knowledge bundle
category: architecture
status: draft
tags:
  - jev
  - okf
  - routing
  - decision-model
---

# Jev Model and OKF Routing

OKF is a portable knowledge representation convention using Markdown files, YAML frontmatter, and standard links. Jev Model is a separate decision API that returns typed decisions such as choice, score, and noul.

## Intended workflow

1. Load and validate the local OKF bundle.
2. Send a bounded user question and compact document catalog to Jev Model when `JEV_API_KEY` is configured.
3. Ask Jev to choose an approved knowledge category and judge whether curated project knowledge is needed.
4. Use the category as a retrieval ranking hint; local retrieval remains the source of selected document content.
5. Add selected OKF content as untrusted reference context for the existing LLM.
6. If Jev is unavailable, use local keyword retrieval and continue safely.

## Important boundaries

- Jev does not generate the chatbot's final prose answer.
- Jev does not access Qdrant or execute tools on its own.
- Jev decisions are advisory and must not bypass authorization, document guards, or policy.
- Never send API keys, passwords, access tokens, raw chat history, or unrelated private information to Jev.
- Probability and confidence are signals, not guarantees of correctness.

## Related knowledge

- [RAG architecture](./rag-architecture.md)
- [Security and guardrails](./security-guardrails.md)
