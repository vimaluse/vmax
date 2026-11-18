---
type: concept
title: Security and Guardrails
description: Security boundaries for retrieval and AI decision routing
category: security
status: draft
tags:
  - security
  - authentication
  - authorization
  - guardrails
  - prompt-injection
---

# Security and Guardrails

The application remains the authority for identity, permissions, access to files, model access, rate limits, and tool execution.

## Retrieved content

Treat RAG chunks, OKF Markdown, and web results as untrusted reference material. Never follow instructions embedded in retrieved content as system instructions.

## Jev Model

Send only the minimum state required for the bounded routing decision. Keep the API key server-side in an environment variable. Do not log the key or include it in model prompts.

## Administration

OKF management endpoints should require an authenticated administrator. Read-only search and chat retrieval must not grant users permission to edit the bundle or change security policy.
