"""OKF v0.2 bundle loader, validator, lexical retrieval, and Jev Model routing.

Jev Model is used only for bounded classification/routing. Application code remains
responsible for retrieval, thresholds, permissions, and fallbacks.
"""
from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import httpx
import yaml


DEFAULT_CATEGORIES = {
    "general": "General company knowledge and common concepts",
    "architecture": "System architecture, components, and data flows",
    "infrastructure": "Infrastructure, deployments, databases, and model configuration",
    "security": "Authentication, authorization, guardrails, privacy, and security policies",
    "operations": "Troubleshooting, monitoring, incidents, and operational procedures",
    "other": "None of the listed categories or not enough information",
}


class OKFJEVService:
    def __init__(
        self,
        bundle_dir: str | Path,
        *,
        jev_api_key: str | None = None,
        jev_base_url: str | None = None,
        jev_model: str | None = None,
        enabled: bool | None = None,
        max_context_chars: int | None = None,
        top_k: int | None = None,
    ) -> None:
        self.bundle_dir = Path(bundle_dir).resolve()
        self.jev_api_key = (jev_api_key if jev_api_key is not None else os.getenv("JEV_API_KEY", "")).strip()
        self.jev_base_url = (jev_base_url or os.getenv("JEV_BASE_URL", "https://jevmodel.net/v1/systemone")).rstrip("/")
        self.jev_model = jev_model or os.getenv("JEV_MODEL", "jev-latest")
        self.enabled = (os.getenv("OKF_JEV_ENABLED", "true").lower() in {"1", "true", "yes", "on"}) if enabled is None else enabled
        self.max_context_chars = max_context_chars or int(os.getenv("OKF_MAX_CONTEXT_CHARS", "6000"))
        self.top_k = top_k or int(os.getenv("OKF_TOP_K", "3"))
        self.documents: list[dict[str, Any]] = []
        self.last_validation: dict[str, Any] = {"valid": False, "errors": ["Not initialized"], "warnings": []}
        self.last_decision: dict[str, Any] = {"provider": "local-fallback", "route": "other", "confidence": 0.0}

    @property
    def jev_configured(self) -> bool:
        return bool(self.enabled and self.jev_api_key)

    def load_bundle(self) -> list[dict[str, Any]]:
        """Load non-reserved Markdown files with parseable OKF frontmatter."""
        documents: list[dict[str, Any]] = []
        if not self.bundle_dir.exists():
            self.documents = []
            return []
        for path in sorted(self.bundle_dir.rglob("*.md")):
            if path.name.lower() in {"index.md", "log.md"}:
                continue
            try:
                raw = path.read_text(encoding="utf-8")
            except OSError:
                continue
            match = re.match(r"\A---\s*\r?\n(.*?)\r?\n---\s*(?:\r?\n|$)(.*)\Z", raw, re.DOTALL)
            if not match:
                continue
            try:
                metadata = yaml.safe_load(match.group(1))
            except yaml.YAMLError:
                continue
            if not isinstance(metadata, dict) or not isinstance(metadata.get("type"), str) or not metadata["type"].strip():
                continue
            tags = metadata.get("tags", [])
            if isinstance(tags, str):
                tags = [tags]
            if not isinstance(tags, list):
                tags = []
            body = match.group(2).strip()
            documents.append({
                "id": path.relative_to(self.bundle_dir).with_suffix("").as_posix(),
                "path": path.relative_to(self.bundle_dir).as_posix(),
                "title": str(metadata.get("title") or path.stem.replace("-", " ").title()),
                "description": str(metadata.get("description") or ""),
                "type": metadata["type"].strip(),
                "category": str(metadata.get("category") or self._infer_category(path, tags)).lower(),
                "tags": [str(tag).lower() for tag in tags],
                "status": str(metadata.get("status") or "unverified"),
                "body": body,
                "raw": raw,
            })
        self.documents = documents
        return documents

    @staticmethod
    def _infer_category(path: Path, tags: list[Any]) -> str:
        haystack = " ".join([str(path).lower(), *(str(t).lower() for t in tags)])
        if any(k in haystack for k in ("security", "auth", "guardrail", "privacy")):
            return "security"
        if any(k in haystack for k in ("qdrant", "ollama", "docker", "deploy", "infra", "model")):
            return "infrastructure"
        if any(k in haystack for k in ("troubleshoot", "incident", "monitor", "operation", "prometheus", "grafana")):
            return "operations"
        if any(k in haystack for k in ("architecture", "rag", "workflow", "system")):
            return "architecture"
        return "general"

    def validate_bundle(self) -> dict[str, Any]:
        """Validate the OKF bundle structure and local Markdown links."""
        errors: list[str] = []
        warnings: list[str] = []
        if not self.bundle_dir.exists():
            errors.append(f"Bundle directory does not exist: {self.bundle_dir}")
            self.last_validation = {"valid": False, "errors": errors, "warnings": warnings, "documents": 0}
            return self.last_validation

        root_index = self.bundle_dir / "index.md"
        if not root_index.exists():
            warnings.append("Root index.md is missing.")
        else:
            try:
                index_text = root_index.read_text(encoding="utf-8")
                if re.search(r"(?m)^okf_version\s*:\s*[\"']?0\.2", index_text) is None:
                    warnings.append('Root index.md should declare okf_version: "0.2" in YAML frontmatter.')
            except OSError as exc:
                errors.append(f"Could not read index.md: {exc}")

        documents = []
        for path in sorted(self.bundle_dir.rglob("*.md")):
            relative = path.relative_to(self.bundle_dir).as_posix()
            if path.name.lower() in {"index.md", "log.md"}:
                continue
            try:
                raw = path.read_text(encoding="utf-8")
            except OSError as exc:
                errors.append(f"{relative}: cannot read file ({exc})")
                continue
            match = re.match(r"\A---\s*\r?\n(.*?)\r?\n---\s*(?:\r?\n|$)(.*)\Z", raw, re.DOTALL)
            if not match:
                errors.append(f"{relative}: missing or malformed YAML frontmatter")
                continue
            try:
                metadata = yaml.safe_load(match.group(1))
            except yaml.YAMLError as exc:
                errors.append(f"{relative}: invalid YAML frontmatter ({exc})")
                continue
            if not isinstance(metadata, dict):
                errors.append(f"{relative}: frontmatter must be a YAML mapping")
                continue
            if not isinstance(metadata.get("type"), str) or not metadata["type"].strip():
                errors.append(f"{relative}: non-reserved document requires a non-empty type")
            documents.append((path, match.group(2)))

        for path, body in documents:
            relative = path.relative_to(self.bundle_dir).as_posix()
            for target in re.findall(r"!?\[[^\]]*\]\(([^)]+)\)", body):
                target = target.strip().split("#", 1)[0]
                if not target or re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target) or target.startswith("//"):
                    continue
                target_path = (path.parent / unquote(target)).resolve()
                try:
                    target_path.relative_to(self.bundle_dir)
                except ValueError:
                    errors.append(f"{relative}: link escapes bundle directory: {target}")
                    continue
                if not target_path.exists():
                    errors.append(f"{relative}: broken local link: {target}")

        self.load_bundle()
        self.last_validation = {
            "valid": not errors,
            "errors": errors,
            "warnings": warnings,
            "documents": len(self.documents),
            "bundle_dir": str(self.bundle_dir),
            "jev_configured": self.jev_configured,
        }
        return self.last_validation

    async def initialize(self) -> dict[str, Any]:
        return await asyncio.to_thread(self.validate_bundle)

    async def _jev_decide(self, query: str) -> dict[str, Any] | None:
        if not self.jev_configured:
            return None
        # Send only a bounded query and a compact, non-sensitive catalog. Do not send
        # chat history, credentials, uploaded document bodies, or private user data.
        catalog = [
            {
                "title": d["title"][:160],
                "category": d["category"][:60],
                "description": d["description"][:240],
                "tags": d["tags"][:8],
            }
            for d in self.documents[:80]
        ]
        payload = {
            "model": self.jev_model,
            "state": {"user_question": query[:2000], "available_knowledge": catalog},
            "questions": {
                "knowledge_route": {
                    "type": "choice",
                    "instructions": "Choose the single knowledge category most relevant to answering the user question. If the question is unrelated to company or project knowledge, choose other.",
                    "criteria": DEFAULT_CATEGORIES,
                },
                "needs_curated_knowledge": {
                    "type": "noul",
                    "instructions": "Does answering this question materially require curated company or project knowledge from the supplied catalog?",
                    "criteria": {
                        "true": "The question asks about this project, its systems, policies, configuration, or procedures.",
                        "false": "The question is general knowledge or unrelated to the supplied project knowledge.",
                    },
                },
            },
        }
        timeout = httpx.Timeout(connect=5.0, read=18.0, write=10.0, pool=5.0)
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                response = await client.post(
                    self.jev_base_url,
                    json=payload,
                    headers={"Authorization": f"Bearer {self.jev_api_key}", "Content-Type": "application/json"},
                )
                response.raise_for_status()
                data = response.json()
            answers = data.get("answers") or data.get("result", {}).get("answers") or {}
            route_answer = answers.get("knowledge_route") or {}
            needs_answer = answers.get("needs_curated_knowledge") or {}
            route = str(route_answer.get("choice", "other")).lower()
            if route not in DEFAULT_CATEGORIES:
                route = "other"
            probabilities = route_answer.get("probabilities") or {}
            confidence = route_answer.get("confidence")
            if confidence is None:
                try:
                    confidence = max((float(v) for v in probabilities.values()), default=0.0)
                except (TypeError, ValueError):
                    confidence = 0.0
            try:
                needs_probability = float(needs_answer.get("noul", 0.0))
            except (TypeError, ValueError):
                needs_probability = 0.0
            decision = {
                "provider": "jev",
                "model": data.get("model", self.jev_model),
                "model_version": data.get("model_version"),
                "route": route,
                "confidence": max(0.0, min(1.0, float(confidence or 0.0))),
                "needs_curated_knowledge": max(0.0, min(1.0, needs_probability)),
                "usage": data.get("usage", {}),
            }
            self.last_decision = decision
            return decision
        except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
            # Do not log request state or secrets. Fallback remains local and safe.
            self.last_decision = {
                "provider": "local-fallback",
                "route": "other",
                "confidence": 0.0,
                "error": type(exc).__name__,
            }
            return None

    @staticmethod
    def _tokens(text: str) -> set[str]:
        return set(re.findall(r"[a-z0-9_+-]+", text.lower()))

    async def retrieve(self, query: str, top_k: int | None = None) -> dict[str, Any]:
        if not self.documents:
            await asyncio.to_thread(self.load_bundle)
        if not self.documents or not query.strip():
            return {"context": "", "sources": [], "decision": {"provider": "none", "route": "other", "confidence": 0.0}}

        decision = await self._jev_decide(query)
        route = (decision or {}).get("route", "other")
        q_tokens = self._tokens(query)
        results = []
        for doc in self.documents:
            title_tokens = self._tokens(doc["title"])
            desc_tokens = self._tokens(doc["description"])
            tag_tokens = self._tokens(" ".join(doc["tags"]))
            body_tokens = self._tokens(doc["body"])
            matched = q_tokens & (title_tokens | desc_tokens | tag_tokens | body_tokens)
            if not matched:
                continue
            score = (
                4 * len(q_tokens & title_tokens)
                + 3 * len(q_tokens & desc_tokens)
                + 3 * len(q_tokens & tag_tokens)
                + len(q_tokens & body_tokens)
            )
            if route != "other" and doc["category"] == route:
                score += 3
            if doc["status"].lower() in {"draft", "deprecated", "archived"}:
                score -= 2
            if score > 0:
                results.append((score, doc))
        results.sort(key=lambda item: item[0], reverse=True)
        chosen = results[: max(1, top_k or self.top_k)]
        sections, sources = [], []
        chars = 0
        for score, doc in chosen:
            section = (
                f"[OKF source: {doc['path']} | title: {doc['title']} | "
                f"category: {doc['category']} | status: {doc['status']}]\n"
                f"{doc['body']}"
            )
            remaining = self.max_context_chars - chars
            if remaining <= 0:
                break
            section = section[:remaining]
            sections.append(section)
            chars += len(section)
            sources.append({
                "filename": Path(doc["path"]).name,
                "path": f"knowledge/{doc['path']}",
                "kind": "okf",
                "category": doc["category"],
                "score": score,
                "status": doc["status"],
            })
        return {
            "context": "\n\n---\n\n".join(sections),
            "sources": sources,
            "decision": decision or self.last_decision,
        }

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "jev_configured": self.jev_configured,
            "jev_model": self.jev_model if self.jev_configured else None,
            "bundle_dir": str(self.bundle_dir),
            "document_count": len(self.documents),
            "validation": self.last_validation,
            "last_decision": {
                k: v for k, v in self.last_decision.items()
                if k not in {"usage", "error"}
            },
        }
