# OKF + Jev Model setup for the FastAPI RAG chatbot

This add-on provides a portable OKF v0.2 knowledge bundle, local validation/search, optional Jev Model routing, admin-only management endpoints, health/status reporting, and chat-context integration.

## Important design distinction

- **OKF** is a knowledge format: Markdown + YAML frontmatter + standard Markdown links.
- **Jev Model** is an external typed decision API. It classifies a bounded state; it does not generate the final chatbot answer.
- **Your existing RAG/Qdrant pipeline remains intact.** OKF retrieval is an additional curated knowledge source.
- If `JEV_API_KEY` is missing or Jev is unavailable, local keyword retrieval continues to work.

## Files

- `okf_jev/service.py`: OKF loading, validation, local retrieval, Jev API client, safe fallback.
- `knowledge/`: starter OKF v0.2 bundle. Verify all project-specific facts before marking them verified.
- `main.py.patched`: patched copy of the uploaded `main.py`, with lifecycle, management routes, health/status, and `/api/chat` integration.
- `.env.okf-jev.example`: environment variables to merge into your existing `.env`.
- `requirements-okf-jev.txt`: additional dependencies.
- `tests/`: tests for validation and local fallback.

## Installation in Windows PowerShell

From `C:\\Vimal\\rag_chatbot`:

1. Back up your current `main.py`.
2. Copy the `okf_jev` directory and `knowledge` directory from this setup into the project root.
3. Replace `main.py` with `main.py.patched` only after reviewing the diff against your current file. The patched copy was generated from the `main.py` uploaded in this conversation; if your local file has changed since upload, manually port the marked integration sections instead.
4. Install the added dependencies:

   ```powershell
   .\\.venv\\Scripts\\Activate.ps1
   pip install -r requirements-okf-jev.txt
   ```

5. Add the variables from `.env.okf-jev.example` to your existing `.env`. Do not replace your existing `.env`. Set `JEV_API_KEY` using a key created at https://jevmodel.net/settings/apikeys.
6. Run tests:

   ```powershell
   pytest -q tests/test_okf_jev.py
   ```

7. Start the application as usual:

   ```powershell
   python main.py
   ```

## Added endpoints

All endpoints require login; OKF administration endpoints require role `admin`.

- `GET /api/okf/status` — bundle status, validation summary, and whether Jev is configured.
- `POST /api/okf/validate` — validate frontmatter and local links.
- `POST /api/okf/reindex` — reload Markdown documents into the in-memory OKF index. This is a local file index, not a Qdrant re-embedding job.
- `GET /api/okf/search?q=...` — preview selected OKF sources.
- Existing `GET /api/health` includes a non-secret OKF/Jev status summary.

## Chat integration

For each chat request, if the OKF bundle has documents, the app can call Jev with only the user query and a compact catalog (title, category, description, tags). It does not send the full chat history, image/audio data, user credentials, or retrieved document bodies to Jev. Jev's category decision only influences local ranking. The selected OKF content is then appended as untrusted reference context before the existing model call.

The existing RAG, web search, uploaded file context, guardrails, output moderation, model authorization, and rate limiting remain in place.

## Operational notes

- JEV calls may incur usage charges and require internet access. Without a key, local OKF retrieval still works.
- Keep `.env` out of Git. Never place the API key in frontend JavaScript.
- The bundle's starter documents use `status: draft`; verify them against your deployed system.
- Admin role checking is explicit. If your deployment uses a different canonical admin role name, adjust the check in the added endpoints.
- `POST /api/okf/reindex` reloads the OKF file bundle only; it does not delete or rewrite existing Qdrant points.
- Test against a staging environment before replacing production `main.py`.
