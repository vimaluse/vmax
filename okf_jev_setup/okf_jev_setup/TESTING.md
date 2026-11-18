# Validation and API smoke tests

Run these from the project root after installation.

## Unit tests

```powershell
pytest -q tests/test_okf_jev.py
```

The tests validate local bundle structure and verify retrieval works without a Jev API key.

## Start the chatbot

```powershell
python main.py
```

## Check the endpoints

Authenticate using your existing `/api/auth/login` flow, then use the resulting bearer token in the Authorization header.

- `GET /api/okf/status`
- `POST /api/okf/validate`
- `POST /api/okf/reindex`
- `GET /api/okf/search?q=Qdrant%20troubleshooting`
- `GET /api/health`

Management endpoints return 401 without a valid login. Status, validate, and reindex return 403 unless the authenticated role is `admin`. Search is available to authenticated users.

## Expected behavior

- If `JEV_API_KEY` is set, `GET /api/okf/status` reports `jev_configured: true`.
- If no key is set, local OKF keyword retrieval remains active.
- If Jev's API is down, chat should continue using local retrieval and the existing RAG pipeline.
- Chat responses now include `used_okf` in addition to the existing response fields.
- OKF source objects use `kind: "okf"` to distinguish them from Qdrant sources.

Do not paste the API key into the terminal command itself or commit it to Git. Put it in the ignored `.env` file.
