
import io
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
from pypdf import PdfReader

BASE_DIR = Path(__file__).resolve().parent
CREDENTIALS_FILE = BASE_DIR / "credentials.json"
TOKEN_FILE = BASE_DIR / "token.json"

SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]

mcp = FastMCP("google-drive-mcp")

MAX_FILE_LIMIT = 100
MAX_SEARCH_LIMIT = 20
MAX_CONTENT_CHARS = 30000


def get_drive_service():
    """Authenticate and return a Google Drive API client."""
    creds = None

    if TOKEN_FILE.exists():
        creds = Credentials.from_authorized_user_file(
            str(TOKEN_FILE), SCOPES
        )

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not CREDENTIALS_FILE.exists():
                raise FileNotFoundError(
                    f"Missing OAuth credentials: {CREDENTIALS_FILE}"
                )

            flow = InstalledAppFlow.from_client_secrets_file(
                str(CREDENTIALS_FILE), SCOPES
            )
            creds = flow.run_local_server(port=0)

        TOKEN_FILE.write_text(creds.to_json(), encoding="utf-8")

    return build("drive", "v3", credentials=creds)


def escape_drive_query(value: str) -> str:
    """Escape values used inside Google Drive query expressions."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


@mcp.tool()
def list_drive_files(
    limit: int = 20,
    page_token: str = "",
    folder_id: str = "",
) -> dict:
    """List Google Drive files, optionally within a folder.

    Args:
        limit: Maximum files to return, from 1 to 100.
        page_token: Next-page token from a previous response.
        folder_id: Optional folder ID to list immediate contents.
    """
    limit = max(1, min(limit, MAX_FILE_LIMIT))
    service = get_drive_service()

    query = "trashed = false"

    if folder_id.strip():
        folder = escape_drive_query(folder_id.strip())
        query += f" and '{folder}' in parents"

    request_params = {
        "q": query,
        "pageSize": limit,
        "orderBy": "folder,name",
        "fields": (
            "nextPageToken,"
            "files(id,name,mimeType,modifiedTime,webViewLink,size)"
        ),
    }

    if page_token.strip():
        request_params["pageToken"] = page_token.strip()

    result = service.files().list(**request_params).execute()

    files = [
        {
            "id": item["id"],
            "name": item["name"],
            "type": item["mimeType"],
            "modified_time": item.get("modifiedTime"),
            "url": item.get("webViewLink"),
            "size_bytes": item.get("size"),
        }
        for item in result.get("files", [])
    ]

    return {
        "count": len(files),
        "files": files,
        "next_page_token": result.get("nextPageToken"),
    }


@mcp.tool()
def search_drive_files(query: str, limit: int = 10) -> dict:
    """Search Google Drive files by name or indexed content.

    Args:
        query: Text to search for.
        limit: Maximum number of results, from 1 to 20.
    """
    query = query.strip()

    if not query:
        return {"error": "Search query cannot be empty."}

    limit = max(1, min(limit, MAX_SEARCH_LIMIT))
    escaped = escape_drive_query(query)
    service = get_drive_service()

    result = service.files().list(
        q=(
            "trashed = false and "
            f"(name contains '{escaped}' or "
            f"fullText contains '{escaped}')"
        ),
        pageSize=limit,
        orderBy="modifiedTime desc",
        fields=(
            "nextPageToken,"
            "files(id,name,mimeType,modifiedTime,webViewLink,size)"
        ),
    ).execute()

    return {
        "count": len(result.get("files", [])),
        "files": result.get("files", []),
        "next_page_token": result.get("nextPageToken"),
    }


@mcp.tool()
def read_drive_file(file_id: str) -> dict:
    """Read a supported Google Doc, Google Sheet, text file, or PDF.

    Args:
        file_id: ID of an accessible Google Drive file.
    """
    if not file_id.strip():
        return {"error": "file_id cannot be empty."}

    service = get_drive_service()

    metadata = service.files().get(
        fileId=file_id.strip(),
        fields="id,name,mimeType,webViewLink",
    ).execute()

    mime_type = metadata["mimeType"]

    if mime_type == "application/vnd.google-apps.document":
        content = service.files().export(
            fileId=file_id.strip(),
            mimeType="text/plain",
        ).execute().decode("utf-8", errors="replace")

    elif mime_type == "application/vnd.google-apps.spreadsheet":
        content = service.files().export(
            fileId=file_id.strip(),
            mimeType="text/csv",
        ).execute().decode("utf-8", errors="replace")

    elif mime_type in ("text/plain", "text/csv"):
        content = service.files().get_media(
            fileId=file_id.strip()
        ).execute().decode("utf-8", errors="replace")

    elif mime_type == "application/pdf":
        request = service.files().get_media(
            fileId=file_id.strip()
        )
        buffer = io.BytesIO()
        downloader = MediaIoBaseDownload(buffer, request)

        done = False
        while not done:
            _, done = downloader.next_chunk()

        buffer.seek(0)
        reader = PdfReader(buffer)
        content = "\n".join(
            page.extract_text() or "" for page in reader.pages
        )

    else:
        return {
            "error": f"Unsupported file type: {mime_type}",
            "name": metadata["name"],
            "mimeType": mime_type,
        }

    return {
        "id": metadata["id"],
        "name": metadata["name"],
        "mimeType": mime_type,
        "url": metadata.get("webViewLink"),
        "content": content[:MAX_CONTENT_CHARS],
        "truncated": len(content) > MAX_CONTENT_CHARS,
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
