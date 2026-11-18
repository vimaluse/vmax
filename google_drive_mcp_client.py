
import sys
from contextlib import AsyncExitStack
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

BASE_DIR = Path(__file__).resolve().parent
SERVER_FILE = BASE_DIR / "google-drive-mcp" / "server.py"

_exit_stack = None
_session = None


async def start_google_drive_mcp():
    """Start the Google Drive MCP server and connect to it."""
    global _exit_stack, _session

    if _session is not None:
        return

    if not SERVER_FILE.exists():
        raise FileNotFoundError(
            f"Google Drive MCP server not found: {SERVER_FILE}"
        )

    stack = AsyncExitStack()

    try:
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(SERVER_FILE)],
            cwd=str(SERVER_FILE.parent),
        )

        read_stream, write_stream = await stack.enter_async_context(
            stdio_client(params)
        )

        session = await stack.enter_async_context(
            ClientSession(read_stream, write_stream)
        )

        await session.initialize()

        # Verify that the server exposes its tools.
        result = await session.list_tools()
        print(
            "Google Drive MCP connected. Tools:",
            [tool.name for tool in result.tools],
        )

        _exit_stack = stack
        _session = session

    except Exception:
        await stack.aclose()
        raise


async def stop_google_drive_mcp():
    """Close the MCP connection and stop the child process."""
    global _exit_stack, _session

    stack = _exit_stack
    _exit_stack = None
    _session = None

    if stack is not None:
        await stack.aclose()


async def call_google_drive_tool(
    tool_name: str,
    arguments: dict | None = None,
):
    """Call a tool exposed by the Google Drive MCP server."""
    if _session is None:
        raise RuntimeError("Google Drive MCP is not connected.")

    allowed_tools = {
        "list_drive_files",
        "search_drive_files",
        "read_drive_file",
    }

    if tool_name not in allowed_tools:
        raise ValueError(f"Unsupported Google Drive tool: {tool_name}")

    result = await _session.call_tool(
        tool_name,
        arguments=arguments or {},
    )

    if result.isError:
        raise RuntimeError(
            f"Google Drive MCP tool failed: {tool_name}"
        )

    return result
