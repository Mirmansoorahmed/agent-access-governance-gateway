"""Upstream MCP client abstraction (pluggable adapter).

The gateway forwards approved calls to a real MCP server, but the decision
pipeline must be testable without a live server. So forwarding goes through the
:class:`UpstreamClient` protocol:

* :class:`InMemoryUpstream` -- a deterministic fake used by unit tests and the
  eval harness (holds a tool catalogue + canned responses).
* A real streamable-HTTP client adapter is wired in CI / the lab where network
  and an MCP server are available (kept out of the offline test path).

A ``tool`` entry mirrors the MCP ``tools/list`` shape:
``{"name": str, "description": str, "inputSchema": dict}``.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class UpstreamClient(Protocol):
    """Minimal MCP surface the gateway proxies."""

    def list_tools(self, server: str) -> list[dict]:
        """Return the live ``tools/list`` catalogue for *server*."""
        ...

    def call_tool(self, server: str, tool: str, arguments: dict) -> Any:
        """Invoke ``tools/call`` on the upstream server and return its result."""
        ...


class InMemoryUpstream:
    """Deterministic in-process upstream for tests and the eval harness."""

    def __init__(self, catalogues: dict[str, list[dict]] | None = None) -> None:
        # server -> list of tool definitions
        self._catalogues: dict[str, list[dict]] = catalogues or {}
        # (server, tool) -> callable(arguments) -> result
        self._handlers: dict[tuple[str, str], Any] = {}
        self.calls: list[tuple[str, str, dict]] = []

    def set_catalogue(self, server: str, tools: list[dict]) -> None:
        self._catalogues[server] = tools

    def set_handler(self, server: str, tool: str, handler) -> None:
        self._handlers[(server, tool)] = handler

    def list_tools(self, server: str) -> list[dict]:
        return list(self._catalogues.get(server, []))

    def find_tool(self, server: str, tool: str) -> dict | None:
        for entry in self._catalogues.get(server, []):
            if entry.get("name") == tool:
                return entry
        return None

    def call_tool(self, server: str, tool: str, arguments: dict) -> Any:
        self.calls.append((server, tool, arguments))
        handler = self._handlers.get((server, tool))
        if handler is not None:
            return handler(arguments)
        return {"ok": True, "server": server, "tool": tool}
