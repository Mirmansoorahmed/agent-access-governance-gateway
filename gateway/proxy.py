"""MCP proxy / PEP shell over the decision engine.

Transport: MCP streamable HTTP (JSON-RPC 2.0 messages over HTTP POST). This
module keeps the wire handling thin and testable: :func:`handle_message` takes a
decoded JSON-RPC request and returns a JSON-RPC response, with no sockets
involved, so the whole request path is unit-testable offline. :class:`Gateway`
wires the engine + upstream; :func:`serve` mounts it on ``http.server`` for the
lab (not exercised by offline unit tests).

Supported methods:
  * ``tools/list`` -- forwarded to upstream; the live catalogue is recorded so
    drift (Check 3) has fresh input. Listing itself is not blocked.
  * ``tools/call`` -- runs the four checks; allow -> forward to upstream; deny
    -> structured JSON-RPC error carrying the reason code.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .decision import CallContext, Decision, DecisionEngine
from .errors import GatewayDenied
from .upstream import UpstreamClient

JSONRPC_VERSION = "2.0"
# JSON-RPC reserved error codes
_METHOD_NOT_FOUND = -32601
_INVALID_PARAMS = -32602


@dataclass
class Gateway:
    """Couples the decision engine, upstream client, and (optional) evidence."""

    engine: DecisionEngine
    upstream: UpstreamClient
    # optional callable(Decision, CallContext) for evidence emission (task 10)
    on_decision: object = None

    def handle_message(self, message: dict) -> dict:
        """Process one decoded JSON-RPC request, return a JSON-RPC response."""
        request_id = message.get("id")
        method = message.get("method")
        params = message.get("params") or {}

        if method == "tools/list":
            return self._handle_list(request_id, params)
        if method == "tools/call":
            return self._handle_call(request_id, params)
        return _error(request_id, _METHOD_NOT_FOUND, f"method not found: {method}")

    def handle_raw(self, raw: str | bytes) -> str:
        """Decode a raw JSON-RPC request body and return the response body."""
        try:
            message = json.loads(raw)
        except (ValueError, json.JSONDecodeError):
            return json.dumps(_error(None, _INVALID_PARAMS, "invalid JSON"))
        return json.dumps(self.handle_message(message))

    # --- method handlers -------------------------------------------------
    def _handle_list(self, request_id, params: dict) -> dict:
        server = params.get("server", "")
        tools = self.upstream.list_tools(server)
        # Recording for drift input happens implicitly: the engine reads the
        # same upstream catalogue at call time. Listing is never blocked.
        return _result(request_id, {"tools": tools})

    def _handle_call(self, request_id, params: dict) -> dict:
        server = params.get("server", "")
        tool = params.get("name", params.get("tool", ""))
        arguments = params.get("arguments", {}) or {}
        token = params.get("token", "")
        ctx = CallContext(server=server, tool=tool, arguments=arguments, token=token)

        decision: Decision = self.engine.decide(ctx)
        if callable(self.on_decision):
            self.on_decision(decision, ctx)

        if not decision.allowed:
            denied = GatewayDenied(decision.reason, decision.detail)
            return _error_obj(request_id, denied.to_mcp_error())

        result = self.upstream.call_tool(server, tool, arguments)
        return _result(request_id, {"content": result, "tier": decision.tier})


def _result(request_id, result: dict) -> dict:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}


def _error(request_id, code: int, message: str) -> dict:
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _error_obj(request_id, error: dict) -> dict:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": error}


def serve(gateway: Gateway, host: str = "127.0.0.1", port: int = 8080):  # pragma: no cover
    """Mount the gateway on a blocking HTTP server (lab use only)."""
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # http.server API requires this exact name
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            response = gateway.handle_raw(body).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *_args):
            return

    httpd = HTTPServer((host, port), _Handler)
    httpd.serve_forever()


__all__ = ["Gateway", "serve"]
