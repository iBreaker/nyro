#!/usr/bin/env python3
"""Local smoke test for nyro-server.

Covers:
- admin auth
- route-level API key auth
- OpenAI ingress (non-stream + stream)
- Anthropic ingress (stream event order)
- Gemini ingress (non-stream + stream)
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def assert_true(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def _decode_response(raw: bytes) -> Any:
    text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def http_request(
    method: str,
    url: str,
    payload: Any | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, Any]:
    req_headers = dict(headers or {})
    data = None
    if payload is not None:
        req_headers.setdefault("content-type", "application/json")
        data = json.dumps(payload).encode("utf-8")

    req = Request(url=url, method=method, data=data, headers=req_headers)
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return int(resp.status), _decode_response(raw)
    except HTTPError as e:
        raw = e.read()
        return int(e.code), _decode_response(raw)


def wait_until_ready(url: str, headers: dict[str, str], timeout_sec: float = 30.0) -> None:
    deadline = time.time() + timeout_sec
    last_error: str | None = None
    while time.time() < deadline:
        try:
            status, _ = http_request("GET", url, headers=headers, timeout=2.0)
            if status < 500:
                return
            last_error = f"status={status}"
        except (URLError, TimeoutError) as e:
            last_error = str(e)
        time.sleep(0.3)
    raise TimeoutError(f"server not ready: {url}, last_error={last_error}")


class MockProviderHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    request_log: list[dict[str, Any]] = []
    request_log_lock = threading.Lock()

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D401
        # Keep smoke output clean.
        return

    @classmethod
    def reset_requests(cls) -> None:
        with cls.request_log_lock:
            cls.request_log.clear()

    @classmethod
    def snapshot_requests(cls) -> list[dict[str, Any]]:
        with cls.request_log_lock:
            return list(cls.request_log)

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def _write_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.send_header("connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def _write_sse(self, events: list[tuple[str | None, dict[str, Any] | str]]) -> None:
        chunks: list[str] = []
        for event, data in events:
            if event is not None:
                chunks.append(f"event: {event}")
            if isinstance(data, str):
                chunks.append(f"data: {data}")
            else:
                chunks.append(f"data: {json.dumps(data)}")
            chunks.append("")
        text = "\n".join(chunks) + "\n"
        raw = text.encode("utf-8")

        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.send_header("connection", "close")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
        self.wfile.flush()

    def do_POST(self) -> None:  # noqa: N802
        body = self._read_json_body()
        path = urlsplit(self.path).path
        with self.request_log_lock:
            self.request_log.append(
                {
                    "path": path,
                    "raw_path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": body,
                }
            )

        # OpenAI upstream mock
        if path == "/v1/chat/completions":
            model = str(body.get("model", "mock-openai-model"))
            messages = body.get("messages") or []
            if body.get("stream"):
                self._write_sse(
                    [
                        (
                            None,
                            {
                                "id": "chatcmpl-mock",
                                "object": "chat.completion.chunk",
                                "model": model,
                                "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}],
                            },
                        ),
                        (
                            None,
                            {
                                "id": "chatcmpl-mock",
                                "object": "chat.completion.chunk",
                                "model": model,
                                "choices": [{"index": 0, "delta": {"content": "mock-"}, "finish_reason": None}],
                            },
                        ),
                        (
                            None,
                            {
                                "id": "chatcmpl-mock",
                                "object": "chat.completion.chunk",
                                "model": model,
                                "choices": [{"index": 0, "delta": {"content": "stream"}, "finish_reason": None}],
                            },
                        ),
                        (
                            None,
                            {
                                "id": "chatcmpl-mock",
                                "object": "chat.completion.chunk",
                                "model": model,
                                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                                "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
                            },
                        ),
                        (None, "[DONE]"),
                    ]
                )
                return

            if any(msg.get("role") == "tool" for msg in messages if isinstance(msg, dict)):
                self._write_json(
                    200,
                    {
                        "id": "chatcmpl-mock-tool-result",
                        "object": "chat.completion",
                        "model": model,
                        "choices": [
                            {
                                "index": 0,
                                "message": {"role": "assistant", "content": "mock-tool-result"},
                                "finish_reason": "stop",
                            }
                        ],
                        "usage": {"prompt_tokens": 19, "completion_tokens": 5, "total_tokens": 24},
                    },
                )
                return

            if body.get("tools"):
                self._write_json(
                    200,
                    {
                        "id": "chatcmpl-mock-tool-call",
                        "object": "chat.completion",
                        "model": model,
                        "choices": [
                            {
                                "index": 0,
                                "message": {
                                    "role": "assistant",
                                    "content": "",
                                    "tool_calls": [
                                        {
                                            "id": "call_mock_weather",
                                            "type": "function",
                                            "function": {
                                                "name": "get_weather",
                                                "arguments": json.dumps({"city": "Hangzhou"}),
                                            },
                                        }
                                    ],
                                },
                                "finish_reason": "tool_calls",
                            }
                        ],
                        "usage": {"prompt_tokens": 17, "completion_tokens": 6, "total_tokens": 23},
                    },
                )
                return

            self._write_json(
                200,
                {
                    "id": "chatcmpl-mock",
                    "object": "chat.completion",
                    "model": model,
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "mock-openai"},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
                },
            )
            return

        # Anthropic upstream mock
        if path == "/v1/messages":
            model = str(body.get("model", "claude-mock"))
            if body.get("stream"):
                self._write_sse(
                    [
                        (
                            "message_start",
                            {
                                "type": "message_start",
                                "message": {
                                    "id": "msg_mock_1",
                                    "type": "message",
                                    "role": "assistant",
                                    "content": [],
                                    "model": model,
                                    "stop_reason": None,
                                    "usage": {"input_tokens": 9, "output_tokens": 0},
                                },
                            },
                        ),
                        (
                            "content_block_start",
                            {
                                "type": "content_block_start",
                                "index": 0,
                                "content_block": {"type": "text", "text": ""},
                            },
                        ),
                        (
                            "content_block_delta",
                            {
                                "type": "content_block_delta",
                                "index": 0,
                                "delta": {"type": "text_delta", "text": "mock-anthropic"},
                            },
                        ),
                        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
                        (
                            "message_delta",
                            {
                                "type": "message_delta",
                                "delta": {"stop_reason": "end_turn"},
                                "usage": {"output_tokens": 6},
                            },
                        ),
                        ("message_stop", {"type": "message_stop"}),
                    ]
                )
                return

            self._write_json(
                200,
                {
                    "id": "msg_mock_1",
                    "type": "message",
                    "role": "assistant",
                    "model": model,
                    "content": [{"type": "text", "text": "mock-anthropic"}],
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 9, "output_tokens": 6},
                },
            )
            return

        # Gemini upstream mock
        if path.startswith("/v1beta/models/"):
            if path.endswith(":streamGenerateContent"):
                self._write_sse(
                    [
                        (
                            None,
                            {
                                "modelVersion": "gemini-2.0-flash",
                                "candidates": [
                                    {
                                        "content": {"parts": [{"text": "mock-gemini-stream"}]},
                                        "finishReason": "STOP",
                                    }
                                ],
                                "usageMetadata": {
                                    "promptTokenCount": 8,
                                    "candidatesTokenCount": 5,
                                    "totalTokenCount": 13,
                                },
                            },
                        )
                    ]
                )
                return

            self._write_json(
                200,
                {
                    "modelVersion": "gemini-2.0-flash",
                    "candidates": [
                        {
                            "content": {"role": "model", "parts": [{"text": "mock-gemini"}]},
                            "finishReason": "STOP",
                        }
                    ],
                    "usageMetadata": {
                        "promptTokenCount": 8,
                        "candidatesTokenCount": 5,
                        "totalTokenCount": 13,
                    },
                },
            )
            return

        self._write_json(404, {"error": f"unknown path: {path}"})


def start_mock_server(port: int) -> tuple[ThreadingHTTPServer, threading.Thread]:
    httpd = ThreadingHTTPServer(("127.0.0.1", port), MockProviderHandler)
    t = threading.Thread(target=httpd.serve_forever, name="mock-provider", daemon=True)
    t.start()
    return httpd, t


def run_smoke() -> None:
    admin_key = "smoke-admin-key"
    mock_port = find_free_port()
    proxy_port = find_free_port()
    admin_port = find_free_port()

    mock_httpd, mock_thread = start_mock_server(mock_port)
    logs: list[str] = []
    proc: subprocess.Popen[str] | None = None
    log_thread: threading.Thread | None = None

    try:
        with tempfile.TemporaryDirectory(prefix="nyro-smoke-") as data_dir:
            cmd = [
                "cargo",
                "run",
                "-p",
                "nyro-server",
                "--",
                "--proxy-host",
                "127.0.0.1",
                "--proxy-port",
                str(proxy_port),
                "--admin-host",
                "127.0.0.1",
                "--admin-port",
                str(admin_port),
                "--data-dir",
                data_dir,
                "--admin-key",
                admin_key,
                "--webui-dir",
                "./webui/dist",
            ]

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=str(Path(__file__).resolve().parents[2]),
                env=dict(os.environ),
            )

            def _drain() -> None:
                assert proc is not None
                if proc.stdout is None:
                    return
                for line in proc.stdout:
                    logs.append(line.rstrip("\n"))

            log_thread = threading.Thread(target=_drain, name="nyro-server-log", daemon=True)
            log_thread.start()

            admin_base = f"http://127.0.0.1:{admin_port}"
            proxy_base = f"http://127.0.0.1:{proxy_port}"
            mock_base = f"http://127.0.0.1:{mock_port}"
            admin_headers = {"authorization": f"Bearer {admin_key}"}
            proxy_headers: dict[str, str] = {}

            wait_until_ready(f"{admin_base}/api/v1/status", headers=admin_headers, timeout_sec=40)

            # Admin auth must reject anonymous access.
            status, _ = http_request("GET", f"{admin_base}/api/v1/status")
            assert_true(status == 401, f"expected admin 401 without token, got {status}")

            # Create providers.
            provider_ids: dict[str, str] = {}
            for protocol, name in [
                ("openai", "mock-openai"),
                ("anthropic", "mock-anthropic"),
                ("gemini", "mock-gemini"),
            ]:
                status, resp = http_request(
                    "POST",
                    f"{admin_base}/api/v1/providers",
                    payload={
                        "name": name,
                        "protocol": protocol,
                        "base_url": mock_base,
                        "api_key": "upstream-secret",
                    },
                    headers=admin_headers,
                )
                assert_true(status == 200, f"create provider {protocol} failed: {status} {resp}")
                provider_ids[protocol] = resp["data"]["id"]

            # Create routes.
            routes = [
                ("nyro-chat", "nyro-chat", provider_ids["openai"], "gpt-mock"),
                ("nyro-claude", "nyro-claude", provider_ids["anthropic"], "claude-mock"),
                ("gemini-2.0-flash", "gemini-2.0-flash", provider_ids["gemini"], "gemini-2.0-flash"),
            ]
            route_ids: list[str] = []
            for name, virtual_model, target_provider, target_model in routes:
                status, resp = http_request(
                    "POST",
                    f"{admin_base}/api/v1/routes",
                    payload={
                        "name": name,
                        "virtual_model": virtual_model,
                        "target_provider": target_provider,
                        "target_model": target_model,
                        "access_control": True,
                    },
                    headers=admin_headers,
                )
                assert_true(status == 200, f"create route {name} failed: {status} {resp}")
                route_ids.append(resp["data"]["id"])

            # Access-controlled route must reject anonymous access.
            status, _ = http_request(
                "POST",
                f"{proxy_base}/v1/chat/completions",
                payload={"model": "nyro-chat", "messages": [{"role": "user", "content": "hi"}]},
            )
            assert_true(status == 401, f"expected route auth 401 without api key, got {status}")

            # Create API key (explicitly bind allowed routes).
            status, key_resp = http_request(
                "POST",
                f"{admin_base}/api/v1/api-keys",
                payload={"name": "smoke-key", "route_ids": route_ids},
                headers=admin_headers,
            )
            assert_true(status == 200, f"create api key failed: {status} {key_resp}")
            proxy_key = key_resp["data"]["key"]
            proxy_headers = {"authorization": f"Bearer {proxy_key}"}

            # OpenAI non-stream
            status, resp = http_request(
                "POST",
                f"{proxy_base}/v1/chat/completions",
                payload={"model": "nyro-chat", "messages": [{"role": "user", "content": "hello"}]},
                headers=proxy_headers,
            )
            assert_true(status == 200, f"openai non-stream failed: {status} {resp}")
            content = resp["choices"][0]["message"]["content"]
            assert_true(content == "mock-openai", f"unexpected openai content: {content}")

            # OpenAI stream
            status, stream_text = http_request(
                "POST",
                f"{proxy_base}/v1/chat/completions",
                payload={"model": "nyro-chat", "stream": True, "messages": [{"role": "user", "content": "hello"}]},
                headers=proxy_headers,
                timeout=15.0,
            )
            assert_true(status == 200, f"openai stream failed: {status} {stream_text}")
            stream_text_s = str(stream_text)
            assert_true("[DONE]" in stream_text_s, "openai stream missing [DONE]")
            assert_true("mock-" in stream_text_s and "stream" in stream_text_s, "openai stream missing text deltas")

            # OpenAI Responses non-stream
            MockProviderHandler.reset_requests()
            status, resp = http_request(
                "POST",
                f"{proxy_base}/v1/responses",
                payload={"model": "nyro-chat", "input": "hello from responses"},
                headers=proxy_headers,
            )
            assert_true(status == 200, f"responses non-stream failed: {status} {resp}")
            assert_true(resp["object"] == "response", f"unexpected responses object: {resp}")
            assert_true(resp["output_text"] == "mock-openai", f"unexpected responses text: {resp}")
            requests = MockProviderHandler.snapshot_requests()
            assert_true(len(requests) == 1, f"expected 1 upstream request for responses, got {len(requests)}")
            upstream_req = requests[0]
            assert_true(
                upstream_req["path"] == "/v1/chat/completions",
                f"responses upstream path mismatch: {upstream_req['path']}",
            )
            assert_true(
                upstream_req["body"].get("model") == "gpt-mock",
                f"responses upstream model mismatch: {upstream_req['body']}",
            )

            # OpenAI Responses stream
            MockProviderHandler.reset_requests()
            status, resp_stream = http_request(
                "POST",
                f"{proxy_base}/v1/responses",
                payload={"model": "nyro-chat", "stream": True, "input": "hello from responses"},
                headers=proxy_headers,
                timeout=15.0,
            )
            assert_true(status == 200, f"responses stream failed: {status} {resp_stream}")
            resp_stream_text = str(resp_stream)
            assert_true(
                "event: response.output_text.delta" in resp_stream_text,
                "responses stream missing output_text.delta",
            )
            assert_true("event: response.completed" in resp_stream_text, "responses stream missing completed")
            assert_true("[DONE]" in resp_stream_text, "responses stream missing [DONE]")

            # OpenAI Responses tool call round-trip
            MockProviderHandler.reset_requests()
            status, tool_resp = http_request(
                "POST",
                f"{proxy_base}/v1/responses",
                payload={
                    "model": "nyro-chat",
                    "input": "check weather",
                    "tools": [
                        {
                            "type": "function",
                            "name": "get_weather",
                            "description": "Get current weather",
                            "parameters": {
                                "type": "object",
                                "properties": {"city": {"type": "string"}},
                                "required": ["city"],
                            },
                        }
                    ],
                },
                headers=proxy_headers,
            )
            assert_true(status == 200, f"responses tool call failed: {status} {tool_resp}")
            tool_items = [item for item in tool_resp["output"] if item.get("type") == "function_call"]
            assert_true(len(tool_items) == 1, f"expected one function_call item, got {tool_resp}")
            tool_item = tool_items[0]
            assert_true(tool_item["name"] == "get_weather", f"unexpected tool name: {tool_item}")
            requests = MockProviderHandler.snapshot_requests()
            assert_true(len(requests) == 1, f"expected one upstream tool request, got {len(requests)}")
            upstream_tool_req = requests[0]["body"]
            assert_true(upstream_tool_req.get("model") == "gpt-mock", f"tool request model mismatch: {upstream_tool_req}")
            upstream_tools = upstream_tool_req.get("tools") or []
            assert_true(len(upstream_tools) == 1, f"expected one upstream tool def, got {upstream_tool_req}")
            assert_true(
                upstream_tools[0].get("function", {}).get("name") == "get_weather",
                f"upstream tool name mismatch: {upstream_tools}",
            )

            MockProviderHandler.reset_requests()
            status, tool_result_resp = http_request(
                "POST",
                f"{proxy_base}/v1/responses",
                payload={
                    "model": "nyro-chat",
                    "input": [
                        {
                            "type": "message",
                            "role": "user",
                            "content": [{"type": "input_text", "text": "check weather"}],
                        },
                        tool_item,
                        {
                            "type": "function_call_output",
                            "call_id": tool_item["call_id"],
                            "output": json.dumps({"city": "Hangzhou", "temp_c": 23}),
                        },
                    ],
                },
                headers=proxy_headers,
            )
            assert_true(status == 200, f"responses tool result failed: {status} {tool_result_resp}")
            assert_true(
                tool_result_resp["output_text"] == "mock-tool-result",
                f"unexpected tool result response: {tool_result_resp}",
            )
            requests = MockProviderHandler.snapshot_requests()
            assert_true(len(requests) == 1, f"expected one upstream tool result request, got {len(requests)}")
            upstream_messages = requests[0]["body"].get("messages") or []
            assert_true(
                any(msg.get("role") == "tool" for msg in upstream_messages if isinstance(msg, dict)),
                f"upstream tool result message missing tool role: {upstream_messages}",
            )

            # Anthropic stream
            status, anth_stream = http_request(
                "POST",
                f"{proxy_base}/v1/messages",
                payload={
                    "model": "nyro-claude",
                    "max_tokens": 64,
                    "stream": True,
                    "messages": [{"role": "user", "content": "hello"}],
                },
                headers={
                    **proxy_headers,
                    "anthropic-version": "2023-06-01",
                },
                timeout=15.0,
            )
            assert_true(status == 200, f"anthropic stream failed: {status} {anth_stream}")
            anth_text = str(anth_stream)
            pos_msg_start = anth_text.find("event: message_start")
            pos_block_start = anth_text.find("event: content_block_start")
            assert_true(pos_msg_start >= 0, "anthropic stream missing message_start")
            assert_true(pos_block_start >= 0, "anthropic stream missing content_block_start")
            assert_true(
                pos_msg_start < pos_block_start,
                "anthropic stream event order invalid: content_block_start before message_start",
            )
            assert_true("mock-anthropic" in anth_text, "anthropic stream missing text delta")

            # Gemini non-stream
            status, gem_resp = http_request(
                "POST",
                f"{proxy_base}/v1beta/models/gemini-2.0-flash:generateContent",
                payload={"contents": [{"role": "user", "parts": [{"text": "hello"}]}]},
                headers=proxy_headers,
            )
            assert_true(status == 200, f"gemini non-stream failed: {status} {gem_resp}")
            gem_text = gem_resp["candidates"][0]["content"]["parts"][0]["text"]
            assert_true(gem_text == "mock-gemini", f"unexpected gemini text: {gem_text}")

            # Gemini stream
            status, gem_stream = http_request(
                "POST",
                f"{proxy_base}/v1beta/models/gemini-2.0-flash:streamGenerateContent?alt=sse",
                payload={"contents": [{"role": "user", "parts": [{"text": "hello"}]}]},
                headers=proxy_headers,
                timeout=15.0,
            )
            assert_true(status == 200, f"gemini stream failed: {status} {gem_stream}")
            assert_true("mock-gemini-stream" in str(gem_stream), "gemini stream missing text delta")

            # Logs should exist after traffic.
            total_logs = 0
            for _ in range(20):
                status, logs_resp = http_request(
                    "GET",
                    f"{admin_base}/api/v1/logs?limit=20&offset=0",
                    headers=admin_headers,
                )
                assert_true(status == 200, f"query logs failed: {status} {logs_resp}")
                total_logs = int(logs_resp["data"]["total"])
                if total_logs >= 3:
                    break
                time.sleep(0.3)
            assert_true(total_logs >= 3, f"expected log entries after traffic, got {total_logs}")

            print(
                "Smoke test passed: admin auth + route API key auth + OpenAI/Responses/Anthropic/Gemini flows"
            )

    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)

        if log_thread is not None:
            log_thread.join(timeout=1)

        mock_httpd.shutdown()
        mock_httpd.server_close()
        mock_thread.join(timeout=1)

        if proc is not None and proc.returncode not in (0, None, -15):
            tail = "\n".join(logs[-120:])
            print("\n--- nyro-server logs (tail) ---", file=sys.stderr)
            print(tail, file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run nyro-server smoke tests")
    _ = parser.parse_args()
    run_smoke()
    return 0


if __name__ == "__main__":
    sys.exit(main())
