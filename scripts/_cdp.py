"""A minimal Chrome DevTools Protocol client built on the standard library.

Chrome's `--screenshot` flag captures exactly the window height it is given.
The operator console's tabs range from roughly 1,700 to 8,400 CSS pixels tall,
so a single fixed window either clips the tall tabs or pads the short ones with
dead background. Capturing each tab at its own full height needs
Page.captureScreenshot, which is only reachable over the DevTools WebSocket.

Rather than add Playwright or Puppeteer -- a browser download measured in
hundreds of megabytes, for a repository whose experiments/ harness is
deliberately stdlib-only -- this speaks just enough of the protocol: the
WebSocket handshake, client-masked text frames, and request/response
correlation by id.

Not a general WebSocket implementation. It handles what Chrome sends on this
channel: text and binary frames, continuation frames, close, and ping. It does
not implement compression, which it declines during the handshake.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import struct
import subprocess
import tempfile
import time
import urllib.request
from contextlib import suppress
from pathlib import Path
from typing import Any

_OPCODE_CONTINUATION = 0x0
_OPCODE_TEXT = 0x1
_OPCODE_BINARY = 0x2
_OPCODE_CLOSE = 0x8
_OPCODE_PING = 0x9
_OPCODE_PONG = 0xA


class CdpError(RuntimeError):
    """Chrome returned an error for a command, or the channel broke."""


class WebSocket:
    """Client-side WebSocket speaking only what the DevTools endpoint needs."""

    def __init__(self, url: str, timeout: float = 30.0) -> None:
        if not url.startswith("ws://"):
            raise CdpError(f"expected a ws:// DevTools URL, got {url!r}")
        remainder = url[len("ws://") :]
        host_port, _, path = remainder.partition("/")
        host, _, port = host_port.partition(":")
        self._socket = socket.create_connection((host, int(port or 80)), timeout=timeout)
        self._socket.settimeout(timeout)
        self._buffer = b""

        key = base64.b64encode(os.urandom(16)).decode("ascii")
        handshake = (
            f"GET /{path} HTTP/1.1\r\n"
            f"Host: {host_port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        self._socket.sendall(handshake.encode("ascii"))

        while b"\r\n\r\n" not in self._buffer:
            chunk = self._socket.recv(4096)
            if not chunk:
                raise CdpError("DevTools closed the connection during the handshake")
            self._buffer += chunk
        header, _, rest = self._buffer.partition(b"\r\n\r\n")
        if b"101" not in header.split(b"\r\n")[0]:
            raise CdpError(f"DevTools refused the upgrade: {header.decode(errors='replace')[:200]}")
        self._buffer = rest

    def _read_exactly(self, count: int) -> bytes:
        while len(self._buffer) < count:
            chunk = self._socket.recv(65536)
            if not chunk:
                raise CdpError("DevTools closed the connection")
            self._buffer += chunk
        payload, self._buffer = self._buffer[:count], self._buffer[count:]
        return payload

    def send(self, text: str) -> None:
        payload = text.encode("utf-8")
        header = bytearray([0x80 | _OPCODE_TEXT])
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < (1 << 16):
            header.append(0x80 | 126)
            header += struct.pack("!H", length)
        else:
            header.append(0x80 | 127)
            header += struct.pack("!Q", length)
        mask = os.urandom(4)
        header += mask
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self._socket.sendall(bytes(header) + masked)

    def recv(self) -> str:
        """Return the next complete text message, reassembling continuations."""
        message = bytearray()
        while True:
            first, second = self._read_exactly(2)
            final = bool(first & 0x80)
            opcode = first & 0x0F
            length = second & 0x7F
            if length == 126:
                (length,) = struct.unpack("!H", self._read_exactly(2))
            elif length == 127:
                (length,) = struct.unpack("!Q", self._read_exactly(8))
            # The server never masks; tolerate it rather than assume.
            mask = self._read_exactly(4) if second & 0x80 else b""
            payload = self._read_exactly(length)
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

            if opcode == _OPCODE_CLOSE:
                raise CdpError("DevTools closed the channel")
            if opcode == _OPCODE_PING:
                self._socket.sendall(bytes([0x80 | _OPCODE_PONG, 0x80]) + os.urandom(4))
                continue
            if opcode == _OPCODE_PONG:
                continue
            if opcode in (_OPCODE_TEXT, _OPCODE_BINARY, _OPCODE_CONTINUATION):
                message += payload
                if final:
                    return message.decode("utf-8", errors="replace")

    def close(self) -> None:
        with suppress(OSError):
            self._socket.sendall(bytes([0x80 | _OPCODE_CLOSE, 0x80]) + os.urandom(4))
        with suppress(OSError):
            self._socket.close()


class Chrome:
    """A headless Chrome process plus a DevTools channel to its first tab."""

    def __init__(self, binary: str, width: int = 1600, height: int = 1000, scale: int = 2) -> None:
        self._profile = tempfile.mkdtemp(prefix="porygon-capture-")
        self._port = _free_port()
        self._scale = scale
        self._process = subprocess.Popen(
            [
                binary,
                "--headless=new",
                "--disable-gpu",
                "--hide-scrollbars",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-extensions",
                "--disable-background-networking",
                f"--user-data-dir={self._profile}",
                f"--remote-debugging-port={self._port}",
                f"--window-size={width},{height}",
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._socket = WebSocket(self._await_debugger_url())
        self._next_id = 0
        self.call("Page.enable")
        self.call("Runtime.enable")

    def _await_debugger_url(self, timeout: float = 30.0) -> str:
        deadline = time.monotonic() + timeout
        last: Exception | None = None
        while time.monotonic() < deadline:
            if self._process.poll() is not None:
                raise CdpError(f"Chrome exited with code {self._process.returncode}")
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{self._port}/json/list", timeout=2
                ) as response:
                    targets = json.loads(response.read())
                for target in targets:
                    if target.get("type") == "page" and target.get("webSocketDebuggerUrl"):
                        return target["webSocketDebuggerUrl"]
            except Exception as error:  # noqa: BLE001 - retried until the deadline
                last = error
            time.sleep(0.2)
        raise CdpError(f"Chrome DevTools never became reachable: {last}")

    def call(self, method: str, **params: Any) -> dict[str, Any]:
        self._next_id += 1
        request_id = self._next_id
        self._socket.send(json.dumps({"id": request_id, "method": method, "params": params}))
        while True:
            message = json.loads(self._socket.recv())
            if message.get("id") != request_id:
                continue  # an event, or a reply to an earlier command
            if "error" in message:
                raise CdpError(f"{method} failed: {message['error']}")
            return message.get("result", {})

    def set_viewport(self, width: int, height: int) -> None:
        self.call(
            "Emulation.setDeviceMetricsOverride",
            width=width,
            height=height,
            deviceScaleFactor=self._scale,
            mobile=False,
        )

    def navigate(self, url: str) -> None:
        self.call("Page.navigate", url=url)

    def evaluate(self, expression: str, await_promise: bool = True) -> Any:
        result = self.call(
            "Runtime.evaluate",
            expression=expression,
            awaitPromise=await_promise,
            returnByValue=True,
        )
        if result.get("exceptionDetails"):
            raise CdpError(f"evaluate failed: {result['exceptionDetails']}")
        return result.get("result", {}).get("value")

    def screenshot(self, path: Path, full_page: bool = True) -> int:
        result = self.call(
            "Page.captureScreenshot",
            format="png",
            captureBeyondViewport=full_page,
            optimizeForSpeed=False,
        )
        payload = base64.b64decode(result["data"])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return len(payload)

    def close(self) -> None:
        with suppress(Exception):
            self._socket.close()
        with suppress(Exception):
            self._process.terminate()
            self._process.wait(timeout=10)
        with suppress(Exception):
            import shutil

            shutil.rmtree(self._profile, ignore_errors=True)

    def __enter__(self) -> Chrome:
        return self

    def __exit__(self, *exception: object) -> None:
        self.close()


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
