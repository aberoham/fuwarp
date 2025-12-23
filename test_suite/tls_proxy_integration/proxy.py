import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

from .helpers import clean_env


class MitmProxy:
    """Small mitmdump manager for TLS interception tests."""

    def __init__(self, workdir: Path):
        self.workdir = workdir
        self.confdir = workdir / "mitmproxy"
        self.log_path = workdir / "mitmdump.log"

        self.port: int | None = None
        self._process: subprocess.Popen | None = None
        self._log_handle = None

    @property
    def url(self) -> str:
        if self.port is None:
            raise RuntimeError("Proxy not started")
        return f"http://127.0.0.1:{self.port}"

    @property
    def ca_cert_path(self) -> Path:
        return self.confdir / "mitmproxy-ca-cert.pem"

    def start(self, timeout_seconds: float = 20.0) -> None:
        if self._process is not None:
            raise RuntimeError("Proxy already started")

        mitmdump_path = shutil.which("mitmdump")
        if not mitmdump_path:
            raise RuntimeError("mitmdump not found (install mitmproxy)")

        self.confdir.mkdir(parents=True, exist_ok=True)
        self.port = _find_free_port()

        cmd = [
            mitmdump_path,
            "--set", f"confdir={self.confdir}",
            "--listen-host", "127.0.0.1",
            "--listen-port", str(self.port),
            "--ssl-insecure",
            "-q",
        ]

        self._log_handle = open(self.log_path, "wb")

        env = clean_env(dict(os.environ))
        self._process = subprocess.Popen(
            cmd,
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
            env=env,
        )

        _wait_for_port("127.0.0.1", self.port, timeout_seconds)
        _wait_for_file(self.ca_cert_path, timeout_seconds)

    def stop(self) -> None:
        if self._process is None:
            return

        self._process.terminate()
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=5)

        self._process = None
        self.port = None

        if self._log_handle is not None:
            try:
                self._log_handle.close()
            finally:
                self._log_handle = None


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_for_port(host: str, port: int, timeout_seconds: float) -> None:
    start = time.monotonic()
    while time.monotonic() - start < timeout_seconds:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex((host, port)) == 0:
                return
        time.sleep(0.05)
    raise TimeoutError(f"mitmdump did not listen on {host}:{port} within {timeout_seconds}s")


def _wait_for_file(path: Path, timeout_seconds: float) -> None:
    start = time.monotonic()
    while time.monotonic() - start < timeout_seconds:
        try:
            if path.exists() and path.stat().st_size > 0:
                return
        except FileNotFoundError:
            pass
        time.sleep(0.05)
    raise TimeoutError(f"mitmdump did not generate CA cert at {path} within {timeout_seconds}s")

