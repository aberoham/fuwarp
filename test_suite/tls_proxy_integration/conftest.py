import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Generator

import pytest

from .helpers import CA_ENV_VARS, PROXY_ENV_VARS, can_passwordless_sudo, clean_env, read_exports
from .proxy import MitmProxy
from .fuwarp_runner import FuwarpRunner


TLS_PROXY_ENABLE_ENV = "FUWARP_RUN_TLS_PROXY_TESTS"

REPO_ROOT = Path(__file__).resolve().parents[2]
FUWARP_PATH = REPO_ROOT / "fuwarp.py"


@dataclass(frozen=True)
class IsolatedHome:
    root: Path
    home: Path
    bin_dir: Path

    @property
    def zshrc_path(self) -> Path:
        return self.home / ".zshrc"

    def base_env(self) -> dict[str, str]:
        env = clean_env(dict(os.environ))
        env["HOME"] = str(self.home)
        env["SHELL"] = "/bin/zsh"
        env["TMPDIR"] = str(self.root)

        existing_path = env.get("PATH", "")
        env["PATH"] = f"{self.bin_dir}{os.pathsep}{existing_path}" if existing_path else str(self.bin_dir)
        return env

    def read_exports(self) -> dict[str, str]:
        return read_exports(self.zshrc_path)


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "tls_proxy: TLS MITM integration tests (requires mitmproxy + network)",
    )
    config.addinivalue_line(
        "markers",
        "sudo: requires passwordless sudo for setup/cleanup",
    )


def pytest_collection_modifyitems(config, items):
    if os.environ.get(TLS_PROXY_ENABLE_ENV) != "1":
        skip_marker = pytest.mark.skip(
            reason=f"Set {TLS_PROXY_ENABLE_ENV}=1 to enable TLS proxy integration tests"
        )
        for item in items:
            item.add_marker(skip_marker)
        return

    if shutil.which("mitmdump") is None:
        skip_marker = pytest.mark.skip(reason="mitmproxy not installed (missing mitmdump)")
        for item in items:
            item.add_marker(skip_marker)


@pytest.fixture(scope="function")
def isolated_home(tmp_path: Path) -> IsolatedHome:
    root = tmp_path / "env"
    home = root / "home"
    bin_dir = root / "bin"

    home.mkdir(parents=True)
    bin_dir.mkdir(parents=True)

    # Pre-create typical shell config to match macOS defaults
    (home / ".zshrc").write_text("\n")
    (home / ".profile").write_text("\n")

    # Create fuwarp-managed directories up-front (not required, but helps debugging)
    (home / ".cloudflare-warp").mkdir(exist_ok=True)

    return IsolatedHome(root=root, home=home, bin_dir=bin_dir)


@pytest.fixture(scope="session")
def mitm_proxy(tmp_path_factory) -> Generator[MitmProxy, None, None]:
    workdir = tmp_path_factory.mktemp("mitmproxy")
    proxy = MitmProxy(Path(workdir))
    proxy.start()
    try:
        yield proxy
    finally:
        proxy.stop()


@pytest.fixture(scope="function")
def warp_ca_file(isolated_home: IsolatedHome, mitm_proxy: MitmProxy) -> Path:
    """A copy of the mitmproxy root CA, provided to fuwarp via --cert-file."""
    dest = isolated_home.home / "warp-ca.pem"
    dest.write_text(mitm_proxy.ca_cert_path.read_text())
    return dest


@pytest.fixture(scope="function")
def fuwarp(isolated_home: IsolatedHome) -> FuwarpRunner:
    assert FUWARP_PATH.exists(), f"Expected fuwarp.py at {FUWARP_PATH}"
    return FuwarpRunner(FUWARP_PATH, isolated_home.base_env())


@pytest.fixture(scope="session")
def network_available() -> bool:
    """Quick smoke check to avoid confusing failures when network is unavailable."""
    script = """
import sys
import urllib.request

try:
    with urllib.request.urlopen('https://example.com/', timeout=10) as r:
        sys.exit(0 if r.status < 400 else 1)
except Exception:
    sys.exit(1)
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.returncode == 0


@pytest.fixture(scope="function")
def require_network(network_available: bool):
    if not network_available:
        pytest.skip("network unavailable (cannot reach https://example.com/)")


@pytest.fixture(scope="session")
def sudo_available() -> bool:
    return can_passwordless_sudo()


@pytest.fixture(scope="function")
def require_sudo(sudo_available: bool):
    if not sudo_available:
        pytest.skip("passwordless sudo not available")


def build_clean_client_env(base_env: dict[str, str], extra_env: dict[str, str] | None = None) -> dict[str, str]:
    """Build a client env that won't accidentally inherit proxy/CA settings."""
    env = dict(base_env)
    for key in CA_ENV_VARS + PROXY_ENV_VARS:
        env.pop(key, None)
        env.pop(key.lower(), None)
    if extra_env:
        env.update(extra_env)
    return env

