import shutil
import subprocess
from pathlib import Path

import pytest

from .clients import run_node_https
from .conftest import build_clean_client_env
from .helpers import bundle_contains_pem


TARGET_URL = "https://example.com/"

pytestmark = pytest.mark.tls_proxy


def _assert_ok(result, label: str) -> None:
    assert result.returncode == 0, (
        f"{label} failed (rc={result.returncode})\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )


def _assert_failed(result, label: str) -> None:
    assert result.returncode != 0, (
        f"{label} unexpectedly succeeded\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )


@pytest.fixture(autouse=True)
def require_node():
    if shutil.which("node") is None:
        pytest.skip("node not installed")


def test_node_baseline_direct_ok_proxy_fails_without_extra_ca(
    require_network,
    isolated_home,
    mitm_proxy,
):
    env = build_clean_client_env(isolated_home.base_env())
    direct = run_node_https(TARGET_URL, env)
    _assert_ok(direct, "node direct")

    proxied = run_node_https(
        TARGET_URL,
        env,
        proxy_host="127.0.0.1",
        proxy_port=mitm_proxy.port,
    )
    _assert_failed(proxied, "node via MITM (no NODE_EXTRA_CA_CERTS)")


def test_node_succeeds_after_fuwarp_sets_node_extra_ca_certs(
    require_network,
    isolated_home,
    mitm_proxy,
    fuwarp,
    warp_ca_file,
):
    result = fuwarp.run_fix(["node"], cert_file=warp_ca_file)
    assert result.returncode == 0, (
        f"fuwarp failed (rc={result.returncode})\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    exports = isolated_home.read_exports()
    node_extra = exports.get("NODE_EXTRA_CA_CERTS")
    assert node_extra, "expected fuwarp to export NODE_EXTRA_CA_CERTS"

    node_extra_path = Path(node_extra)

    assert node_extra_path.exists(), f"NODE_EXTRA_CA_CERTS path does not exist: {node_extra_path}"
    assert bundle_contains_pem(node_extra_path.read_text(), warp_ca_file.read_text())

    env = build_clean_client_env(
        isolated_home.base_env(),
        {"NODE_EXTRA_CA_CERTS": str(node_extra_path)},
    )

    direct = run_node_https(TARGET_URL, env)
    _assert_ok(direct, "node direct (after fuwarp)")

    proxied = run_node_https(
        TARGET_URL,
        env,
        proxy_host="127.0.0.1",
        proxy_port=mitm_proxy.port,
    )
    _assert_ok(proxied, "node via MITM (after fuwarp)")


def _run_npm(env: dict[str, str], *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["npm", *args],
        capture_output=True,
        text=True,
        env=dict(env),
        timeout=60,
    )


def test_conflicting_config_npm_cafile_and_node_extra_ca_certs_is_aligned(
    isolated_home,
    fuwarp,
    warp_ca_file,
):
    if shutil.which("npm") is None:
        pytest.skip("npm not installed")

    base_env = isolated_home.base_env()

    node_extra_path = isolated_home.home / "node-extra.pem"
    node_extra_path.write_text(warp_ca_file.read_text())

    npm_cafile_path = isolated_home.home / "npm-cafile.pem"
    npm_cafile_path.write_text(warp_ca_file.read_text())

    set_result = _run_npm(base_env, "config", "set", "cafile", str(npm_cafile_path))
    assert set_result.returncode == 0, f"npm config set failed: {set_result.stderr}"

    before = _run_npm(base_env, "config", "get", "cafile")
    assert before.returncode == 0
    assert before.stdout.strip() == str(npm_cafile_path)

    result = fuwarp.run_fix(
        ["node"],
        cert_file=warp_ca_file,
        extra_env={"NODE_EXTRA_CA_CERTS": str(node_extra_path)},
        stdin="y\n" * 5,
    )
    assert result.returncode == 0, (
        f"fuwarp failed (rc={result.returncode})\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    after = _run_npm(base_env, "config", "get", "cafile")
    assert after.returncode == 0
    managed = isolated_home.home / ".cloudflare-warp" / "npm" / "ca-bundle.pem"
    assert after.stdout.strip() == str(managed)

    assert managed.exists()
    assert managed.stat().st_size > 50 * 1024
    assert bundle_contains_pem(managed.read_text(), warp_ca_file.read_text())


def test_stale_shell_node_extra_ca_certs_is_commented_and_updated(
    isolated_home,
    fuwarp,
    warp_ca_file,
):
    zshrc = isolated_home.zshrc_path
    old_path = "/old/broken/path.pem"
    zshrc.write_text(f'export NODE_EXTRA_CA_CERTS="{old_path}"\n')

    result = fuwarp.run_fix(
        ["node"],
        cert_file=warp_ca_file,
        stdin="y\n" * 10,
    )
    assert result.returncode == 0, (
        f"fuwarp failed (rc={result.returncode})\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    text = zshrc.read_text().splitlines()
    active = [line for line in text if line.strip().startswith("export NODE_EXTRA_CA_CERTS=")]
    commented = [line for line in text if line.strip().startswith("#export NODE_EXTRA_CA_CERTS=")]

    assert len(active) == 1
    assert len(commented) >= 1
    assert old_path in "\n".join(commented)

    expected_bundle = isolated_home.home / ".cloudflare-warp" / "node" / "ca-bundle.pem"
    assert str(expected_bundle) in active[0]

    assert (isolated_home.home / ".zshrc.bak").exists()
