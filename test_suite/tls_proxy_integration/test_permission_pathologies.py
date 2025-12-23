import os
import platform
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from .clients import run_python_requests
from .conftest import build_clean_client_env
from .helpers import bundle_contains_pem, find_system_ca_bundle


TARGET_URL = "https://example.com/"

pytestmark = pytest.mark.tls_proxy


def _assert_ok(result, label: str) -> None:
    assert result.returncode == 0, (
        f"{label} failed (rc={result.returncode})\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )


@pytest.mark.sudo
def test_requests_ca_bundle_root_owned_file_is_repointed_to_user_writable_copy(
    require_network,
    require_sudo,
    isolated_home,
    mitm_proxy,
    fuwarp,
    warp_ca_file,
):
    system_bundle = find_system_ca_bundle()
    if system_bundle is None:
        pytest.skip("system CA bundle not found")

    locked_bundle = isolated_home.root / "locked-system-ca.pem"
    shutil.copy(system_bundle, locked_bundle)

    # Make it root-owned so the non-root test user can't write (simulates prior sudo run)
    owner = "root:wheel" if platform.system() == "Darwin" else "root:root"
    subprocess.run(["sudo", "chown", owner, str(locked_bundle)], check=True)

    assert not os.access(locked_bundle, os.W_OK)

    result = fuwarp.run_fix(
        ["python"],
        cert_file=warp_ca_file,
        extra_env={"REQUESTS_CA_BUNDLE": str(locked_bundle)},
        stdin="y\n",
    )
    assert result.returncode == 0, (
        f"fuwarp failed (rc={result.returncode})\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    expected_new_bundle = isolated_home.home / ".cloudflare-warp" / "python" / locked_bundle.name
    assert expected_new_bundle.exists(), "expected fuwarp to create a user-writable copy"

    new_text = expected_new_bundle.read_text()
    assert bundle_contains_pem(new_text, warp_ca_file.read_text())

    exports = isolated_home.read_exports()
    assert exports.get("REQUESTS_CA_BUNDLE") == str(expected_new_bundle)

    fixed_env = build_clean_client_env(
        isolated_home.base_env(),
        {"REQUESTS_CA_BUNDLE": str(expected_new_bundle)},
    )
    direct_fixed = run_python_requests(TARGET_URL, fixed_env)
    _assert_ok(direct_fixed, "python requests direct (root-owned bundle repointed)")

    proxied_fixed = run_python_requests(TARGET_URL, fixed_env, proxy_url=mitm_proxy.url)
    _assert_ok(proxied_fixed, "python requests via MITM (root-owned bundle repointed)")


def test_managed_python_bundle_unwritable_should_fall_back_to_alternative_path(
    require_network,
    isolated_home,
    mitm_proxy,
    fuwarp,
    warp_ca_file,
):
    system_bundle = find_system_ca_bundle()
    if system_bundle is None:
        pytest.skip("system CA bundle not found")

    managed_bundle = isolated_home.home / ".python-ca-bundle.pem"
    shutil.copy(system_bundle, managed_bundle)
    managed_bundle.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    assert not os.access(managed_bundle, os.W_OK)

    result = fuwarp.run_fix(["python"], cert_file=warp_ca_file)
    assert result.returncode == 0

    expected_fallback = isolated_home.home / ".cloudflare-warp" / "python" / managed_bundle.name
    assert expected_fallback.exists(), "expected fuwarp to avoid using an unwritable managed bundle"

    fixed_env = build_clean_client_env(
        isolated_home.base_env(),
        {"REQUESTS_CA_BUNDLE": str(expected_fallback)},
    )
    direct_fixed = run_python_requests(TARGET_URL, fixed_env)
    _assert_ok(direct_fixed, "python requests direct (fallback bundle)")

    proxied_fixed = run_python_requests(TARGET_URL, fixed_env, proxy_url=mitm_proxy.url)
    _assert_ok(proxied_fixed, "python requests via MITM (fallback bundle)")


def test_java_keytool_permission_failure_is_surfaceable(
    isolated_home,
    fuwarp,
    warp_ca_file,
):
    if shutil.which("java") is None:
        pytest.skip("java not installed")

    # Fake keytool to simulate permission errors from modifying system cacerts.
    keytool_path = isolated_home.bin_dir / "keytool"
    keytool_path.write_text(
        "#!/bin/sh\n"
        "echo 'keytool error: java.io.FileNotFoundException: cacerts (Permission denied)' 1>&2\n"
        "exit 1\n"
    )
    keytool_path.chmod(0o755)

    result = fuwarp.run_fix(
        ["java"],
        cert_file=warp_ca_file,
        extra_env={"PATH": f"{isolated_home.bin_dir}{os.pathsep}{isolated_home.base_env().get('PATH','')}"},
    )

    # fuwarp currently warns but still exits 0.
    assert result.returncode == 0
    combined = (result.stdout + result.stderr)
    assert "Failed to add certificate to Java keystore" in combined


@pytest.mark.xfail(reason="fuwarp does not yet recover from sudo-owned ~/.cloudflare-ca.pem")
def test_cert_path_unwritable_should_not_hard_fail(
    isolated_home,
    fuwarp,
    warp_ca_file,
):
    cert_path = isolated_home.home / ".cloudflare-ca.pem"
    cert_path.write_text("dummy")
    cert_path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    assert not os.access(cert_path, os.W_OK)

    result = fuwarp.run_fix(["python"], cert_file=warp_ca_file)
    assert result.returncode == 0, (
        "Expected fuwarp to handle unwritable CERT_PATH gracefully (e.g., suggest a user-writable path)"
    )


def test_environment_sanity_warns_on_missing_ca_paths(
    isolated_home,
    fuwarp,
):
    missing = isolated_home.home / "definitely-missing.pem"
    assert not missing.exists()

    result = fuwarp.run_status(
        ["python"],
        extra_env={
            "SSL_CERT_FILE": str(missing),
            "REQUESTS_CA_BUNDLE": str(missing),
            "CURL_CA_BUNDLE": str(missing),
        },
    )

    combined = (result.stdout + result.stderr)
    assert "BROKEN ENVIRONMENT DETECTED" in combined
    assert "SSL_CERT_FILE" in combined
    assert "REQUESTS_CA_BUNDLE" in combined
    assert "CURL_CA_BUNDLE" in combined
