import pytest

from .clients import run_python_requests, run_python_urllib
from .conftest import build_clean_client_env
from .helpers import bundle_contains_pem, count_pem_certificates


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


def test_python_baseline_direct_ok_proxy_fails_without_ca(
    require_network,
    isolated_home,
    mitm_proxy,
):
    env = build_clean_client_env(isolated_home.base_env())
    direct = run_python_requests(TARGET_URL, env)
    _assert_ok(direct, "python requests direct")

    proxied = run_python_requests(TARGET_URL, env, proxy_url=mitm_proxy.url)
    _assert_failed(proxied, "python requests via MITM (no CA trust)")


def test_python_suspicious_requests_ca_bundle_breaks_direct_but_proxy_ok_then_fuwarp_fixes(
    require_network,
    isolated_home,
    mitm_proxy,
    fuwarp,
    warp_ca_file,
):
    warp_only_bundle = isolated_home.home / "warp-only.pem"
    warp_only_bundle.write_text(warp_ca_file.read_text())

    bad_env = build_clean_client_env(
        isolated_home.base_env(),
        {"REQUESTS_CA_BUNDLE": str(warp_only_bundle)},
    )

    direct_bad = run_python_requests(TARGET_URL, bad_env)
    _assert_failed(direct_bad, "python requests direct (suspicious bundle)")

    proxied_bad = run_python_requests(TARGET_URL, bad_env, proxy_url=mitm_proxy.url)
    _assert_ok(proxied_bad, "python requests via MITM (suspicious bundle)")

    result = fuwarp.run_fix(
        ["python"],
        cert_file=warp_ca_file,
        extra_env={"REQUESTS_CA_BUNDLE": str(warp_only_bundle)},
    )
    assert result.returncode == 0, (
        f"fuwarp failed (rc={result.returncode})\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    python_bundle = isolated_home.home / ".python-ca-bundle.pem"
    assert python_bundle.exists(), "expected fuwarp to create ~/.python-ca-bundle.pem"

    bundle_text = python_bundle.read_text()
    assert count_pem_certificates(bundle_text) > 2
    assert python_bundle.stat().st_size > 50 * 1024
    assert bundle_contains_pem(bundle_text, warp_ca_file.read_text())

    exports = isolated_home.read_exports()
    assert exports.get("REQUESTS_CA_BUNDLE") == str(python_bundle)
    assert exports.get("SSL_CERT_FILE") == str(python_bundle)
    assert exports.get("CURL_CA_BUNDLE") == str(python_bundle)

    fixed_env = build_clean_client_env(
        isolated_home.base_env(),
        {"REQUESTS_CA_BUNDLE": str(python_bundle)},
    )
    direct_fixed = run_python_requests(TARGET_URL, fixed_env)
    _assert_ok(direct_fixed, "python requests direct (fixed bundle)")

    proxied_fixed = run_python_requests(TARGET_URL, fixed_env, proxy_url=mitm_proxy.url)
    _assert_ok(proxied_fixed, "python requests via MITM (fixed bundle)")


def test_python_ssl_cert_file_breaks_direct_but_proxy_ok_then_fuwarp_fixes(
    require_network,
    isolated_home,
    mitm_proxy,
    fuwarp,
    warp_ca_file,
):
    warp_only_bundle = isolated_home.home / "warp-only-ssl-cert-file.pem"
    warp_only_bundle.write_text(warp_ca_file.read_text())

    bad_env = build_clean_client_env(
        isolated_home.base_env(),
        {"SSL_CERT_FILE": str(warp_only_bundle)},
    )

    direct_bad = run_python_urllib(TARGET_URL, bad_env)
    _assert_failed(direct_bad, "python urllib direct (SSL_CERT_FILE=warp-only)")

    proxied_bad = run_python_urllib(TARGET_URL, bad_env, proxy_url=mitm_proxy.url)
    _assert_ok(proxied_bad, "python urllib via MITM (SSL_CERT_FILE=warp-only)")

    result = fuwarp.run_fix(
        ["python"],
        cert_file=warp_ca_file,
        extra_env={"SSL_CERT_FILE": str(warp_only_bundle)},
    )
    assert result.returncode == 0

    python_bundle = isolated_home.home / ".python-ca-bundle.pem"
    assert python_bundle.exists(), "expected fuwarp to create ~/.python-ca-bundle.pem"

    fixed_env = build_clean_client_env(
        isolated_home.base_env(),
        {"SSL_CERT_FILE": str(python_bundle)},
    )
    direct_fixed = run_python_urllib(TARGET_URL, fixed_env)
    _assert_ok(direct_fixed, "python urllib direct (fixed bundle)")

    proxied_fixed = run_python_urllib(TARGET_URL, fixed_env, proxy_url=mitm_proxy.url)
    _assert_ok(proxied_fixed, "python urllib via MITM (fixed bundle)")


def test_ghost_bundle_requests_ca_bundle_points_to_deleted_file_is_detected_and_recovers(
    require_network,
    isolated_home,
    mitm_proxy,
    fuwarp,
    warp_ca_file,
):
    ghost_path = isolated_home.root / "deleted_file.pem"
    assert not ghost_path.exists()

    bad_env = build_clean_client_env(
        isolated_home.base_env(),
        {"REQUESTS_CA_BUNDLE": str(ghost_path)},
    )

    direct_bad = run_python_requests(TARGET_URL, bad_env)
    _assert_failed(direct_bad, "python requests direct (ghost bundle)")

    # Even proxied will fail because REQUESTS_CA_BUNDLE overrides trust with a missing file.
    proxied_bad = run_python_requests(TARGET_URL, bad_env, proxy_url=mitm_proxy.url)
    _assert_failed(proxied_bad, "python requests via MITM (ghost bundle)")

    result = fuwarp.run_fix(
        ["python"],
        cert_file=warp_ca_file,
        extra_env={"REQUESTS_CA_BUNDLE": str(ghost_path)},
    )
    assert result.returncode == 0, (
        f"fuwarp failed (rc={result.returncode})\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "BROKEN ENVIRONMENT DETECTED" in (result.stdout + result.stderr)

    python_bundle = isolated_home.home / ".python-ca-bundle.pem"
    assert python_bundle.exists(), "expected fuwarp to create ~/.python-ca-bundle.pem"

    fixed_env = build_clean_client_env(
        isolated_home.base_env(),
        {"REQUESTS_CA_BUNDLE": str(python_bundle)},
    )

    direct_fixed = run_python_requests(TARGET_URL, fixed_env)
    _assert_ok(direct_fixed, "python requests direct (ghost bundle recovered)")

    proxied_fixed = run_python_requests(TARGET_URL, fixed_env, proxy_url=mitm_proxy.url)
    _assert_ok(proxied_fixed, "python requests via MITM (ghost bundle recovered)")


def test_empty_bundle_at_cloudflare_warp_python_bundle_is_regenerated(
    require_network,
    isolated_home,
    mitm_proxy,
    fuwarp,
    warp_ca_file,
):
    empty_bundle = isolated_home.home / ".cloudflare-warp" / "python" / "ca-bundle.pem"
    empty_bundle.parent.mkdir(parents=True, exist_ok=True)
    empty_bundle.write_bytes(b"")
    assert empty_bundle.exists() and empty_bundle.stat().st_size == 0

    result = fuwarp.run_fix(
        ["python"],
        cert_file=warp_ca_file,
        extra_env={"REQUESTS_CA_BUNDLE": str(empty_bundle)},
    )
    assert result.returncode == 0, (
        f"fuwarp failed (rc={result.returncode})\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    # When the user is already pointing at a fuwarp-managed path, prefer repairing it in-place.
    assert empty_bundle.stat().st_size > 50 * 1024
    assert count_pem_certificates(empty_bundle.read_text()) > 2

    fixed_env = build_clean_client_env(
        isolated_home.base_env(),
        {"REQUESTS_CA_BUNDLE": str(empty_bundle)},
    )
    direct_fixed = run_python_requests(TARGET_URL, fixed_env)
    _assert_ok(direct_fixed, "python requests direct (empty bundle regenerated)")

    proxied_fixed = run_python_requests(TARGET_URL, fixed_env, proxy_url=mitm_proxy.url)
    _assert_ok(proxied_fixed, "python requests via MITM (empty bundle regenerated)")


def test_permission_nightmare_chmod_000_bundle_is_recovered_via_user_path(
    require_network,
    isolated_home,
    mitm_proxy,
    fuwarp,
    warp_ca_file,
):
    protected = isolated_home.home / "protected.pem"
    protected.write_text(warp_ca_file.read_text())
    protected.chmod(0)

    result = fuwarp.run_fix(
        ["python"],
        cert_file=warp_ca_file,
        extra_env={"REQUESTS_CA_BUNDLE": str(protected)},
        stdin="y\n",
    )

    assert result.returncode == 0, (
        f"fuwarp failed (rc={result.returncode})\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    # fuwarp should suggest/choose a user-writable path under ~/.cloudflare-warp/python/
    expected_new_bundle = isolated_home.home / ".cloudflare-warp" / "python" / protected.name
    assert expected_new_bundle.exists()
    assert expected_new_bundle.stat().st_size > 50 * 1024
    assert count_pem_certificates(expected_new_bundle.read_text()) > 2

    fixed_env = build_clean_client_env(
        isolated_home.base_env(),
        {"REQUESTS_CA_BUNDLE": str(expected_new_bundle)},
    )
    direct_fixed = run_python_requests(TARGET_URL, fixed_env)
    _assert_ok(direct_fixed, "python requests direct (chmod 000 recovered)")

    proxied_fixed = run_python_requests(TARGET_URL, fixed_env, proxy_url=mitm_proxy.url)
    _assert_ok(proxied_fixed, "python requests via MITM (chmod 000 recovered)")
