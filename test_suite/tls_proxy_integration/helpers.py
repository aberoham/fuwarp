import os
from pathlib import Path


CA_ENV_VARS = (
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
)

PROXY_ENV_VARS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
)


def find_system_ca_bundle() -> Path | None:
    candidates = [
        Path("/etc/ssl/cert.pem"),
        Path("/etc/ssl/certs/ca-certificates.crt"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def read_exports(shell_config_path: Path) -> dict[str, str]:
    if not shell_config_path.exists():
        return {}

    exports: dict[str, str] = {}
    for raw_line in shell_config_path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("export "):
            continue

        key_value = line[len("export "):]
        if "=" not in key_value:
            continue

        key, value = key_value.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        exports[key] = value

    return exports


def count_pem_certificates(pem_text: str) -> int:
    return pem_text.count("-----BEGIN CERTIFICATE-----")


def pem_base64_prefix(pem_text: str, length: int = 100) -> str:
    lines: list[str] = []
    in_cert = False
    for raw_line in pem_text.splitlines():
        line = raw_line.strip()
        if "-----BEGIN CERTIFICATE-----" in line:
            in_cert = True
            continue
        if "-----END CERTIFICATE-----" in line:
            break
        if in_cert and line:
            lines.append(line)

    return "".join(lines)[:length]


def bundle_contains_pem(bundle_text: str, pem_text: str) -> bool:
    prefix = pem_base64_prefix(pem_text)
    if not prefix:
        return False
    return prefix in bundle_text


def clean_env(env: dict[str, str]) -> dict[str, str]:
    cleaned = dict(env)

    for key in CA_ENV_VARS + PROXY_ENV_VARS:
        cleaned.pop(key, None)
        cleaned.pop(key.lower(), None)

    # Avoid user-site leakage in CI and local runs
    cleaned.setdefault("PYTHONNOUSERSITE", "1")
    return cleaned


def can_passwordless_sudo() -> bool:
    try:
        # -n: never prompt (fail fast)
        result = os.system("sudo -n true >/dev/null 2>&1")
        return result == 0
    except Exception:
        return False

