# TLS Proxy (MITM) Integration Tests

These tests exercise `fuwarp.py` end-to-end against a real TLS-intercepting proxy
(`mitmproxy`) to better approximate a real developer laptop running behind
Cloudflare WARP / Gateway TLS inspection.

They are **disabled by default** to avoid accidental slow/networked runs.

## Running

```bash
cd test_suite
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
uv pip install -r tls_proxy_integration/requirements.txt

FUWARP_RUN_TLS_PROXY_TESTS=1 python -m pytest tls_proxy_integration -v
```

## Notes

- Requires network access (uses `https://example.com/`).
- Requires `mitmdump` (installed via `mitmproxy`).
- Some tests are marked `xfail` to capture known permission/"sudo" pathologies
  that fuwarp does not fully fix yet.

