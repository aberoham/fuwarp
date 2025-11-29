# Windows Refactoring Notes

This document tracks refactoring patterns applied to fuwarp.py that should
also be applied to fuwarp_windows.py for consistency.

## Known Unused Globals (Pending Cleanup)

The test suite has identified these unused global variables in fuwarp_windows.py:

- `ALT_CERT_NAMES` - defined but never used
- `SHELL_MODIFIED` - defined but never used (class uses `self.shell_modified`)
- `CERT_FINGERPRINT` - defined but never used (class uses `self.cert_fingerprint`)

These are tracked in the test file with a `known_unused` set to avoid test failures
until the Windows refactoring is complete.

## Patterns to Apply

### 1. Dead Code Removal
- Delete unused globals listed above
- Check for dead functions not in registry (similar to `setup_curl_cert` in fuwarp.py)

### 2. Helper Function Extraction (PR #29)
The `create_bundle_with_system_certs()` helper was implemented in fuwarp.py:
- Centralizes system CA bundle detection logic
- Returns bool to indicate if system certs were found
- Windows equivalent needed with different system paths:
  - Windows doesn't have `/etc/ssl/cert.pem` or `/etc/ssl/certs/ca-certificates.crt`
  - May need to use Windows Certificate Store APIs or certifi package
  - Consider using `certifi.where()` if available

### 3. Message Standardization (PR #29)
- Changed 16 occurrences of "Setting up X certificate" to "Configuring X certificate"
- Apply same pattern to fuwarp_windows.py for consistency
- Check with: `grep -n "Setting up" fuwarp_windows.py`

### 4. Exception Handling (PR #29)
- Replaced 28 bare `except:` with `except Exception:` in fuwarp.py
- Rationale: `except Exception:` catches all "normal" exceptions but allows:
  - `KeyboardInterrupt` (Ctrl+C) to propagate
  - `SystemExit` to propagate
- Apply same pattern to fuwarp_windows.py
- Check with: `grep -n "except:" fuwarp_windows.py | grep -v "Exception"`

### 5. Performance: Pure Python Certificate Matching (PR #30)
The `certificate_likely_exists_in_file()` function was refactored to use no subprocess calls:
- **Before**: Used `openssl x509 -subject` to extract CN, then string search (1 subprocess call)
- **After**: Pure Python extraction of first 100 chars of base64 content (0 subprocess calls)
- Apply same pattern to fuwarp_windows.py

The `certificate_exists_in_file()` function was simplified:
- **Before**: In install mode, iterated through all certs in bundle and compared fingerprints via openssl (O(N) subprocess calls)
- **After**: Delegates to `certificate_likely_exists_in_file()` for all modes (O(1), no subprocess)
- Rationale: Fast string matching is sufficient; false negatives (duplicate appended) are harmless

New regression tests added:
- `test_certificate_likely_exists_uses_no_subprocess`
- `test_no_subprocess_explosion_for_large_bundles`
- `test_safe_append_uses_fast_check`

### 6. Update Check Functionality (PR #31)
Added `check_for_updates()` method to compare local file hash against GitHub:
- Uses `ssl._create_unverified_context()` since WARP certificate might not be configured yet
- Fetches from `https://raw.githubusercontent.com/aberoham/fuwarp/main/fuwarp.py`
- Compares SHA256 hashes and warns user if update is available
- Apply same pattern to fuwarp_windows.py with appropriate URL

### 7. Connectivity-First Status Checks (PR #31)
The `check_gcloud_status()` function was improved to verify actual connectivity:
- **Before**: Flagged as issue if `core/custom_ca_certs_file` not configured
- **After**: First calls `verify_connection("gcloud")` to test actual connectivity
- If gcloud works (e.g., via system trust store), no issue is flagged
- Apply same pattern to fuwarp_windows.py

Added `verify_connection("gcloud")` handler:
- Runs `gcloud config list --format=value(core.account)` to test connectivity
- Distinguishes SSL errors from other errors (non-SSL errors = connectivity OK)
- Handles timeout gracefully

## Windows-Specific Considerations

- Windows uses different system certificate paths
- Registry-based configuration differs from file-based
- Some tools have different installation patterns on Windows
- `winreg` module is Windows-only (tests skip on other platforms)

## Related Issues

- See #27 for curl handling discussion (applies to both platforms)
