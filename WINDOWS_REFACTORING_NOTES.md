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

## Windows-Specific Considerations

- Windows uses different system certificate paths
- Registry-based configuration differs from file-based
- Some tools have different installation patterns on Windows
- `winreg` module is Windows-only (tests skip on other platforms)

## Related Issues

- See #27 for curl handling discussion (applies to both platforms)
