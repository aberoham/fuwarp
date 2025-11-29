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

### 2. Helper Function Extraction
- Windows equivalent of `create_bundle_with_system_certs()` (once implemented in fuwarp.py)
- May need different system paths for Windows

### 3. Message Standardization
- Use "Configuring <tool> certificate..." consistently (not "Setting up")

### 4. Exception Handling
- Replace bare `except:` with specific exceptions like `subprocess.SubprocessError`

## Windows-Specific Considerations

- Windows uses different system certificate paths
- Registry-based configuration differs from file-based
- Some tools have different installation patterns on Windows
- `winreg` module is Windows-only (tests skip on other platforms)

## Related Issues

- See #27 for curl handling discussion (applies to both platforms)
