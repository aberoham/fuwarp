# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

fuwarp (Cloudflare WARP Certificate Fixer Upper) is a Python script that automatically fixes TLS certificate trust issues when using Cloudflare WARP with TLS decryption. The script configures various development tools to trust WARP's Gateway CA certificate.

## Key Commands

### Running the Script

```bash
# Check current certificate status (no changes made)
./fuwarp.py

# Actually install/update certificates (makes changes)
./fuwarp.py --fix

# Run with detailed debug output for troubleshooting
./fuwarp.py --debug
./fuwarp.py --debug --fix  # Debug mode with fixes

# Show help
./fuwarp.py --help

# Show version information
./fuwarp.py --version

# List all available tools and their tags
./fuwarp.py --list-tools

# Check/fix specific tools only
./fuwarp.py --tools node --tools python  # Check Node.js and Python only
./fuwarp.py --fix --tools node-npm,gcloud  # Fix Node.js/npm and gcloud only
./fuwarp.py --fix --tools java,db  # Fix Java and database tools using tags
```

### Testing

The project has a pytest-based test suite in `test_suite/`:

```bash
# Run all tests
cd test_suite
source .venv/bin/activate  # or create with: uv venv && uv pip install -r requirements.txt
python -m pytest test_fuwarp_integration.py -v

# Run specific test classes
python -m pytest test_fuwarp_integration.py::TestStatusFunctionContracts -v
python -m pytest test_fuwarp_integration.py::TestCodeQuality -v
```

Key test categories:
- **TestCertificateManagement**: Certificate download and validation
- **TestToolSetup**: Tool-specific certificate setup workflows
- **TestStatusFunctionContracts**: Ensures all `check_*_status()` functions return booleans
- **TestCodeQuality**: Static analysis tests that enforce code standards:
  - No unsafe certificate appends (use `safe_append_certificate()`)
  - No unused global variables
  - Consistent messaging ("Configuring" not "Setting up")
  - No bare `except:` clauses (use `except Exception:`)
- **TestBundleCreation**: Tests for `create_bundle_with_system_certs()` helper
- **TestCertificateAppending**: Tests for safe PEM file handling (issue #13 fix)

## Architecture Overview

The script follows a modular architecture with these key components:

1. **Mode System**: Two modes - "status" (default, read-only) and "install" (with `--fix` flag)

2. **Certificate Management**: 
   - Downloads certificate from `warp-cli certs`
   - Stores at `$HOME/.cloudflare-ca.pem`
   - Checks for updates and certificate validity

3. **Tool-Specific Setup Functions**:
   - Each supported tool has its own `setup_*_cert()` function
   - Functions check current configuration before making changes
   - Handle permission issues by suggesting user-writable alternatives
   - Support for: Node.js/npm, Python, gcloud, Git, curl, Java/JVM, jenv, Gradle, DBeaver, wget, Podman, Rancher, Colima, Android Emulator
   - Tools can be selectively processed using `--tools` option with keys or tags

4. **Certificate Helpers**:
   - `create_bundle_with_system_certs(path)`: Creates a CA bundle initialized with system certificates from `/etc/ssl/cert.pem` (macOS) or `/etc/ssl/certs/ca-certificates.crt` (Linux)
   - `safe_append_certificate(cert, target)`: Safely appends a certificate to a bundle file, ensuring proper PEM formatting
   - `certificate_exists_in_file()`: Checks if certificate already exists in bundle files
   - `verify_connection()`: Tests if tools can connect through WARP

5. **Status Checking**:
   - `check_all_status()`: Comprehensive status report of all configurations
   - Shows what needs fixing without making changes

## Key Implementation Details

- Uses Python's exception handling for robust error management
- Preserves existing CA bundles by appending rather than replacing
- Handles multiple certificate formats and locations across different tools
- Provides user-friendly colored output with clear status indicators
- Supports both system-wide and user-specific certificate locations
- Detects and adapts to user's shell (bash, zsh, fish)
- Cross-platform Python implementation with proper type handling