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
```

### Testing

The script doesn't have a formal test suite. Manual testing involves:
- Running in status mode to verify detection: `./fuwarp.py`
- Running with `--fix` to test installation on different tool configurations

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
   - Support for: Node.js/npm, Python, gcloud, Java/JVM, DBeaver, wget, Podman, Rancher, Android Emulator

4. **Certificate Verification**:
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