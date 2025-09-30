# fuwarp (Cloudflare WARP Certificate Fixer Upper) - Windows Guide

Script to automatically verify and fix Cloudflare Warp Gateway TLS distrust issues on Windows

## Usage

```powershell
# Download the Windows-specific script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/aberoham/fuwarp/main/fuwarp-windows.py" -OutFile "fuwarp-windows.py"

# Check status (no changes made)
python fuwarp-windows.py

# Apply fixes to all supported tools
python fuwarp-windows.py --fix

# Fix only specific tools (can specify multiple)
python fuwarp-windows.py --fix --tools node --tools python
python fuwarp-windows.py --fix --tools node-npm,gcloud

# List all available tools and their tags
python fuwarp-windows.py --list-tools

# Run with detailed debug/verbose output (useful for troubleshooting)
python fuwarp-windows.py --debug
python fuwarp-windows.py --verbose

# Show version information
python fuwarp-windows.py --version

# Show help and all available commands
python fuwarp-windows.py --help
```

## Command Line Options

- `-h, --help` - Show help message and exit
- `--fix` - Actually make changes (default is status check only)
- `--tools, --tool TOOLS` - Specific tools to check/fix (can be specified multiple times)
  - Examples: `--tools node --tools python` or `--tools node-npm,gcloud`
- `--list-tools` - List all available tools and their tags
- `--debug, --verbose` - Show detailed debug information
- `--version` - Show program's version number and exit

## FU Warp Rational

When your organization runs Cloudflare WARP Gateway with TLS inspection enabled, the gateway intercepts and records virtually all HTTPS traffic for policy enforcement and security auditing. WARP's Gateway achieves this introspection by presenting its own root certificate to your TLS clients -- essentially performing a sanctioned man-in-the-middle (MITM) attack on your TLS (aka SSL) connections.

Typically, MacOS and Windows themselves will automatically trust WARP's certificate through system keychains. Most third-party development tools completely ignore these system certificates. Each tool maintains its own certificate bundle or looks for specific environment variables. This fragmentation creates endless annoying "certificate verify failed" errors across your toolchain whenever Warp Gateway's inspection is turned on.

One particularly annoying detail is that simply pointing tools to your organization's WARP Gateway certificate by itself rarely works. You often need to append the custom WARP CA to an existing bundle of public CAs, which quickly becomes a brittle process that needs repeating for each tool. 

FU Warp!

## Don't Disable Warp

Whilst the quick temporary workaround might be to toggle Cloudflare Warp OFF, this is incredibly distressing to any nearby Information Security professionals who will one day need to forensically examine dodgy dependencies or MCPs that have slipped onto your laptop.

The act of toggling Warp off also seriously hints that you have no clue what you're doing, as understanding TLS certificate-based trust is a critical concept underpinning modern vibe'n.

## Windows Requirements

- Cloudflare WARP must be installed and connected
- `warp-cli.exe` command must be available (typically installed with WARP)
- Python 3 for Windows
- Administrator privileges may be required for some fixes

## Windows-Specific Notes

The Windows version (`fuwarp-windows.py`) includes Windows-specific functionality:

- Uses Windows Registry to locate certificates and configuration
- Handles Windows paths and file permissions
- Works with Windows-specific certificate stores
- Supports PowerShell environment variable management

## Contribute

Something amiss or not quite right? Please post the full output of a run to an issue or simply submit a PR

## List of supported fixes (Windows)

- **Node.js/npm**: configures `NODE_EXTRA_CA_CERTS` for Node.js and the cafile setting for npm
- **Python**: sets the `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, and `CURL_CA_BUNDLE` environment variables  
- **Google Cloud SDK (gcloud)**: configures the `core/custom_ca_certs_file` for the Google Cloud `gcloud` CLI
- **Java/JVM**: adds the Cloudflare certificate to any found Java keystore (cacerts)
- **wget**: configures the `ca_certificate` in the `.wgetrc` file
- **Podman**: installs certificate in Podman container runtime
- **Rancher Desktop**: installs certificate in Rancher Desktop Kubernetes environment
- **Git**: configures Git to use the custom certificate bundle via `http.sslCAInfo`
- **Windows Certificate Store**: installs the certificate in the Windows system certificate store

### WSL Support

Fuwarp should auto-detect WSL environments where `warp-cli` is only available on the underlying Windows host. Within WSL, fuwarp will guide the user where to obtain their Cloudflare cert and will skip slow verification tests.

## Installation Alternative

You can also run the script directly from the repository:

```powershell
# Clone the repository
git clone https://github.com/aberoham/fuwarp.git
cd fuwarp

# Run the Windows-specific script
python fuwarp-windows.py --fix
```

## Troubleshooting

If you encounter issues:

1. Ensure WARP is connected: `warp-cli status`
2. Run with debug output: `python fuwarp-windows.py --debug`
3. Check that Python 3 is properly installed and in your PATH
4. Verify you have appropriate permissions for the tools you're trying to fix