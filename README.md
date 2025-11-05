# fuwarp (Cloudflare WARP Certificate Fixer Upper)

Script to automatically verify and fix Cloudflare Warp Gateway TLS distrust issues

## Usage

```bash
# Download the script
curl -LsSf https://raw.githubusercontent.com/aberoham/fuwarp/main/fuwarp.py -o fuwarp.py
chmod +x ./fuwarp.py

# Check status (no changes made)
./fuwarp.py

# Apply fixes
./fuwarp.py --fix

# Run with detailed debug output (useful for troubleshooting)
./fuwarp.py --debug
```
## FU Warp Rational

When your organization runs Cloudflare WARP Gateway with TLS inspection enabled, the gateway intercepts and records virtually all HTTPS traffic for policy enforcement and security auditing. WARP's Gateway achieves this introspection by presenting its own root certificate to your TLS clients -- essentially performing a sanctioned man-in-the-middle (MITM) attack on your TLS (aka SSL) connections.

Typically, MacOS and Windows themselves will automatically trust WARP's certificate through system keychains. Most third-party development tools completely ignore these system certificates. Each tool maintains its own certificate bundle or looks for specific environment variables. This fragmentation creates endless annoying "certificate verify failed" errors across your toolchain whenever Warp Gateway's inspection is turned on.

One particularly annoying detail is that simply pointing tools to your organization's WARP Gateway certificate by itself rarely works. You often need to append the custom WARP CA to an existing bundle of public CAs, which quickly becomes a brittle process that needs repeating for each tool. 

FU Warp!

## Don't Disable Warp

Whilst the quick temporary workaround might be to toggle Cloudflare Warp OFF, this is incredibly distressing to any nearby Information Security professionals who will one day need to forensically examine dodgy dependencies or MCPs that have slipped onto your laptop.

The act of toggling Warp off also seriously hints that you have no clue what you're doing, as understanding TLS certificate-based trust is a critical concept underpinning modern vibe'n.

## Requirements

- Cloudflare WARP must be installed and connected
- `warp-cli` command must be available
- Python 3 (macOS, Windows/WSL)

## Contribute

Something amiss or not quite right? Please post the full output of a run to an issue or simply submit a PR

## List of supported fixes

- Node.js/npm: configures `NODE_EXTRA_CA_CERTS` for Node.js and the cafile setting for npm.
- Python: sets the `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, and `CURL_CA_BUNDLE` environment variables.
- gcloud: configures the `core/custom_ca_certs_file` for the Google Cloud `gcloud` CLI.
- Java/JVM: adds the Cloudflare certificate to any found Java keystore (cacerts).
 - Gradle: sets `systemProp` entries in `gradle.properties` (respecting `GRADLE_USER_HOME`) for the WARP certificate.
- DBeaver: targets the bundled JRE and adds the certificate to its keystore.
- wget: configures the `ca_certificate` in the `.wgetrc` file.
- Podman: installs certificate in Podman VM's trust store.
- Rancher Desktop: installs certificate in Rancher VM's trust store.
- Android Emulator: helps install certificate on running Android emulators.

### VS Code Devcontainers / WSL

Fuwarp should auto-detect VS Code devcontainers and WSL environments where `warp-cli` is only available on the underlying host. Within these environments, fuwarp will guide the user where to obtain their Cloudflare cert and will skip slow verification tests.

