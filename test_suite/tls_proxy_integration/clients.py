import subprocess
import sys


def run_python_requests(url: str, env: dict[str, str], proxy_url: str | None = None) -> subprocess.CompletedProcess:
    script = r'''
import os
import sys

try:
    import requests
except Exception as e:
    print(f"requests import failed: {e}", file=sys.stderr)
    sys.exit(2)

url = sys.argv[1]
proxy_url = os.environ.get("FUWARP_TEST_PROXY_URL")

kwargs = {"timeout": 10}
if proxy_url:
    kwargs["proxies"] = {"http": proxy_url, "https": proxy_url}

try:
    r = requests.get(url, **kwargs)
    print(f"status={r.status_code}")
    sys.exit(0 if r.status_code < 400 else 1)
except Exception as e:
    print(f"{type(e).__name__}: {e}", file=sys.stderr)
    sys.exit(1)
'''

    child_env = dict(env)
    if proxy_url:
        child_env["FUWARP_TEST_PROXY_URL"] = proxy_url
    else:
        child_env.pop("FUWARP_TEST_PROXY_URL", None)

    return subprocess.run(
        [sys.executable, "-c", script, url],
        capture_output=True,
        text=True,
        env=child_env,
        timeout=30,
    )


def run_python_urllib(url: str, env: dict[str, str], proxy_url: str | None = None) -> subprocess.CompletedProcess:
    script = r'''
import os
import sys
import urllib.request

url = sys.argv[1]
proxy_url = os.environ.get("FUWARP_TEST_PROXY_URL")

handlers = []
if proxy_url:
    handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))

opener = urllib.request.build_opener(*handlers)
req = urllib.request.Request(url, headers={"User-Agent": "fuwarp-tls-proxy-tests"})

try:
    with opener.open(req, timeout=10) as resp:
        print(f"status={resp.status}")
        sys.exit(0 if resp.status < 400 else 1)
except Exception as e:
    print(f"{type(e).__name__}: {e}", file=sys.stderr)
    sys.exit(1)
'''

    child_env = dict(env)
    if proxy_url:
        child_env["FUWARP_TEST_PROXY_URL"] = proxy_url
    else:
        child_env.pop("FUWARP_TEST_PROXY_URL", None)

    return subprocess.run(
        [sys.executable, "-c", script, url],
        capture_output=True,
        text=True,
        env=child_env,
        timeout=30,
    )


def run_node_https(url: str, env: dict[str, str], proxy_host: str | None = None, proxy_port: int | None = None) -> subprocess.CompletedProcess:
    """Run a minimal Node HTTPS client.

    If proxy_host/proxy_port are provided, use an HTTP CONNECT tunnel.
    """

    if proxy_host is None or proxy_port is None:
        script = r'''
const https = require('https');

const urlStr = process.argv[1];
const target = new URL(urlStr);

const req = https.request({
  hostname: target.hostname,
  port: target.port || 443,
  path: target.pathname || '/',
  method: 'GET',
  headers: { 'User-Agent': 'fuwarp-tls-proxy-tests' },
  rejectUnauthorized: true,
}, (res) => {
  console.log(`status=${res.statusCode}`);
  process.exit(res.statusCode < 400 ? 0 : 1);
});

req.on('error', (e) => {
  console.error(`Error: ${e.message}`);
  if (e.code) console.error(`Code: ${e.code}`);
  process.exit(1);
});

req.end();
'''
        cmd = ["node", "-e", script, url]
    else:
        script = r'''
const http = require('http');
const https = require('https');
const tls = require('tls');

const urlStr = process.argv[1];
const proxyHost = process.argv[2];
const proxyPort = parseInt(process.argv[3], 10);

const target = new URL(urlStr);

const connectReq = http.request({
  host: proxyHost,
  port: proxyPort,
  method: 'CONNECT',
  path: `${target.hostname}:${target.port || 443}`,
});

connectReq.on('connect', (res, socket) => {
  if (res.statusCode !== 200) {
    console.error(`Proxy CONNECT failed: ${res.statusCode}`);
    process.exit(1);
  }

  const tlsSocket = tls.connect({
    socket: socket,
    servername: target.hostname,
    rejectUnauthorized: true,
  }, () => {
    const req = https.request({
      hostname: target.hostname,
      port: target.port || 443,
      path: target.pathname || '/',
      method: 'GET',
      headers: { 'User-Agent': 'fuwarp-tls-proxy-tests' },
      socket: tlsSocket,
      agent: false,
    }, (resp) => {
      console.log(`status=${resp.statusCode}`);
      process.exit(resp.statusCode < 400 ? 0 : 1);
    });

    req.on('error', (e) => {
      console.error(`Request error: ${e.message}`);
      if (e.code) console.error(`Code: ${e.code}`);
      process.exit(1);
    });

    req.end();
  });

  tlsSocket.on('error', (e) => {
    console.error(`TLS error: ${e.message}`);
    if (e.code) console.error(`Code: ${e.code}`);
    process.exit(1);
  });
});

connectReq.on('error', (e) => {
  console.error(`Proxy error: ${e.message}`);
  process.exit(1);
});

connectReq.setTimeout(10000, () => {
  console.error('Proxy timeout');
  connectReq.destroy();
  process.exit(1);
});

connectReq.end();
'''
        cmd = ["node", "-e", script, url, proxy_host, str(proxy_port)]

    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=dict(env),
        timeout=30,
    )

