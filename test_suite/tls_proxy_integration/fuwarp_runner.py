import subprocess
import sys
from pathlib import Path


class FuwarpRunner:
    def __init__(self, fuwarp_path: Path, base_env: dict[str, str]):
        self.fuwarp_path = fuwarp_path
        self.base_env = dict(base_env)

    def run_fix(
        self,
        tools: list[str],
        cert_file: Path,
        extra_env: dict[str, str] | None = None,
        extra_args: list[str] | None = None,
        stdin: str = "y\n" * 20,
        timeout_seconds: int = 120,
    ) -> subprocess.CompletedProcess:
        cmd = [
            sys.executable,
            str(self.fuwarp_path),
            "--fix",
            "--skip-verify",
            "--cert-file",
            str(cert_file),
        ]

        for tool in tools:
            cmd.extend(["--tools", tool])

        if extra_args:
            cmd.extend(extra_args)

        env = dict(self.base_env)
        if extra_env:
            env.update(extra_env)

        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            input=stdin,
            env=env,
            timeout=timeout_seconds,
        )

    def run_status(
        self,
        tools: list[str],
        extra_env: dict[str, str] | None = None,
        extra_args: list[str] | None = None,
        timeout_seconds: int = 120,
    ) -> subprocess.CompletedProcess:
        cmd = [sys.executable, str(self.fuwarp_path)]

        for tool in tools:
            cmd.extend(["--tools", tool])

        if extra_args:
            cmd.extend(extra_args)

        env = dict(self.base_env)
        if extra_env:
            env.update(extra_env)

        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout_seconds,
        )

