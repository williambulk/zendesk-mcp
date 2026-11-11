#!/usr/bin/env python3
"""Install a persistent per-user macOS LaunchAgent that serves Zendesk MCP over Streamable HTTP on 127.0.0.1:3849."""
import os
import pathlib
import plistlib
import shutil
import subprocess
import sys

if sys.platform != "darwin":
    raise SystemExit(
        "Use systemd to run `node /absolute/path/dist/index.js serve --transport=http` on other platforms."
    )

repo = pathlib.Path(__file__).resolve().parent.parent
node = shutil.which("node") or str(pathlib.Path.home() / ".local/bin/node")
if not pathlib.Path(node).is_file() or not (repo / "dist/index.js").is_file():
    raise SystemExit("Install Node and run npm run build first.")

label = "com.williambulk.zendesk-mcp-http"
logs = pathlib.Path.home() / "Library/Logs/zendesk-mcp"
logs.mkdir(parents=True, exist_ok=True, mode=0o700)
os.chmod(logs, 0o700)

for name in ("http.stdout.log", "http.stderr.log"):
    logfile = logs / name
    logfile.touch(mode=0o600, exist_ok=True)
    os.chmod(logfile, 0o600)

agents = pathlib.Path.home() / "Library/LaunchAgents"
agents.mkdir(parents=True, exist_ok=True)
target = agents / (label + ".plist")

job = {
    "Label": label,
    "ProgramArguments": [
        str(node),
        str(repo / "dist/index.js"),
        "serve",
        "--transport=http",
    ],
    "WorkingDirectory": str(repo),
    "RunAtLoad": True,
    "KeepAlive": True,
    "ProcessType": "Background",
    "Umask": 0o077,
    "StandardOutPath": str(logs / "http.stdout.log"),
    "StandardErrorPath": str(logs / "http.stderr.log"),
}

with target.open("wb") as handle:
    plistlib.dump(job, handle)
os.chmod(target, 0o600)

domain = f"gui/{os.getuid()}"
subprocess.run(["launchctl", "bootout", f"{domain}/{label}"], capture_output=True)
subprocess.run(["launchctl", "bootstrap", domain, str(target)], check=True)
print(f"Installed and started {label} on http://127.0.0.1:3849/mcp")
print(f"Status: launchctl print {domain}/{label}")
print(f"Logs: {logs}/http.stderr.log")
print(f"Stop: launchctl bootout {domain}/{label}")
