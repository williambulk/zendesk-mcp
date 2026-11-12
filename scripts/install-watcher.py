#!/usr/bin/env python3
"""Install a per-user macOS job that polls Zendesk every 15 minutes while logged in."""
import os
import pathlib
import plistlib
import shutil
import subprocess
import sys
import time

if sys.platform != "darwin":
    raise SystemExit("Use cron/systemd to run `node /absolute/path/dist/index.js watch` every 15 minutes on other platforms.")
repo = pathlib.Path(__file__).resolve().parent.parent
node = shutil.which("node")
if not node or not (repo / "dist/index.js").is_file():
    raise SystemExit("Install Node and run npm run build first.")
label = "com.williambulk.zendesk-mcp-watch"
logs = pathlib.Path.home() / "Library/Logs/zendesk-mcp"
logs.mkdir(parents=True, exist_ok=True, mode=0o700)
os.chmod(logs, 0o700)
for name in ("watch.stdout.log", "watch.stderr.log"):
    logfile = logs / name
    logfile.touch(mode=0o600, exist_ok=True)
    os.chmod(logfile, 0o600)
agents = pathlib.Path.home() / "Library/LaunchAgents"
agents.mkdir(parents=True, exist_ok=True)
target = agents / (label + ".plist")
job = {
    "Label": label,
    "ProgramArguments": [node, str(repo / "dist/index.js"), "watch"],
    "WorkingDirectory": str(repo),
    "StartInterval": 900,
    "RunAtLoad": True,
    "ProcessType": "Interactive",
    "Umask": 0o077,
    "StandardOutPath": str(logs / "watch.stdout.log"),
    "StandardErrorPath": str(logs / "watch.stderr.log"),
}
with target.open("wb") as handle:
    plistlib.dump(job, handle)
os.chmod(target, 0o600)
domain = f"gui/{os.getuid()}"
subprocess.run(["launchctl", "bootout", f"{domain}/{label}"], capture_output=True)
time.sleep(0.5)
subprocess.run(["launchctl", "bootstrap", domain, str(target)], check=True)
print(f"Installed {label}: all accessible tickets, every 15 minutes while this Mac is awake and the user is logged in.")
print(f"Status: launchctl print {domain}/{label}")
print(f"Logs: {logs}")
print(f"Stop: launchctl bootout {domain}/{label}")
