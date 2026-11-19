#!/usr/bin/env python3
import os
import sys
from getpass import getpass
from pathlib import Path
import yaml
from netmiko import ConnectHandler

if len(sys.argv) != 3:
    print("Usage: python3 restore_backup.py <HOSTNAME> <PATH_TO_BACKUP.cfg>")
    sys.exit(1)

target_host = sys.argv[1].upper()
backup_path = Path(sys.argv[2])

inv = yaml.safe_load(Path("inventory.yaml").read_text(encoding="utf-8"))["devices"]
dev = next((d for d in inv if d["hostname"].upper() == target_host), None)
if not dev:
    sys.exit(f"Hostname {target_host} not found in inventory.yaml")

# Strip 'Building configuration...' / 'Current configuration' header and 'end'
lines = []
started = False
for raw in backup_path.read_text(encoding="utf-8").splitlines():
    if raw.startswith("version "):
        started = True
    if started and raw.strip() not in ("", "end") and not raw.lstrip().startswith("!"):
        lines.append(raw)

user = os.environ.get("TVI_SSH_USERNAME") or input("SSH username: ").strip()
password = os.environ.get("TVI_SSH_PASSWORD") or getpass("SSH password: ")
secret = os.environ.get("TVI_ENABLE_SECRET") or ""

params = {
    "device_type": dev["device_type"],
    "host": dev["ip"],
    "port": int(dev.get("port", 22)),
    "username": user,
    "password": password,
    "fast_cli": False,
}
if secret:
    params["secret"] = secret

print(f"[*] Restoring {backup_path.name} -> {dev['hostname']} ({dev['ip']})...")
with ConnectHandler(**params) as conn:
    if secret:
        conn.enable()
    out = conn.send_config_set(lines, cmd_verify=False, read_timeout=120)
    conn.send_command("write memory", read_timeout=60)
    print("[+] Restore complete and saved to startup-config.")
