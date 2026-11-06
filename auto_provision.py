#!/usr/bin/env python3
"""
auto_provision.py - Baseline provisioning, VLAN creation and configuration backup
(Member 4, BTL 2 - TechViet Innovations lab).

MODES
-----
1. Read-only (default)
       Back up `show running-config` and run verification `show` commands.
       Nothing is changed on the devices.

2. --push  (idempotent provisioning)
       For every device:
         a. capture "pre" state   (running-config backup + verification output)
         b. compare the running-config with the desired baseline and work out
            ONLY what is missing
         c. push the missing lines, `write memory` if anything was changed
         d. capture "post" state and write a pre/post diff
       Running it a second time changes nothing ("OK (no change)").

3. --push --dry-run
       Print the commands that WOULD be pushed. Nothing is changed and no files
       are written. Use it before the first real push.

WHAT THE BASELINE CONTAINS (all values come from inventory.yaml, section `baseline`)
       local admin user (privilege 15), vty lines (SSH only, local login),
       SSH v2 + password encryption, AAA (local), NTP, Syslog, login banner,
       and the corporate VLANs (switches only, section `vlans`).

SECURITY
       No password is stored in this file or in inventory.yaml. Credentials come from
       environment variables, or are asked interactively with getpass:
           TVI_SSH_USERNAME   SSH login
           TVI_SSH_PASSWORD   SSH password
           TVI_ENABLE_SECRET  enable secret (empty = not needed, user is privilege 15)
           TVI_ADMIN_SECRET   secret for `username admin privilege 15 secret ...`
       Secrets are masked in every log line and console message.

       IMPORTANT: the `username admin ... secret` command REPLACES the admin password.
       Set TVI_ADMIN_SECRET to the value the lab already uses, or leave it empty so the
       user is not managed. The script never overwrites an existing admin user unless
       you pass --force-admin-secret.

USAGE (run it from the console of AUTO-NODE01, inside the lab)
       pip3 install netmiko pyyaml
       python3 auto_provision.py --device HANOI-RND-SW01 --push --dry-run
       python3 auto_provision.py --device HANOI-RND-SW01 --push
       python3 auto_provision.py --site HCMC --push
       python3 auto_provision.py --push                  # all devices
       python3 auto_provision.py --site HCMC --label pre # read-only backup only

Exit code: 0 = every device succeeded, 1 = at least one device FAILED or PARTIAL.
"""

from __future__ import annotations

import argparse
import difflib
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from getpass import getpass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml
from netmiko import (
    ConnectHandler,
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)
from paramiko.ssh_exception import SSHException

# --------------------------------------------------------------------------- #
# Paths: relative to this file, so the script runs from any directory
# --------------------------------------------------------------------------- #
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_INVENTORY = BASE_DIR / "inventory.yaml"
BACKUP_DIR = BASE_DIR / "backups"
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "automation.log"

# --------------------------------------------------------------------------- #
# Defaults used when inventory.yaml has no `baseline` / `vlans` section
# --------------------------------------------------------------------------- #
DEFAULT_BASELINE = {
    "admin_user": "admin",
    "ntp_servers": ["10.10.10.50"],
    "syslog_hosts": ["10.10.10.51"],
    # One line, no '#' character (it is used as the banner delimiter).
    "banner": "Unauthorized access to TVI Corporate Infrastructure is prohibited.",
    "aaa": True,
}
DEFAULT_VLANS = [
    {"id": 10, "name": "EXEC_FINANCE"},
    {"id": 20, "name": "RND_ENGINEERING"},
    {"id": 30, "name": "LOGISTICS_OPS"},
    {"id": 99, "name": "MANAGEMENT"},
]

# vty block the assignment requires: SSH only, local login
VTY_BLOCK = ("line vty 0 4", ["transport input ssh", "login local"])

# --------------------------------------------------------------------------- #
# Verification commands (label, command). Unsupported commands are recorded as
# "N/A" and logged as WARNING; they never abort the session.
# --------------------------------------------------------------------------- #
L2_COMMANDS: List[Tuple[str, str]] = [
    ("VLAN", "show vlan brief"),
    ("TRUNK 802.1Q", "show interfaces trunk"),
    ("ETHERCHANNEL", "show etherchannel summary"),
    ("STP SUMMARY", "show spanning-tree summary"),
    ("STP ROOT", "show spanning-tree root"),
    ("IP INTERFACE", "show ip interface brief"),
    ("INTERFACE STATUS", "show interfaces status"),
]
ROUTER_COMMANDS: List[Tuple[str, str]] = [
    ("IP INTERFACE", "show ip interface brief"),
    ("OSPF NEIGHBOR", "show ip ospf neighbor"),
    ("BGP SUMMARY", "show ip bgp summary"),
]
FHRP_COMMANDS: Dict[str, Tuple[str, str]] = {
    "hsrp": ("HSRP", "show standby brief"),
    "vrrp": ("VRRP", "show vrrp brief"),
}
# The DHCP server is HCMC-DC-SRV01 (Linux), so switches have no `show ip dhcp binding`.
# On core switches only the relay configuration of the SVIs is checked.
DHCP_COMMANDS: List[Tuple[str, str]] = [
    ("DHCP RELAY (SVI)", "show running-config | include ^interface Vlan|helper-address"),
]
RUNNING_CONFIG = "show running-config"

# `show` command rejected by IOS
INVALID_RE = re.compile(r"^\s*%\s*(Invalid input|Ambiguous command|Incomplete command)|"
                        r"Invalid input detected", re.IGNORECASE | re.MULTILINE)
# Any IOS error line while pushing configuration (lines starting with '%')
CONFIG_ERR_RE = re.compile(r"^\s*%.*$", re.MULTILINE)

log = logging.getLogger("tvi.automation")


# --------------------------------------------------------------------------- #
# Data types
# --------------------------------------------------------------------------- #
@dataclass
class Credentials:
    username: str
    password: str
    enable_secret: Optional[str] = None
    admin_secret: Optional[str] = None

    def secrets(self) -> List[str]:
        return [s for s in (self.password, self.enable_secret, self.admin_secret) if s]


@dataclass
class Change:
    """One logical change: a description and the CLI lines that implement it."""
    what: str
    commands: List[str]


@dataclass
class Capture:
    files: List[Path]
    warnings: int
    sections: int
    running: str


@dataclass
class Result:
    hostname: str
    ip: str
    status: str = "FAILED"   # OK | OK (no change) | OK (N changed) | OK (warnings) | DRY-RUN | PARTIAL | FAILED
    detail: str = ""
    files: List[Path] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
def setup_logging() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    file_h = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_h.setFormatter(fmt)
    console_h = logging.StreamHandler(sys.stdout)
    console_h.setFormatter(logging.Formatter("%(levelname)-7s %(message)s"))
    log.setLevel(logging.INFO)
    log.addHandler(file_h)
    log.addHandler(console_h)


def mask(text: str, secrets: List[str]) -> str:
    """Replace every secret value with ******** before it reaches a log or the screen."""
    for s in secrets:
        if s:
            text = text.replace(s, "********")
    return text


# --------------------------------------------------------------------------- #
# Inventory and credentials
# --------------------------------------------------------------------------- #
def load_inventory(path: Path) -> Tuple[List[dict], dict, List[dict]]:
    """Read inventory.yaml -> (devices, baseline, vlans). Validates required fields."""
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    raw_devices = data.get("devices")
    if not raw_devices:
        raise ValueError(f"{path} has no 'devices' section")

    devices = []
    for i, d in enumerate(raw_devices, 1):
        for key in ("hostname", "ip"):
            if not d.get(key):
                raise ValueError(f"Device #{i} is missing '{key}'")
        d.setdefault("port", 22)
        d.setdefault("device_type", "cisco_ios")
        d.setdefault("role", "access")      # core | access | router
        d.setdefault("fhrp", "hsrp")
        d.setdefault("site", "")
        devices.append(d)

    baseline = {**DEFAULT_BASELINE, **(data.get("baseline") or {})}
    if "#" in baseline["banner"]:
        raise ValueError("baseline.banner must not contain '#' (used as delimiter)")

    vlans = []
    for v in (data.get("vlans") or DEFAULT_VLANS):
        if "id" not in v or "name" not in v:
            raise ValueError(f"VLAN entry needs 'id' and 'name': {v}")
        vlans.append({
            "id": int(v["id"]),
            "name": str(v["name"]),
            "sites": [str(s).upper() for s in (v.get("sites") or [])],
        })
    return devices, baseline, vlans


def get_credentials(push: bool) -> Credentials:
    """Environment variables first, getpass otherwise. Nothing is ever stored on disk."""
    user = os.environ.get("TVI_SSH_USERNAME") or input("SSH username: ").strip()
    password = os.environ.get("TVI_SSH_PASSWORD") or getpass("SSH password: ")
    enable = os.environ.get("TVI_ENABLE_SECRET")
    if enable is None:
        enable = getpass("Enable secret (Enter if the user is already privilege 15): ")
    admin = None
    if push:
        admin = os.environ.get("TVI_ADMIN_SECRET")
        if admin is None:
            admin = getpass("Admin secret to enforce (Enter = do not manage the local user): ")
    return Credentials(user, password, enable or None, admin or None)


# --------------------------------------------------------------------------- #
# Running-config parsing (used for idempotency)
# --------------------------------------------------------------------------- #
def parse_running_config(text: str) -> Tuple[Set[str], Dict[str, Set[str]]]:
    """Return (top-level lines, {parent line: set of child lines})."""
    top: Set[str] = set()
    children: Dict[str, Set[str]] = {}
    parent: Optional[str] = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("!"):
            continue
        if raw[0] in " \t":
            if parent is not None:
                children[parent].add(raw.strip())
        else:
            parent = raw.strip()
            top.add(parent)
            children.setdefault(parent, set())
    return top, children


def parse_vlan_brief(text: str) -> Dict[int, str]:
    """Return {vlan id: vlan name} from `show vlan brief`."""
    vlans: Dict[int, str] = {}
    pattern = re.compile(r"^(\d+)\s+(.+?)\s+(active|act/\S+|sus\S*)\b", re.IGNORECASE)
    for line in text.splitlines():
        m = pattern.match(line)
        if m:
            vlans[int(m.group(1))] = m.group(2).strip()
    return vlans


# --------------------------------------------------------------------------- #
# Planning: what is missing on this device?
# --------------------------------------------------------------------------- #
def build_plan(dev: dict, running: str, existing_vlans: Dict[int, str], baseline: dict,
               vlans: List[dict], admin_secret: Optional[str],
               args: argparse.Namespace) -> List[Change]:
    """Compare the device with the desired baseline and return only the missing changes."""
    host = dev["hostname"]
    top, kids = parse_running_config(running)
    changes: List[Change] = []

    def want_global(line: str, what: str) -> None:
        if line not in top:
            changes.append(Change(what, [line]))

    # 1. Local admin user. The stored secret is hashed, so it cannot be compared:
    #    an existing privilege-15 user is left alone unless --force-admin-secret is given.
    user = baseline["admin_user"]
    user_present = any(l.startswith(f"username {user} ") and "privilege 15" in l for l in top)
    if admin_secret and (not user_present or args.force_admin_secret):
        changes.append(Change(f"local user '{user}'",
                              [f"username {user} privilege 15 secret {admin_secret}"]))
    elif user_present:
        log.info("%s: user '%s' already exists - not touched", host, user)
    else:
        log.warning("%s: user '%s' missing and no admin secret given - skipped", host, user)

    # 2. vty lines: SSH only, local login (only the missing children are pushed)
    parent, wanted = VTY_BLOCK
    missing = [w for w in wanted if w not in kids.get(parent, set())]
    if missing:
        changes.append(Change(parent, [parent, *missing, "exit"]))

    # 3. SSH and password hygiene
    want_global("ip ssh version 2", "SSH version 2")
    want_global("service password-encryption", "password encryption")

    # 4. AAA (local). Skipped with --no-aaa.
    if baseline.get("aaa") and not args.no_aaa:
        want_global("aaa new-model", "AAA enable")
        want_global("aaa authentication login default local", "AAA login (local)")
        want_global("aaa authorization exec default local", "AAA exec authorization (local)")

    # 5. NTP and Syslog
    for server in baseline["ntp_servers"]:
        want_global(f"ntp server {server}", f"NTP server {server}")
    for syslog in baseline["syslog_hosts"]:
        want_global(f"logging host {syslog}", f"Syslog host {syslog}")

    # 6. Login banner (the config stores the text between ^C delimiters)
    if baseline["banner"] not in running:
        changes.append(Change("login banner", [f"banner motd #{baseline['banner']}#"]))

    # 7. VLANs - switches only
    if dev["role"] in ("core", "access"):
        site = str(dev.get("site", "")).upper()
        for v in vlans:
            if v["sites"] and site not in v["sites"]:
                continue
            vid, name = v["id"], v["name"]
            current = existing_vlans.get(vid)
            if current is None or current == f"VLAN{vid:04d}":
                changes.append(Change(f"VLAN {vid} ({name})", [f"vlan {vid}", f"name {name}", "exit"]))
            elif current != name:
                if args.rename_vlans:
                    changes.append(Change(f"rename VLAN {vid} -> {name}",
                                          [f"vlan {vid}", f"name {name}", "exit"]))
                else:
                    log.warning("%s: VLAN %d is named '%s' (inventory says '%s') - kept; "
                                "use --rename-vlans to change it", host, vid, current, name)
    return changes


# --------------------------------------------------------------------------- #
# Capture: running-config backup + verification commands
# --------------------------------------------------------------------------- #
def commands_for(dev: dict) -> List[Tuple[str, str]]:
    if dev["role"] == "router":
        cmds = list(ROUTER_COMMANDS)
    else:
        cmds = list(L2_COMMANDS)
        if dev["role"] == "core":
            cmds.append(FHRP_COMMANDS.get(str(dev["fhrp"]).lower(), FHRP_COMMANDS["hsrp"]))
            cmds += DHCP_COMMANDS
    for extra in dev.get("extra_commands", []) or []:
        cmds.append(("EXTRA", extra))
    return cmds


def _write(path: Path, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def capture(conn, dev: dict, label: str) -> Capture:
    """Save <host>_<ts>[_label]_backup.cfg and <host>_<ts>[_label]_verify.txt."""
    host, ip = dev["hostname"], dev["ip"]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix = f"_{label}" if label else ""

    running = conn.send_command(RUNNING_CONFIG, read_timeout=60)
    cfg_path = BACKUP_DIR / f"{host}_{ts}{suffix}_backup.cfg"
    _write(cfg_path, running)
    log.info("%s: saved backup %s", host, cfg_path.name)

    sections, warnings = [], 0
    for title, cmd in commands_for(dev):
        out = conn.send_command(cmd, read_timeout=30)
        if INVALID_RE.search(out):
            warnings += 1
            log.warning("%s: command '%s' not supported / invalid", host, cmd)
            out = "[N/A] Command not supported by this device or feature not configured."
        sections.append(f"{'=' * 78}\n# {title}\n# {host}# {cmd}\n{'=' * 78}\n{out}\n")
    ver_path = BACKUP_DIR / f"{host}_{ts}{suffix}_verify.txt"
    _write(ver_path, f"! {host} ({ip}) - verification @ {ts}\n" + "\n".join(sections))
    return Capture([cfg_path, ver_path], warnings, len(sections), running)


# --------------------------------------------------------------------------- #
# One device
# --------------------------------------------------------------------------- #
def run_read_only(conn, dev: dict, args: argparse.Namespace, res: Result) -> None:
    cap = capture(conn, dev, args.label)
    res.files += cap.files
    res.status = "OK" if cap.warnings == 0 else "OK (warnings)"
    res.detail = f"{cap.sections} commands, {cap.warnings} warning(s)"


def run_push(conn, dev: dict, creds: Credentials, baseline: dict, vlans: List[dict],
             args: argparse.Namespace, res: Result) -> None:
    host = dev["hostname"]
    secrets = creds.secrets()

    # --- Dry run: read only, print the plan, write nothing ---
    if args.dry_run:
        running = conn.send_command(RUNNING_CONFIG, read_timeout=60)
        existing = {}
        if dev["role"] in ("core", "access"):
            existing = parse_vlan_brief(conn.send_command("show vlan brief", read_timeout=30))
        changes = build_plan(dev, running, existing, baseline, vlans, creds.admin_secret, args)
        for ch in changes:
            log.info("%s: [dry-run] would push %s: %s", host, ch.what,
                     mask(" | ".join(ch.commands), secrets))
        res.status = "DRY-RUN"
        res.detail = f"{len(changes)} change(s) pending" if changes else "nothing to change"
        return

    # --- a. PRE capture ---
    pre = capture(conn, dev, "pre")
    res.files += pre.files
    warnings = pre.warnings

    # --- b. Plan ---
    existing = {}
    if dev["role"] in ("core", "access"):
        existing = parse_vlan_brief(conn.send_command("show vlan brief", read_timeout=30))
    changes = build_plan(dev, pre.running, existing, baseline, vlans, creds.admin_secret, args)

    # --- c. Apply only what is missing ---
    applied, rejected = 0, 0
    for ch in changes:
        out = conn.send_config_set(ch.commands, cmd_verify=False, read_timeout=60)
        errors = CONFIG_ERR_RE.findall(out)
        if errors:
            rejected += 1
            log.error("%s: %s REJECTED: %s", host, ch.what, mask(" ".join(e.strip() for e in errors), secrets))
        else:
            applied += 1
            log.info("%s: applied %s", host, ch.what)

    if applied:
        conn.send_command("write memory", read_timeout=60)
        log.info("%s: configuration saved (write memory)", host)

    # --- d. POST capture and diff ---
    post = capture(conn, dev, "post")
    res.files += post.files
    warnings += post.warnings
    if applied:
        diff = "\n".join(difflib.unified_diff(
            pre.running.splitlines(), post.running.splitlines(),
            fromfile=f"{host} pre", tofile=f"{host} post", lineterm=""))
        diff_path = BACKUP_DIR / f"{host}_{datetime.now():%Y%m%d_%H%M%S}_pre_post.diff"
        _write(diff_path, mask(diff, secrets) + "\n")
        res.files.append(diff_path)

    # --- status ---
    if rejected:
        res.status = "PARTIAL"
        res.detail = f"{applied} applied, {rejected} rejected by device"
    elif applied:
        res.status = f"OK ({applied} changed)"
        res.detail = f"{applied} change(s) pushed and saved"
    else:
        res.status = "OK (no change)"
        res.detail = "device already matches the baseline"
    if warnings and not rejected:
        res.detail += f"; {warnings} unsupported show command(s)"


def process_device(dev: dict, creds: Credentials, baseline: dict, vlans: List[dict],
                   args: argparse.Namespace) -> Result:
    host, ip = dev["hostname"], dev["ip"]
    res = Result(hostname=host, ip=ip)
    params = {
        "device_type": dev["device_type"],
        "host": ip,
        "port": int(dev["port"]),
        "username": creds.username,
        "password": creds.password,
        "conn_timeout": 15,
        "auth_timeout": 20,
        "banner_timeout": 20,    # vIOS boots slowly
        "fast_cli": False,       # more reliable on virtual images
    }
    if creds.enable_secret:
        params["secret"] = creds.enable_secret

    log.info("Connecting to %s (%s:%s)...", host, ip, dev["port"])
    try:
        with ConnectHandler(**params) as conn:
            if creds.enable_secret:
                conn.enable()
            if args.push:
                run_push(conn, dev, creds, baseline, vlans, args, res)
            else:
                run_read_only(conn, dev, args, res)
            log.info("%s: %s - %s", host, res.status, res.detail)

    except NetmikoTimeoutException:
        res.detail = "SSH connection timed out"
        log.error("%s (%s): %s", host, ip, res.detail)
    except NetmikoAuthenticationException:
        res.detail = "Authentication failed (wrong username/password)"
        log.error("%s (%s): %s", host, ip, res.detail)
    except SSHException as exc:
        res.detail = f"SSH error: {exc}"
        log.error("%s (%s): %s", host, ip, res.detail)
    except OSError as exc:  # file or socket error
        res.detail = f"I/O error: {exc}"
        log.error("%s (%s): %s", host, ip, res.detail)
    except Exception as exc:  # noqa: BLE001 - one bad node must not stop the whole run
        res.detail = mask(f"Unexpected error: {exc}", creds.secrets())
        log.exception("%s (%s): %s", host, ip, res.detail)
    return res


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="TVI automation: backup, verification and idempotent baseline provisioning.")
    ap.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    ap.add_argument("--site", help="Only devices of this site (HCMC / HANOI / DANANG)")
    ap.add_argument("--device", action="append", help="Only this hostname (repeatable)")
    ap.add_argument("--label", default="",
                    help="Label added to file names in read-only mode (e.g. pre / post)")
    ap.add_argument("--push", action="store_true",
                    help="Provision the baseline and VLANs (pre-backup, push, save, post-backup)")
    ap.add_argument("--dry-run", action="store_true",
                    help="With --push: show what would change, change nothing (implies --push)")
    ap.add_argument("--force-admin-secret", action="store_true",
                    help="Re-apply 'username <admin> privilege 15 secret' even if the user exists")
    ap.add_argument("--rename-vlans", action="store_true",
                    help="Rename existing VLANs whose name differs from the inventory")
    ap.add_argument("--no-aaa", action="store_true", help="Do not push the AAA lines")
    args = ap.parse_args(argv)
    if args.dry_run:
        args.push = True
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    setup_logging()

    devices, baseline, vlans = load_inventory(args.inventory)
    if args.site:
        devices = [d for d in devices if str(d["site"]).upper() == args.site.upper()]
    if args.device:
        wanted = {h.upper() for h in args.device}
        devices = [d for d in devices if d["hostname"].upper() in wanted]
    if not devices:
        log.error("No device matches the filters.")
        return 1

    creds = get_credentials(args.push)
    mode = "DRY-RUN" if args.dry_run else ("PUSH" if args.push else "READ-ONLY")
    log.info("=== Run started: %d device(s), mode %s ===", len(devices), mode)

    results = [process_device(d, creds, baseline, vlans, args) for d in devices]

    print("\n" + "-" * 96)
    print(f"{'HOSTNAME':<20}{'IP':<16}{'STATUS':<20}DETAIL")
    print("-" * 96)
    for r in results:
        print(f"{r.hostname:<20}{r.ip:<16}{r.status:<20}{r.detail}")
    failed = [r for r in results if r.status in ("FAILED", "PARTIAL")]
    log.info("=== Run finished: %d/%d ok, %d failed ===",
             len(results) - len(failed), len(results), len(failed))
    print(f"Backups: {BACKUP_DIR}\nLog:     {LOG_FILE}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
