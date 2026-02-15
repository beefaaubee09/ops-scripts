# -----------------------------------------------------------------------------
# linux_vuln_scout.py
# Copyright (c) 2025 Ibad Shah (beefaaubee09)
#
# Licensed under the MIT License. You may obtain a copy at:
#     https://opensource.org/licenses/MIT
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# -----------------------------------------------------------------------------


"""
linux_vuln_scout.py — Read-only Linux hardening & misconfiguration checker

Outputs per-check verdicts (VULNERABLE / NOT_VULNERABLE / INCONCLUSIVE) with evidence and remediation hints.
- Safe-by-default: no exploitation or modification; limited scanning.
- Run locally on a Linux foothold.
- Requires Python 3.8+.

Examples
--------
$ python3 linux_vuln_scout.py
$ python3 linux_vuln_scout.py --csv out.csv --json out.json --max-find 100
$ sudo -n python3 linux_vuln_scout.py  # optional; improves some checks (e.g., sudoers visibility)

"""

import argparse
import csv
import dataclasses
import datetime as dt
import getpass
import json
import os
import re
import shlex
import stat
import subprocess
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

# ---------------------------- Utilities ----------------------------

def run(cmd: List[str], timeout: int = 5) -> Tuple[int, str, str]:
    """Run a command safely, return (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as e:
        return 127, "", f"{type(e).__name__}: {e}"

def file_is_world_writable(p: Path) -> bool:
    try:
        mode = p.stat().st_mode
        return bool(mode & stat.S_IWOTH)
    except Exception:
        return False

def file_is_world_readable(p: Path) -> bool:
    try:
        mode = p.stat().st_mode
        return bool(mode & stat.S_IROTH)
    except Exception:
        return False

def path_is_writable(p: Path) -> bool:
    try:
        return os.access(str(p), os.W_OK)
    except Exception:
        return False

def first_existing(paths: List[Path]) -> Optional[Path]:
    for p in paths:
        if p.exists():
            return p
    return None

def short(s: str, limit: int = 400) -> str:
    s = s.strip()
    return (s[:limit] + " …") if len(s) > limit else s

def whoami() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return os.getenv("USER", "unknown")

def mode_octal(p: Path) -> str:
    try:
        return oct(p.stat().st_mode & 0o777)
    except Exception:
        return "?"

# ---------------------------- Data model ----------------------------

@dataclasses.dataclass
class CheckResult:
    check_id: str
    name: str
    severity: str
    status: str  # VULNERABLE | NOT_VULNERABLE | INCONCLUSIVE
    evidence: str
    remediation: str

CheckFunc = Callable[[int], CheckResult]  # takes max_find, returns CheckResult

# ---------------------------- Checks ----------------------------

def check_sshd_permit_root_login(_: int) -> CheckResult:
    """Root SSH login permitted is generally undesirable."""
    rc, out, _ = run(["sshd", "-T"], timeout=8)
    permit = None
    if rc == 0:
        m = re.search(r"(?m)^permitrootlogin\s+(\S+)", out)
        if m:
            permit = m.group(1).lower()
    else:
        # Fallback to config file parse (coarse)
        cfg = first_existing([
            Path("/etc/ssh/sshd_config"),
            Path("/etc/ssh/sshd_config.d/00-defaults.conf"),
        ])
        if cfg and cfg.exists():
            try:
                text = cfg.read_text(errors="ignore")
                m = re.search(r"(?im)^\s*PermitRootLogin\s+(\S+)", text)
                if m:
                    permit = m.group(1).lower()
            except Exception:
                pass

    if permit is None:
        return CheckResult(
            "SSH-001", "SSH PermitRootLogin",
            "Medium", "INCONCLUSIVE",
            "Could not determine PermitRootLogin (no sshd -T, parsing failed).",
            "Ensure PermitRootLogin is set to 'no' unless a documented break-glass process exists."
        )

    if permit in ("yes", "without-password", "prohibit-password"):  # last two still allow some forms
        return CheckResult(
            "SSH-001", "SSH PermitRootLogin",
            "Medium", "VULNERABLE",
            f"PermitRootLogin={permit} reported by sshd -T/config.",
            "Set PermitRootLogin no and use per-user sudo with MFA; deploy emergency root login via console-only if required."
        )
    return CheckResult(
        "SSH-001", "SSH PermitRootLogin",
        "Medium", "NOT_VULNERABLE",
        f"PermitRootLogin={permit}.",
        "Keep root SSH disabled; review periodically."
    )

def check_sudo_nopasswd(_: int) -> CheckResult:
    """NOPASSWD sudo grants privilege without auth; risky if broad."""
    rc, out, err = run(["sudo", "-n", "-l"], timeout=6)
    if rc != 0:
        return CheckResult(
            "SUDO-001", "Sudo NOPASSWD Entries",
            "High", "INCONCLUSIVE",
            f"Unable to list sudo privileges without password (rc={rc}). stderr={short(err)}",
            "Run with a user able to list sudo or review /etc/sudoers & /etc/sudoers.d on the host; remove broad NOPASSWD where not strictly needed."
        )
    nopass = []
    for line in out.splitlines():
        if "NOPASSWD:" in line:
            nopass.append(line.strip())
    if nopass:
        return CheckResult(
            "SUDO-001", "Sudo NOPASSWD Entries",
            "High", "VULNERABLE",
            f"Found NOPASSWD rules:\n" + "\n".join(nopass[:10]),
            "Replace with PASSWD rules, restrict Cmnd_Alias scope, and require MFA for privileged actions."
        )
    return CheckResult(
        "SUDO-001", "Sudo NOPASSWD Entries",
        "High", "NOT_VULNERABLE",
        "No NOPASSWD entries found for current user.",
        "Maintain least privilege and require authentication for privileged commands."
    )

def check_path_writable(_: int) -> CheckResult:
    """Writable directories in PATH enable command hijack if privileged processes trust PATH."""
    path_dirs = [Path(p) for p in os.getenv("PATH", "").split(":") if p]
    writable = [str(p) for p in path_dirs if path_is_writable(p)]
    if writable:
        return CheckResult(
            "ENV-001", "Writable Directories in PATH",
            "High", "VULNERABLE",
            "Writable PATH entries:\n" + "\n".join(writable),
            "Remove writable directories from PATH or set them to 755; ensure privileged scripts use absolute paths and sanitized PATH."
        )
    return CheckResult(
        "ENV-001", "Writable Directories in PATH",
        "High", "NOT_VULNERABLE",
        "No user-writable entries detected in PATH.",
        "Keep PATH entries owned by root with 755 and immutable where feasible."
    )

def check_docker_socket(_: int) -> CheckResult:
    """Writable Docker socket => root-equivalent."""
    sock = Path("/var/run/docker.sock")
    if not sock.exists():
        return CheckResult(
            "DOCKER-001", "Docker Socket Writable",
            "Critical", "NOT_VULNERABLE",
            "No Docker socket found at /var/run/docker.sock.",
            "If Docker is required, restrict docker group membership and socket permissions."
        )
    writable = path_is_writable(sock)
    if writable:
        return CheckResult(
            "DOCKER-001", "Docker Socket Writable",
            "Critical", "VULNERABLE",
            f"{sock} mode={mode_octal(sock)} is writable by current user ({whoami()}).",
            "Remove user from docker group and restrict socket to 660 root:docker; audit for breakout abuse."
        )
    return CheckResult(
        "DOCKER-001", "Docker Socket Writable",
        "Critical", "NOT_VULNERABLE",
        f"{sock} present with mode {mode_octal(sock)}; not writable by current user.",
        "Restrict group membership and monitor access to the Docker daemon."
    )

def check_docker_group(_: int) -> CheckResult:
    rc, out, _ = run(["id"])
    if rc != 0:
        return CheckResult("DOCKER-002", "User in docker group",
                           "Critical", "INCONCLUSIVE",
                           "Unable to run 'id'.", "Inspect /etc/group for 'docker' membership.")
    if re.search(r"\bdocker\b", out):
        return CheckResult("DOCKER-002", "User in docker group",
                           "Critical", "VULNERABLE",
                           f"Current user in groups: {out}",
                           "Remove non-admin users from 'docker' group; treat docker as privileged.")
    return CheckResult("DOCKER-002", "User in docker group",
                       "Critical", "NOT_VULNERABLE",
                       f"Groups: {out}",
                       "Keep docker group tightly controlled.")

def check_world_writable_etc(max_find: int) -> CheckResult:
    """World-writable files in /etc are dangerous."""
    hits: List[str] = []
    base = Path("/etc")
    try:
        for root, dirs, files in os.walk(base):
            for name in files:
                p = Path(root) / name
                if file_is_world_writable(p):
                    hits.append(f"{p} mode={mode_octal(p)}")
                    if len(hits) >= max_find:
                        break
            if len(hits) >= max_find:
                break
    except Exception as e:
        return CheckResult("FS-001", "/etc World-writable Files",
                           "High", "INCONCLUSIVE",
                           f"Traversal error: {type(e).__name__}: {e}",
                           "Review /etc recursively and remove world-writable bits; set 0644 or stricter.")
    if hits:
        return CheckResult("FS-001", "/etc World-writable Files",
                           "High", "VULNERABLE",
                           "Examples:\n" + "\n".join(hits[:20]),
                           "Remove world-writable bits (chmod o-w); ensure ownership by root and proper permissions.")
    return CheckResult("FS-001", "/etc World-writable Files",
                       "High", "NOT_VULNERABLE",
                       "No world-writable files in /etc within scan limit.",
                       "Keep /etc strictly controlled; use configuration management to enforce modes.")

def check_authorized_keys_perms(_: int) -> CheckResult:
    """authorized_keys should be 600 and directory 700."""
    home = Path(os.path.expanduser("~"))
    ssh_dir = home / ".ssh"
    ak = ssh_dir / "authorized_keys"
    if not ak.exists():
        return CheckResult("SSH-002", "~/.ssh/authorized_keys Permissions",
                           "Medium", "NOT_VULNERABLE",
                           f"{ak} not present for user {whoami()}.",
                           "Ensure per-user keys use 600 (file) and 700 (~/.ssh).")
    issues = []
    if (ak.stat().st_mode & 0o077) != 0:
        issues.append(f"{ak} mode={mode_octal(ak)} (should be 600)")
    if ssh_dir.exists() and (ssh_dir.stat().st_mode & 0o077) != 0:
        issues.append(f"{ssh_dir} mode={mode_octal(ssh_dir)} (should be 700)")
    if issues:
        return CheckResult("SSH-002", "~/.ssh/authorized_keys Permissions",
                           "Medium", "VULNERABLE",
                           "; ".join(issues),
                           "chmod 600 ~/.ssh/authorized_keys && chmod 700 ~/.ssh; restrict ownership to the user.")
    return CheckResult("SSH-002", "~/.ssh/authorized_keys Permissions",
                       "Medium", "NOT_VULNERABLE",
                       f"authorized_keys and ~/.ssh modes appear strict ({mode_octal(ak)}, {mode_octal(ssh_dir) if ssh_dir.exists() else 'n/a'}).",
                       "Re-check after user provisioning or key changes.")

def check_private_key_perms(max_find: int) -> CheckResult:
    """Identify overly permissive private key files in user homes (perm only, no reads)."""
    homes = [Path(os.path.expanduser("~"))]  # current user scope
    patterns = (r"id_rsa$", r"id_ed25519$", r"id_dsa$")
    bad: List[str] = []
    for home in homes:
        ssh = home / ".ssh"
        if not ssh.exists():
            continue
        try:
            for root, dirs, files in os.walk(ssh):
                for f in files:
                    if any(re.search(pat, f) for pat in patterns):
                        p = Path(root) / f
                        mode = p.stat().st_mode & 0o777
                        if mode & 0o077:  # group/other any perms
                            bad.append(f"{p} mode={oct(mode)}")
                            if len(bad) >= max_find:
                                break
                if len(bad) >= max_find:
                    break
        except Exception as e:
            return CheckResult("SSH-003", "Private Key File Permissions",
                               "High", "INCONCLUSIVE",
                               f"Traversal error under {ssh}: {type(e).__name__}: {e}",
                               "Ensure private keys are 600; restrict directory to 700.")
    if bad:
        return CheckResult("SSH-003", "Private Key File Permissions",
                           "High", "VULNERABLE",
                           "Overly permissive private keys:\n" + "\n".join(bad),
                           "chmod 600 on private keys; rotate keys if exposure suspected.")
    return CheckResult("SSH-003", "Private Key File Permissions",
                       "High", "NOT_VULNERABLE",
                       "No overly permissive private keys found in current user's ~/.ssh.",
                       "Maintain 600 for keys and 700 for ~/.ssh.")

def check_cron_writable_scripts(max_find: int) -> CheckResult:
    """Root-run cron files that are world-writable are dangerous."""
    candidates = [
        Path("/etc/crontab"),
        Path("/etc/cron.d"),
        Path("/etc/cron.daily"),
        Path("/etc/cron.hourly"),
        Path("/etc/cron.weekly"),
        Path("/etc/cron.monthly"),
    ]
    hits: List[str] = []
    for c in candidates:
        if not c.exists():
            continue
        try:
            if c.is_file():
                if file_is_world_writable(c):
                    hits.append(f"{c} mode={mode_octal(c)}")
            else:
                for root, dirs, files in os.walk(c):
                    for f in files:
                        p = Path(root) / f
                        if file_is_world_writable(p):
                            hits.append(f"{p} mode={mode_octal(p)}")
                            if len(hits) >= max_find:
                                break
                    if len(hits) >= max_find:
                        break
        except Exception as e:
            return CheckResult("CRON-001", "Cron Files World-writable",
                               "High", "INCONCLUSIVE",
                               f"Traversal error: {type(e).__name__}: {e}",
                               "Ensure cron files are owned by root and not world-writable.")
    if hits:
        return CheckResult("CRON-001", "Cron Files World-writable",
                           "High", "VULNERABLE",
                           "Examples:\n" + "\n".join(hits),
                           "Remove world-writable bits; keep cron files 600/700 root-owned.")
    return CheckResult("CRON-001", "Cron Files World-writable",
                       "High", "NOT_VULNERABLE",
                       "No world-writable cron files found within scan limit.",
                       "Enforce permissions via configuration management.")

def check_exports_no_root_squash(_: int) -> CheckResult:
    """NFS no_root_squash allows clients to act as root."""
    exports = Path("/etc/exports")
    if not exports.exists():
        return CheckResult("NFS-001", "NFS no_root_squash",
                           "High", "NOT_VULNERABLE",
                           "/etc/exports not present.",
                           "If NFS is used, ensure 'root_squash' is enabled except for tightly controlled cases.")
    try:
        text = exports.read_text(errors="ignore")
    except Exception as e:
        return CheckResult("NFS-001", "NFS no_root_squash",
                           "High", "INCONCLUSIVE",
                           f"Unable to read /etc/exports: {type(e).__name__}: {e}",
                           "Review NFS export options; use root_squash and secure hosts.allow.")
    if re.search(r"\bno_root_squash\b", text):
        return CheckResult("NFS-001", "NFS no_root_squash",
                           "High", "VULNERABLE",
                           "Found 'no_root_squash' in /etc/exports.",
                           "Replace with 'root_squash'; restrict clients and export as read-only where possible.")
    return CheckResult("NFS-001", "NFS no_root_squash",
                       "High", "NOT_VULNERABLE",
                       "No 'no_root_squash' option detected.",
                       "Keep root squashing enabled.")

def check_tmp_mount_opts(_: int) -> CheckResult:
    """/tmp lacking noexec/nosuid is a common hardening gap (low severity)."""
    rc, out, _ = run(["mount"])
    if rc != 0:
        return CheckResult("MNT-001", "/tmp Mount Options",
                           "Low", "INCONCLUSIVE",
                           "Could not read mount info.", "Harden /tmp with nodev,nosuid,noexec if compatible.")
    m = re.search(r" on (/tmp) type .* \(([^)]+)\)", out)
    if not m:
        return CheckResult("MNT-001", "/tmp Mount Options",
                           "Low", "INCONCLUSIVE",
                           "No explicit /tmp mount entry found.", "Consider separate /tmp with nodev,nosuid,noexec.")
    opts = m.group(2).split(",")
    missing = [o for o in ("nodev","nosuid","noexec") if o not in opts]
    if missing:
        return CheckResult("MNT-001", "/tmp Mount Options",
                           "Low", "VULNERABLE",
                           f"/tmp mount options missing: {', '.join(missing)} (got: {m.group(2)})",
                           "Mount /tmp with nodev,nosuid,noexec; validate application compatibility first.")
    return CheckResult("MNT-001", "/tmp Mount Options",
                       "Low", "NOT_VULNERABLE",
                       f"/tmp options appear hardened: {m.group(2)}",
                       "Re-validate after OS upgrades.")

def check_sshd_ciphers(_: int) -> CheckResult:
    """Very rough check for legacy ciphers in sshd -T output."""
    rc, out, _ = run(["sshd", "-T"], timeout=8)
    if rc != 0:
        return CheckResult("SSH-003", "SSH Legacy Ciphers",
                           "Medium", "INCONCLUSIVE",
                           "Unable to query sshd -T.", "Set modern ciphers/MACs/KEX per distro benchmarks (e.g., chacha20-poly1305@openssh.com, aes256-gcm@openssh.com).")
    m = re.search(r"(?m)^ciphers\s+(.+)$", out)
    if not m:
        return CheckResult("SSH-003", "SSH Legacy Ciphers",
                           "Medium", "INCONCLUSIVE",
                           "Ciphers line not found in sshd -T.", "Define explicit strong cipher list in sshd_config.")
    ciphers = [c.strip() for c in m.group(1).split(",")]
    legacy_markers = {"cbc", "hmac-md5", "arcfour"}
    legacy = [c for c in ciphers if any(mark in c for mark in legacy_markers)]
    if legacy:
        return CheckResult("SSH-003", "SSH Legacy Ciphers",
                           "Medium", "VULNERABLE",
                           "Legacy patterns present: " + ", ".join(legacy[:10]),
                           "Remove legacy CBC/arcfour; prefer chacha20-poly1305@openssh.com and aes*-gcm; update clients as needed.")
    return CheckResult("SSH-003", "SSH Legacy Ciphers",
                       "Medium", "NOT_VULNERABLE",
                       "No obvious legacy ciphers detected in sshd -T.",
                       "Keep cipher/MAC/KEX lists aligned with current hardening guides.")

def check_local_listeners(_: int) -> CheckResult:
    """Identify services listening on 0.0.0.0 (informational -> low)."""
    rc, out, _ = run(["ss", "-tulpen"], timeout=6)
    if rc != 0:
        return CheckResult("NET-001", "Wide-open Listeners",
                           "Low", "INCONCLUSIVE",
                           "Could not list sockets with ss.", "Use ss -tulpen or netstat -plant to review listeners.")
    lines = [l for l in out.splitlines() if re.search(r"\bLISTEN\b", l)]
    open_any = [l for l in lines if re.search(r"\b0\.0\.0\.0:|\[::\]:", l)]
    if open_any:
        return CheckResult("NET-001", "Wide-open Listeners",
                           "Low", "VULNERABLE",
                           f"Listeners bound to 0.0.0.0/[::]:\n" + "\n".join(open_any[:20]),
                           "Bind services to explicit interfaces; restrict via firewalld/nftables and service ACLs.")
    return CheckResult("NET-001", "Wide-open Listeners",
                       "Low", "NOT_VULNERABLE",
                       "No 0.0.0.0/[::] listeners observed.",
                       "Keep listeners bound narrowly and filtered.")

# Register checks in desired order
CHECKS: List[Tuple[str, CheckFunc]] = [
    ("SSH PermitRootLogin", check_sshd_permit_root_login),
    ("SSH Legacy Ciphers", check_sshd_ciphers),
    ("Sudo NOPASSWD", check_sudo_nopasswd),
    ("Writable PATH entries", check_path_writable),
    ("Docker socket writable", check_docker_socket),
    ("User in docker group", check_docker_group),
    ("/etc world-writable files", check_world_writable_etc),
    ("authorized_keys perms", check_authorized_keys_perms),
    ("Private key perms", check_private_key_perms),
    ("Cron world-writable", check_cron_writable_scripts),
    ("NFS no_root_squash", check_exports_no_root_squash),
    ("/tmp mount options", check_tmp_mount_opts),
    ("Wide-open listeners", check_local_listeners),
]

# ---------------------------- Runner & Output ----------------------------

def write_csv(path: Path, rows: List[CheckResult]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["check_id", "name", "severity", "status", "evidence", "remediation"])
        for r in rows:
            w.writerow([r.check_id, r.name, r.severity, r.status, r.evidence, r.remediation])

def write_json(path: Path, rows: List[CheckResult], host_meta: Dict[str,str]) -> None:
    data = {
        "generated_at": dt.datetime.utcnow().isoformat() + "Z",
        "host": host_meta,
        "results": [dataclasses.asdict(r) for r in rows],
    }
    path.write_text(json.dumps(data, indent=2))

def host_metadata() -> Dict[str, str]:
    rc1, uname, _ = run(["uname", "-a"])
    osrel = ""
    try:
        osrel = Path("/etc/os-release").read_text(errors="ignore")
    except Exception:
        pass
    return {
        "user": whoami(),
        "uname": uname if rc1 == 0 else "",
        "os_release": short(osrel, 400),
    }

def main():
    ap = argparse.ArgumentParser(description="Read-only Linux hardening/misconfiguration checks.")
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    ap.add_argument("--csv", default=f"linux_vuln_scout_{ts}.csv", help="CSV output path")
    ap.add_argument("--json", default=f"linux_vuln_scout_{ts}.json", help="JSON output path")
    ap.add_argument("--max-find", type=int, default=200, help="Cap for file-system finding lists (performance/safety)")
    args = ap.parse_args()

    results: List[CheckResult] = []
    for name, fn in CHECKS:
        try:
            res = fn(args.max_find)
            results.append(res)
        except Exception as e:
            results.append(CheckResult(
                check_id=f"ERR-{re.sub('[^A-Z0-9]','', name.upper())[:6]}",
                name=name,
                severity="Low",
                status="INCONCLUSIVE",
                evidence=f"Check threw {type(e).__name__}: {e}",
                remediation="Re-run with appropriate privileges or review manually."
            ))

    csv_path = Path(args.csv).resolve()
    json_path = Path(args.json).resolve()
    write_csv(csv_path, results)
    write_json(json_path, results, host_metadata())

    # Console summary
    ok = sum(1 for r in results if r.status == "NOT_VULNERABLE")
    vulns = sum(1 for r in results if r.status == "VULNERABLE")
    inc = sum(1 for r in results if r.status == "INCONCLUSIVE")
    print(f"[+] Completed {len(results)} checks — VULN: {vulns}  OK: {ok}  INCONCLUSIVE: {inc}")
    print(f"[+] CSV:  {csv_path}")
    print(f"[+] JSON: {json_path}")

if __name__ == "__main__":
    main()
