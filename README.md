# 🛡️ SOC Alert Monitor v1.0

**Real-Time Security Event Detection + Telegram Alerts**

A Python-based Security Operations Center (SOC) monitoring tool built on Kali Linux that detects cyber threats in real-time by analyzing Linux system logs, applies 18 detection rules mapped to MITRE ATT&CK, and sends instant formatted alerts to Telegram.

**Author:** Itay Bechor

---

## 📋 Features

- **Real-time log monitoring** — Tails /var/log/auth.log and /var/log/syslog every second
- **18 detection rules** — Each mapped to a MITRE ATT&CK technique
- **Telegram alerts** — Instant formatted messages with severity, details, and response recommendations
- **Brute force aggregation** — Counts failed logins per IP within a 5-minute window
- **Cooldown filter** — Prevents duplicate alerts (120-second window)
- **SQLite database** — Stores all alerts for forensic investigation
- **Severity classification** — CRITICAL 🔴 / HIGH 🟠 / MEDIUM 🟡 / LOW 🟢 / INFO 🔵
- **Daily summary** — Automated Telegram report every 24 hours
- **Simulation mode** — Test all rules with fake attack events

---

## 🔍 Detection Rules

| # | Rule | Severity | MITRE ATT&CK |
|---|------|----------|---------------|
| 1 | SSH Brute Force (aggregated) | 🔴 CRITICAL | T1110.001 - Password Guessing |
| 2 | Reverse Shell Detected | 🔴 CRITICAL | T1059 - Command Interpreter |
| 3 | Suspicious Tool Execution (mimikatz, BloodHound) | 🔴 CRITICAL | T1003 - Credential Dumping |
| 4 | SSH Root Login | 🟠 HIGH | T1078.003 - Local Accounts |
| 5 | Sudo Auth Failure | 🟠 HIGH | T1548.003 - Sudo Caching |
| 6 | New User Created | 🟠 HIGH | T1136.001 - Local Account |
| 7 | User Deleted | 🟠 HIGH | T1531 - Account Access Removal |
| 8 | Group Membership Changed | 🟠 HIGH | T1098 - Account Manipulation |
| 9 | Firewall Rule Changed | 🟠 HIGH | T1562.004 - Modify Firewall |
| 10 | Base64 Encoded Command | 🟠 HIGH | T1027 - Obfuscated Files |
| 11 | Download to /tmp | 🟠 HIGH | T1105 - Ingress Tool Transfer |
| 12 | SSH Config Changed | 🟠 HIGH | T1098 - Account Manipulation |
| 13 | SSH Failed Login | 🟡 MEDIUM | T1110 - Brute Force |
| 14 | Password Changed | 🟡 MEDIUM | T1098 - Account Manipulation |
| 15 | Su Command Used | 🟡 MEDIUM | T1548 - Abuse Elevation Control |
| 16 | Cron Job Modified | 🟡 MEDIUM | T1053.003 - Cron |
| 17 | Sudo Command Executed | 🟢 LOW | T1548.003 - Sudo Caching |
| 18 | Service State Change | 🟢 LOW | T1543 - Modify System Process |

---

## 🏗️ Architecture



Log Sources → Log Reader → SOC Detection Engine (18 Rules) → Alert Builder → Cooldown Filter → Telegram + SQLite + Terminal


**4-Stage Pipeline:**
1. **Log Monitoring** — Tails auth.log and syslog in real-time
2. **Rule Matching** — 18 regex patterns with MITRE ATT&CK mapping
3. **Alert Building** — Extracts IP, user, port, assigns severity, generates hash
4. **Output Delivery** — Telegram bot + SQLite database + Terminal console

---

## ⚡ Quick Start

### Prerequisites
- Kali Linux / Debian-based system
- Python 3
- Telegram Bot (create via @BotFather)

### Installation

```bash
pip3 install requests python-telegram-bot --break-system-packages

sudo apt install rsyslog -y
sudo systemctl enable rsyslog
sudo systemctl start rsyslog


Configuration
Edit the script and set your Telegram credentials:

TELEGRAM_BOT_TOKEN = "your_bot_token_here"
TELEGRAM_CHAT_ID = "your_chat_id_here"


Run
# Simulation mode (test with fake events)
python3 soc_alert_monitor.py --simulate

# Live monitoring (real system logs)
sudo python3 soc_alert_monitor.py



🧪 Simulation Mode
The –simulate flag generates a full attack chain:
	1.	SSH Brute Force — 5 failed logins from 192.168.1.100
	2.	Successful SSH Login — User itay from 10.0.0.50
	3.	Root SSH Login — From suspicious IP 203.0.113.42
	4.	Sudo Command — cat /etc/shadow
	5.	Sudo Auth Failure — User hacker failed sudo
	6.	Backdoor User Created — useradd backdoor
	7.	Password Changed — For user backdoor
	8.	Reverse Shell — bash -i to 10.10.14.1:9001
	9.	mimikatz Execution — Credential dumping tool
	10.	Base64 Encoded Command — Obfuscated execution
	11.	Payload Download — wget to /tmp/
	12.	Cron Job Modified — Persistence mechanism
	13.	Firewall Rule Changed — Opening port 4444
	14.	Service Started — Apache HTTP Server



📱 Telegram Alert Example
🔴 SOC ALERT — CRITICAL 🔴
━━━━━━━━━━━━━━━━━━━━━━
📋 Rule: SSH Brute Force
🖥 Host: kali
📁 Source: /var/log/auth.log
🕐 Time: 2026-04-05 04:36:46
━━━━━━━━━━━━━━━━━━━━━━
📝 Description:
🚨 5 failed SSH logins from 127.0.0.1 in 5 min!

🔍 Details:
  • source_ip: 127.0.0.1
  • target_user: fakeuser
  • attempts: 5
  • window: 5 minutes

🛡 MITRE ATT&CK: T1110.001 - Password Guessing

💡 Recommendation:
⚠️ Block the source IP immediately!
  sudo iptables -A INPUT -s 127.0.0.1 -j DROP
━━━━━━━━━━━━━━━━━━━━━━



🛠️ Tech Stack
