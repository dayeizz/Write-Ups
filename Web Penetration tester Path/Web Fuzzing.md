# Web Fuzzing 

---

## 1. Hidden Path Fuzzing (Directories & Files)

**Objective:**
Fuzz folders and files inside a known hidden path to retrieve the flag.

**Target Path**

```
http://IP:PORT/webfuzzing_hidden_path/
```

**Command**

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
-u http://IP:PORT/webfuzzing_hidden_path/FUZZ \
-e .php,.html,.txt,.bak,.js \
-v
```

---

## 2. Recursive Directory Fuzzing

**Objective:**
Recursively fuzz directories to discover nested content and retrieve the flag.

**Target Path**

```
http://IP:PORT/recursive_fuzz/
```

**Command**

```bash
ffuf -u http://IP:PORT/recursive_fuzz/FUZZ \
-w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
-recursion \
-rate 500 \
-t 200 \
-ic -ac
```

**Manual Verification**

```bash
curl http://IP:PORT/recursive_fuzz/<DISCOVERED_PATH>
```

---

## 3. GET Parameter Fuzzing

**Objective:**
Fuzz a GET parameter to find the correct value that returns a flag.

**Initial Check**

```bash
curl http://IP:PORT/get.php
```

**Response**

```
Incorrect parameter value
x:
```

**Fuzzing Command**

```bash
ffuf -u "http://IP:PORT/get.php?x=FUZZ" \
-w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
-ac -ic -t 100
```

**Valid Parameter Found**

```bash
curl "http://IP:PORT/get.php?x=<VALID_VALUE>"
```

---

## 4. POST Parameter Fuzzing

**Objective:**
Identify the correct POST parameter value to retrieve the flag.

**Initial Check**

```bash
curl http://IP:PORT/post.php -d ""
```

**Response**

```
Incorrect parameter value
y:
```

**Fuzzing Command**

```bash
ffuf -u "http://IP:PORT/post.php" \
-X POST \
-d "y=FUZZ" \
-H "Content-Type: application/x-www-form-urlencoded" \
-w /usr/share/seclists/Discovery/Web-Content/common.txt \
-ac -ic -t 200
```

**Valid Parameter Found**

```bash
curl http://IP:PORT/post.php -d "y=<VALID_VALUE>"
```

---

## 5. Virtual Host Fuzzing (GoBuster)

### 5.1 VHost Enumeration (Prefix: `web-`)

**Objective:**
Identify a virtual host starting with `web-`.

**Hosts File**

```bash
echo "IP inlanefreight.htb" | sudo tee -a /etc/hosts
```

**Command**

```bash
gobuster vhost \
-u http://inlanefreight.htb:PORT \
-w /usr/share/seclists/Discovery/Web-Content/common.txt \
--append-domain \
-t 200 | grep web
```

**Result**

```
web-XXXX.inlanefreight.htb
```

---

### 5.2 Subdomain Enumeration (Prefix: `su`)

**Objective:**
Identify a subdomain starting with `su`.

**Command**

```bash
gobuster dns \
--domain inlanefreight.com \
-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
--quiet | grep su
```

**Result**

```
support.inlanefreight.com
```

---

## 6. Hidden Directory & Backup File Analysis

**Objective:**
Locate a hidden directory and analyze a `.tar.gz` file to validate the vulnerability.

**Directory Fuzzing**

```bash
ffuf -u http://IP:PORT/FUZZ \
-w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
-ac -ic -t 200
```

**File Fuzzing**

```bash
ffuf -u http://IP:PORT/<HIDDEN_DIR>/FUZZ.tar.gz \
-w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
-ac -ic -t 200
```

**Header Analysis**

```bash
curl -i "http://IP:PORT/<HIDDEN_DIR>/backup.tar.gz"
```

**Result**

```
Content-Length: 210
```

---

## 7. API Endpoint Fuzzing

**Objective:**
Identify a hidden API endpoint and retrieve its response value.

**Fuzzing Command**

```bash
ffuf -u http://IP:PORT/FUZZ \
-w /usr/share/seclists/Discovery/Web-Content/common.txt \
-mc 200 -ic -ac -t 200
```

**Discovered Endpoint**

```bash
curl "http://IP:PORT/<API_ENDPOINT>"
```

**Response**

```
h1dd3n_r357
```

---

## 8. Final Challenge – Full Attack Chain

**Objective:**
Complete enumeration and access chaining to retrieve the final HTB flag.

### Directory & File Discovery

```bash
ffuf -u http://IP:PORT/FUZZ \
-w /usr/share/seclists/Discovery/Web-Content/common.txt \
-recursion \
-e .php,.txt,.bak,.js \
-fc 403,404 \
-ic -t 200
```

### Parameter Fuzzing

```bash
ffuf -u http://IP:PORT/admin/panel.php?accessID=FUZZ \
-w /usr/share/seclists/Discovery/Web-Content/common.txt \
-ac -ic -t 200
```

```bash
curl "http://IP:PORT/admin/panel.php?accessID=getaccess"
```

---

### VHost Pivoting

```bash
echo "IP fuzzing_fun.htb" | sudo tee -a /etc/hosts
gobuster vhost -u http://fuzzing_fun.htb:PORT \
-w /usr/share/seclists/Discovery/Web-Content/common.txt \
--append-domain -t 200
```

```bash
echo "IP hidden.fuzzing_fun.htb" | sudo tee -a /etc/hosts
curl http://hidden.fuzzing_fun.htb:PORT
```

---

### Deep Recursive Fuzzing

```bash
ffuf -u http://hidden.fuzzing_fun.htb:PORT/godeep/FUZZ \
-w /usr/share/seclists/Discovery/Web-Content/common.txt \
-recursion -ic -ac -t 200
```

**Final Access**

```bash
curl http://hidden.fuzzing_fun.htb:PORT/godeep/<PATH>/index.php
```

---

## ✅ Final Flag

```
HTB{w3b_fuzz1ng_sk1lls}
```

---