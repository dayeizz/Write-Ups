# Information Gathering & Reconnaissance (Structured)

---

## 1. DNS Enumeration Basics

### 1.1 DNS Query (A Record)

**Command:**

```
dig google.com
```

**Result:**

* Domain: `google.com`
* Record Type: A
* IP Address: `142.251.47.142`
* Status: `NOERROR`

---

## 2. WHOIS Enumeration

### 2.1 PayPal Domain

**Task:** Identify registrar IANA ID for `paypal.com`

**Command:**

```
whois paypal.com
```

**Result:**

* Registrar IANA ID: *(from WHOIS output)*

### 2.2 Tesla Domain

**Task:** Identify admin email contact for `tesla.com`

**Command:**

```
whois tesla.com
```

**Result:**

* Admin Email: *(from WHOIS output)*

---

## 3. DNS Resolution & Reverse Lookup

### 3.1 Domain to IP Mapping

**Domain:** `inlanefreight.com`

**Command:**

```
dig inlanefreight.com
```

**Result:**

* IP Address: `134.209.24.248`

### 3.2 Reverse DNS (PTR Record)

**IP Address:** `134.209.24.248`

**Command:**

```
dig -x 134.209.24.248
```

**Result:**

* PTR Domain: `inlanefreight.com`

---

## 4. Mail Server Enumeration

### 4.1 MX Records

**Domain:** `facebook.com`

**Command:**

```
dig facebook.com MX
```

**Result:**

* Mail Server: `smtpin.vvv.facebook.com`

---

## 5. Subdomain Enumeration

### 5.1 Known Subdomains

* www
* ns1
* ns2
* ns3
* blog
* support
* customer

### 5.2 Brute-Forcing Subdomains

**Command:**

```
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

**Discovered Subdomain:**

* `my.inlanefreight.com`

---

## 6. DNS Zone Transfer (AXFR)

### 6.1 Zone Transfer Execution

**Domain:** `inlanefreight.htb`

**Command:**

```
dig axfr @dns_zone_transfer inlanefreight.htb
```

**Results:**

* Total DNS Records Retrieved: `22`

### 6.2 Key Findings from Zone Records

* **FTP Admin Host IP:** `10.10.34.2`
* **Largest IP in 10.10.200.0/24 Range:** `10.10.200.14`

---

## 7. Local Host Configuration

### 7.1 Hosts File Update

**File:** `/etc/hosts`

**Entry Added:**

```
83.136.252.57 inlanefreight.htb
```

---

## 8. Virtual Host (vHost) Enumeration

### 8.1 Brute-Forcing vHosts

**Tool:** gobuster

**Command Template:**

```
gobuster vhost -u http://inlanefreight.htb:<PORT> \
-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```

### 8.2 Identified vHosts

* `app.inlanefreight.local`
* `dev.inlanefreight.local`

---

## 9. Web Server & Application Enumeration

### 9.1 app.inlanefreight.local

**Tool:** nikto

**Command:**

```
nikto -h app.inlanefreight.local -Tuning b
```

**Findings:**

* Apache Version: `2.4.41`
* CMS: `Joomla`

### 9.2 dev.inlanefreight.local

**Finding:**

* Operating System: `Ubuntu`

---

## 10. Web Crawling & Spidering

### 10.1 ReconSpider Setup

**Steps:**

1. `pip3 install scrapy --break-system-packages`
2. `wget https://academy.hackthebox.com/storage/modules/279/ReconSpider.zip`
3. `unzip ReconSpider.zip`
4. `python3 ReconSpider.py http://inlanefreight.com`

**Result:**

* Future reports location: `files.inlanefreight.com`

---

## 11. Historical Web Intelligence (Wayback)

* **HackTheBox Labs (08-Aug-2018):** `74`
* **HackTheBox Members (10-Jun-2017):** `3054`
* **facebook.com redirect (Mar 2002):** `http://site.aboutface.com/`
* **PayPal (Oct 1999) product:** `Palm Organizer`
* **Google prototype (Nov 1998):** `http://google.stanford.edu/`
* **IANA.org last updated (Mar 2000):** `17-December-99`
* **Wikipedia articles (09-Feb-2003):** `3000` 

---

## 12. Targeted Assessment Summary

**Target:** `83.136.248.107:52116`

### 12.1 Domain & Registrar Info

* **Domain:** `inlanefreight.com`
* **Registrar IANA ID:** `468`

### 12.2 Web Server Identification

**Command:**

```
curl -i http://inlanefreight.htb:<PORT>
```

**Result:**

* HTTP Server Software: `nginx`

---

## 13. Hidden Admin & API Key Discovery

### 13.1 Discovery Process

1. `gobuster vhost -u http:/inlanefreight.htb:port -w /usr/share/seclist/discovery/dns/subdomains-top1million-110000.txt --append-domain` → `web1337.inlanefreight.htb`
2. `ffuf -u http://web1337.inlanefreight.htb:<PORT>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .html -v` → `robots.txt`
3. Hidden path → `/admin_h1dd3n/` → API key

### 13.2 Developer Subdomain Crawl

1. `gobuster vhost -u http:/web1337.inlanefreight.htb:port -w /usr/share/seclist/discovery/dns/subdomains-top1million-110000.txt --append-domain` → `dev.web1337.inlanefreight.htb`
2. `python3 ReconSpider.py http://dev.web1337.inlanefreight.htb:<port>` → `cat result.json` → Email address & New API key developers plan to rotate to.
