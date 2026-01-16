# JavaScript Deobfuscation – Structured Notes

---

## 1. Source Code Inspection

**Objective:**
Identify hidden information by reviewing the page source.

**Method**

* Open browser DevTools
* Inspect the page source

**Result**

```
HTB{4lw4y5_r34d_7h3_50urc3}
```

---

## 2. Deobfuscating JavaScript (`eval` Abuse)

**Objective:**
Reveal hidden logic inside an obfuscated JavaScript file.

**Steps**

1. Open `secret.js` from the page source
2. Copy the JavaScript code
3. Paste it into the browser console
4. Replace `eval()` with `console.log()`
5. Execute the script

**Flag**

```
HTB{1_4m_7h3_53r14l_g3n3r470r!}
```

---

## 3. Sending a POST Request (`serial.php`)

**Objective:**
Interact with a backend endpoint to retrieve encoded data.

**Request**

```bash
curl http://IP:PORT/serial.php -d ""
```

**Response**

```
N2gxNV8xNV9hX3MzY3IzN19tMzU1NGcz
```

---

## 4. Identify & Decode the Encoding

**Objective:**
Determine the encoding type and decode the returned string.

**Encoding Identified**

* Base64

**Decoded Value**

```
7h15_15_a_s3cr37_m3554g3
```

---

## 5. Submit the Decoded Serial

**Request**

```bash
curl http://IP:PORT/keys.php -d "serial=7h15_15_a_s3cr37_m3554g3"
```

**Flag**

```
HTB{ju57_4n07h3r_r4nd0m_53r14l}
```

---

## 6. Identify JavaScript File Used by the Page

**Objective:**
Find the JavaScript file referenced in the HTML source.

**Method**

* Inspect HTML source code

**JavaScript File**

```
api.min.js
```

---

## 7. Execute JavaScript Code

**Objective:**
Run the JavaScript file and observe its behavior.

**Method**

* Load the file
* Execute code in browser console

**Output**

```
HTB{j4v45cr1p7_3num3r4710n_15_k3y}
```

---

## 8. Deobfuscate the JavaScript Code

**Objective:**
Extract the hidden `flag` variable from obfuscated JavaScript.

**Deobfuscated Code**

```javascript
var flag = 'HTB{n' + '3v3r_' + 'run_0' + 'bfu5c' + '473d_' + 'c0d3!' + '}';
console.log(flag);
```

**Flag**

```
HTB{n3v3r_run_0bfu5c473d_c0d3!}
```

---

## 9. Analyze JavaScript Logic to Extract a Secret Key

**Objective:**
Replicate JavaScript logic to retrieve a backend-generated key.

**Request**

```bash
curl http://IP:PORT/keys.php -d ""
```

**Response**

```
4150495f70336e5f37333537316e365f31355f66756e
```

---

## 10. Decode the Secret Key

**Objective:**
Identify encoding and decode the secret key.

**Encoding Identified**

* Hex

**Decoded Key**

```
API_p3n_73571n6_15_fun
```

---

## 11. Submit the Decoded Key

**Request**

```bash
curl http://IP:PORT/keys.php -d "key=API_p3n_73571n6_15_fun"
```

**Final Flag**

```
HTB{r34dy_70_h4ck_my_w4y_1n_2_HTB}
```

---