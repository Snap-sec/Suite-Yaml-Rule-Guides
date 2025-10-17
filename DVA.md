# 💀 Vulnerable API — Security Training (Markdown) 💀

> **WARNING:** This API is intentionally insecure and designed purely for educational purposes to demonstrate common API vulnerabilities. **DO NOT** use this code or deploy it in any production environment.

---

**Base URL:** `http://localhost:3000`

---

## 🔐 Authentication & Authorization Vulnerabilities

### 1. Authentication Bypass (Logic Flaw)

* **Endpoint:** `POST /api/auth_bypass`
* **Field / Value:**

  ```json
  { "username": "admin", "password": "A-N-Y-T-H-I-N-G" }
  ```
* **Vulnerability:** Authentication uses a flawed comparison check — an attacker can bypass the password verification if they know the administrator's username.
* **How to test:** Send the POST request with the payload above. The server responds with a successful login (HTTP 200) without requiring the actual admin password.

---

### 2. Authorization Bypass (RBAC)

* **Endpoint:** `GET /api/admin/flag`
* **Testing header:** `Authorization: Bearer 1` (token for user `alice`, role `user`)
* **Vulnerability:** RBAC enforcement is weak or missing. A normal admin-only endpoint returns sensitive data when requested by a non-admin user.
* **How to test:** Make the GET request while authenticated as user ID `1` (alice). If the secret (`secret_flag`) is returned, the authorization check is insufficient or bypassed.

---

## 💉 Injection Vulnerabilities

### 3. SQL Injection (SQLi)

* **Endpoint:** `POST /api/sqli_lookup`
* **Field / Value:**

  ```json
  { "id": "1 OR 1=1" }
  ```
* **Vulnerability:** User input is concatenated directly into a SQL query string (no parameterized queries). The injected condition `OR 1=1` makes the WHERE clause always true and may return all rows.
* **How to test:** POST the payload above. Observe that the server returns more records than expected (potentially all users).

---

### 4. Server-Side Template Injection (SSTI)

* **Endpoint:** `POST /api/ssti_render`
* **Field / Value:**

  ```json
  { "template": "The result is: <%= 99 * 11 %>" }
  ```
* **Exploit example:**

  ```json
  { "template": "Template says: <%= global.process.mainModule.require('child_process').execSync('whoami').toString() %>" }
  ```
* **Vulnerability:** The server renders user-supplied input using EJS, allowing execution of arbitrary template expressions and potentially OS-level code.
* **How to test:** POST the template payload. The server evaluates the expression and returns the result (e.g., `1089` for the multiplication example). More dangerous payloads may execute system commands.

---

### 5. NoSQL Injection (Conceptual)

* **Endpoint:** `POST /api/nosqli_lookup`
* **Field / Value:**

  ```json
  { "productId": "product_A1", "secret": false }
  ```
* **Vulnerability:** The endpoint performs loose comparisons or uses user input directly in logical checks. In a real NoSQL database, query operators (e.g. `{"secret": {"$ne": null}}`) or type-juggling could alter logic and bypass intended checks.
* **How to test:** Construct payloads that use operator-like objects (if the server deserializes them into query objects) and observe unintended results.

---

### 6. Command Injection

* **Endpoint:** `POST /api/command_injection`
* **Field / Value:**

  ```json
  { "target": "127.0.0.1; cat vulnerable_api.js" }
  ```
* **Vulnerability:** User input is concatenated into a shell command executed with `spawn('/bin/sh', ['-c', command])` without sanitization. Delimiters (`;`, `&&`, `|`) allow additional commands to run.
* **How to test:** POST the payload above. The server may execute the injected `cat` command and return the file contents in the response.

---

## 🛠️ Data Exposure & Manipulation

### 7. IDOR (Insecure Direct Object Reference)

* **Endpoint:** `GET /api/idor/view_note/:id`
* **Example path:** `/api/idor/view_note/2`
* **Testing header:** `Authorization: Bearer 1` (user `alice`)
* **Vulnerability:** The endpoint returns resources by ID without verifying requester ownership.
* **How to test:** Have Alice (ID 1) request Note ID 2 (belongs to Bob, ID 2). If Alice receives Bob's private note, the endpoint lacks proper access control.

---

### 8. Mass Assignment

* **Endpoint:** `POST /api/mass_assignment/update`
* **Field / Value:**

  ```json
  { "email": "alice_new_email@test.com", "role": "admin", "balance": 9999999.00 }
  ```
* **Vulnerability:** The server merges user-supplied JSON directly into a database object without whitelisting allowed fields. This permits changes to privileged fields (`role`, `balance`, etc.).
* **How to test:** Authenticate as a regular user (Bearer 1) and POST the payload above. If restricted fields are updated, mass-assignment protections are missing.

---

## 🌐 Client-Side & State Vulnerabilities

### 9. XSS (Stored)

* **Injection endpoint:** `POST /api/update_profile`
* **Exploitation endpoint:** `GET /api/xss_profile`
* **Injection payload:**

  ```json
  { "bio": "XSS Demo: <img src=x onerror=alert('Stored-XSS-Success')>" }
  ```
* **Vulnerability:** User-supplied content is stored and later rendered unescaped in profile views, enabling stored XSS.
* **How to test:** POST the payload to store the malicious `bio`, then GET the profile. The script runs when the profile is rendered.

---

### 10. OTP Bruteforce

* **Endpoint:** `POST /api/otp_verify`
* **Field / Value:**

  ```json
  { "email": "alice@test.com", "otp": "1234" }
  ```
* **Vulnerability:** No rate limiting and the OTP is a short numeric code. An attacker can enumerate all `0000`–`9999` combinations programmatically.
* **How to test:** Script all 10,000 combinations; without rate-limiting or lockouts, the OTP will eventually be guessed.

---

### 11. CSRF (Cross-Site Request Forgery)

* **Endpoint:** `POST /api/csrf_action`
* **Field / Value:**

  ```json
  { "action": "Transfer 1000 to Malicious Account" }
  ```
* **Vulnerability:** The endpoint accepts state-changing requests without a CSRF token or same-site protections.
* **How to test:** Send the POST request with a valid Authorization header (Bearer 1). If processed, an external site could coerce an authenticated browser to perform actions on the user’s behalf.

---

### 12. Clickjacking

* **Endpoint:** `GET /api/clickjacking_page`
* **Vulnerability:** The response lacks anti-framing headers (e.g., `X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors 'none'`), allowing the page to be embedded in an attacker-controlled iframe.
* **How to test:** GET the endpoint and inspect response headers. If framing protection headers are absent or weak, the page can be used in a clickjacking attack.

---

## ⚙️ Configuration & Miscellaneous Vulnerabilities

### 13. CORS Issue (Overly Permissive)

* **Endpoint:** `GET /api/cors_issue`
* **Vulnerability:** Server is configured with `cors({ origin: '*', credentials: true })`. This combination is insecure because `Access-Control-Allow-Origin: *` with credentials is contradictory and enables cross-origin credentialed requests.
* **How to test:** Inspect response headers. The presence of `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true` confirms the misconfiguration.

---

### 14. SSRF (Server-Side Request Forgery)

* **Endpoint:** `GET /api/ssrf_proxy?url=`
* **Testing URL example:**

  ```
  ```

[http://localhost:3000/api/ssrf_proxy?url=http://localhost:3000/api/admin/flag](http://localhost:3000/api/ssrf_proxy?url=http://localhost:3000/api/admin/flag)

````
- **Vulnerability:** The server fetches the user-supplied URL without validating that it points to an external resource, enabling access to internal services and metadata endpoints.
- **How to test:** Request an internal-only resource through the proxy (e.g., the admin flag). If returned, the SSRF is successful.

---

### 15. Insecure File Upload
- **Endpoint:** `POST /api/upload` (multipart/form-data)
- **Fields:** `file` (File), optional `fileName` (Text)
- **Vulnerability:** No validation of file type, extension, or filename. Unsanitized filenames may allow path traversal (e.g., `../`) or web shell placement if the server stores uploaded files in a web-accessible directory.
- **Exploit example:** Setting `fileName` to `../vulnerable_api.js` attempts to overwrite or place files outside the intended directory (depending on server configuration).
- **How to test:** Upload a file while manipulating `fileName`. Observe whether the file is stored in unexpected locations or becomes executable.

---

### 16. Validation Bypass (Input Length)
- **Endpoint:** `POST /api/validation_bypass`
- **Field / Value:**
```json
{ "name": "<1000 character string>" }
````

* **Vulnerability:** Missing or weak input validation allows extremely long input, increasing risks for resource exhaustion or database issues.
* **How to test:** POST very large payloads (e.g., 1000+ characters). If accepted, input length checks are absent or insufficient.

---

## ✅ Safe use / training recommendations

* Run this vulnerable API **only** in an isolated lab environment (local VM, container, or isolated network). Do not expose it to the public internet.
* Use this project for **educational, testing, and demonstration** purposes only.
* When practicing exploits, always obtain explicit permission from the system owner.

---

*Document prepared for training and classroom use.*
