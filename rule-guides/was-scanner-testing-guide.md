# WAS Scanner Capabilities & Testing Guide

This document outlines the current security scanners implemented in the WAS (Web Application Scanner) pipeline. It details how they work, what vulnerabilities they find, and how security testers can simulate these vulnerabilities for validation.

---

## 1. Vulnerable JavaScript Library Scanner (Retire.js Engine)
**Files:** `vulnerable-library-scan.js`, `retire-js-scan.js`

### How it works
This scanner analyzes the HTTP response body (HTML/JS) and request URLs to identify third-party JavaScript libraries (e.g., jQuery, React, Vue, Bootstrap). It utilizes two engines:
1. A static, lightweight engine for basic checks (`vulnerable-library-scan.js`).
2. An advanced engine (`retire-js-scan.js`) that dynamically fetches and caches the official [Retire.js vulnerability repository](https://github.com/RetireJS/retire.js). It uses complex URI and file-content regular expressions to accurately extract library versions.

It compares the extracted versions against known CVEs and vulnerability databases.

### Vulnerabilities Found
- **CWE-1104:** Use of Third Party Components with Known Vulnerabilities.
- Outdated libraries that can lead to Cross-Site Scripting (XSS), Prototype Pollution, ReDoS, or Remote Code Execution (RCE) depending on the library.

### Simulation / Test Cases
To test this scanner, configure the target application to serve the following responses:
1. **URI Matching:** Serve a script file with a vulnerable version in the name, e.g., `<script src="/assets/js/jquery-3.4.0.js"></script>`.
2. **Content Matching:** Embed a vulnerable library's signature inside the response body of a `.js` file, e.g., `/*! jQuery v1.11.3 */`.
3. **HTML Inline Matching:** Include vulnerable versions of React or AngularJS inside an HTML response, e.g., `AngularJS v1.5.0`.

---

## 2. Hardcoded Secrets & API Key Scanner
**File:** `js-secret-scan.js`

### How it works
This scanner specifically targets responses with `.js` extensions or `application/javascript` / `text/html` content types. It parses the response body looking for high-entropy strings and predefined signature patterns matching sensitive API keys, tokens, and cryptographic keys. To protect sensitive data during scans, the scanner masks the found secrets before persisting them to the database.

### Vulnerabilities Found
- **CWE-798:** Use of Hard-coded Credentials.
- Exposed AWS Access Keys, Google Cloud API Keys, Stripe API Keys, Slack Tokens, GitHub Personal Access Tokens, RSA Private Keys, and generic authorization tokens.

### Simulation / Test Cases
Serve an HTTP response (with `Content-Type: text/javascript` or `text/html`) containing any of the following strings:
1. **AWS Key:** `const accessKey = "xxxxx";`
2. **Slack Token:** `var token = "xoxb-xxxxxx-xxxxxxxx-xxxxx";`
3. **RSA Private Key:** 
   ```text
   -----BEGIN RSA PRIVATE KEY-----
   MIIEpQIBAAKCAQEA...
   -----END RSA PRIVATE KEY-----
   ```
4. **Generic Token:** `const api_key = "sk_live_1234567890abcdef12345678";`

---

## 3. Second-Order Subdomain Takeover Scanner
**File:** `subdomain-takeover-scan.js`

### How it works
This passive scanner extracts all external resource domains loaded in an HTML response (e.g., via `href="..."` or `src="..."`). It compares these domains against the target organization's root domain (extracted from the scan metadata). If a domain does *not* belong to the target organization, it flags it as an external dependency.

While this doesn't actively verify if the third-party domain is vulnerable/unregistered (to avoid aggressive outbound requests), it flags all external references as potential Broken Link Hijacking or 2nd-Order Subdomain Takeover risks.

### Vulnerabilities Found
- **CWE-350:** Reliance on Reverse DNS Resolution for a Security-Critical Action (adapted for Subdomain Takeover / Broken Link Hijacking).
- Points out abandoned SaaS services (Heroku, GitHub Pages, S3 Buckets) that are still linked in the application source.

### Simulation / Test Cases
Assuming the scan target is configured as `example.com`:
1. **External Script:** Serve an HTML page containing `<script src="https://my-abandoned-project.herokuapp.com/app.js"></script>`. 
2. **External Image/Resource:** Include `<img src="https://unclaimed-company-bucket.s3.amazonaws.com/logo.png" />`.
3. **Valid Domain (Negative Test):** Include `<script src="https://api.example.com/data.js"></script>`. The scanner should *not* flag this, as it shares the `example.com` root domain.

---

## 4. Server-Side Request Forgery (SSRF) Scanner
**File:** `ssrf-scan.js`

### How it works
This is an **active scanner** that uses **Out-of-Band (OOB) detection** via the public [interactsh](https://interact.sh) service to confirm SSRF vulnerabilities with zero false positives.

**Workflow:**
1. On first execution, the scanner registers a session with `interact.sh`, obtaining a unique `correlationId` and `secretKey`. This session is cached for the lifetime of the worker process.
2. It recursively scans all `request.params` and `request.body` fields, looking for ~35 parameter names known to trigger server-side URL fetching (e.g., `url`, `redirect`, `callback`, `webhook`, `src`, `endpoint`, `proxy`, etc.).
3. For each matching parameter, it generates a **unique 8-char token** and injects a crafted interactsh URL: `http://{token}.{correlationId}.interact.sh`.
4. The modified request is replayed against the target server.
5. After all injections, it waits **5 seconds** for OOB interactions to arrive.
6. It polls the interactsh API and **correlates each OOB hit back to the exact parameter** that triggered it using the unique token.
7. Confirmed SSRF findings are deduplicated per scan using Redis.

### Vulnerabilities Found
- **CWE-918:** Server-Side Request Forgery (SSRF).
- Any endpoint that accepts a URL in a parameter and fetches it server-side without validation.

### Impact of SSRF
A confirmed SSRF finding can lead to:
- **Cloud credential theft** — Fetching `http://169.254.169.254/latest/meta-data/iam/security-credentials/` to steal AWS IAM keys.
- **Internal network pivoting** — Scanning `http://10.0.0.x:port` to discover unexposed internal services.
- **Firewall bypass** — Accessing internal APIs gated by network policy (e.g., Kubernetes API server, Redis, Elasticsearch).
- **Remote Code Execution** — In chained exploitation scenarios (e.g., Gopher protocol to Redis RCE).

### Simulation / Test Cases
Set up an endpoint on your test application that accepts a URL parameter and fetches its content server-side (e.g., using `curl`, `file_get_contents`, `urllib`, `axios`):

#### Test 1 — Query Parameter Injection
```
GET /api/fetch?url=http://[your-collaborator-url]
```
Expected: The scanner injects its interactsh URL into the `url` param. If the server fetches it, an OOB interaction is confirmed.

#### Test 2 — JSON Body Injection
```http
POST /api/preview
Content-Type: application/json

{ "callback": "http://[your-collaborator-url]" }
```
Expected: The scanner replaces `callback` with the interactsh payload and receives an OOB interaction.

#### Test 3 — Redirect Parameter
```
GET /api/login?redirect_url=http://[your-collaborator-url]
```
Expected: The scanner targets `redirect_url` as a high-signal SSRF vector.

#### Test 4 — Escalation After Confirmation
Once SSRF is confirmed via OOB, manually escalate with:
```
http://169.254.169.254/latest/meta-data/          (AWS metadata)
http://metadata.google.internal/computeMetadata/  (GCP metadata)
http://localhost:6379                              (internal Redis)
http://kubernetes.default.svc/api/v1/pods         (Kubernetes API)
```

#### Negative Test
An endpoint that accepts a `redirect_url` but validates it against an allowlist of permitted domains should **not** receive an OOB interaction, and no finding should be reported.
