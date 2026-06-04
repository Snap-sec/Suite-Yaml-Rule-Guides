# New Advanced Rules Documentation

This page contains the raw YAML for the newly added advanced vulnerability detection rules so you can easily copy and use them directly in your scanner.

---

## 1. HTTP Method Override Bypass
**Path:** `authorization_and_authentication/method-override-bypass.yml`
**Description:** Tests if authorization or WAF restrictions can be bypassed by spoofing the HTTP method via `X-HTTP-Method-Override`.

```yaml
rule_name: HTTP Method Override Bypass
description: "Detects authorization bypass or WAF evasion by spoofing the HTTP method via override headers."

single_match: true

transform:
  header:
    add:
      X-HTTP-Method-Override: "PUT"
      X-Method-Override: "PUT"
      X-Forwarded-Method: "PUT"
      X-HTTP-Method: "PUT"

match_on:
  status: 
    in: [200, 201, 204]
  body:
    contains:
      - value: "(?i)(success|updated|created|modified|admin|true)"
        options:
          regex: true

report:
  title: "Authorization Bypass via HTTP Method Override"
  description: |
    The application processes HTTP Method Override headers (e.g., X-HTTP-Method-Override) 
    and successfully executed a restricted action or bypassed authorization controls.
    
    This technique is often used to bypass Web Application Firewalls (WAFs) or 
    poorly configured routing rules that only protect specific verbs like POST or DELETE.

    Original Request:
    {{original}}

    Transformed Request:
    {{req}}

    Response:
    {{res}}

  cwe: "CWE-650"
  severity: low
  cvssScore: "7.5"
  mitigation: |
    1. Ignore method override headers unless strictly necessary for legacy clients.
    2. Ensure authorization checks are applied consistently regardless of the HTTP method.
    3. Configure WAFs to block requests containing unexpected method override headers.
  stepsToReproduce: |
    1. Send the request with 'X-HTTP-Method-Override: PUT' added to the headers.
    2. Observe that the server treats the request as a PUT and succeeds.
  tags: "bypass,authorization,headers,high"
  impact: "Unauthorized data modification or access control bypass."
```

---

## 2. Host Header Poisoning (Open Redirect / Routing Bypass)
**Path:** `open_redirect/host-header-poisoning.yml`
**Description:** Injects an attacker-controlled domain into the `Host` and `X-Forwarded-Host` headers and checks if it reflects in the `Location` header, leading to Open Redirects or Web Cache Poisoning.

```yaml
rule_name: Host Header Poisoning (Open Redirect / Routing Bypass)
description: "Detects Host header poisoning by injecting a malicious host and observing if it reflects in routing or Location headers."

single_match: true

transform:
  header:
    add:
      X-Forwarded-Host: "evil.snapsec.co"
      X-Host: "evil.snapsec.co"
    modify:
      Host: "evil.snapsec.co"

match_on:
  status:
    in: [301, 302, 307, 308]
  header:
    Location:
      contains:
        - value: "(?i)^https?://evil\\.snapsec\\.co.*"
          options:
            regex: true

report:
  title: "Host Header Poisoning Detected"
  description: |
    The application is vulnerable to Host header poisoning. 
    By manipulating the 'Host', 'X-Forwarded-Host', or 'X-Host' headers, the application 
    was tricked into reflecting the attacker-controlled domain in the 'Location' header.
    
    This can lead to Open Redirects, Password Reset Poisoning, or Web Cache Poisoning.

    Original Request:
    {{original}}

    Transformed Request:
    {{req}}

    Response:
    {{res}}

  cwe: "CWE-601"
  severity: medium
  cvssScore: "6.1"
  mitigation: |
    1. Do not rely on the 'Host' header or 'X-Forwarded-Host' for absolute URL generation.
    2. Use a statically configured server name or base URL in application settings.
    3. Validate the Host header against an allowlist of trusted domains.
  stepsToReproduce: |
    1. Send a request with 'X-Forwarded-Host: evil.snapsec.co'.
    2. Observe the server responding with a 3xx redirect to 'http://evil.snapsec.co/...'.
  tags: "host-poisoning,open-redirect,headers,medium"
  impact: "Phishing via Open Redirect or Password Reset token theft."
```

---

## 3. Directory Listing Enabled (Recursive Path Traversal)
**Path:** `error_and_logs/directory-listing.yml`
**Description:** Uses the `recursive: true` engine feature to traverse parent directories and looks for common Apache/Nginx directory listing signatures (e.g., "Index of /").

```yaml
rule_name: Directory Listing Enabled
description: "Detects exposed web directories and file listings by recursively checking parent paths."

single_match: true

transform:
  recursive: true
  method: ["GET"]

match_on:
  status: 200
  body:
    contains:
      - "Index of /"
      - "Parent Directory"
      - "[To Parent Directory]"
      - "Directory Listing For"
      - "<title>Index of"
      - "Directory contents of"

report:
  title: "Directory Listing Enabled"
  description: |
    The web server is configured to display a directory listing when a directory 
    is requested without a default index file (e.g., index.html). 
    
    This can expose sensitive source code, configuration files, backup archives, 
    and other internal application assets.

    Affected Endpoint (and parents):
    {{req.url}}

    Response Extract:
    {{res.body}}

  cwe: "CWE-548"
  severity: medium
  cvssScore: "5.3"
  mitigation: |
    1. Disable directory listing (Options -Indexes in Apache, autoindex off in Nginx).
    2. Ensure an empty index.html is present in sensitive directories if listing cannot be disabled globally.
    3. Ensure no sensitive files are stored in publicly accessible web roots.
  stepsToReproduce: |
    1. Navigate to the parent directory of the current endpoint (e.g., strip the filename).
    2. Observe the auto-generated HTML index of files.
  tags: "directory-listing,misconfiguration,information-disclosure,medium"
  impact: "Information Disclosure, exposing source code or backups."
```

---

## 4. Referer-Based Open Redirection
**Path:** `open_redirect/referer-based-redirect.yml`
**Description:** Tests Open Redirection vulnerabilities where the application unsafely relies on the `Referer` header to determine the destination of a redirect (often used in "Go Back" buttons).

```yaml
rule_name: Referer-Based Open Redirection
description: "Detects Open Redirection vulnerabilities where the application redirects the user based on the Referer header."

single_match: true

transform:
  header:
    add:
      Referer: "https://evil.snapsec.co"
    modify:
      Referer: "https://evil.snapsec.co"

match_on:
  status:
    in: [301, 302, 303, 307, 308]
  header:
    Location:
      contains:
        - value: "(?i)^https?://evil\\.snapsec\\.co.*"
          options:
            regex: true

report:
  title: "Open Redirection via Referer Header"
  description: |
    The application is vulnerable to Referer-Based Open Redirection. 
    It relies on the 'Referer' header to determine the destination of a redirect 
    (e.g., redirecting a user back to the previous page after a login or action).
    
    If an attacker controls the Referer header, they can force the application 
    to redirect the victim to an arbitrary, malicious domain.

    Original Request:
    {{original}}

    Transformed Request:
    {{req}}

    Response:
    {{res}}

  cwe: "CWE-601"
  severity: medium
  cvssScore: "6.1"
  mitigation: |
    1. Do not use the Referer header for routing or redirection logic.
    2. Maintain a strict allowlist of permitted redirection domains.
    3. Use relative paths for local redirects instead of absolute URLs.
  stepsToReproduce: |
    1. Send a request with the header 'Referer: https://evil.snapsec.co'.
    2. Observe the server responding with a 3xx redirect to 'https://evil.snapsec.co'.
  tags: "open-redirect,referer,headers,medium"
  impact: "Phishing, credential theft, and bypassing domain-based access controls."
```

---

## 5. Server-Side Template Injection (SSTI)
**Path:** `command_injections/server-side-template-injection.yml`
**Description:** Injects math expressions (e.g., `{{1337*1337}}`) into parameters and bodies. Evaluates responses for the computed result (`1787569`) to detect SSTI across multiple template engines (Jinja2, Twig, ERB, FreeMarker, Velocity) with zero false positives.

```yaml
rule_name: Server-Side Template Injection (SSTI)
description: "Detects Server-Side Template Injection vulnerabilities by injecting math expressions into parameters and checking if the engine evaluates them."

transform:
  query:
    transformations:
      - replace_all_values_one_by_one:
          - "${1337*1337}"
          - "{{1337*1337}}"
          - "<%= 1337*1337 %>"
          - "#{1337*1337}"
          - "*{1337*1337}"
  body:
    transformations:
      - replace_all_values_one_by_one:
          - "${1337*1337}"
          - "{{1337*1337}}"
          - "<%= 1337*1337 %>"
          - "#{1337*1337}"
          - "*{1337*1337}"

match_on:
  status:
    notIn: [404, 400]
  body:
    contains:
      - "1787569"

report:
  title: "Server-Side Template Injection (SSTI)"
  description: |
    The application is vulnerable to Server-Side Template Injection (SSTI).
    A math expression (1337 * 1337) was injected into a parameter using various template 
    engine syntaxes (e.g., Freemarker, Jinja2, ERB, Twig, Velocity) and the server 
    evaluated it, returning the result (1787569) in the response.
    
    This indicates that user input is being directly embedded into a server-side template 
    and executed, which almost always leads to Remote Code Execution (RCE).

    Original Request:
    {{original}}

    Transformed Request:
    {{req}}

    Response:
    {{res}}

  cwe: "CWE-1336"
  severity: critical
  cvssScore: "9.8"
  mitigation: |
    1. Never concatenate user input directly into template strings.
    2. Pass user input into templates strictly as data/context variables.
    3. Use a logic-less template engine if possible (e.g., Mustache).
    4. Run template engines in a sandboxed or restricted environment.
  stepsToReproduce: |
    1. Send a request injecting a template expression like {{1337*1337}} into a parameter.
    2. Observe the server evaluating the expression and returning the result (1787569).
  tags: "ssti,injection,rce,critical,vuln"
  impact: "Remote Code Execution (RCE) and full server compromise."
```
