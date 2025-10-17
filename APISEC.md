# Security Rule Documentation

Complete guide to writing YAML security rules with transform and match conditions.

---

## Table of Contents

- [Rule Structure](#rule-structure)
- [Transform Section](#transform-section)
- [Match On Section](#match-on-section)
- [Report Section](#report-section)
- [Placeholders](#placeholders)
- [Complete Examples](#complete-examples)

---

## Rule Structure

Every security rule follows this structure:

```yaml
rule_name: My Security Rule

transform:
  # Request transformation rules

match_on:
  # Response matching criteria

report:
  title: ""
  description: ""
  cwe: ""
  cvssScore: ""
  mitigation: ""
  stepsToReproduce: ""
  tags: ""
  impact: ""
```

---

## Transform Section

The `transform` section modifies the request before sending it. All transformations are optional.

### Headers Transformations

#### Remove Headers

Remove specific headers from the request:

```yaml
transform:
  headers:
    remove:
      - Authorization
      - X-API-Key
      - Cookie
```

#### Add Headers

Add new headers to the request:

```yaml
transform:
  headers:
    add:
      X-Forwarded-For: 127.0.0.1
      X-Custom-Header: test-value
      User-Agent: Mozilla/5.0
```

#### Replace All Header Values

Set all headers to the same value (useful for testing header handling):

```yaml
transform:
  headers:
    replace_all_values: "placeholder"
```

### Cookie Transformations

#### Remove Cookies

Remove specific cookies:

```yaml
transform:
  cookies:
    remove:
      - session_id
      - auth_token
      - tracking_id
```

#### Add Cookies

Add new cookies:

```yaml
transform:
  cookies:
    add:
      admin: "true"
      role: "superuser"
      bypass: "enabled"
```

### URL/Host Transformations

#### Override Host

Change the hostname:

```yaml
transform:
  override_host: "attacker.com"
```

#### Override Protocol

Change the protocol (http/https):

```yaml
transform:
  override_protocol: "http:"
```

#### Override Port

Change the port:

```yaml
transform:
  override_port: "8080"
```

### Query Parameter Transformations

#### Replace Specific Parameter Values

Replace values for specific parameters:

```yaml
transform:
  replace_param_value:
    user_id: "999"
    product_id: "1"
    page: "admin"
```

Only replaces if the parameter exists in the original request.

#### Replace All Parameter Values

Set all query parameters to the same value:

```yaml
transform:
  replace_all_param_values: "test"
```

**Example:**
- Original: `?foo=1&bar=2&baz=3`
- After: `?foo=test&bar=test&baz=test`

#### Replace Parameters One-By-One

Create a separate request for each parameter, replacing one at a time:

```yaml
transform:
  replace_params_one_by_one: "payload"
```

**Example:**
- Original URL: `?foo=1&bar=2&baz=3`
- Generates 3 requests:
  - `?foo=payload&bar=2&baz=3`
  - `?foo=1&bar=payload&baz=3`
  - `?foo=1&bar=2&baz=payload`


## Query Parameter Transformers:

**1. `replace_query_param` (singular - key/value format):**
```yaml
replace_query_param:
  key: userId
  value: admin123
```

**2. `replace_query_params` (plural - object format):**
```yaml
replace_query_params:
  userId: admin123
  role: administrator
  debug: true
```

**3. `replace_all_query_params` (single value for all):**
```yaml
replace_all_query_params: "' OR '1'='1"
```

**4. `replace_query_params_one_by_one` (creates variants):**
```yaml
replace_query_params_one_by_one: "<script>alert(1)</script>"
```

**5. `add_query_param` (singular - key/value format):**
```yaml
add_query_param:
  key: debug
  value: true
```

## Body Parameter Transformers:

**1. `replace_body_param` (singular - key/value format):**
```yaml
replace_body_param:
  key: isAdmin
  value: true
```

**2. `replace_body_params` (plural - object format):**
```yaml
replace_body_params:
  username: admin
  role: superuser
  active: true
```

**3. `replace_all_body_params` (single value for all):**
```yaml
replace_all_body_params: "{{7*7}}"
```

**4. `add_body_params` (plural - object format):**
```yaml
add_body_params:
  __proto__: polluted
  constructor: overridden
  isAdmin: true
```

### Method Transformations

#### Repeat with Multiple Methods

Send the same request with different HTTP methods:

```yaml
transform:
  repeat_with_methods:
    - GET
    - POST
    - PUT
    - DELETE
    - PATCH
```

### Complete Transform Example

```yaml
transform:
  headers:
    remove:
      - Authorization
    add:
      X-Forwarded-For: 127.0.0.1
  cookies:
    add:
      admin: "true"
  override_host: "internal.local"
  replace_param_value:
    user_id: "1"
  add_query_params:
    debug: "true"
  repeat_with_methods:
    - GET
    - POST
```

---

## Match On Section

The `match_on` section defines criteria for response validation. A response matches if **at least one** criterion is true.

### Status Code Matching

Match specific HTTP status code:

```yaml
match_on:
  status: 200
```

### Response Body Matching

#### Single String

Check if response body contains a specific string:

```yaml
match_on:
  body_contains: "success"
```

#### Multiple Strings

Match if body contains any of these strings (first match wins):

```yaml
match_on:
  body_contains:
    - "admin"
    - "superuser"
    - "root"
```

### Response Size Matching

#### Exact Size

Match if response is exactly N bytes:

```yaml
match_on:
  size: 1024
```

#### Size Range

Match if response falls within a size range:

```yaml
match_on:
  size:
    min: 100
    max: 5000
```

#### Minimum Size

Match if response is at least N bytes:

```yaml
match_on:
  size:
    min: 1000
```

#### Maximum Size

Match if response is at most N bytes:

```yaml
match_on:
  size:
    max: 10000
```

### Header Matching

#### Exact Header Match

Match if headers have exact values:

```yaml
match_on:
  headers:
    Content-Type: "application/json"
    X-Custom: "value"
```

All specified headers must match (case-insensitive).

#### Check Headers Exist

Match if specific headers are present (value doesn't matter):

```yaml
match_on:
  headers_exist: Content-Type
```

Multiple headers:

```yaml
match_on:
  headers_exist:
    - Content-Type
    - X-API-Version
    - Authorization
```

#### Check Header Value

Match if a specific header has a specific value:

```yaml
match_on:
  header_has_value:
    key: Authorization
    value: "Bearer token123"
```

Multiple checks (any match wins):

```yaml
match_on:
  header_has_value:
    - key: X-Admin
      value: "true"
    - key: X-Role
      value: "superuser"
```

### Content-Type Matching

Match if Content-Type contains a specific value:

```yaml
match_on:
  content_type: "application/json"
```

This will match:
- `application/json`
- `application/json; charset=utf-8`
- `application/json; boundary=...`

### Response Time Matching

#### Exact Time

Match if response time is exactly N milliseconds:

```yaml
match_on:
  time: 500
```

#### Time Range

Match if response falls within time range:

```yaml
match_on:
  time:
    min: 100
    max: 1000
```

#### Minimum Time

Match if response takes at least N milliseconds:

```yaml
match_on:
  time:
    min: 5000
```

#### Maximum Time

Match if response takes at most N milliseconds:

```yaml
match_on:
  time:
    max: 1000
```

### Response Contains Matching

Search entire response (status, body, headers) for text:

```yaml
match_on:
  response_contains: "error"
```

Multiple values (first match wins):

```yaml
match_on:
  response_contains:
    - "admin"
    - "superuser"
    - "root"
```

This searches:
- Status code
- Response body
- All header key-value pairs

### Complete Match On Example

```yaml
match_on:
  status: 200
  body_contains:
    - "admin"
    - "superuser"
  headers:
    Content-Type: "application/json"
  response_time:
    max: 2000
```

---

## Report Section

The `report` section defines how findings are reported. All fields support placeholders.

```yaml
report:
  title: "Potential {{vuln_type}} Vulnerability"
  description: "The application appears to be vulnerable to {{vuln_type}}"
  cwe: "CWE-79"
  cvssScore: "7.5"
  mitigation: "Implement proper input validation"
  stepsToReproduce: "Send request to {{req.url}}"
  tags: "xss,injection,security"
  impact: "Attacker could inject malicious scripts"
```

### Report Fields

| Field | Purpose | Example |
|-------|---------|---------|
| `title` | Short vulnerability title | "XSS Vulnerability Detected" |
| `description` | Detailed description | "User input is reflected without sanitization" |
| `cwe` | CWE identifier | "CWE-79" |
| `cvssScore` | CVSS score (0-10) | "7.5" |
| `mitigation` | How to fix | "Sanitize all user inputs" |
| `stepsToReproduce` | How to reproduce | "Access /search?q=<script>" |
| `tags` | Comma-separated tags | "xss,owasp,injection" |
| `impact` | Business impact | "Session hijacking, data theft" |

---

## Placeholders

Placeholders allow dynamic content in report fields. Use double curly braces: `{{ placeholder }}`.

### Request Placeholders

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `{{ req.url }}` | Transformed request URL | `https://api.example.com/users?id=1` |
| `{{ req.method }}` | Request method | `GET`, `POST` |
| `{{ req.headers }}` | Request headers (JSON) | `{"Content-Type":"application/json"}` |
| `{{ req.body }}` | Request body | `{"user":"admin"}` |

### Response Placeholders

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `{{ res.status }}` | Response status code | `200`, `404` |
| `{{ res.headers }}` | Response headers (JSON) | `{"X-Admin":"true"}` |
| `{{ res.body }}` | Response body | `"Admin panel accessed"` |
| `{{ res.time }}` | Response time in ms | `150` |
| `{{ res.size }}` | Response size in bytes | `2048` |

### Original Request Placeholders

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `{{ original.url }}` | Original request URL (before transform) | `https://api.example.com/users` |
| `{{ original.method }}` | Original method | `GET` |
| `{{ original.headers }}` | Original headers (JSON) | `{"Authorization":"Bearer..."}` |
| `{{ original.body }}` | Original body | `{}` |

### Custom Placeholders

```yaml
report:
  title: "Vulnerability in {{req.url}}"
  description: "Original request: {{original.url}}"
  stepsToReproduce: "Use URL: {{req.url}}"
```

---

## Complete Examples

### Example 1: Authentication Bypass Detection

```yaml
rule_name: Authentication Bypass via Host Header

transform:
  headers:
    add:
      X-Forwarded-For: "127.0.0.1"
      X-Original-URL: "/admin"
  override_host: "internal.local"

match_on:
  status: 200
  response_contains: "admin"

report:
  title: "Potential Authentication Bypass"
  description: "Admin panel accessible after host header modification"
  cwe: "CWE-74"
  cvssScore: "8.5"
  mitigation: "Validate Host header against whitelist"
  stepsToReproduce: |
    1. Send request to {{original.url}}
    2. Modify Host header to: {{req.headers}}
    3. Admin content returned
  tags: "auth,bypass,host-header"
  impact: "Unauthorized access to admin functionality"
```

### Example 2: Cookie Manipulation

```yaml
rule_name: Session Elevation via Cookie Tampering

transform:
  cookies:
    add:
      admin: "true"
      role: "superuser"
  replace_param_value:
    user_id: "1"

match_on:
  status: 200
  body_contains:
    - "admin"
    - "superuser"

report:
  title: "Possible Session Elevation"
  description: "System accepted elevated privileges via cookie manipulation"
  cwe: "CWE-384"
  cvssScore: "7.0"
  mitigation: "Validate and sign session cookies"
  stepsToReproduce: "Set cookie admin=true and access {{req.url}}"
  tags: "session,cookie,privilege-escalation"
  impact: "Account takeover, unauthorized access"
```

### Example 3: Parameter Injection Testing

```yaml
rule_name: SQL Injection via Parameter Manipulation

transform:
  replace_params_one_by_one: "' OR '1'='1"
  repeat_with_methods:
    - GET
    - POST

match_on:
  status: 200
  time:
    min: 3000
  response_contains:
    - "error"
    - "sql"
    - "syntax"

report:
  title: "Potential SQL Injection"
  description: |
    The application appears vulnerable to SQL injection.
    Original URL: {{original.url}}
    Test URL: {{req.url}}
  cwe: "CWE-89"
  cvssScore: "9.0"
  mitigation: "Use parameterized queries"
  stepsToReproduce: |
    1. Send GET/POST to {{req.url}}
    2. SQL error returned
    3. Database version: {{res.body}}
  tags: "sql-injection,database,owasp"
  impact: "Complete database compromise, data exfiltration"
```

### Example 4: XSS Detection with Payload

```yaml
rule_name: Reflected XSS in Search Parameter

transform:
  add_query_params:
    search: "<script>alert('xss')</script>"
  repeat_with_methods:
    - GET
    - POST

match_on:
  response_contains: "<script>alert('xss')</script>"
  status: 200

report:
  title: "Reflected XSS Vulnerability Found"
  description: |
    User-supplied input is reflected without encoding.
    Attack URL: {{req.url}}
  cwe: "CWE-79"
  cvssScore: "6.1"
  mitigation: "HTML encode all user input in responses"
  stepsToReproduce: |
    Step 1: Visit {{req.url}}
    Step 2: JavaScript executes in browser context
    Step 3: Session cookies could be stolen
  tags: "xss,owasp-a7"
  impact: "Session hijacking, credential theft, malware injection"
```

### Example 5: Complex Multi-Condition Rule

```yaml
rule_name: Privilege Escalation via Method Override

transform:
  headers:
    add:
      X-HTTP-Method-Override: PUT
  cookies:
    add:
      admin_token: "bypass"
  replace_param_value:
    user_id: "admin"
    role: "superuser"

match_on:
  status: 200
  headers:
    X-Admin: "true"
  body_contains:
    - "admin"
    - "privilege"
  time:
    max: 500

report:
  title: "Privilege Escalation: {{req.method}} Override"
  description: |
    The application accepts privilege escalation through:
    - Method override headers
    - Direct role parameter manipulation
    
    Original request: {{original.url}}
    Transformed request: {{req.url}}
    
    Response headers indicate admin access: {{res.headers}}
  cwe: "CWE-269"
  cvssScore: "9.8"
  mitigation: |
    1. Use server-side role validation
    2. Ignore X-HTTP-Method-Override
    3. Never trust client-supplied role parameters
  stepsToReproduce: |
    1. Send transformed request to {{req.url}}
    2. Response contains admin data
    3. User can modify other accounts
  tags: "privilege-escalation,authorization,critical"
  impact: "Complete application compromise, data breach"
```

---

## Best Practices

1. **Be Specific with Match Conditions**: More specific conditions reduce false positives
2. **Use Multiple Match Conditions**: Combine multiple conditions for confidence
3. **Document Placeholders**: Always reference relevant placeholders in stepsToReproduce
4. **Include CWE/CVSS**: Help with prioritization and remediation
5. **Test Transformations**: Verify transforms work as expected
6. **Use Meaningful Tags**: Tags help with reporting and filtering
7. **Clear Mitigation Steps**: Make it easy for developers to fix issues


### Report
## Template Variables Reference

---

### 📨 Request (Transformed) — `req.*`

* `{{ req.method }}` — HTTP method (GET, POST, etc.)
* `{{ req.url }}` — Full URL
* `{{ req.headers.* }}` — Any header (e.g., `{{ req.headers.Authorization }}`)
* `{{ req.body }}` — Request body
* `{{ req.params.* }}` — URL parameters

---

### 📦 Original Request — `original.*`

* `{{ original.name }}` — Request name from Postman
* `{{ original.method }}` — Original HTTP method
* `{{ original.url }}` — Original URL
* `{{ original.collectionName }}` — Collection name
* `{{ original.folderName }}` — Folder name
* `{{ original.workspaceName }}` — Workspace name
* `{{ original.description }}` — Request description

---

### 📥 Response — `res.*`

* `{{ res.status }}` — HTTP status code (200, 404, etc.)
* `{{ res.statusText }}` — Status text
* `{{ res.headers.* }}` — Response headers
* `{{ res.body }}` — Response body
* `{{ res.responseTime }}` — Response time (in ms)
* `{{ res.size }}` — Response size

---

### ⚙️ Rule — `rule.*`

* `{{ rule.name }}` — Rule name
* `{{ rule.category }}` — Rule category
* `{{ rule.severity }}` — Severity level
* `{{ rule.type }}` — Vulnerability type

---

### 🎯 Match Result — `match.*`

* `{{ match.matched }}` — Boolean match result
* `{{ match.criteria }}` — What was matched
* `{{ match.expected }}` — Expected value
* `{{ match.actual }}` — Actual value
* `{{ match.operator }}` — Match operator

---

### 🔧 Other Variables

* `{{ transformations }}` — Array of applied transformations
* `{{ transformationSummary }}` — Summary of transformations
* `{{ endpoint }}` — URL path only
* `{{ host }}` — Host from URL
* `{{ scan.name }}` — Scan name
* `{{ scan.id }}` — Scan ID
