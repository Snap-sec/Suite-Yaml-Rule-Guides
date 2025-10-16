This document explains how to create transformation rules and matching conditions to test API endpoints using YAML files.

---

## 🧹 Structure of a Rule

Each rule is a `.yaml` file placed inside the `rules/` folder. A rule contains 3 main parts:

```yaml
rule_name: "Meaningful Rule Name"
target: all

transform:
  # Transformation logic

match_on:
  # Conditions to trigger a report

report:
  title: "Report Title"
  description: "What this rule checks"
  severity: "low | medium | high | critical"
  cvssScore: 0.0 - 10.0
```

---

## ⚛️ Transform Section

### ✅ Add or Remove Headers

```yaml
transform:
  headers:
    add:
      X-Debug: true
    remove:
      - Authorization
```

### 🍪 Add or Remove Cookies

```yaml
transform:
  cookies:
    add:
      test_auth: "1"
    remove:
      - session_id
```

### 🏡 Override Host

```yaml
transform:
  override_host: "evil.example.com"
```

### 🪨 Replace Param Values

```yaml
transform:
  replace_param_value:
    username: xxyyzz

  replace_all_param_values: xxyyzz
```

### 📉 Replace All Header Values

```yaml
transform:
  headers:
    replace_all_values: xxyyzz
```

### ➕ Add New Query Parameters

```yaml
transform:
  add_query_params:
    mode: "test"
```

### 🔄 Repeat Request with Multiple Methods

```yaml
transform:
  repeat_with_methods:
    - GET
    - POST
    - DELETE
```

---

## ⚖️ match_on Section

### ✅ Match Status Code
```yaml
match_on:
  status: 403
```

### 📃 Match String in Response Body
```yaml
match_on:
  response_contains: "unauthorized"
```

### ⚡️ Match on Response Time (in ms)
```yaml
match_on:
  response_time_gt: 3000
```

### 🛋️ Match on Response Size (bytes)
```yaml
match_on:
  response_size_gt: 500
```

### 📄 Header Exists
```yaml
match_on:
  header_exists: X-Custom-Token
```

### 🍿 Header Value Match
```yaml
match_on:
  header_value:
    Content-Type: application/json
```

### 📃 Content Type Match
```yaml
match_on:
  content_type: "application/json"
```

---

## 📅 Report Section

Describes what happens if the rule matches:

```yaml
report:
  title: "Auth Removed Test"
  description: "Check how the API behaves when no auth is present"
  severity: "high"
  cvssScore: 7.5
```

---

### 🚀 Example Rule

```yaml
rule_name: Remove Auth Test

target: all

transform:
  headers:
    remove:
      - Authorization

match_on:
  status: 403
  response_contains: "unauthorized"

report:
  title: "Unauthorized Without Token"
  description: "Endpoint returns 403 when token is removed"
  severity: "medium"
  cvssScore: 6.3
```

---

## ⚛️ Response Matching Section Section

## 🧪 Matcher Section

The `match_on` section defines how a response is validated. If the response matches all specified criteria, the rule is considered triggered, and a report is sent.

Each matcher supports flexible options to handle real-world testing scenarios.

---

### 1. ✅ Match Status Code

```yaml
match_on:
  status: 200
```

This ensures the response returns with a specific HTTP status code.

---

### 2. 🔍 Match Body Contains Text

```yaml
match_on:
  body_contains: "Success"
```

You can also use an array:

```yaml
match_on:
  body_contains:
    - "token"
    - "user_id"
```

Checks if the response body (or stringified JSON) contains given strings.

---

### 3. 📦 Match Response Size

Match exact size:
```yaml
match_on:
  size: 1234
```

Or use a range:
```yaml
match_on:
  size:
    min: 500
    max: 2000
```

---

### 4. 🧾 Match Headers Exactly

```yaml
match_on:
  headers:
    content-type: application/json
    cache-control: no-cache
```

All header keys and their values must match exactly.

---

### 5. 📌 Check Header Exists

```yaml
match_on:
  headers_exist:
    - set-cookie
    - x-request-id
```

You can also provide a single string:
```yaml
match_on:
  headers_exist: x-api-key
```

---

### 6. 🎯 Match Header Has Value

Check specific header key-value pairs:

```yaml
match_on:
  header_has_value:
    - key: x-api-key
      value: secret123
    - key: server
      value: nginx
```

Or just one:
```yaml
match_on:
  header_has_value:
    key: x-session-id
    value: abc123
```

---

### 7. 🧪 Match Content-Type

```yaml
match_on:
  content_type: application/json
```

Checks if the response has that content type in headers.

---

### 8. ⏱ Match Response Time

Exact match:
```yaml
match_on:
  time: 300
```

Or use min/max:
```yaml
match_on:
  time:
    min: 200
    max: 500
```

---


### Report
All available template variables are available in the createVulnerabilityContext method in src/utils/template.js. Here's a quick reference:
Available Template Variables:
Request (Transformed) - req.\\\\\\*
{{ req.method }} - HTTP method (GET, POST, etc.)
{{ req.url }} - Full URL
{{ req.headers.\\\\\\* }} - Any header (e.g., {{ req.headers.Authorization }})
{{ req.body }} - Request body
{{ req.params.\\\\\\* }} - URL parameters

Original Request - original.\\\\\\*
{{ original.name }} - Request name from Postman
{{ original.method }} - Original method
{{ original.url }} - Original URL
{{ original.collectionName }} - Collection name
{{ original.folderName }} - Folder name
{{ original.workspaceName }} - Workspace name
{{ original.description }} - Request description

Response - res.\\\\\\*
{{ res.status }} - HTTP status code (200, 404, etc.)
{{ res.statusText }} - Status text
{{ res.headers.\\\\\\* }} - Response headers
{{ res.body }} - Response body
{{ res.responseTime }} - Response time in ms
{{ res.size }} - Response size

Rule - rule.\\\\\\*
{{ rule.name }} - Rule name
{{ rule.category }} - Rule category
{{ rule.severity }} - Severity level
{{ rule.type }} - Vulnerability type

Match Result - match.\\\\\\*
{{ match.matched }} - Boolean match result
{{ match.criteria }} - What was matched
{{ match.expected }} - Expected value
{{ match.actual }} - Actual value
{{ match.operator }} - Match operator

Other
{{ transformations }} - Array of applied transformations
{{ transformationSummary }} - Summary of transformations
{{ endpoint }} - URL path only
{{ host }} - Host from URL
{{ scan.name }} - Scan name
{{ scan.id }} - Scan ID

