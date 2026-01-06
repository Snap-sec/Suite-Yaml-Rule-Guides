# Rule Engine Documentation

## Table of Contents

1. [Basic Structure](#basic-structure)
2. [Transformation](#transformation)

   * [Supported Request Mutations](#supported-request-mutations)
   * [Query Transformer](#query-transformer)
   * [Header Transformer](#header-transformer)
   * [Body Transformer](#body-transformer)
   * [URL Rebuilding](#url-rebuilding)
3. [Matching](#matching)
4. [Report Generation](#report-generation)

   * [Template Evaluation](#template-evaluation)

---

# Basic Structure

A rule describes:

* How to mutate the outgoing request (`transform`)
* What to match in the response (`match_on`)
* What to report when a match occurs (`report`)

Example rule:

```yaml
rule_name: Privilege Escalation via Method Override

# if this rule matches, for that (host), it will not match again
single_match: true

transform:
  header:
    add:
      X-HTTP-Method-Override: PUT

match_on:
  status: 200
  header:
    X-Admin: "true"
  body:
    contains:
      - "admin"
      - "privilege"

report:
  title: "Privilege Escalation: {{req.method}} Override"
  description: |
    The application accepts privilege escalation through:
    - Method override headers
    - Direct role parameter manipulation

    Original Request:
    {{original}}

    Transformed Request:
    {{req}}

    Response:
    {{res}}

  cwe: "CWE-269"
  cvssScore: "9.8"
  severity: "critical"
  mitigation: |
    1. Use server-side role validation
    2. Ignore X-HTTP-Method-Override
    3. Never trust client-supplied role parameters
  stepsToReproduce: |
    1. Send transformed request to {{req.url}}
    2. Response contains admin indicators
    3. Attacker can modify other user accounts
  tags: "privilege-escalation,authorization,critical"
  impact: "Complete application compromise, data breach"
```

---

# Transformation

The `transform` block defines how outgoing requests are mutated. Each mutation may produce multiple variations of the request.

The transformation pipeline:

1. Clone original request
2. Apply global modifications (`method`, `override_host`, `http_version`, `recursive`)
3. Apply component-level transformers (query, headers, body)
4. Rebuild URL with updated query parameters
5. Return all mutated requests

## Supported Request Mutations

### **Method Override**

Produces one request per method.

```yaml
method: ["GET", "PUT"]
```

### **Recursive Path Traversal**

Generates all parent paths.

```
/users/123/orders → /users/123/orders, /users/123, /users
```

```yaml
recursive: true
```

---

## Query Transformer

Operations supported:

```yaml
query:
  add: { token: "abc" }
  remove: ["debug"]
  modify: { id: 999 }
  replace_all_values: "X"
  replace_all_values_one_by_one: "test"
```

Features:

* Normalizes keys to lowercase
* Supports nested `transformations`
* Generates multiple mutated requests

---

## Header Transformer

```yaml
header:
  add: { X-Admin: "1" }
  remove: ["Cookie"]
  modify: { host: "fake.com" }
  replace_all_values: "injected"
```

Features:

* Normalizes header names to lowercase
* Supports combinatorial mutations via `replace_all_values_one_by_one`

---

## Body Transformer (JSON)

Supports:

* `add`
* `remove`
* `modify`
* `replace_all_values`
* `replace_all_values_one_by_one`
* nested `transformations`

Example:

```yaml
body:
  add: { role: "admin" }
  modify: { user_id: "admin" }
```

---

## URL Rebuilding

After query mutation:

```
basePath + "?" + encoded parameters
```

Ensures the final outgoing URL always reflects updated query params.

---

# Matching

The `match_on` block determines whether a transformed request triggers a rule finding.
A match **only succeeds if all defined match conditions pass**.

Supported match types:

* **Status code** (`status`)
* **Response body** (`body`)
* **Response headers** (`header`)

Each matcher returns:

* `location` – where the match occurred
* `matched_on` – value or pattern responsible
* `highlight` – a regex-style highlight pattern for UI display

---

## Status Matching

Status codes may be matched in three ways:

### **Exact match**

```yaml
status: 200
```

Matches only if `response.status === 200`.

### **List match**

```yaml
status: [200, 201, 204]
```

Matches if status is in the list.

### **Object form**

```yaml
status:
  in: [200, 403]
```

```yaml
status:
  notIn: [500, 502]
```

---

## Body Matching

The `body` matcher supports:

* **contains** (string or list)
* **regex** (raw JS regex)

### **Contains (regex-capable)**

```yaml
body:
  contains: "admin"
```

```yaml
body:
  contains:
    - "admin"
    - "privilege"
```

Matches if **any** of the patterns match the response body.

### **Full regex match**

```yaml
body:
  regex: "^\{.*admin.*\}$"
```

---

## Header Matching

Header names are normalized to lowercase.

Supported forms:

### **Exact match**

```yaml
header:
  X-Admin: "true"
```

### **Contains** (regex-capable)

```yaml
header:
  server:
    contains: "nginx"
```

### **Regex match**

```yaml
header:
  set-cookie:
    regex: "session=.*secure"
```

---

## Match Evaluation Logic

All match conditions must pass.

---

# Report Generation

When a response satisfies `match_on`, the rule engine generates a finding using the template fields within `report`.

Template variables available:

| Variable   | Meaning                       |
| ---------- | ----------------------------- |
| `req`      | The transformed request       |
| `original` | The original incoming request |
| `res`      | The received response         |

Templates support full JSON expansion for objects.

Example usage inside a report:

```yaml
description: |
  Request Sent:
  {{req}}

  Response Received:
  {{res}}

  Original Request Context:
  {{original}}
```

---

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
