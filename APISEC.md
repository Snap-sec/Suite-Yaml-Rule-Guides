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

# HTTP Request Transformer - YAML Documentation

## Introduction

The HTTP Request Transformer allows you to define transformation rules in YAML that generate multiple HTTP requests from a single base request. Use these rules to create test scenarios, perform API fuzzing, or generate request variations for testing different endpoints and payloads.

---

## Global Operators

Global operators apply to the entire request and are defined at the top level of your transform rules.

### `method`

Transform the HTTP method used in the request. Accepts a single method or an array of methods.

**Syntax:**
```yaml
transform:
  method: POST
```

Or for multiple methods:
```yaml
transform:
  method:
    - POST
    - GET
    - OPTIONS
```

**Expected Behavior:**

When you specify a single method, all requests are sent with that method. When you specify multiple methods, the transformer creates a separate request for each method specified. If other multiplying transformations exist (like `transformations` arrays), they combine with method multiplication.

**Example:**
```yaml
transform:
  method:
    - POST
    - PUT
  path:
    transformations:
      - add: details
      - add: info
```

This generates **4 requests**: 2 methods × 2 path transformations.

### `http_version`

Set the HTTP protocol version for the request.

**Syntax:**
```yaml
transform:
  http_version: 1.1
```

**Expected Behavior:**

All generated requests will use the specified HTTP version. Common values are `1.0`, `1.1`, and `2.0`. This is typically used alongside other transformations to ensure consistent protocol versions across all generated requests.

**Example:**
```yaml
transform:
  method:
    - GET
    - POST
  http_version: 2.0
```

Both GET and POST requests will use HTTP/2.0.

---

## Path Transformations

Path transformations modify the URL path of requests. Use these to test different endpoints, add suffixes, or manipulate URL segments.

### `add`

Append a new path segment to the end of the current path.

**Syntax:**
```yaml
transform:
  path:
    add: segment_name
```

**Expected Behavior:**

The specified segment is appended to the end of the path with a forward slash separator. This is useful for adding sub-resources or action endpoints.

**Example:**
```yaml
transform:
  path:
    add: details
```

```
Input path:  /api/users/123
Output path: /api/users/123/details
```

### `remove`

Remove a substring from the path.

**Syntax:**
```yaml
transform:
  path:
    remove: /api
```

**Expected Behavior:**

The exact substring matching `remove` value is removed from the path. This is case-sensitive and performs a simple string replacement.

**Example:**
```yaml
transform:
  path:
    remove: /v1
```

```
Input path:  /api/v1/users/123
Output path: /api/users/123
```

### `modify`

Replace specific path segments with new values. Define a mapping of old segment → new segment.

**Syntax:**
```yaml
transform:
  path:
    modify:
      old_segment: new_segment
      another_old: another_new
```

**Expected Behavior:**

Each key in the modify object is replaced with its corresponding value. Multiple replacements can be performed in a single transformation. The replacements are applied sequentially.

**Example:**
```yaml
transform:
  path:
    modify:
      users: customers
      '123': '456'
```

```
Input path:  /api/users/123/profile
Output path: /api/customers/456/profile
```

### `replace_all`

Replace all non-empty path segments with a single value.

**Syntax:**
```yaml
transform:
  path:
    replace_all: placeholder
```

**Expected Behavior:**

Every non-empty segment in the path is replaced with the provided value. Empty segments (like consecutive slashes) are preserved to maintain path structure. This generates a single modified request.

**Example:**
```yaml
transform:
  path:
    replace_all: xyz
```

```
Input path:  /api/users/123/details
Output path: /xyz/xyz/xyz/xyz
```

### `replace_all_one_by_one`

Replace each path segment individually, generating a separate request for each segment replacement.

**Syntax:**
```yaml
transform:
  path:
    replace_all_one_by_one: test_value
```

**Expected Behavior:**

The transformer creates multiple requests, each with a single path segment replaced. If the original path has N non-empty segments, N separate requests are generated. This is useful for fuzzing different parts of the URL path.

**Example:**
```yaml
transform:
  path:
    replace_all_one_by_one: fuzz
```

```
Input path: /api/users/123/details

Generates 4 requests:
Request 1: /fuzz/users/123/details
Request 2: /api/fuzz/123/details
Request 3: /api/users/fuzz/details
Request 4: /api/users/123/fuzz
```

### `transformations`

Define multiple independent path transformations that each generate separate requests.

**Syntax:**
```yaml
transform:
  path:
    transformations:
      - add: segment1
      - remove: /api
      - modify:
          users: customers
```

**Expected Behavior:**

Each transformation in the array creates a separate request. If you have 3 transformations and other multipliers (like multiple methods), the total requests = methods × transformations. Any global path rules defined outside `transformations` are applied to each generated request.

**Example:**
```yaml
transform:
  path:
    transformations:
      - add: details
      - add: info
      - remove: /api
    modify:
      users: products
```

```
Generates 3 requests:
Request 1: /products/users/123/details (added details, then modified users)
Request 2: /products/users/123/info (added info, then modified users)
Request 3: /products/users/123 (removed /api, then modified users)
```

---

## Query Parameter Transformations

Query transformations modify URL query parameters. Use these to test different filtering options, pagination, and query-based variations.

### `add`

Add new query parameters or override existing ones.

**Syntax:**
```yaml
transform:
  query:
    add:
      key1: value1
      key2: value2
```

**Expected Behavior:**

The specified key-value pairs are added to the query string. If a parameter already exists, its value is overwritten. New parameters are merged with existing ones.

**Example:**
```yaml
transform:
  query:
    add:
      filter: active
      sort: name
      limit: 100
```

```
Input query:  ?id=123
Output query: ?id=123&filter=active&sort=name&limit=100
```

### `remove`

Remove specific query parameters from the request.

**Syntax:**
```yaml
transform:
  query:
    remove:
      - param_name1
      - param_name2
```

**Expected Behavior:**

Each parameter in the remove array is deleted from the query string. Non-existent parameters are safely ignored. Removing a parameter that doesn't exist has no effect.

**Example:**
```yaml
transform:
  query:
    remove:
      - debug
      - session_token
```

```
Input query:  ?id=123&debug=true&session_token=abc
Output query: ?id=123
```

### `modify`

Change the values of specific query parameters.

**Syntax:**
```yaml
transform:
  query:
    modify:
      param_name: new_value
      another_param: different_value
```

**Expected Behavior:**

Each parameter specified in modify has its value replaced with the new value. Only the values change, not the parameter names. Multiple parameters can be modified in a single operation.

**Example:**
```yaml
transform:
  query:
    modify:
      id: '999'
      status: inactive
```

```
Input query:  ?id=123&status=active&name=john
Output query: ?id=999&status=inactive&name=john
```

### `replace_all_values`

Replace all query parameter values with a single value.

**Syntax:**
```yaml
transform:
  query:
    replace_all_values: replacement_value
```

**Expected Behavior:**

Every query parameter's value is replaced with the provided value. Parameter names remain unchanged. This generates a single modified request.

**Example:**
```yaml
transform:
  query:
    replace_all_values: placeholder
```

```
Input query:  ?id=123&filter=active&sort=name
Output query: ?id=placeholder&filter=placeholder&sort=placeholder
```

### `replace_all_values_one_by_one`

Replace each query parameter value individually, generating a separate request for each.

**Syntax:**
```yaml
transform:
  query:
    replace_all_values_one_by_one: test_value
```

**Expected Behavior:**

Creates multiple requests, each with a single query parameter value replaced. If there are N parameters, N separate requests are generated. This is useful for fuzzing individual query parameters.

**Example:**
```yaml
transform:
  query:
    replace_all_values_one_by_one: fuzz
```

```
Input query: ?id=123&filter=active&sort=name

Generates 3 requests:
Request 1: ?id=fuzz&filter=active&sort=name
Request 2: ?id=123&filter=fuzz&sort=name
Request 3: ?id=123&filter=active&sort=fuzz
```

### `transformations`

Define multiple independent query parameter transformations that each generate separate requests.

**Syntax:**
```yaml
transform:
  query:
    transformations:
      - add:
          filter: active
      - add:
          filter: inactive
      - remove:
          - debug
```

**Expected Behavior:**

Each transformation in the array creates a separate request with that specific transformation applied. Global query rules outside `transformations` are applied to each request. This is ideal for testing different filter values or parameter combinations.

**Example:**
```yaml
transform:
  query:
    transformations:
      - add:
          status: draft
      - add:
          status: published
      - add:
          status: archived
    modify:
      limit: 50
```

```
Generates 3 requests:
Request 1: ?status=draft&limit=50
Request 2: ?status=published&limit=50
Request 3: ?status=archived&limit=50
```

---

## Header Transformations

Header transformations modify HTTP headers including special handling for cookie headers.

### `add`

Add new headers or overwrite existing ones.

**Syntax:**
```yaml
transform:
  headers:
    add:
      Header-Name: header_value
      Another-Header: value
```

**Expected Behavior:**

New headers are added to the request. If a header with the same name already exists, it is overwritten. Header names are case-sensitive.

**Example:**
```yaml
transform:
  headers:
    add:
      Authorization: 'Bearer token123'
      X-Custom-Header: 'custom-value'
      Content-Type: 'application/json'
```

```
Added headers are merged with existing headers
```

### `remove`

Remove specific headers from the request.

**Syntax:**
```yaml
transform:
  headers:
    remove:
      - Header-Name1
      - Header-Name2
```

**Expected Behavior:**

Each header in the remove array is deleted from the request. Removing a header that doesn't exist has no effect.

**Example:**
```yaml
transform:
  headers:
    remove:
      - Authorization
      - X-Old-Header
      - Cookie
```

```
Specified headers are deleted
```

### `modify`

Change header values with optional prefix and suffix support.

**Syntax:**
```yaml
transform:
  headers:
    modify:
      Header-Name: new_value
      Another-Header:
        value: new_value
        prefix: 'prefix_'
        suffix: '_suffix'
```

**Expected Behavior:**

For simple string values, the header is updated directly. For object values with `value`, `prefix`, and/or `suffix` fields, the transformation works as follows:
- Start with the provided `value`
- Prepend `prefix` if specified
- Append `suffix` if specified

If `value` is not provided, the current header value is used as the base.

**Example:**
```yaml
transform:
  headers:
    modify:
      Authorization: 'Bearer newtoken'
      X-Request-ID:
        prefix: 'req_'
        suffix: '_v2'
        value: '12345'
```

```
Authorization: Bearer oldtoken → Bearer newtoken
X-Request-ID: (any value) → req_12345_v2
```

### Cookie Header Operations

The Cookie header supports special nested operations for adding, removing, and modifying individual cookies.

#### Add Cookies

Add new cookies to the Cookie header or override existing ones.

**Syntax:**
```yaml
transform:
  headers:
    modify:
      Cookie:
        add:
          cookie_name: cookie_value
          another_cookie: another_value
```

**Expected Behavior:**

New cookies are added to the existing Cookie header. Cookies are formatted as `name=value` pairs separated by `; `. Existing cookies are preserved unless they have the same name as a new cookie being added.

**Example:**
```yaml
transform:
  headers:
    modify:
      Cookie:
        add:
          sessionId: abc123xyz
          userId: user456
```

```
Input Cookie:  sessionId=old123; theme=dark
Output Cookie: sessionId=abc123xyz; theme=dark; userId=user456
```

#### Remove Cookies

Remove specific cookies from the Cookie header.

**Syntax:**
```yaml
transform:
  headers:
    modify:
      Cookie:
        remove:
          - cookie_name1
          - cookie_name2
```

**Expected Behavior:**

Each cookie in the remove array is deleted from the Cookie header. The remaining cookies are preserved.

**Example:**
```yaml
transform:
  headers:
    modify:
      Cookie:
        remove:
          - sessionId
          - tempToken
```

```
Input Cookie:  sessionId=abc; tempToken=xyz; userId=user123
Output Cookie: userId=user123
```

#### Modify Cookies

Change cookie values with prefix and suffix support.

**Syntax:**
```yaml
transform:
  headers:
    modify:
      Cookie:
        modify:
          cookie_name:
            value: new_value
            prefix: 'prefix_'
            suffix: '_suffix'
```

**Expected Behavior:**

Similar to header modification, cookies can be updated with optional prefix and suffix. The resulting cookie value is formatted as `name=value` and merged back into the Cookie header.

**Example:**
```yaml
transform:
  headers:
    modify:
      Cookie:
        modify:
          sessionId:
            prefix: 'session_'
            suffix: '_v1'
          userId:
            value: newuser789
```

```
Input Cookie:  sessionId=abc123; userId=olduser123
Output Cookie: sessionId=session_abc123_v1; userId=newuser789
```

### `transformations`

Define multiple independent header transformations that each generate separate requests.

**Syntax:**
```yaml
transform:
  headers:
    transformations:
      - add:
          Authorization: 'Bearer token1'
      - add:
          Authorization: 'Bearer token2'
      - remove:
          - Authorization
```

**Expected Behavior:**

Each transformation creates a separate request. Useful for testing different authentication tokens, API keys, or header variations.

**Example:**
```yaml
transform:
  headers:
    transformations:
      - add:
          Authorization: 'Bearer admin_token'
      - add:
          Authorization: 'Bearer user_token'
      - add:
          Authorization: 'Bearer guest_token'
    add:
      X-Request-ID: '12345'
```

```
Generates 3 requests:
Request 1: With admin token and Request-ID
Request 2: With user token and Request-ID
Request 3: With guest token and Request-ID
```

---

## Body Transformations

Body transformations modify the request body, supporting both simple values and nested object structures.

### `add`

Add new fields to the request body or nested objects.

**Syntax:**
```yaml
transform:
  body:
    add:
      field_name: value
      another_field: another_value
```

**Expected Behavior:**

New fields are added to the body object. Existing fields are not affected unless they have the same name as a new field being added (in which case they are overwritten).

**Example:**
```yaml
transform:
  body:
    add:
      username: admin
      email: admin@example.com
      status: active
```

```
Input body:  { name: 'john' }
Output body: { name: 'john', username: 'admin', email: 'admin@example.com', status: 'active' }
```

### `remove`

Remove specific fields from the request body.

**Syntax:**
```yaml
transform:
  body:
    remove:
      - field_name1
      - field_name2
```

**Expected Behavior:**

Each field in the remove array is deleted from the body. Removing a field that doesn't exist has no effect. Nested fields cannot be removed with this operation; use modify with empty values instead.

**Example:**
```yaml
transform:
  body:
    remove:
      - password
      - api_token
      - internal_id
```

```
Input body:  { username: 'john', password: 'secret', email: 'john@example.com', api_token: 'xyz' }
Output body: { username: 'john', email: 'john@example.com' }
```

### `modify`

Change field values with support for prefix, suffix, and nested objects.

**Syntax:**
```yaml
transform:
  body:
    modify:
      field_name: new_value
      another_field:
        value: new_value
        prefix: 'pre_'
        suffix: '_post'
      nested_object:
        value:
          key: value
```

**Expected Behavior:**

- For simple string values: Replace the field value directly
- For object values: Can include `value`, `prefix`, and `suffix`
- The `value` field can be a string, number, or nested object
- Prefix and suffix are applied around the value for string values
- Non-existent fields are created with the new value

**Example:**
```yaml
transform:
  body:
    modify:
      username: admin
      firstName:
        prefix: 'Mr. '
        suffix: ' Jr.'
      profile:
        value:
          name: 'John Doe'
          age: 30
          active: true
```

```
Input body:
{
  username: 'john',
  firstName: 'Smith',
  profile: { role: 'user' }
}

Output body:
{
  username: 'admin',
  firstName: 'Mr. Smith Jr.',
  profile: { name: 'John Doe', age: 30, active: true }
}
```

### `replace_all`

Replace all leaf values in the body with a single value.

**Syntax:**
```yaml
transform:
  body:
    replace_all: replacement_value
```

**Expected Behavior:**

Every scalar (non-object) value in the body is replaced with the provided value. Nested object structures are preserved but their scalar values are replaced. This generates a single modified request.

**Example:**
```yaml
transform:
  body:
    replace_all: 'XXX'
```

```
Input body:
{
  username: 'john',
  email: 'john@example.com',
  active: true,
  count: 42
}

Output body:
{
  username: 'XXX',
  email: 'XXX',
  active: 'XXX',
  count: 'XXX'
}
```

### `replace_all_one_by_one`

Replace each scalar value individually, generating a separate request for each replacement.

**Syntax:**
```yaml
transform:
  body:
    replace_all_one_by_one: test_value
```

**Expected Behavior:**

Creates multiple requests, each with a single body field value replaced. If there are N scalar values in the body, N separate requests are generated. This is useful for fuzzing individual body parameters.

**Example:**
```yaml
transform:
  body:
    replace_all_one_by_one: 'FUZZ'
```

```
Input body: { username: 'john', email: 'john@example.com', active: true }

Generates 3 requests:
Request 1: { username: 'FUZZ', email: 'john@example.com', active: true }
Request 2: { username: 'john', email: 'FUZZ', active: true }
Request 3: { username: 'john', email: 'john@example.com', active: 'FUZZ' }
```

### `transformations`

Define multiple independent body transformations that each generate separate requests.

**Syntax:**
```yaml
transform:
  body:
    transformations:
      - add:
          role: admin
      - add:
          role: user
      - remove:
          - password
```

**Expected Behavior:**

Each transformation creates a separate request. Useful for testing different user roles, permissions, or payload variations.

**Example:**
```yaml
transform:
  body:
    transformations:
      - add:
          role: admin
          permissions: ['read', 'write', 'delete']
      - add:
          role: user
          permissions: ['read']
      - add:
          role: guest
          permissions: []
    modify:
      email: test@example.com
```

```
Generates 3 requests:
Request 1: { email: 'test@example.com', role: 'admin', permissions: [...] }
Request 2: { email: 'test@example.com', role: 'user', permissions: ['read'] }
Request 3: { email: 'test@example.com', role: 'guest', permissions: [] }
```

---

## Complex Transformation Examples

These examples demonstrate advanced combinations of multiple transformations working together.

### Example 1: Multi-Tenant Testing with Authentication

Test the same endpoint with different tenants and authentication tokens:

```yaml
transform:
  method: POST
  path:
    modify:
      tenants: clients
  headers:
    transformations:
      - add:
          Authorization: 'Bearer admin_token_12345'
          X-Tenant-ID: 'tenant_001'
      - add:
          Authorization: 'Bearer user_token_67890'
          X-Tenant-ID: 'tenant_002'
      - add:
          Authorization: 'Bearer restricted_token_xyz'
          X-Tenant-ID: 'tenant_003'
  query:
    add:
      format: json
      include_metadata: 'true'
  body:
    modify:
      timestamp:
        value: '2024-01-15T10:30:00Z'
```

**Result:** Generates 3 requests, one for each tenant with different authentication, all with added query parameters and updated body timestamp.

### Example 2: API Versioning with Progressive Payload

Test multiple API versions with evolving request bodies:

```yaml
transform:
  path:
    transformations:
      - modify:
          api: 'v1'
      - modify:
          api: 'v2'
      - modify:
          api: 'v3'
  body:
    transformations:
      - add:
          legacy_field: 'value'
      - add:
          new_field: 'value'
          legacy_field: 'value'
      - add:
          new_field: 'value'
          advanced_option: 'enabled'
    modify:
      request_id:
        prefix: 'req_'
```

**Result:** Generates 3 requests (one per API version), each with different payload structure, all with prefixed request IDs.

### Example 3: Security Testing - SQL Injection Payloads

Generate requests with various SQL injection test payloads:

```yaml
transform:
  method:
    - GET
    - POST
  query:
    transformations:
      - add:
          id: "1' OR '1'='1"
      - add:
          id: "1; DROP TABLE users;--"
      - add:
          id: "1' UNION SELECT * FROM admin;--"
      - add:
          id: "1' AND SLEEP(5);--"
  body:
    transformations:
      - add:
          username: "admin' --"
      - add:
          username: "' OR 1=1 --"
```

**Result:** Generates 8 requests (2 methods × 4 query payloads), plus 2 additional requests with body payloads, totaling 10 requests for comprehensive SQL injection testing.

### Example 4: Pagination and Filtering Testing

Test all combinations of pagination and filtering:

```yaml
transform:
  query:
    transformations:
      - add:
          page: '1'
          limit: '10'
      - add:
          page: '2'
          limit: '10'
      - add:
          page: '1'
          limit: '50'
      - add:
          page: '1'
          limit: '100'
    transformations:
      - add:
          status: active
      - add:
          status: inactive
      - add:
          status: archived
    add:
      sort: '-created_at'
```

**Result:** Generates multiple requests combining different pagination parameters with different status filters, all sorted by creation date.

### Example 5: Content Negotiation Testing

Test API with different content types and accept headers:

```yaml
transform:
  headers:
    transformations:
      - add:
          Content-Type: 'application/json'
          Accept: 'application/json'
      - add:
          Content-Type: 'application/xml'
          Accept: 'application/xml'
      - add:
          Content-Type: 'application/x-www-form-urlencoded'
          Accept: 'text/html'
  query:
    add:
      format: auto
```

**Result:** Generates 3 requests with different content types and accept headers for comprehensive content negotiation testing.

### Example 6: Deep Fuzzing with Nested Objects

Fuzz nested body structures:

```yaml
transform:
  body:
    modify:
      user:
        value:
          id: '12345'
          profile:
            first_name: 'John'
            last_name: 'Doe'
            bio: 'Software engineer'
    replace_all_one_by_one: 'FUZZ'
  query:
    add:
      strict_validation: 'false'
```

**Result:** Generates multiple requests (one for each nested scalar value) with FUZZ replacing individual values while maintaining object structure. Useful for identifying which fields cause validation errors.

### Example 7: Multi-Stage Request Transformation

Complex transformation combining methods, paths, headers, and body:

```yaml
transform:
  method:
    - POST
    - PUT
  path:
    add: validate
  headers:
    modify:
      Authorization:
        prefix: 'Bearer '
        value: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
    transformations:
      - add:
          X-API-Key: 'key_admin_v1'
          X-Request-Priority: 'high'
      - add:
          X-API-Key: 'key_user_v1'
          X-Request-Priority: 'normal'
  query:
    add:
      strict: 'true'
      include_warnings: 'true'
  body:
    transformations:
      - add:
          action: create
      - add:
          action: update
      - add:
          action: delete
    modify:
      audit:
        value:
          user: 'system'
          timestamp: '2024-01-15T10:00:00Z'
```

**Result:** Generates 6 requests (2 methods × 3 body actions × 1 header transformation combination), each with:
- Different HTTP method
- `/validate` appended to path
- JWT token in Authorization header
- Different API key and priority header
- Added query parameters
- Different action in body with audit information

### Example 8: Rate Limit Testing with Progressive Delay

Generate requests to test API rate limiting:

```yaml
transform:
  query:
    transformations:
      - add:
          request_number: '1'
          delay_ms: '0'
      - add:
          request_number: '2'
          delay_ms: '100'
      - add:
          request_number: '3'
          delay_ms: '200'
      - add:
          request_number: '4'
          delay_ms: '500'
      - add:
          request_number: '5'
          delay_ms: '1000'
  headers:
    add:
      X-Request-ID:
        prefix: 'rate_test_'
  body:
    modify:
      test_type: rate_limiting
```

**Result:** Generates 5 requests with incremental delays, allowing you to measure how the API responds to rapid successive requests and identify rate limit thresholds.

### Example 9: Field Value Fuzzing with One-by-One

Test each query parameter individually with a fuzzing payload:

```yaml
transform:
  query:
    add:
      user_id: '12345'
      org_id: '67890'
      session_id: 'abc123xyz'
      api_version: '2'
    replace_all_values_one_by_one: 'INJECTION_TEST'
  headers:
    add:
      X-Fuzz-Mode: 'enabled'
```

**Result:** Generates 4 requests, each with a single query parameter set to 'INJECTION_TEST' while others retain their original values. Helps identify which parameters are vulnerable.

### Example 10: Complete CRUD Testing

Generate all CRUD operation requests with proper methods and paths:

```yaml
transform:
  method:
    - POST
    - GET
    - PUT
    - DELETE
  path:
    transformations:
      - add: ''
      - add: '123'
  headers:
    add:
      Authorization: 'Bearer valid_token'
      Content-Type: 'application/json'
  body:
    transformations:
      - add:
          action: create
          data: { name: 'Resource', description: 'New resource' }
      - add:
          action: update
          data: { name: 'Updated Resource' }
      - remove:
          - action
```

**Result:** Generates 12 requests covering:
- POST /resource (create)
- POST /resource/123 (create at specific ID)
- GET /resource (read all)
- GET /resource/123 (read specific)
- PUT /resource (update all)
- PUT /resource/123 (update specific)
- DELETE /resource (delete all)
- DELETE /resource/123 (delete specific)
Each with different body payloads for respective operations.

---

# Response Matcher - Complete Documentation

## Overview

The Response Matcher allows you to define declarative rules in YAML to validate HTTP responses. Match on status codes, headers, and body content with flexible operators that support simple comparisons, regex patterns, and deep object matching. The matcher is fully extensible, allowing you to register custom operators for application-specific validation logic.

---

## Core Concepts

### Match Rule Structure

```yaml
match_on:
  status: 200
  header:
    Content-Type: application/json
  body:
    contains: success
```

Match rules are organized into three sections:
- **status** - HTTP status code matching
- **header** - HTTP header matching
- **body** - Request body matching

### Response Object

The matcher receives a response object with the following structure:

```javascript
{
  status: 200,
  headers: { 'content-type': 'application/json', ... },
  body: '{"result":"success"}' or { result: "success" }
}
```

### Matching Result

The matcher returns `true` if the response matches all specified rules, and `false` if any rule fails. Empty or undefined rules are always considered a match.

---

## Status Code Matching

### Single Status Code

Match a specific HTTP status code.

**Syntax:**
```yaml
match_on:
  status: 200
```

**Expected Behavior:**

The response matches only if the status code is exactly 200.

**Example:**
```yaml
match_on:
  status: 404
```

Matches responses with HTTP 404 status only.

### Multiple Status Codes

Match any status code from a list of acceptable codes.

**Syntax:**
```yaml
match_on:
  status: [200, 201, 204]
```

**Expected Behavior:**

The response matches if the status code is any of the values in the array. This is useful for endpoints that return multiple valid status codes.

**Example:**
```yaml
match_on:
  status: [200, 302, 304]
```

Matches if the status code is 200 (OK), 302 (Found), or 304 (Not Modified).

### Status Code with Operators

Use operators for more complex status code matching.

**Syntax:**
```yaml
match_on:
  status:
    gt: 199
    lt: 300
```

**Expected Behavior:**

When an object is provided with operators, all operators must pass for the match to succeed. This allows range checking and other comparisons.

**Example:**
```yaml
match_on:
  status:
    gte: 200
    lte: 299
```

Matches any successful 2xx status code.

---

## Header Matching

Headers are matched case-insensitively by name. You can match exact header values, search headers, or use operators.

### Exact Header Value Match

Match a specific header with an exact value.

**Syntax:**
```yaml
match_on:
  header:
    Content-Type: application/json
    Cache-Control: no-cache
```

**Expected Behavior:**

Each header specified is matched exactly against the response headers. Header names are case-insensitive. If any header doesn't match, the entire rule fails.

**Example:**
```yaml
match_on:
  header:
    Authorization: 'Bearer token123'
    X-Custom-Header: my-value
```

Matches responses where Authorization header is exactly "Bearer token123" AND X-Custom-Header is exactly "my-value".

### Header Contains Search

Search all headers for a value without knowing the header name.

**Syntax:**
```yaml
match_on:
  header:
    contains: search_value
```

Or with regex:

```yaml
match_on:
  header:
    contains:
      value: search_pattern
      regex: true
```

**Expected Behavior:**

The matcher searches all header values for the specified string or regex pattern. At least one header must contain the value for the match to succeed. This is useful when you don't know which header will contain the value you're looking for.

**Example:**
```yaml
match_on:
  header:
    contains: 'Bearer'
```

Matches any response where any header contains the string "Bearer".

**Regex Example:**
```yaml
match_on:
  header:
    contains:
      value: '^Bearer\s+[a-zA-Z0-9_\-\.]+$'
      regex: true
```

Matches responses where any header matches the JWT bearer token pattern.

### Header with Operators

Use operators for complex header matching.

**Syntax:**
```yaml
match_on:
  header:
    Content-Length:
      gte: 1000
      lte: 50000
    Content-Type:
      regex: 'application/(json|xml)'
```

**Expected Behavior:**

Operators are applied to specific headers. Multiple operators for the same header must all pass.

**Example:**
```yaml
match_on:
  header:
    Set-Cookie:
      contains: 'session_id='
    X-Rate-Limit-Remaining:
      gt: 0
```

Matches responses where Set-Cookie header contains "session_id=" AND X-Rate-Limit-Remaining is greater than 0.

### Combining Exact Match and Contains

You can mix exact header matching with contains searches in a single rule.

**Syntax:**
```yaml
match_on:
  header:
    Content-Type: application/json
    contains: Authorization
```

**Expected Behavior:**

Both conditions must be met: Content-Type must be exactly "application/json" AND at least one header must contain "Authorization".

**Example:**
```yaml
match_on:
  header:
    Server: nginx
    contains:
      value: 'gzip'
      regex: false
```

Matches responses where Server header is "nginx" AND any header contains the string "gzip".

---

## Body Matching

Body matching supports searching for content, matching JSON structures, and using operators for deep validation.

### Simple String Contains

Search the body for a substring.

**Syntax:**
```yaml
match_on:
  body:
    contains: success
```

**Expected Behavior:**

The response body (converted to string if necessary) is searched for the exact substring. The match succeeds if the substring is found anywhere in the body.

**Example:**
```yaml
match_on:
  body:
    contains: error
```

Matches responses where the body contains the string "error".

### Contains with Regex

Search the body using a regular expression pattern.

**Syntax:**
```yaml
match_on:
  body:
    contains:
      value: 'pattern.*here'
      regex: true
```

**Expected Behavior:**

The body is searched using the provided regex pattern. The regex is treated as a full regex string (not anchored by default).

**Example:**
```yaml
match_on:
  body:
    contains:
      value: '"status":\s*"(success|ok)"'
      regex: true
```

Matches responses where the body contains a JSON status field with value "success" or "ok".

### JSON Structure Matching

Match specific fields within a JSON body.

**Syntax:**
```yaml
match_on:
  body:
    json:
      result: success
      count: 5
      user:
        name: John
        age: 30
```

**Expected Behavior:**

The body is parsed as JSON and matched against the specified structure. Nested objects are supported. Values are matched exactly unless operators are used.

**Example:**
```yaml
match_on:
  body:
    json:
      status: ok
      data:
        id: 123
        active: true
```

Matches JSON responses where status equals "ok" AND data.id equals 123 AND data.active is true.

### JSON Structure with Operators

Use operators within JSON matching for flexible validation.

**Syntax:**
```yaml
match_on:
  body:
    json:
      status:
        in: ['success', 'ok', 'completed']
      timestamp:
        regex: '^\d{4}-\d{2}-\d{2}T'
      items:
        length_gte: 1
      code:
        gte: 100
        lte: 199
```

**Expected Behavior:**

Operators are applied to JSON fields. Multiple operators for the same field must all pass. Nested objects are supported.

**Example:**
```yaml
match_on:
  body:
    json:
      error:
        exists: false
      data:
        count:
          gt: 0
      message:
        contains: welcome
```

Matches JSON where error field doesn't exist, data.count is greater than 0, AND message contains "welcome".

### Combining Body Matching Methods

Mix different body matching techniques in a single rule.

**Syntax:**
```yaml
match_on:
  body:
    contains: '"status":"success"'
    json:
      status: success
      count:
        gte: 1
```

**Expected Behavior:**

All body matching conditions must pass. The contains pattern is found AND the JSON structure matches.

**Example:**
```yaml
match_on:
  body:
    contains:
      value: '\{"result":'
      regex: true
    json:
      result:
        in: ['ok', 'success']
      timestamp:
        exists: true
```

Matches responses that contain a JSON object with a "result" field AND the result value is "ok" or "success" AND timestamp field exists.

---

## Operators Reference

Operators provide flexible matching capabilities. They can be used in status, headers, and body matching.

### Equality Operators

#### `equals`

Exact equality comparison.

**Syntax:**
```yaml
field:
  equals: value
```

**Expected Behavior:**

The field value must exactly equal the specified value. Works with strings, numbers, and booleans.

**Example:**
```yaml
match_on:
  header:
    X-Status:
      equals: active
```

#### `exact`

Alias for `equals`. Exact match comparison.

**Syntax:**
```yaml
field:
  exact: value
```

**Example:**
```yaml
match_on:
  status:
    exact: 200
```

#### `strict_equals`

Strict equality comparison (uses === comparison).

**Syntax:**
```yaml
field:
  strict_equals: value
```

**Expected Behavior:**

Identical to `equals` in most cases. Ensures strict type comparison.

**Example:**
```yaml
match_on:
  body:
    json:
      count:
        strict_equals: 0
```

#### `not_equals`

Not equal comparison.

**Syntax:**
```yaml
field:
  not_equals: value
```

**Expected Behavior:**

The field value must not equal the specified value.

**Example:**
```yaml
match_on:
  status:
    not_equals: 404
```

### String Operators

#### `contains`

String contains substring match.

**Syntax:**
```yaml
field:
  contains: substring
```

Or with regex:

```yaml
field:
  contains:
    value: pattern
    regex: true
```

**Expected Behavior:**

Field is converted to string and checked for substring presence. If `regex: true`, the value is treated as a regex pattern.

**Example:**
```yaml
match_on:
  header:
    Content-Type:
      contains: json
```

#### `not_contains`

String does not contain substring.

**Syntax:**
```yaml
field:
  not_contains: substring
```

**Expected Behavior:**

The field (as string) must not contain the specified substring.

**Example:**
```yaml
match_on:
  body:
    json:
      message:
        not_contains: error
```

#### `contains_i`

Case-insensitive contains.

**Syntax:**
```yaml
field:
  contains_i: substring
```

**Expected Behavior:**

Performs case-insensitive substring matching.

**Example:**
```yaml
match_on:
  header:
    Server:
      contains_i: apache
```

Matches "Apache", "apache", "APACHE", etc.

#### `regex`

Regular expression match.

**Syntax:**
```yaml
field:
  regex: 'pattern'
```

**Expected Behavior:**

Field is converted to string and matched against the regex pattern. Exceptions are caught and treated as no match.

**Example:**
```yaml
match_on:
  body:
    json:
      email:
        regex: '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
```

#### `starts_with`

String starts with prefix.

**Syntax:**
```yaml
field:
  starts_with: prefix
```

**Expected Behavior:**

The field (as string) must start with the specified prefix.

**Example:**
```yaml
match_on:
  header:
    Authorization:
      starts_with: 'Bearer '
```

#### `ends_with`

String ends with suffix.

**Syntax:**
```yaml
field:
  ends_with: suffix
```

**Expected Behavior:**

The field (as string) must end with the specified suffix.

**Example:**
```yaml
match_on:
  body:
    json:
      url:
        ends_with: .json
```

### Numeric Operators

#### `gt`

Greater than comparison.

**Syntax:**
```yaml
field:
  gt: number
```

**Expected Behavior:**

Field is converted to number and compared. Must be strictly greater than the specified value.

**Example:**
```yaml
match_on:
  status:
    gt: 199
```

#### `gte`

Greater than or equal comparison.

**Syntax:**
```yaml
field:
  gte: number
```

**Expected Behavior:**

Field is converted to number and compared. Must be greater than or equal to the specified value.

**Example:**
```yaml
match_on:
  header:
    X-Rate-Limit-Remaining:
      gte: 100
```

#### `lt`

Less than comparison.

**Syntax:**
```yaml
field:
  lt: number
```

**Expected Behavior:**

Field is converted to number and compared. Must be strictly less than the specified value.

**Example:**
```yaml
match_on:
  status:
    lt: 300
```

#### `lte`

Less than or equal comparison.

**Syntax:**
```yaml
field:
  lte: number
```

**Expected Behavior:**

Field is converted to number and compared. Must be less than or equal to the specified value.

**Example:**
```yaml
match_on:
  body:
    json:
      response_time_ms:
        lte: 5000
```

### Array Operators

#### `in`

Value is in array.

**Syntax:**
```yaml
field:
  in: [value1, value2, value3]
```

**Expected Behavior:**

Field value must be one of the values in the specified array.

**Example:**
```yaml
match_on:
  status:
    in: [200, 201, 204]
```

#### `not_in`

Value is not in array.

**Syntax:**
```yaml
field:
  not_in: [value1, value2]
```

**Expected Behavior:**

Field value must not be any of the values in the specified array.

**Example:**
```yaml
match_on:
  status:
    not_in: [400, 401, 403, 404, 500, 502, 503]
```

#### `includes`

Array includes value (for array fields).

**Syntax:**
```yaml
field:
  includes: value
```

**Expected Behavior:**

Field must be an array and must contain the specified value.

**Example:**
```yaml
match_on:
  body:
    json:
      permissions:
        includes: 'admin'
```

### Type and Existence Operators

#### `type`

Check field type.

**Syntax:**
```yaml
field:
  type: 'string'
```

**Expected Behavior:**

Field type must match the specified type. Valid types: 'string', 'number', 'boolean', 'object', 'array'.

**Example:**
```yaml
match_on:
  body:
    json:
      data:
        type: 'object'
      count:
        type: 'number'
```

#### `exists`

Check if field exists or is null.

**Syntax:**
```yaml
field:
  exists: true
```

Or:

```yaml
field:
  exists: false
```

**Expected Behavior:**

When `true`, field must not be null or undefined. When `false`, field must be null or undefined.

**Example:**
```yaml
match_on:
  body:
    json:
      error:
        exists: false
      success:
        exists: true
```

#### `empty`

Check if field is empty.

**Syntax:**
```yaml
field:
  empty: true
```

Or:

```yaml
field:
  empty: false
```

**Expected Behavior:**

When `true`, field must be empty (null, undefined, or length 0). When `false`, field must have length > 0.

**Example:**
```yaml
match_on:
  body:
    json:
      message:
        empty: false
      items:
        empty: false
```

### Length Operators

#### `length`

Exact length match.

**Syntax:**
```yaml
field:
  length: 10
```

**Expected Behavior:**

Field must have exactly the specified length. Works with strings and arrays.

**Example:**
```yaml
match_on:
  body:
    json:
      id:
        length: 36
      items:
        length: 5
```

#### `length_gte`

Length greater than or equal.

**Syntax:**
```yaml
field:
  length_gte: 1
```

**Expected Behavior:**

Field length must be greater than or equal to the specified value.

**Example:**
```yaml
match_on:
  body:
    json:
      results:
        length_gte: 1
      message:
        length_gte: 3
```

#### `length_lte`

Length less than or equal.

**Syntax:**
```yaml
field:
  length_lte: 1000
```

**Expected Behavior:**

Field length must be less than or equal to the specified value.

**Example:**
```yaml
match_on:
  body:
    json:
      data:
        length_lte: 100
```

### JSON Operator

#### `json`

Parse and match nested JSON structure (for body matching).

**Syntax:**
```yaml
match_on:
  body:
    json:
      nested:
        structure: value
```

**Expected Behavior:**

Body is parsed as JSON and matched against the nested structure. All fields and operators within the JSON rule must match.

**Example:**
```yaml
match_on:
  body:
    json:
      user:
        name: John
        age:
          gte: 18
      roles:
        includes: 'admin'
```

---

## Complex Matching Examples

### Example 1: API Success Response Validation

Validate a successful API response with status, headers, and JSON body structure.

```yaml
match_on:
  status: 200
  header:
    Content-Type: application/json
    Cache-Control: 'no-cache'
  body:
    json:
      status: success
      data:
        user_id:
          type: 'number'
          gt: 0
        email:
          regex: '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
```

**Validates:**
- HTTP 200 response
- Content-Type is application/json
- Cache-Control header is no-cache
- Response body contains status: "success"
- user_id is a number greater than 0
- email matches email regex pattern

### Example 2: Error Handling with Multiple Possible Status Codes

Match error responses that could have different HTTP codes.

```yaml
match_on:
  status:
    in: [400, 401, 403, 404]
  header:
    contains:
      value: 'application/.*json'
      regex: true
  body:
    json:
      error:
        exists: true
      error_code:
        in: ['VALIDATION_ERROR', 'UNAUTHORIZED', 'FORBIDDEN', 'NOT_FOUND']
      message:
        not_empty: true
```

**Validates:**
- Status is one of the error codes
- Response contains an application JSON header
- Error object exists in response
- Error code matches expected values
- Error message is not empty

### Example 3: Rate Limit Response Validation

Validate rate limit headers and ensure retry information is present.

```yaml
match_on:
  status: 429
  header:
    X-RateLimit-Limit:
      type: 'string'
    X-RateLimit-Remaining:
      gte: 0
    X-RateLimit-Reset:
      regex: '^\d+$'
  body:
    contains:
      value: 'rate limit'
      regex: false
```

**Validates:**
- Status 429 (Too Many Requests)
- Rate limit headers are present
- Remaining count is non-negative
- Reset time is a numeric timestamp
- Body mentions "rate limit"

### Example 4: Paginated List Response

Validate paginated list responses with nested arrays.

```yaml
match_on:
  status: 200
  body:
    json:
      page:
        gte: 1
      per_page:
        in: [10, 25, 50, 100]
      total:
        gte: 0
      items:
        length_gte: 0
        length_lte: 100
      items:
        type: 'array'
      data:
        - id:
            type: 'number'
        - name:
            length_gte: 1
```

**Validates:**
- Status 200 response
- Page number is at least 1
- Per-page value is one of the allowed options
- Total count is non-negative
- Items array contains between 0-100 items
- Each item has numeric id and non-empty name

### Example 5: Redirect Response Validation

Validate redirect responses.

```yaml
match_on:
  status:
    in: [301, 302, 307, 308]
  header:
    Location:
      regex: '^https?://.*'
    Location:
      not_contains: localhost
  body:
    empty: true
```

**Validates:**
- Status is a redirect code
- Location header contains valid URL
- Location doesn't redirect to localhost
- Body is empty

### Example 6: Authentication Token Validation

Validate responses containing authentication tokens.

```yaml
match_on:
  status: 200
  header:
    Authorization:
      starts_with: 'Bearer '
    Set-Cookie:
      contains: 'session'
  body:
    json:
      token:
        regex: '^[a-zA-Z0-9_\-\.]+$'
      token_type: Bearer
      expires_in:
        gt: 0
      refresh_token:
        length_gte: 20
```

**Validates:**
- Status 200 with successful authentication
- Authorization header contains Bearer token
- Set-Cookie header contains session info
- Token matches JWT-like format
- Token type is Bearer
- Expiration is in the future
- Refresh token is at least 20 characters

### Example 7: Health Check Response

Simple health check validation.

```yaml
match_on:
  status: 200
  header:
    Content-Type:
      contains: json
  body:
    json:
      status:
        in: [ok, healthy, up]
      timestamp:
        regex: '^\d{4}-\d{2}-\d{2}T'
      version:
        regex: '^\d+\.\d+\.\d+$'
```

**Validates:**
- Status 200
- Content-Type contains "json"
- Status is one of: ok, healthy, up
- Timestamp is ISO format
- Version follows semantic versioning

### Example 8: Search Results with Facets

Validate complex search response with nested facets.

```yaml
match_on:
  status: 200
  body:
    json:
      query:
        not_empty: true
      total_results:
        gte: 0
      results:
        type: 'array'
        length_lte: 100
      facets:
        type: 'object'
      facets:
        categories:
          type: 'array'
        facets:
          categories:
            - count:
                type: 'number'
                gte: 0
            - name:
                length_gte: 1
```

**Validates:**
- Status 200
- Query string is not empty
- Total results is non-negative
- Results array exists and has max 100 items
- Facets object exists
- Category facets are an array
- Each category has count (number >= 0) and name (non-empty)

### Example 9: Form Submission with Validation Errors

Validate form submission responses that may include field-level errors.

```yaml
match_on:
  status:
    in: [400, 422]
  body:
    json:
      success: false
      errors:
        type: 'object'
      errors:
        exists: true
      errors:
          empty: false
      message:
        contains: 'validation'
        contains_i: 'failed'
```

**Validates:**
- Status is 400 or 422 (validation error)
- Success is false
- Errors object exists and is not empty
- Message contains "validation" (case-insensitive) and "failed"

### Example 10: File Download Response

Validate file download responses.

```yaml
match_on:
  status: 200
  header:
    Content-Type:
      in: ['application/pdf', 'application/zip', 'image/png']
    Content-Disposition:
      starts_with: 'attachment'
    Content-Length:
      gte: 1
  body:
    contains: ''
```

**Validates:**
- Status 200
- Content-Type is one of the allowed file types
- Content-Disposition header indicates attachment
- Content-Length is positive (file not empty)
- Body exists (any content)

---

## Best Practices

1. **Be Specific** - Use specific status codes or ranges rather than matching everything
2. **Combine Matching Types** - Mix status, header, and body matching for comprehensive validation
3. **Use Regex Carefully** - Regex patterns are powerful but can be slow; use simple contains when possible
4. **Validate Structure** - Use JSON matching to validate response structure, not just content
5. **Test Edge Cases** - Consider what happens with empty responses, missing fields, and unexpected types
6. **Document Complex Rules** - Add comments explaining what each rule validates
7. **Use Contains for Search** - For headers or body, use contains when you don't need exact matches
8. **Combine Operators** - Use multiple operators on the same field for range checking and complex logic

---

## Error Handling

The matcher handles various error conditions gracefully:

- **Invalid Regex** - Regex errors are caught and treated as no match
- **JSON Parse Errors** - Invalid JSON is treated as no match for JSON rules
- **Type Mismatches** - Operations that don't apply to field type are handled safely
- **Missing Fields** - Missing fields in JSON structures are treated as no match
- **Null Values** - Null values are handled appropriately by operators

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
