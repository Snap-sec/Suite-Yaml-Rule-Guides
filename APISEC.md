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
