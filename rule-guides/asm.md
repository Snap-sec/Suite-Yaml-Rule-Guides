# 🧩 Rule Engine Documentation

### (Asset Exposure Classification Rules)

This document explains how to write YAML-based rules that the system converts into MongoDB queries to automatically classify **assets** as *exposed* or *not exposed*.

It’s designed for power users and enterprise teams who want to define flexible, auditable exposure logic without modifying code.

---

## 1. Rule Structure

A rule consists of two main parts:

```yaml
match:        # Defines which assets the rule targets
set:          # Defines what changes to apply when a match occurs
```

Example:

```yaml
match:
  conditions:
    - field: "type"
      operator: "=="
      value: "certificate"

    - field: "properties.certificate_is_expired"
      operator: "=="
      value: true

set:
  - field: "exposure_status"
    value: "exposed"
  - field: "exposure_reason"
    value: "Expired certificate"
```

> ⚠️ **Important:** Each rule’s match conditions **must** be placed inside a `conditions:` block. If you define them directly under `match:` (like `match: - field: xz`), the rule will still be parsed but will generate a list query like `[ { query1 }, { query2 } ]` instead of a proper MongoDB `$and` structure.

---

## 2. Match Section

The `match` block defines filters using **logical conditions** (`and`, `or`) and **field comparisons** (`==`, `<`, `in`, etc.) that operate on the Asset schema.

### 2.1. Condition Structure

Each condition has:

| Field         | Description                                                                      |
| ------------- | -------------------------------------------------------------------------------- |
| `field`       | Path to the field in the Asset document (e.g., `type`, `properties.port_status`) |
| `operator`    | Comparison type (see operator list below)                                        |
| `value`       | Value to compare against                                                         |
| `transformer` | *(optional)* Converts value (e.g. to date, number, or list)                      |
| `options`     | *(optional)* Controls regex, negation, or array matching                         |

---

### 2.2. Supported Operators

| Operator             | Description              | Mongo Equivalent             |
| -------------------- | ------------------------ | ---------------------------- |
| `==`                 | Equal                    | `$eq`                        |
| `!=`                 | Not equal                | `$ne`                        |
| `<`, `<=`, `>`, `>=` | Comparisons              | `$lt`, `$lte`, `$gt`, `$gte` |
| `in`                 | Value in list            | `$in`                        |
| `not_in`             | Value not in list        | `$nin`                       |
| `regex`              | Regular expression match | `$regex`                     |
| `contains`           | Array contains any       | `$in`                        |
| `not_contains`       | Array does not contain   | `$nin`                       |

---

### 2.3. Logical Operators

Combine multiple condition groups using logical operators:

```yaml
match:
  and:
    - conditions:
        - field: "type"
          operator: "=="
          value: "port"
        - field: "properties.port_status"
          operator: "=="
          value: "open"
    - or:
        - conditions:
            - field: "properties.port_service"
              operator: "in"
              value: ["ssh", "ftp"]
            - field: "properties.port_protocol"
              operator: "=="
              value: "udp"
```

---

### 2.4. Transformers

| Transformer | Description                            | Example                                                         |
| ----------- | -------------------------------------- | --------------------------------------------------------------- |
| `Date`      | Relative time from now                 | `"transformer": "Date", "value": "-30 days"` → date 30 days ago |
| `Number`    | Convert to number                      | `"value": "8080"` → `8080`                                      |
| `List`      | Split comma-separated values into list | `"value": "ssh,ftp,http"` → `["ssh","ftp","http"]`              |

---

### 2.5. Options

| Option                 | Description                                                    | Example                         |
| ---------------------- | -------------------------------------------------------------- | ------------------------------- |
| `match_case`           | For regex matches, enable case sensitivity                     | `options: { match_case: true }` |
| `negate`               | Negate the condition                                           | Marks assets that *don’t* match |
| `matchType: elemMatch` | Use `$elemMatch` for nested arrays like `associatedSubdomains` | (See below)                     |

#### Example: Matching inside an array

```yaml
field: "associatedSubdomains.value"
operator: "regex"
value: "admin"
options:
  matchType: "elemMatch"
```

---

## 3. Set Section

Defines the MongoDB `$set` operation to update asset fields when the match succeeds.

```yaml
set:
  - field: "exposure_status"
    value: "exposed"
  - field: "exposure_reason"
    value: "Open SSH port detected"
  - field: "marked_by"
    value: "auto_rule_engine"
```

> **Note:**
>
> * If no `severity` is set, it defaults to `"info"`.
> * You can update any field in the Asset schema (e.g., `properties.*`).

---

## 4. Example Rules

### 🧠 Example 1 — Expired Certificate

Mark assets with expired certificates as exposed.

```yaml
match:
  conditions:
    - field: "type"
      operator: "=="
      value: "certificate"
    - field: "properties.certificate_is_expired"
      operator: "=="
      value: true
set:
  - field: "exposure_status"
    value: "exposed"
  - field: "exposure_reason"
    value: "Certificate expired"
  - field: "marked_by"
    value: "auto_rule_engine"
```

---

### 🔒 Example 2 — Open Admin Ports (SSH, FTP) on Public IPs

Flag open admin-related ports on public IPs.

```yaml
match:
  and:
    - conditions:
        - field: "type"
          operator: "=="
          value: "port"
        - field: "properties.port_status"
          operator: "=="
          value: "open"
        - field: "properties.port_service"
          operator: "in"
          transformer: "List"
          value: "ssh,ftp"
    - conditions:
        - field: "properties.ip_is_public"
          operator: "=="
          value: true
set:
  - field: "exposure_status"
    value: "exposed"
  - field: "exposure_reason"
    value: "Admin port open on public IP"
```

---

### 🧩 Example 3 — Weak TLS Configurations

Mark web servers using old TLS or small key size.

```yaml
match:
  and:
    - conditions:
        - field: "type"
          operator: "=="
          value: "web_server"
        - field: "properties.certificate_tls_version"
          operator: "in"
          transformer: "List"
          value: "TLSv1,TLSv1.1"
    - or:
        - conditions:
            - field: "properties.certificate_temp_public_key_size"
              operator: "<"
              transformer: "Number"
              value: 2048
set:
  - field: "exposure_status"
    value: "exposed"
  - field: "exposure_reason"
    value: "Weak TLS or small key size"
```

---

### 🌐 Example 4 — Recently Discovered Assets (last 7 days)

Identify newly discovered subdomains to review.

```yaml
match:
  conditions:
    - field: "type"
      operator: "=="
      value: "subdomain"
    - field: "createdAt"
      operator: ">="
      transformer: "Date"
      value: "-7 days"
set:
  - field: "exposure_status"
    value: "not_exposed"
  - field: "exposure_reason"
    value: "Newly discovered, pending review"
```

---

### ⚙️ Example 5 — Associated Subdomains Containing “admin”

Use `elemMatch` to detect dangerous subdomains.

```yaml
match:
  conditions:
    - field: "associatedSubdomains.value"
      operator: "regex"
      value: "admin"
      options:
        matchType: "elemMatch"
set:
  - field: "exposure_status"
    value: "exposed"
  - field: "exposure_reason"
    value: "Contains admin-related subdomain"
```

---

## 5. Notes

* All rules automatically filter by `orgId` or `isUniversal`.
* Always wrap field-based conditions under `conditions:`.
* If a field doesn’t exist in an asset, the condition simply doesn’t match.
* Nested logical operators (`and`/`or`) can be deeply combined.
* Relative dates (`Date` transformer) are calculated at runtime.
* Rules are evaluated one by one — you can define multiple rules for different exposures.
