# Rule Engine Documentation

This document provides complete documentation for the YAML-based **Rule Engine**.
The rule engine is used to define, transform, and evaluate match conditions into MongoDB queries.

---

## Table of Contents

1. [Rule Structure](#rule-structure)
2. [Top-Level Fields](#top-level-fields)
3. [Match Conditions](#match-conditions)

   * [Basic Operators](#basic-operators)
   * [Regex Matching](#regex-matching)
   * [Array Matching (](#array-matching-elemmatch)[`elemMatch`](#array-matching-elemmatch)[)](#array-matching-elemmatch)
   * [Negation](#negation)
4. [Logical Operators](#logical-operators)
5. [Transformers](#transformers)

   * [Date Transformer](#date-transformer)
   * [Number Transformer](#number-transformer)
   * [List Transformer](#list-transformer)
6. [Set Queries](#set-queries)
7. [Examples](#examples)

   * [Basic Rule](#basic-rule)
   * [Rule with Negation](#rule-with-negation)
   * [Rule with Regex](#rule-with-regex)
   * [Rule with Date Transformer](#rule-with-date-transformer)
   * [Rule with Number Transformer](#rule-with-number-transformer)
   * [Rule with List Transformer](#rule-with-list-transformer)
   * [Rule with Set Queries](#rule-with-set-queries)

---

## Rule Structure

Each rule is defined in YAML format. A rule describes conditions that must be matched in a dataset (such as risks, assets, or vulnerabilities).

#### Example Rule

```yaml
name: rule name
description: rule description
severity: critical
product: risk-register
assetType: subdomain
match:
  - field: properties.vulnerabilityStats.critical
    operator: '>='
    value: 1
```

---

## Top-Level Fields

| Field         | Type         | Description                                                                 |
| ------------- | ------------ | --------------------------------------------------------------------------- |
| `name`        | String       | Name of the rule.                                                           |
| `description` | String       | Human-readable description of what this rule does.                          |
| `severity`    | String       | The severity of the rule (e.g., `critical`, `high`, `medium`, `low`).       |
| `product`     | String       | The product/module this rule applies to (e.g., `risk-register`).            |
| `assetType`   | String       | The type of asset this rule applies to (e.g., `subdomain`, `ip`, `server`). |
| `match`       | Object/Array | Defines the conditions to evaluate (see below).                             |
| `set`         | Object/Array | Defines update operations to apply if the match condition is satisfied.     |

---

## Match Conditions

The `match` section defines the actual query rules.
It can either be:

* **An array of conditions** (field/operator/value triplets)
* **An object with logical operators** (`and`, `or`, `conditions`)

---

### Basic Operators

The following operators are supported:

| Operator       | MongoDB Equivalent | Example (`value`)            |
| -------------- | ------------------ | ---------------------------- |
| `==`           | `$eq`              | `"status"` → `"active"`      |
| `!=`           | `$ne`              | `"status"` → `"inactive"`    |
| `>`            | `$gt`              | `"age"` → `18`               |
| `>=`           | `$gte`             | `"age"` → `21`               |
| `<`            | `$lt`              | `"age"` → `65`               |
| `<=`           | `$lte`             | `"age"` → `60`               |
| `in`           | `$in`              | `"country"` → `["US","IN"]`  |
| `not_in`       | `$nin`             | `"country"` → `["CN"]`       |
| `regex`        | `$regex`           | `"email"` → `".*@gmail.com"` |
| `contains`     | `$in`              | `"tags"` → `["security"]`    |
| `not_contains` | `$nin`             | `"tags"` → `["spam"]`        |

---

### Regex Matching

```yaml
- field: email
  operator: regex
  value: ".*@gmail.com"
  options:
    match_case: false
```

* `match_case: false` → makes the regex case-insensitive (`$options: i`).
* `match_case: true` → case-sensitive (default MongoDB behavior).

---

### Array Matching (`elemMatch`)

```yaml
- field: vulnerabilities.severity
  operator: "=="
  value: "critical"
  options:
    matchType: elemMatch
```

This generates a query using `$elemMatch`.

---

### Negation

```yaml
- field: status
  operator: "=="
  value: "inactive"
  options:
    negate: true
```

Equivalent MongoDB query:

```js
{ status: { $not: { $eq: "inactive" } } }
```

---

## Logical Operators

```yaml
match:
  and:
    - conditions:
        - field: age
          operator: '>='
          value: 18
    - conditions:
        - field: country
          operator: 'in'
          value: ["US", "CA"]
```

Equivalent MongoDB query:

```js
{
  $and: [
    { age: { $gte: 18 } },
    { country: { $in: ["US", "CA"] } }
  ]
}
```

---

## Transformers

Transformers allow automatic type conversion for the `value` field.
You can specify `transformer` alongside a condition.

### Date Transformer

```yaml
- field: createdAt
  operator: ">="
  value: -3days
  transformer: Date
```

* `3days` → 3 days in the future.
* `-3days` → 3 days ago.
* Supports: `minutes`, `hours`, `days`, `months`, `years`.

---

### Number Transformer

```yaml
- field: properties.size
  operator: ">="
  value: "1000"
  transformer: Number
```

Transforms `"1000"` → `1000`.

---

### List Transformer

```yaml
- field: tags
  operator: in
  value: "security,compliance,network"
  transformer: List
```

Transforms into:

```js
["security", "compliance", "network"]
```

---

## Set Queries

The `set` section allows rules to **update fields** in documents that match the query.

### Syntax

```yaml
set:
  - field: field1
    value: newValue
  - field: field2
    value: anotherValue
```

* Each entry defines a field to be updated with a new value.
* If no `severity` field is specified, a default value of `info` will be set automatically.

### Example

```yaml
set:
  - field: status
    value: flagged
  - field: reviewed
    value: true
```

This produces the following MongoDB update:

```js
{
  $set: {
    status: "flagged",
    reviewed: true,
    severity: "info" // default if not provided
  }
}
```

A rule can have both `match` and `set`, but `set` is optional.

---

## Examples

### Basic Rule

```yaml
name: Critical Vulnerabilities
description: Detect assets with >= 1 critical vulnerability
severity: critical
product: risk-register
assetType: subdomain
match:
  - field: properties.vulnerabilityStats.critical
    operator: '>='
    value: 1
```

---

### Rule with Negation

```yaml
match:
  - field: status
    operator: "=="
    value: "inactive"
    options:
      negate: true
```

---

### Rule with Regex

```yaml
match:
  - field: email
    operator: regex
    value: ".*@example.com"
    options:
      match_case: false
```

---

### Rule with Date Transformer

```yaml
match:
  - field: createdAt
    operator: ">="
    value: -30days
    transformer: Date
```

Finds documents created in the last 30 days.

---

### Rule with Number Transformer

```yaml
match:
  - field: properties.riskScore
    operator: ">"
    value: "75"
    transformer: Number
```

---

### Rule with List Transformer

```yaml
match:
  - field: category
    operator: in
    value: "network,application,cloud"
    transformer: List
```

---

### Rule with Set Queries

```yaml
name: Flag High-Risk Assets
description: Mark assets with riskScore >= 80 as flagged
severity: high
product: risk-register
assetType: server
match:
  - field: properties.riskScore
    operator: ">="
    value: 80
set:
  - field: status
    value: flagged
  - field: severity
    value: high
```

This finds high-risk assets and updates their status and severity.

---

## Summary

* Rules are written in YAML.
* `match` defines field/operator/value conditions.
* `set` allows updating fields in matched documents.
* Options allow `elemMatch`, regex sensitivity, and negation.
* Transformers convert values into Dates, Numbers, or Lists.
* Logical operators (`and`, `or`) combine conditions.

This engine translates YAML rules into **MongoDB queries and updates**.
