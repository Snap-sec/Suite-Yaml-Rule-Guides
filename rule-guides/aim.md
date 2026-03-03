# Policy Engine Documentation

## Overview

The Policy Engine allows you to define **declarative rules** using YAML to evaluate data, enrich it, and perform actions when certain conditions are met.

Policies are evaluated against incoming data (assets, events, scan results, findings, etc.) and fall into **three types**:

1. **Classifier** – Enriches or modifies data by setting fields when conditions match
2. **Trigger** – Executes actions (e.g., create Jira ticket, run scan) when conditions match
3. **Alert** – Notifies users (email, Slack, in-app) when conditions match

All policies share a **common matching language**, making them easy to reason about and extend.

---

## Common Concepts

### Match Block

The `match` block defines **conditions** that must be satisfied for the policy to execute.

```yaml
match:
  - field: <field_name>
    operator: <operator>
    value: <value>
```

### Supported Operators

| Operator   | Description           |
| ---------- | --------------------- |
| `==`       | Equals                |
| `!=`       | Not equals            |
| `>`        | Greater than          |
| `<`        | Less than             |
| `>=`       | Greater than or equal |
| `<=`       | Less than or equal    |
| `in`       | Value exists in array |
| `contains` | String contains value |
| `exists`   | Field exists          |

> Multiple match conditions are **ANDed** by default.

---

## 1. Classifier Policy

### Purpose

Classifiers are used to **enrich, normalize, or tag data** after it is ingested.

Typical use cases:

* Assign severity
* Tag assets
* Normalize fields
* Categorize findings

### Structure

```yaml
name: <string>
description: <string>

match:
  - field: <field>
    operator: <operator>
    value: <value>

set:
  - field: <field>
    value: <value>
```

### Example

```yaml
name: classify-high-risk-subdomain
description: Mark admin subdomains as high risk

match:
  - field: subdomain
    operator: contains
    value: admin

set:
  - field: risk_level
    value: high

  - field: tags
    value: ["admin", "critical"]
```

### Behavior

* If all `match` conditions are satisfied:

  * Fields defined in `set` are **added or overwritten**
* No side effects (no notifications, no actions)

---

## 2. Trigger Policy

### Purpose

Triggers execute **automated actions** when conditions are met.

Typical use cases:

* Create Jira tickets
* Run vulnerability scans
* Start workflows
* Call internal services

### Structure

```yaml
name: <string>
description: <string>

match:
  - field: <field>
    operator: <operator>
    value: <value>

action:
  type: <action_type>
  config:
    <key>: <value>
```

### Supported Action Types

| Action Type      | Description                     |
| ---------------- | ------------------------------- |
| `jira.create`    | Create a Jira issue             |
| `scan.run`       | Run vulnerability or asset scan |
| `webhook.call`   | Call an external webhook        |
| `workflow.start` | Trigger internal workflow       |

### Example: Create Jira Ticket on Critical Vulnerability

```yaml
name: trigger-jira-on-critical-vuln
description: Create Jira ticket when critical vulnerability is found

match:
  - field: severity
    operator: ==
    value: critical

  - field: status
    operator: ==
    value: open

action:
  type: jira.create
  config:
    project: SEC
    issue_type: Bug
    priority: Highest
    summary: "Critical vulnerability detected"
```

### Example: Run Vulnerability Scan on New Asset

```yaml
name: trigger-scan-on-new-asset
description: Automatically scan newly discovered assets

match:
  - field: asset_status
    operator: ==
    value: new

action:
  type: scan.run
  config:
    scan_type: vulnerability
    depth: full
```

### Behavior

* Trigger executes **exactly once per match event**
* Triggers **cause side effects**
* Can be rate-limited or deduplicated by engine logic

---

## 3. Alert Policy

### Purpose

Alerts notify users when specific conditions occur.

Typical use cases:

* High-severity findings
* SLA breaches
* Asset changes
* Scan failures

### Structure

```yaml
name: <string>
description: <string>

match:
  - field: <field>
    operator: <operator>
    value: <value>

alert:
  channels:
    - type: <channel_type>
      config:
        <key>: <value>
```

### Supported Alert Channels

| Channel        | Description         |
| -------------- | ------------------- |
| `email`        | Send email          |
| `slack`        | Slack message       |
| `notification` | In-app notification |
| `webhook`      | External webhook    |

### Example: Email Alert on High Risk Asset

```yaml
name: alert-high-risk-asset
description: Notify security team when high-risk asset is detected

match:
  - field: risk_level
    operator: ==
    value: high

alert:
  channels:
    - type: email
      config:
        to:
          - security@company.com
        subject: "High Risk Asset Detected"
        template: high_risk_asset
```

### Example: Slack Alert on Scan Failure

```yaml
name: alert-scan-failure
description: Notify on failed scans

match:
  - field: scan_status
    operator: ==
    value: failed

alert:
  channels:
    - type: slack
      config:
        channel: "#security-alerts"
        message: "Scan failed for asset {{asset_id}}"
```

### Behavior

* Alerts **do not mutate data**
* Alerts **do not execute workflows**
* Multiple channels can be configured per alert

---

## Execution Order (Recommended)

1. **Classifier policies** – enrich data
2. **Trigger policies** – execute actions
3. **Alert policies** – notify users

This ensures alerts and triggers operate on **fully classified data**.

---

## Design Principles

* Declarative and readable
* Deterministic evaluation
* Extensible operators and actions
* Separation of concerns:

  * Classify
  * Act
  * Notify

---

## Future Extensions

* `any` / `all` match groups
* Rule versioning
* Policy priority
* Dry-run mode
* Policy simulation and testing
