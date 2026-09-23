# Automations Field Mapping

## Overview

In the automation workflow engine, action nodes (such as database operations) often need to reference data produced by previous nodes. This data transfer is achieved using **placeholders**. Placeholders allow you to dynamically map values from the `previous_output.data` context into the configuration fields of your action nodes.

## Placeholder Syntax

The engine uses [jq](https://jqlang.github.io/jq/) expressions under the hood to evaluate and resolve placeholders. You can define placeholders using two conventions:

1. **JSONPath style:** Expressions starting with `$.` (e.g., `$.user.email`)
2. **jq style:** Expressions starting with `.` (e.g., `.user.email`)

*Note: Any placeholder starting with `$.` is automatically converted to the `.` format prior to evaluation.*

## Resolving Values from Arrays

If the output from the previous node is an array of objects, the placeholder resolution engine handles the mapping intelligently:

- When the input context is an array, simple accessors (e.g., `.location.city` or `$.location.city`) are automatically wrapped in a `jq` `map()` function.
- For example, `.location.city` becomes `map(.location.city)`. This extracts the nested `city` property for every item in the array.
- In bulk actions like a database `updateMany` or `bulkWrite`, the array of resolved values is mapped index-by-index `[i]` to each corresponding item being processed.

## Advanced jq Queries

Because the engine utilizes `jq` for evaluation, you are not strictly limited to simple property access. You can write custom `jq` filters if you need more complex data extraction, filtering, or transformations. 

If your query already contains `[]` or starts with `map(`, the engine will execute it exactly as written without wrapping it.

## Example: Database Operation Action

When configuring a database operation node, placeholders are heavily used to map `matchKeys` and `keysToUpdate`:

```json
{
  "database": "internal_db",
  "collection": "users",
  "operation": "update",
  "matchKeys": [
    { "field": "user_id", "value": "$.id" }
  ],
  "keysToUpdate": [
    { "field": "status", "value": "$.status_string" },
    { "field": "last_login", "value": "$.metadata.last_login" }
  ]
}
```

In this example, if the previous node outputs an array of user objects, `$.id` resolves to an array of IDs, which the database actualizer pairs with the corresponding rows to execute the bulk updates.
