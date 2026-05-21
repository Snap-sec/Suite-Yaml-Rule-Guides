# Scanner Development Guide

This guide provides technical details on how to implement new security scanners for the WAS (Web Application Scanner) platform.

---

## 1. Scanner Architecture

Scanners are located in `src/workers/scan-flow/scanners/`. They are triggered by the `ScannerOrchestrator` for every unique request-response pair captured during a scan.

### The Lifecycle of a Scan
1.  **Request Capture**: The crawler or proxy captures an HTTP request.
2.  **Request Execution**: The orchestrator executes the request to get a fresh response.
3.  **Pipeline Execution**: The orchestrator passes the `request`, `response`, `metadata`, and `redis` instance to each scanner in the `pipeline` array.
4.  **Enrichment**: The orchestrator collects all findings, enriches them with system metadata (orgId, evidence, etc.), and templates the results.

---

## 2. Input Parameters Reference

Every scanner receives a single object with the following properties:

### `request`
The raw HTTP request that was sent.
```javascript
{
    method: "POST",
    url: "https://api.example.com/v1/user/profile",
    headers: {
        "content-type": "application/json",
        "authorization": "Bearer ..."
    },
    params: { "debug": "true" },
    body: { "name": "John Doe" }
}
```

### `response`
The HTTP response received from the server.
```javascript
{
    status_code: 200,
    status_text: "OK",
    headers: {
        "content-type": "application/json",
        "set-cookie": ["session=..."]
    },
    body: { "status": "success" }, // Can be String or Object (if JSON)
    size: 1024, // in bytes
    time: 150   // duration in milliseconds
}
```

### `metadata`
Contextual information about the current scan and project.
```javascript
{
    project: {
        _id: "...",
        orgId: "...",
        name: "My Project",
        scanSettings: { ... }
    },
    scan: {
        _id: "...",
        name: "Weekly Security Audit",
        status: "in_progress"
    }
}
```

### `redis`
The Redis client (ioredis) used for sharing state across the entire scan.
*   **`await redis.get(key)`**: Retrieve a value.
*   **`await redis.set(key, value, "EX", seconds)`**: Store a value with a TTL.
*   **`await redis.exists(key)`**: Check if a finding was already processed.
*   **`await redis.incr(key)`**: Increment a counter.

---

## 3. Implementation Patterns

### Pattern A: Response Filtering (Performance)
Always check if the response is relevant to your scanner before running heavy analysis.
```javascript
const contentType = (response.headers['content-type'] || '').toLowerCase();
if (!contentType.includes('text/html')) return { vuln_list: [] };
```

### Pattern B: Deduplication (Clean Reports)
Use Redis to ensure you only report a specific vulnerability once per scan, even if it appears on multiple pages.
```javascript
const scanId = metadata.scan._id;
const redisKey = `scan:${scanId}:vuln:my-check-id`;

if (await redis.exists(redisKey)) return { vuln_list: [] };
await redis.set(redisKey, "true", "EX", 86400);
```

---

## 4. Complete Example: Cookie Security Scanner

This scanner checks if sensitive cookies are missing the `HttpOnly` or `Secure` flags.

```javascript
/**
 * src/workers/scan-flow/scanners/cookie-security-scan.js
 */
export async function cookieSecurityScan({ request, response, metadata, redis }) {
    const foundVulns = [];
    const setCookieHeader = response.headers['set-cookie'];

    if (!setCookieHeader) return { vuln_list: [] };

    // Convert to array if it's a single string
    const cookies = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];

    for (const cookie of cookies) {
        const isSecure = cookie.toLowerCase().includes('secure');
        const isHttpOnly = cookie.toLowerCase().includes('httponly');
        
        // Extract cookie name for deduplication
        const cookieName = cookie.split('=')[0].trim();
        const scanId = metadata.scan._id;
        const redisKey = `scan:${scanId}:vuln:cookie-security:${cookieName}`;

        if (!isSecure || !isHttpOnly) {
            // Check Redis to avoid duplicate reports for the same cookie name in this scan
            if (await redis.exists(redisKey)) continue;
            await redis.set(redisKey, "true", "EX", 86400);

            foundVulns.push({
                title: `Insecure Cookie Attributes: ${cookieName}`,
                description: `The cookie **${cookieName}** was set without the following flags: ` +
                             `${!isHttpOnly ? '`HttpOnly` ' : ''}${!isSecure ? '`Secure`' : ''}.`,
                severity: "low",
                type: "insecure-cookie",
                cwe: "CWE-614",
                impact: "Missing 'HttpOnly' allows JavaScript to access the cookie (prone to XSS). " +
                        "Missing 'Secure' allows the cookie to be sent over unencrypted connections.",
                mitigation: "Update the server configuration to include `HttpOnly` and `Secure` attributes for all sensitive cookies.",
                stepsToReproduce: "1. Capture the response for {{req.url}}\n2. Inspect the `Set-Cookie` header.\n3. Verify missing attributes for ${cookieName}."
            });
        }
    }

    return { vuln_list: foundVulns };
}
```

---

## 5. Wiring into the Pipeline

Once your scanner is ready:
1.  Open `src/workers/scan-flow/scanners/orchestrator.js`.
2.  Import your function.
3.  Add it to the `pipeline` array.

```javascript
import { vulnerableLibraryScan } from "./vulnerable-library-scan.js";
import { cookieSecurityScan } from "./cookie-security-scan.js";

const pipeline = [
    vulnerableLibraryScan,
    cookieSecurityScan,
];
```

## 6. Dynamic Placeholders

The orchestrator automatically replaces these in your `title`, `description`, `mitigation`, etc.:
*   `{{req.url}}`: The full URL of the request.
*   `{{req.method}}`: GET, POST, etc.
*   `{{res.status}}`: 200, 404, etc.
*   `{{res.headers.X}}`: Value of header X (e.g., `{{res.headers.server}}`).
*   `{{res.body}}`: The full response body.
*   `{{res.responseTime}}`: Duration of the request in ms.

---

## 7. Testing Your Scanner

Before deploying a scanner, you should test it locally using the test utility script located at `src/workers/scan-flow/scanners/test-scanner.js`.

### How to use the Test Script

1.  **Open `test-scanner.js`**.
2.  **Import your scanner** at the top of the file.
3.  **Adjust `mockRequest` and `mockResponse`** to match the scenario you want to test (e.g., set specific headers or body content).
4.  **Set `scannerToTest`** to your scanner function inside the `runTest` function.
5.  **Run the script** from the root directory:
    ```bash
    node src/workers/scan-flow/scanners/test-scanner.js
    ```

### Sample Test Script Structure

The script provides a mock environment that simulates the Orchestrator, including a local memory-based Redis mock:

```javascript
import { myNewScanner } from './my-new-scanner.js';

// ... (mocks for request, response, metadata, redis)

async function runTest() {
    const result = await myNewScanner({
        request: mockRequest,
        response: mockResponse,
        metadata: mockMetadata,
        redis: mockRedis
    });

    console.log(JSON.stringify(result, null, 2));
}
```

This allows you to verify:
*   Regex matches work correctly.
*   Redis deduplication logic is sound.
*   The returned `vuln_list` has the correct structure.
