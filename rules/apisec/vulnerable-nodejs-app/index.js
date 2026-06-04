const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { exec } = require('child_process');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = 'super-secret-banking-key-do-not-share';

// Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.text({ type: ['text/xml', 'application/xml'] }));
app.use(cookieParser());

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'public')));

// Vulnerable CORS Middleware (Arbitrary Origin Reflection)
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    next();
});

// Remove any default CSP or security headers to simulate Missing CSP & other headers
app.use((req, res, next) => {
    res.removeHeader("Content-Security-Policy");
    res.removeHeader("X-Content-Type-Options");
    res.removeHeader("X-Frame-Options");
    res.removeHeader("Strict-Transport-Security");
    res.removeHeader("X-XSS-Protection");
    res.removeHeader("Referrer-Policy");
    res.setHeader("Server", "Apache/2.4.1"); // Server Disclosure
    
    // Set an insecure cookie to trigger HttpOnly and Secure missing rules
    res.cookie('session_id', 'nexus_session_token_123');
    
    next();
});

// ==========================================
// VULNERABLE CORS ENDPOINTS
// ==========================================
app.get('/api/cors/null', (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', 'null');
    res.json({ data: "Null origin allowed" });
});

app.get('/api/cors/wildcard', (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.json({ data: "Wildcard with credentials allowed" });
});

app.get('/api/cors/regex', (req, res) => {
    const origin = req.headers.origin || '';
    if (origin.match(/nexusbank\.com/)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    res.json({ data: "Regex origin allowed" });
});

// Database Setup
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run("CREATE TABLE users (id INT, username TEXT, password TEXT, role TEXT, email TEXT)");
    db.run("INSERT INTO users VALUES (1, 'admin', 'admin123', 'admin', 'admin@bank.local')");
    db.run("INSERT INTO users VALUES (2, 'john', 'password123', 'user', 'john@example.com')");

    db.run("CREATE TABLE transactions (id INT, user_id INT, amount DECIMAL, description TEXT)");
    db.run("INSERT INTO transactions VALUES (1, 2, 50.00, 'Grocery Store')");
    db.run("INSERT INTO transactions VALUES (2, 2, 100.00, 'Gas Station')");
});

// Setup public directory
const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)){
    fs.mkdirSync(publicDir);
}

// ==========================================
// VULNERABLE ENDPOINTS
// ==========================================

// --- 1. Database Injections & Transactions ---

// Error-based SQL Injection
// Target: /api/transactions?id=1'
app.get('/api/transactions', (req, res) => {
    const id = req.query.id;
    if (!id) return res.status(400).send("Missing 'id' parameter");

    // Vulnerable: Direct concatenation
    const query = `SELECT * FROM transactions WHERE id = ${id}`;
    
    db.all(query, [], (err, rows) => {
        if (err) {
            // Vulnerable: Leaking database error to client
            return res.status(500).json({ error: err.message });
        }
        res.json({ data: rows });
    });
});

// Secure Transaction History
app.get('/api/v2/transactions', (req, res) => {
    res.json({ data: [{ id: 1, amount: 50, desc: "Grocery" }] });
});

// Transaction Search (NoSQLi Simulation)
app.post('/api/transactions/search', (req, res) => {
    const bodyStr = JSON.stringify(req.body);
    if (bodyStr.includes('"$gt"') || bodyStr.includes('"$ne"') || bodyStr.includes('"$where"') || bodyStr.includes('"$regex"')) {
        return res.status(500).json({ error: "MongoError: unknown operator" });
    }
    
    // Realistic benign response
    res.json({ results: [
        { id: 1, amount: 50.00, desc: "Grocery Store", date: "2026-05-21" },
        { id: 2, amount: 100.00, desc: "Gas Station", date: "2026-05-22" }
    ]});
});

// Transaction Export (Sensitive Data Leak)
app.get('/api/transactions/export', (req, res) => {
    res.json({
        exportData: [
            { 
                "SSN": "123-45-6789", 
                "CreditCard": "4111 1111 1111 1111", 
                "CVV": "123", 
                "DebitCard": "4111 1111 1111 1111",
                "BankAcc": "Account Number: 123456789", 
                "IBAN": "GB99BOSC11223344556677", 
                "Swift": "BOSCGB21",
                "InternalIP": "192.168.1.100"
            },
            { 
                "AWS_KEY": "AKIAIOSFODNN7EXAMPLE", 
                "StripeKey": "sk_live_1234567890abcdef",
                "GitHubToken": "ghp_123456789012345678901234567890123456", 
                "GitLabToken": "glpat-12345678901234567890",
                "DB_Conn": "mongodb://admin:pass123@10.0.0.1:27017/db",
                "password": "mysecretpassword123",
                "StackTrace": "java.lang.NullPointerException\\n\\tat com.example",
                "SSHKey": "-----BEGIN RSA PRIVATE KEY-----\\nMIIE"
            }
        ]
    });
});

// Mass Assignment
// Target: POST /api/profile with body { "email": "new@email.com", "role": "admin", "snap_xyz_123": "a9s8x9a8sxasx89as" }
app.post('/api/profile', (req, res) => {
    const { email } = req.body;
    
    const userProfile = {
        email: email || 'default@email.com',
        role: 'user', // Default role
        ...req.body // Vulnerability: Merging all request body properties
    };

    res.status(200).json({
        message: "Profile updated successfully",
        profile: userProfile,
        // The mass assignment rule checks if snap_xyz_123 is reflected
        reflection: userProfile.snap_xyz_123 ? userProfile.snap_xyz_123 : undefined
    });
});

// --- 2. Command Injections & Diagnostics ---

// Simple Command Injection
// Target: /api/system/ping?ip=127.0.0.1; uname -a
app.get('/api/system/ping', (req, res) => {
    const ip = req.query.ip;
    if (!ip) return res.status(400).send("Missing 'ip' parameter");

    // Vulnerable: Passing input directly to exec
    exec(`ping -c 1 ${ip}`, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).send(stdout || stderr || error.message);
        }
        res.send(stdout);
    });
});

// Script Runner (Python Code Injection Simulation)
app.post('/api/diagnostics/run-script', (req, res) => {
    const script = req.body.script || '';
    if (script.includes('cat /etc/passwd')) {
        return res.send("root:x:0:0:root:/root:/bin/bash\n");
    } else if (script.includes('id') && script.includes('os.popen')) {
        return res.send("uid=0(root) gid=0(root) groups=0(root)\n");
    } else if (script.includes('whoami')) {
        return res.send("root\n");
    } else if (script.includes('uname')) {
        return res.send("Linux server 5.4.0-1045-aws #47-Ubuntu SMP x86_64 GNU/Linux\n");
    } else if (script.includes('win.ini')) {
        return res.send("[fonts]");
    } else if (script.includes('systeminfo')) {
        return res.send("OS Name: Microsoft Windows Server 2019");
    }
    
    if (script.trim() === '') {
        return res.send("Node runtime environment active. Awaiting script.");
    }
    
    // Realistic benign response
    res.send(`[Execution Output]\nSuccessfully compiled and executed routine (length: ${script.length} bytes).\nStatus: OK\nReturns: null`);
});

// System Logs (Realistic Log Simulation)
app.get('/api/system/logs', (req, res) => {
    res.send(`
[INFO] 2026-05-22 10:00:01 - System booted successfully.
[INFO] 2026-05-22 10:05:12 - User 'john' authenticated via JWT.
[INFO] 2026-05-22 10:15:44 - Database connection pooled: 5 active.
[WARN] 2026-05-22 10:42:10 - High memory usage detected on worker thread.
[INFO] 2026-05-22 11:01:23 - Batch transaction sync completed.
[INFO] 2026-05-22 11:15:00 - Scheduled diagnostics ran successfully.
    `);
});

// Dedicated ASP.NET Trace Endpoint (For Scanner Rule)
app.get('/trace.axd', (req, res) => {
    res.send(`
        <html><body>
        <h1>Application Trace</h1>
        <h2>Request Details</h2>
        <h2>Trace Information</h2>
        <table><tr><th>Category</th><th>Message</th></tr><tr><td>aspx.page</td><td>End Render</td></tr></table>
        </body></html>
    `);
});

// --- 3. Authorization and Authentication ---

// JWT None Algorithm
// Custom middleware to check JWT
const verifyJwt = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1] || req.body.token || req.query.token;

    if (!token) return res.status(401).json({ error: "No token provided" });

    // Vulnerable: Accepting 'none' algorithm by not explicitly setting algorithms in verify options
    // and decoding header first to dynamically pick algorithm (or default to none if missing/none)
    const decodedHeader = jwt.decode(token, { complete: true });
    
    if (!decodedHeader) return res.status(401).json({ error: "Invalid token format" });

    if (decodedHeader.header.alg.toLowerCase() === 'none') {
        // Exploit logic: Accept signature-less token
        req.user = decodedHeader.payload;
        return next();
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: "Invalid token" });
    }
};

// Protected endpoint (but vulnerable to JWT None)
// Target: Send JWT with alg:none and payload {"role":"admin"}
app.get('/api/admin/users', verifyJwt, (req, res) => {
    if (req.user.role === 'admin') {
        res.json({ message: "Admin access granted", secret: "BANK_VAULT_CODE_777" });
    } else {
        res.status(403).json({ error: "Requires admin role" });
    }
});

// Endpoint to get a valid token for testing
app.get('/api/login/demo', (req, res) => {
    const token = jwt.sign({ id: 2, username: 'john', role: 'user' }, JWT_SECRET, { algorithm: 'HS256' });
    res.json({ token });
});

// Unauthorized Access (Missing Auth completely on sensitive data)
// Target: Access without Authorization header -> gets 200 JSON
app.get('/api/public/data', (req, res) => {
    res.status(200).json({ status: "success", data: "This should be protected but isn't." });
});

// --- 4. Cross-Site Scripting (XSS) & Template Injection ---

// Reflected XSS
// Target: /api/search?q=<script>alert(0)</script>
app.get('/api/search', (req, res) => {
    const q = req.query.q || '';
    
    // Set content type to HTML to trigger XSS
    res.setHeader('Content-Type', 'text/html');
    
    // Vulnerable: Reflecting input without encoding
    res.send(`
        <html>
            <body>
                <h1>Search Results for: ${q}</h1>
                <p>No results found.</p>
            </body>
        </html>
    `);
});

// Dynamic Template Renderer (Angular CSTI Simulation)
app.get('/api/template/render', (req, res) => {
    const msg = req.query.msg || '';
    if (msg.includes('{{13337*7}}')) {
        return res.send("Rendered: 93359");
    } else if (msg.includes("{{'angular'+'csti'}}")) {
        return res.send("Rendered: angularcsti");
    }
    res.send(`Rendered: ${msg}`);
});

// --- 5. Server-Side Request Forgery (SSRF) ---

// SSRF - High confidence internal access
// Target: POST /api/fetch-receipt with body {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
app.post('/api/fetch-receipt', async (req, res) => {
    const targetUrl = req.body.url;
    if (!targetUrl) return res.status(400).send("Missing 'url' in body");

    // Mock SSRF behavior for scanning tools that hit hardcoded internal IPs
    if (targetUrl.includes('169.254.169.254') || targetUrl.includes('127.0.0.1') || targetUrl.includes('localhost')) {
        if (targetUrl.includes('security-credentials')) {
            return res.json({
                "Code" : "Success",
                "AccessKeyId" : "AKIAIOSFODNN7EXAMPLE",
                "SecretAccessKey" : "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            });
        }
        if (targetUrl.includes('_all_dbs')) {
            return res.send('["_users","_replicator"]');
        }
    }

    try {
        // Vulnerable: Fetching arbitrary user-provided URL
        const response = await axios.get(targetUrl, { timeout: 3000 });
        res.status(200).send(response.data);
    } catch (error) {
        // Return some error details which might help attacker
        res.status(500).send(`Fetch failed: ${error.message}`);
    }
});

// Mock internal endpoint for SSRF testing if running locally
app.get('/latest/meta-data/iam/security-credentials/', (req, res) => {
    res.send("admin\n");
});
app.get('/latest/meta-data/iam/security-credentials/admin', (req, res) => {
    res.json({
        "Code" : "Success",
        "LastUpdated" : "2026-05-22T00:00:00Z",
        "Type" : "AWS-HMAC",
        "AccessKeyId" : "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey" : "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Token" : "token...",
        "Expiration" : "2026-05-23T00:00:00Z"
    });
});

// Blind SSRF (3 different query parameters)
// Target: GET /api/blind-ssrf?url=http://attacker.com OR ?src=http://attacker.com OR ?link=http://attacker.com
app.get('/api/blind-ssrf', (req, res) => {
    // Extract the payload from either url, src, or link
    const targetUrl = req.query.url || req.query.src || req.query.link;
    
    // Always return a generic success message quickly (blind behavior)
    res.status(200).send("Request logged and processed in the background.");
    
    if (targetUrl) {
        // Asynchronously fetch the target without returning the result to the client
        // This simulates a background worker or async logging that performs an HTTP request
        axios.get(targetUrl, { timeout: 3000 }).catch(() => {
            // Silently ignore errors (it's blind)
        });
    }
});


// --- 6. XML External Entity (XXE) / XInclude Injection ---

// XInclude Injection
// Target: POST XML with XInclude payload to read /etc/passwd
app.post('/api/transactions/import', (req, res) => {
    const xmlData = req.body; // Expecting raw text/xml body
    
    if (!xmlData || typeof xmlData !== 'string') {
        return res.status(400).send('Expected XML body');
    }

    try {
        let parsedData = xmlData;
        // Simulate XInclude/XXE vulnerability manually since native XML parsers fail to build on Hostinger
        const xincludeRegex = /<xi:include\s+parse="text"\s+href="(file:\/\/[^"]+)"\s*\/>/gi;
        let match;
        while ((match = xincludeRegex.exec(xmlData)) !== null) {
            const fileUrl = match[1];
            const filePath = fileUrl.replace('file://', '');
            try {
                const fileContent = fs.readFileSync(filePath, 'utf8');
                parsedData = parsedData.replace(match[0], fileContent);
            } catch (e) {
                // Ignore file read errors
            }
        }

        res.status(200).send(`XML parsed successfully. Content: ${parsedData}`);
    } catch (err) {
        res.status(500).send(`XML Parsing Error: ${err.message}`);
    }
});

// --- 7. Open Redirect ---

// Simple Param Redirect
// Target: POST /api/login with body {"redirect_to": "https://example.com"}
app.post('/api/login', (req, res) => {
    const redirectTo = req.body.redirect_to;
    
    if (redirectTo && redirectTo !== '/home') {
        // Vulnerable: Unvalidated redirect to external absolute URL
        return res.redirect(302, redirectTo);
    }
    
    const token = jwt.sign({ id: 2, username: 'john', role: 'user' }, JWT_SECRET, { algorithm: 'HS256' });
    res.json({ token });
});

// --- 8. CRLF Injection ---

// CRLF Injection
// Target: /api/set-preference?lang=%0d%0aSet-Cookie:crlfinjection=crlfinjection
app.get('/api/set-preference', (req, res) => {
    const lang = req.query.lang || 'en';
    
    // Vulnerable: Taking user input and placing it directly into a header value
    // Note: Modern Node.js core 'http' module usually blocks CRLF in headers, 
    // but we can simulate the vulnerability for the sake of the tool's test
    // by manually constructing the raw HTTP response socket write, or 
    // depending on the exact Node version, `res.setHeader` might throw.
    // To ensure the test tool catches it, we'll write raw HTTP to the socket.
    
    const socket = req.socket;
    socket.write(
        `HTTP/1.1 200 OK\r\n` +
        `Content-Type: text/plain\r\n` +
        `Set-Cookie: language=${lang}\r\n` + // Vulnerable reflection
        `\r\n` +
        `Preference set.`
    );
    socket.end();
});


// --- 9. Document Center (LFI/RFI) ---

// Secure Document Download
app.get('/api/v2/documents', (req, res) => {
    res.send("Secure document content");
});

// Vulnerable Document Download (LFI/RFI)
app.get('/api/documents/download', (req, res) => {
    const file = req.query.file || '';
    
    // Remote File Inclusion (RFI) Mock
    if (file.startsWith('http://') || file.startsWith('https://')) {
        if (file.includes('example.com')) {
            return res.send("<!doctype html><html><head><title>Example Domain</title></head><body><h1>Example Domain</h1></body></html>");
        }
        return res.send(`Successfully included remote file from: ${file}`);
    }
    
    // Local File Inclusion (LFI) Mock
    if (file.includes('etc/passwd')) {
        return res.send("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin");
    } else if (file.toLowerCase().includes('win.ini')) {
        return res.send("; for 16-bit app support\n[fonts]\n[extensions]");
    }
    
    if (file === '') {
        return res.status(400).send("Error: Please specify a document filename.");
    }
    
    // Realistic benign response
    res.send(`%PDF-1.4\n%...\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n... \n\n(Simulated PDF Content for: ${file})`);
});

// --- NEW ENDPOINTS FOR RECENTLY ADDED RULES ---

// 1. HTTP Method Override Bypass
app.all('/api/admin/settings', (req, res) => {
    // If it's literally a PUT request, or if it uses the override header
    const methodOverride = req.get('X-HTTP-Method-Override') || req.get('X-Method-Override') || req.get('X-Forwarded-Method') || req.get('X-HTTP-Method');
    if (req.method === 'PUT' || methodOverride === 'PUT') {
        return res.status(200).json({ success: true, message: "Settings updated successfully", role: "admin" });
    }
    return res.status(403).json({ error: "Forbidden: Only PUT method is allowed for this administrative endpoint." });
});

// 2. Host Header Poisoning (Open Redirect / Routing Bypass)
app.get('/api/password-reset', (req, res) => {
    // Uses the injected Host or X-Forwarded-Host to generate absolute reset URL
    const host = req.get('X-Forwarded-Host') || req.get('Host') || 'localhost:3000';
    const resetUrl = `http://${host}/reset-token-12345`;
    return res.redirect(302, resetUrl);
});

// 3. Directory Listing Enabled (Recursive Traversal)
app.get('/api/docs/', (req, res) => {
    // Simulates an exposed directory index
    const html = `
        <html>
            <head><title>Index of /api/docs/</title></head>
            <body>
                <h1>Index of /api/docs/</h1>
                <hr>
                <a href="../">Parent Directory</a><br>
                <a href=".env">.env</a><br>
                <a href="architecture.md">architecture.md</a><br>
                <a href="database.sqlite">database.sqlite</a><br>
                <hr>
            </body>
        </html>
    `;
    res.send(html);
});

// 4. Referer-Based Open Redirection
app.get('/api/auth/callback', (req, res) => {
    // Blindly redirects the user back to the Referer after auth
    const referer = req.get('Referer');
    if (referer) {
        return res.redirect(302, referer);
    }
    return res.send("Authenticated successfully.");
});

// 5. Server-Side Template Injection (SSTI)
app.all('/api/template/render-doc', (req, res) => {
    const tmpl = req.query.tmpl || req.body.tmpl || '';
    // Simulates the evaluation of our exact payload
    if (tmpl.includes('{1337*1337}') || tmpl.includes('<%= 1337*1337 %>')) {
        return res.send(`Rendered Document: 1787569`);
    }
    return res.send(`Rendered Document: ${tmpl}`);
});


app.listen(port, () => {
    console.log(`Vulnerable Banking API listening on port ${port}`);
    console.log(`Loaded endpoints for testing SQLi, Command Injection, Mass Assignment, JWT, XSS, SSRF, XXE, CORS, Open Redirect, CRLF, NoSQLi, CSTI, LFI, Server Disclosure, Sensitive Data Exposure.`);
});
