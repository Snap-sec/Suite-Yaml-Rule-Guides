import { vulnerableLibraryScan } from './vulnerable-library-scan.js';
// import { cookieSecurityScan } from './cookie-security-scan.js';

/**
 * Mock objects to simulate the environment provided by ScannerOrchestrator
 */
const mockRequest = {
    method: "GET",
    url: "https://example.com/assets/main.js",
    headers: {
        "User-Agent": "Mozilla/5.0 WAS-Scanner/1.0"
    },
    params: {},
    body: null
};

const mockResponse = {
    status_code: 200,
    status_text: "OK",
    headers: {
        "content-type": "application/javascript",
        "server": "nginx/1.18.0",
        "set-cookie": "session=abc; Path=/;" // Missing HttpOnly/Secure
    },
    body: "/*! jQuery v1.12.4 */", // Example vulnerable library
    size: 1024,
    time: 120
};

const mockMetadata = {
    project: { _id: "650af1...", orgId: "org_123" },
    scan: { _id: "650af2...", name: "Test Scan" }
};

// Mock Redis with console logging for visibility
const mockRedis = {
    data: new Map(),
    get: async (key) => {
        console.log(`[REDIS] GET ${key}`);
        return mockRedis.data.get(key);
    },
    set: async (key, val) => {
        console.log(`[REDIS] SET ${key} = ${val}`);
        mockRedis.data.set(key, val);
        return "OK";
    },
    exists: async (key) => {
        console.log(`[REDIS] EXISTS ${key}`);
        return mockRedis.data.has(key);
    },
    incr: async (key) => {
        const val = (parseInt(mockRedis.data.get(key)) || 0) + 1;
        mockRedis.data.set(key, val.toString());
        return val;
    }
};

async function runTest() {
    console.log("-----------------------------------------");
    console.log("STARTING SCANNER TEST");
    console.log("-----------------------------------------");

    try {
        // Change this to the scanner you want to test
        const scannerToTest = vulnerableLibraryScan;
        
        const result = await scannerToTest({
            request: mockRequest,
            response: mockResponse,
            metadata: mockMetadata,
            redis: mockRedis
        });

        console.log("\n[RESULT] Vulnerabilities Found:", result.vuln_list.length);
        console.log(JSON.stringify(result, null, 2));

    } catch (err) {
        console.error("\n[ERROR] Scanner failed during execution:", err);
    }

    console.log("\n-----------------------------------------");
    console.log("TEST COMPLETED");
    console.log("-----------------------------------------");
}

runTest();
