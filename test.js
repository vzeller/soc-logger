/**
 * test.js — CLI test runner for the soc-logger AnythingLLM agent skill
 *
 * Usage (manual):
 *   node test.js [query] [limit] [dataset]
 *
 * Usage (automated suite):
 *   node test.js
 *
 * Configuration via environment variables:
 *   OPENSEARCH_HOST      OpenSearch host IP/hostname (required)
 *   OPENSEARCH_PORT      OpenSearch port (required, typically 9200)
 *   OPENSEARCH_API_KEY   Base64 API key (required)
 *   VERIFY_TLS           'true' or 'false' (default: false)
 *   DATASET_CONTEXT      Pipe-separated dataset descriptions
 *   ARCHITECTURE_NOTES   Architecture notes for LLM context
 *   KNOWN_BENIGN         Known-benign traffic patterns
 *
 * Example:
 *   OPENSEARCH_HOST=<your-so-host> OPENSEARCH_PORT=9200 OPENSEARCH_API_KEY="<your-api-key>" node test.js "*" 10 "pfsense.log"
 */

const { runtime } = require("./handler.js");

// -----------------------------------------------------------------------
// Read configuration from environment variables
// -----------------------------------------------------------------------
const config = {
  OPENSEARCH_HOST:    process.env.OPENSEARCH_HOST     || "",
  OPENSEARCH_PORT:    process.env.OPENSEARCH_PORT     || "",
  OPENSEARCH_API_KEY: process.env.OPENSEARCH_API_KEY  || "",
  VERIFY_TLS:         process.env.VERIFY_TLS          || "false",
  DATASET_CONTEXT:    process.env.DATASET_CONTEXT     || "",
  ARCHITECTURE_NOTES: process.env.ARCHITECTURE_NOTES  || "",
  KNOWN_BENIGN:       process.env.KNOWN_BENIGN        || "",
};

if (!config.OPENSEARCH_HOST || !config.OPENSEARCH_PORT || !config.OPENSEARCH_API_KEY) {
  console.error("\nERROR: OPENSEARCH_HOST, OPENSEARCH_PORT, and OPENSEARCH_API_KEY environment variables are required.");
  console.error("Example:");
  console.error('  OPENSEARCH_HOST=<your-so-host> OPENSEARCH_PORT=9200 OPENSEARCH_API_KEY="<your-api-key>" node test.js\n');
  process.exit(1);
}

// -----------------------------------------------------------------------
// Mock the AnythingLLM runtime context (this.runtimeArgs, this.introspect, etc.)
// -----------------------------------------------------------------------
const mockContext = {
  runtimeArgs: config,
  config: { name: "Security Onion Log Query", version: "3.0.0", hubId: "soc-logger" },
  introspect: (msg) => console.log(`  [introspect] ${msg}`),
  logger: (msg) => console.log(`  [logger] ${msg}`),
};

async function runTest(label, query, limit, dataset) {
  console.log(`\n${"=".repeat(70)}`);
  console.log(`TEST: ${label}`);
  console.log(`  query="${query}"  limit=${limit}  dataset="${dataset}"`);
  console.log("=".repeat(70));

  try {
    const result = await runtime.handler.call(mockContext, { query, limit, dataset });
    console.log("\n--- RESULT ---");
    console.log(result);
  } catch (e) {
    console.error(`\n--- ERROR ---\n${e.message}`);
  }
}

async function main() {
  // If CLI arguments are provided, run a single manual test
  const [,, cliQuery, cliLimit, cliDataset] = process.argv;
  if (cliQuery !== undefined) {
    await runTest(
      "CLI Test",
      cliQuery,
      parseInt(cliLimit) || 5,
      cliDataset || "*"
    );
    return;
  }

  // -----------------------------------------------------------------------
  // Automated test suite — covers all major datasets and query types.
  // The cross-dataset IP test uses a placeholder — replace with a real
  // internal IP from your environment to get meaningful results.
  // -----------------------------------------------------------------------
  console.log(`\nRunning automated test suite against ${config.OPENSEARCH_HOST}:${config.OPENSEARCH_PORT}`);

  const tests = [
    // Basic connectivity
    ["Wildcard: all datasets, 5 results",                    "*",       5,  "*"],

    // Firewall
    ["pfsense.log: recent firewall logs",                    "*",       10, "pfsense.log"],
    ["pfsense.log: blocked traffic",                         "block",   10, "pfsense.log"],
    ["pfsense.log: passed traffic",                          "pass",    10, "pfsense.log"],

    // Live alerts
    ["detections.alerts: all recent alerts",                 "*",       20, "detections.alerts"],
    ["detections.alerts: failed events",                     "failed",  10, "detections.alerts"],

    // Auth
    ["system.auth: recent auth events",                      "*",       10, "system.auth"],
    ["system.auth: failed logins",                           "failed",  10, "system.auth"],

    // System
    ["system.syslog: recent syslog",                         "*",       10, "system.syslog"],

    // Zeek
    ["zeek.notice: network anomalies",                       "*",       10, "zeek.notice"],

    // SOC internal
    ["soc.detections: detection rule status",                "*",       10, "soc.detections"],

    // Rule stores (should return rule definitions, not live alerts)
    ["so-detectionhistory: CRITICAL rules (rule defs only)", "CRITICAL", 5, "so-detectionhistory"],
    ["so-detection: sample rules (rule defs only)",          "*",        5, "so-detection"],

    // Cross-dataset IP search — replace the placeholder with a real IP in your environment
    ["Cross-dataset: search all for an IP (replace placeholder)", "10.0.0.1", 20, "*"],

    // Kratos identity service
    ["kratos.access: recent identity service logs",          "*",        5, "kratos.access"],

    // Unknown dataset (should fall back gracefully)
    ["Unknown dataset: graceful fallback test",              "*",        5, "suricata"],
  ];

  for (const [label, query, limit, dataset] of tests) {
    await runTest(label, query, limit, dataset);
    // Small delay to avoid overwhelming OpenSearch
    await new Promise(r => setTimeout(r, 300));
  }

  console.log(`\n${"=".repeat(70)}`);
  console.log("Test suite complete.");
}

main().catch(console.error);
