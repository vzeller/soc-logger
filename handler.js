/**
 * Security Onion Log Query — AnythingLLM Agent Skill
 * https://github.com/vzeller/soc-logger
 *
 * Queries Security Onion logs stored in OpenSearch/Elasticsearch.
 * All connection details and dataset descriptions are configured via
 * the AnythingLLM plugin settings UI (setup_args in plugin.json).
 *
 * Supports three Security Onion document schemas:
 *   1. Standard ECS  — pfsense.log, system.auth, zeek (fields at top level)
 *   2. detections.alerts — real alert data nested under event_data{}
 *   3. Rule definition store — so-detectionhistory, so-detection (no IPs)
 */

module.exports.runtime = {

  handler: async function ({ query, limit = 5, dataset = "*" }) {
    const callerId = `${this.config.name} v${this.config.version}`;

    // -----------------------------------------------------------------------
    // READ CONFIGURATION FROM PLUGIN SETTINGS (setup_args)
    // -----------------------------------------------------------------------
    const host       = (this.runtimeArgs["OPENSEARCH_HOST"]    || "").trim();
    const port       = (this.runtimeArgs["OPENSEARCH_PORT"]    || "").trim();
    const apiKey     = (this.runtimeArgs["OPENSEARCH_API_KEY"] || "").trim();
    const verifyTls  = (this.runtimeArgs["VERIFY_TLS"]         || "false").trim().toLowerCase() === "true";
    const dsContext  = (this.runtimeArgs["DATASET_CONTEXT"]    || "").trim();
    const archNotes  = (this.runtimeArgs["ARCHITECTURE_NOTES"] || "").trim();
    const knownBenign = (this.runtimeArgs["KNOWN_BENIGN"]      || "").trim();

    if (!host) return "Error: OPENSEARCH_HOST is not configured. Please set it in the skill settings.";
    if (!port) return "Error: OPENSEARCH_PORT is not configured. Please set it in the skill settings (default: 9200).";
    if (!apiKey) return "Error: OPENSEARCH_API_KEY is not configured. Please set it in the skill settings.";

    // Disable TLS verification for self-signed certs (common in Security Onion)
    if (!verifyTls) process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

    const baseUrl = `https://${host}:${port}`;

    this.introspect(`${callerId}: querying dataset="${dataset || "*"}" query="${query || "*"}" limit=${limit}`);

    // -----------------------------------------------------------------------
    // DATASET → INDEX ROUTING
    // Maps known Security Onion event.dataset values to their real index patterns.
    // This avoids slow wildcard scans across all 100+ indices.
    // Extend this map if your Security Onion instance has additional data sources.
    // -----------------------------------------------------------------------
    const datasetIndexMap = {
      // OPNsense / pfSense firewall logs — real traffic with source/dest IPs
      "pfsense.log":                  ".ds-logs-pfsense.log-default-*",
      "pfsense":                      ".ds-logs-pfsense.log-default-*",

      // Security Onion internal service logs
      "soc.server":                   ".ds-logs-soc-so-*",
      "soc.sensoroni":                ".ds-logs-soc-so-*",
      "soc.detections":               ".ds-logs-soc-so-*",
      "soc.salt_relay":               ".ds-logs-soc-so-*",
      "soc.auth_sync":                ".ds-logs-soc-so-*",
      "soc":                          ".ds-logs-soc-so-*",

      // Live triggered IDS/Sigma alerts — real alert data nested under event_data{}
      "detections.alerts":            ".ds-logs-detections.alerts-so-*",
      "detections":                   ".ds-logs-detections.alerts-so-*",
      "alerts":                       ".ds-logs-detections.alerts-so-*",

      // Ory Kratos identity service
      "kratos.access":                ".ds-logs-kratos-so-*",
      "kratos.audit":                 ".ds-logs-kratos-so-*",
      "kratos.application":           ".ds-logs-kratos-so-*",
      "kratos":                       ".ds-logs-kratos-so-*",

      // Zeek network metadata
      "zeek.notice":                  ".ds-logs-zeek-so-*",
      "zeek.conn":                    ".ds-logs-zeek-so-*",
      "zeek.dns":                     ".ds-logs-zeek-so-*",
      "zeek.http":                    ".ds-logs-zeek-so-*",
      "zeek.ssl":                     ".ds-logs-zeek-so-*",
      "zeek":                         ".ds-logs-zeek-so-*",

      // Linux system logs
      "system.syslog":                ".ds-logs-system.syslog-default-*",
      "system.auth":                  ".ds-logs-system.auth-default-*",
      "syslog":                       ".ds-logs-system.syslog-default-*",
      "auth":                         ".ds-logs-system.auth-default-*",

      // Infrastructure services
      "redis.log":                    ".ds-logs-redis.log-default-*",
      "redis":                        ".ds-logs-redis.log-default-*",
      "elasticsearch.server":         ".ds-logs-elasticsearch.server-default-*",
      "elasticsearch":                ".ds-logs-elasticsearch.server-default-*",

      // Elastic Agent
      "elastic_agent.fleet_server":   ".ds-logs-elastic_agent.fleet_server-default-*",
      "elastic_agent.filebeat":       ".ds-logs-elastic_agent.filebeat-default-*",
      "elastic_agent.osquerybeat":    ".ds-logs-elastic_agent.osquerybeat-default-*",
      "elastic_agent.metricbeat":     ".ds-logs-elastic_agent.metricbeat-default-*",
      "elastic_agent":                ".ds-logs-elastic_agent-default-*",

      // Sigma/ElastAlert
      "sigma.alert":                  "elastalert",
      "sigma":                        "elastalert",

      // RULE DEFINITION STORES — NOT live alert logs.
      // These contain Suricata/Sigma rule text with NO source/destination IPs.
      // Do not use for incident investigation.
      "so-detection":                 "so-detection",
      "so-detectionhistory":          "so-detectionhistory",
      "elastalert_error":             "elastalert_error",
      "elastalert_status":            "elastalert_status",
    };

    // Resolve index target and optional dataset filter
    const ds = (dataset && dataset.trim() !== "" && dataset !== "*") ? dataset.trim() : null;
    let indexTarget = "*";
    let datasetFilter = null;

    if (ds) {
      if (datasetIndexMap[ds]) {
        indexTarget = datasetIndexMap[ds];
        // Only apply event.dataset filter for dotted names that aren't already
        // uniquely identified by their index pattern
        if (ds.includes(".") && !["pfsense.log", "redis.log", "elasticsearch.server"].includes(ds)) {
          datasetFilter = ds;
        }
      } else {
        // Unknown dataset — fall back to wildcard index with a filter
        indexTarget = "*";
        datasetFilter = ds;
      }
    }

    const url = `${baseUrl}/${indexTarget}/_search`;
    const searchQuery = (query && query.trim() !== "" && query !== "*") ? query : "*";
    let finalQueryString = searchQuery;
    if (datasetFilter) {
      finalQueryString = `(${searchQuery}) AND (event.dataset:"${datasetFilter}" OR event.module:"${datasetFilter}")`;
    }

    const searchSize = Math.min(Math.max(parseInt(limit) || 5, 1), 100);

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Authorization": `ApiKey ${apiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          query: { query_string: { query: finalQueryString } },
          size: searchSize,
          sort: [{ "@timestamp": { order: "desc" } }]
        })
      });

      if (!response.ok) {
        const errText = await response.text();
        return `OpenSearch returned HTTP ${response.status}: ${errText.substring(0, 300)}`;
      }

      const data = await response.json();

      if (!data.hits || data.hits.hits.length === 0) {
        return `No logs found for query: "${searchQuery}" in dataset: "${dataset || "*"}"`;
      }

      const formattedLogs = data.hits.hits.map(hit => {
        const s   = hit._source;
        const idx = hit._index || "unknown-index";

        // -----------------------------------------------------------------------
        // SCHEMA DETECTION
        // Three document schemas exist in Security Onion:
        //
        // 1. Standard ECS (pfsense, system.auth, zeek): fields at top level
        // 2. detections.alerts: rule info at top level, event data under event_data{}
        // 3. Rule definition store (so-detectionhistory): so_detection.content,
        //    no IPs — explicitly labelled to prevent LLM confusion
        // -----------------------------------------------------------------------
        const isDetectionAlert = idx.includes("detections.alerts");
        const isRuleStore      = idx.startsWith("so-detection");
        const ed               = s.event_data || {};  // nested event data in detections.alerts

        const eventDataset = s.event?.dataset || s.event?.module || ed.event?.dataset ||
          idx.replace(/^\.ds-logs-/, "").replace(/-so-.*$/, "").replace(/-default-.*$/, "") ||
          "unknown";

        const time = s["@timestamp"] || "N/A";

        // --- Network fields: ECS top-level first, then detections.alerts nested ---
        const srcIp    = s.source?.ip    || ed.source?.ip    || s["source.ip"]    || "";
        const srcPort  = s.source?.port  || ed.source?.port  || s["source.port"]  || "";
        const destIp   = s.destination?.ip   || ed.destination?.ip   || s["destination.ip"]   || "";
        const destPort = s.destination?.port || ed.destination?.port || s["destination.port"] || "";
        const protocol = s.network?.protocol || ed.network?.protocol || s.network?.transport  || "";

        const src = srcPort  ? `${srcIp}:${srcPort}`   : srcIp;
        const dst = destPort ? `${destIp}:${destPort}` : destIp;
        const networkFlow = (src || dst) ? `${src} -> ${dst}${protocol ? " (" + protocol + ")" : ""}` : "";

        // --- Host info (fallback when src/dst IPs are absent) ---
        const hostIp = Array.isArray(s.host?.ip) ?
          s.host.ip.filter(ip => !ip.startsWith("127.") && !ip.startsWith("::1")).join(",") :
          Array.isArray(ed.host?.ip) ?
          ed.host.ip.filter(ip => !ip.startsWith("127.") && !ip.startsWith("::1")).join(",") :
          (s.host?.ip || ed.host?.ip || "");
        const hostName = s.host?.name || ed.host?.name || ed.agent?.name || "";
        const hostInfo = (hostIp || hostName) ?
          `Host: ${hostName || ""}${hostIp ? "[" + hostIp + "]" : ""}` : "";

        // --- Detection / alert fields ---
        const det      = s.so_detection || {};
        const ruleName = s.rule?.name || s["rule.name"] || det.title || "";
        const rawSev   = s.sigma_level || det.severity || s.event?.severity_name ||
                         ed.event?.severity_name || s["event.severity_name"] || "";
        const severity = rawSev ? `[${rawSev.toUpperCase()}]` : "";

        // --- Auth fields (system.auth and detections.alerts SSH failures) ---
        const sshEvent  = s.system?.auth?.ssh?.event  || ed.system?.auth?.ssh?.event  || "";
        const sshMethod = s.system?.auth?.ssh?.method || ed.system?.auth?.ssh?.method || "";
        const authUser  = s.user?.name || ed.user?.name ||
                          (Array.isArray(s.related?.user)  ? s.related.user[0]  : "") ||
                          (Array.isArray(ed.related?.user) ? ed.related.user[0] : "") || "";
        const authResult = s.event?.outcome || ed.event?.outcome || sshEvent || "";
        const authInfo  = (authUser || sshEvent) ?
          `User: ${authUser || "?"}${sshMethod ? " via " + sshMethod : ""}${authResult ? " [" + authResult + "]" : ""}` : "";

        // --- HTTP fields ---
        const httpMethod = s.http?.request?.method || ed.http?.request?.method || "";
        const httpUri    = s.url?.path || s.url?.original || ed.url?.path || ed.url?.original || "";
        const httpStatus = s.http?.response?.status_code || ed.http?.response?.status_code || "";
        const httpInfo   = (httpMethod || httpUri) ?
          `HTTP ${httpMethod} ${httpUri}${httpStatus ? " " + httpStatus : ""}` : "";

        // --- DNS fields ---
        const dnsName = s.dns?.question?.name || ed.dns?.question?.name || "";
        const dnsType = s.dns?.question?.type || ed.dns?.question?.type || "";
        const dnsInfo = dnsName ? `DNS ${dnsType ? dnsType + " " : ""}Query: ${dnsName}` : "";

        // --- General message ---
        const message = s.message || ed.message ||
          (isRuleStore ? `[RULE DEFINITION — not a live alert] ${det.title || ""}` : "");

        // Build output line
        let parts = [`[${time}]`, `[Index: ${idx}]`, `[Dataset: ${eventDataset}]`];
        if (severity)    parts.push(severity);
        if (ruleName)    parts.push(`Alert: ${ruleName} |`);
        if (networkFlow) parts.push(`Flow: ${networkFlow} |`);
        if (hostInfo)    parts.push(`${hostInfo} |`);
        if (httpInfo)    parts.push(`${httpInfo} |`);
        if (dnsInfo)     parts.push(`${dnsInfo} |`);
        if (authInfo)    parts.push(`${authInfo} |`);
        if (message && message !== ruleName) {
          parts.push(`Msg: ${message.substring(0, 250)}`);
        }

        return parts.join(" ").replace(/\|\s*$/, "").trim();
      });

      const uniqueDatasets = [...new Set(
        data.hits.hits.map(h =>
          h._source.event?.dataset || h._source.event?.module ||
          h._index.replace(/^\.ds-logs-/, "").replace(/-so-.*$/, "").replace(/-default-.*$/, "") ||
          "unknown"
        )
      )];

      const totalHits = data.hits.total?.value ?? formattedLogs.length;
      const relation  = data.hits.total?.relation === "gte" ? "+" : "";

      // Build context footer from configured settings
      let contextLines = [];
      if (dsContext)    contextLines.push(`DATASETS: ${dsContext}`);
      if (archNotes)    contextLines.push(`ARCHITECTURE: ${archNotes}`);
      if (knownBenign)  contextLines.push(`KNOWN BENIGN TRAFFIC: ${knownBenign}`);

      let result  = `Retrieved ${formattedLogs.length} of ${totalHits}${relation} matching logs.\n`;
      result += `Queried index: ${indexTarget} | Search: "${finalQueryString}"\n`;
      result += `Datasets in results: ${uniqueDatasets.join(", ")}\n`;
      if (contextLines.length > 0) result += contextLines.join("\n") + "\n";
      result += "\n" + formattedLogs.join("\n");

      return result;

    } catch (e) {
      this.logger(`${callerId} error: ${e.message}`);
      return `Error querying OpenSearch at ${baseUrl}: ${e.message}`;
    }
  }
};
