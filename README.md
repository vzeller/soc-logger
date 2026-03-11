# soc-logger — AnythingLLM Agent Skill for Security Onion

An [AnythingLLM](https://anythingllm.com) custom agent skill that queries **Security Onion** logs stored in OpenSearch. Gives your local LLM direct, structured access to firewall logs, IDS alerts, authentication events, DNS queries, and network metadata — enabling natural-language threat hunting, log correlation, and security analysis without leaving the chat interface.

## Features

- **Dataset-aware routing** — queries are automatically routed to the correct OpenSearch index based on the dataset name (e.g., `pfsense.log` → `.ds-logs-pfsense.log-default-*`), avoiding slow full-cluster scans
- **Multi-schema extraction** — correctly handles three different Security Onion document schemas: standard ECS, the nested `event_data{}` schema used in `detections.alerts`, and the rule definition store schema
- **Fully configurable** — all connection details (host, port, API key, TLS verification) and dataset descriptions are set via the AnythingLLM settings UI — no credentials in code
- **LLM context injection** — every query result includes configurable dataset descriptions, architecture notes, and known-benign traffic patterns to prevent false-positive analysis
- **Rule store awareness** — explicitly labels `so-detectionhistory` and `so-detection` documents as rule definitions (not live alerts) to prevent the LLM from fabricating incidents

## Supported Data Sources

| `event.dataset` value | What it contains |
|---|---|
| `pfsense.log` | OPNsense / pfSense firewall pass/block decisions with real source and destination IPs |
| `detections.alerts` | Live triggered IDS/Sigma alerts; event data nested under `event_data{}` |
| `system.auth` | SSH, PAM, and sudo authentication events |
| `system.syslog` | Linux OS syslog from Security Onion nodes |
| `soc.detections` | Detection rule execution status and errors |
| `zeek.notice` | Zeek network anomaly notices |
| `zeek.conn` | Zeek connection summaries |
| `kratos.access` | Ory Kratos identity service HTTP access logs |
| `sigma.alert` | Sigma rule alerts via ElastAlert |
| `so-detectionhistory` | Suricata/Sigma **rule definitions** (not live alerts — no IPs) |
| `so-detection` | Current Suricata/Sigma **rule definitions** (not live alerts — no IPs) |

> **Note:** Your Security Onion instance may have different or additional datasets. Run the discovery command in the [Configuration](#4-discover-your-actual-dataset-names) section to see exactly what is in your deployment.

## Requirements

- [AnythingLLM](https://anythingllm.com) v1.6.0 or later (custom agent skills support)
- Security Onion 2.4+ with OpenSearch enabled
- An OpenSearch API key with read access to your log indices

## Installation

### 1. Copy the skill into AnythingLLM

**Docker deployment:**
```bash
# Clone this repository
git clone https://github.com/vzeller/soc-logger.git

# Copy into the AnythingLLM skills directory
docker cp soc-logger/ <your-anythingllm-container>:/app/server/storage/plugins/agent-skills/soc-logger/

# Restart AnythingLLM to load the skill
docker restart <your-anythingllm-container>
```

**Desktop / bare-metal deployment:**
```bash
# Copy to the AnythingLLM storage directory
cp -r soc-logger/ ~/anythingllm/storage/plugins/agent-skills/soc-logger/
```

### 2. Generate an OpenSearch API key

In Security Onion Console, go to **Administration → API Keys**, or run:
```bash
curl -sk -X POST \
  -H "Content-Type: application/json" \
  -u "admin:yourpassword" \
  "https://<your-so-host>:<opensearch-port>/_security/api_key" \
  -d '{
    "name": "anythingllm-soc-logger",
    "role_descriptors": {
      "reader": {
        "indices": [{"names": ["*"], "privileges": ["read", "view_index_metadata"]}]
      }
    }
  }'
```

The response contains an `encoded` field — that is your base64 API key. Copy it for the next step.

### 3. Configure the skill in AnythingLLM

1. Open AnythingLLM → **Settings → Agent Skills**
2. Find **Security Onion Log Query** and click **Configure**
3. Fill in the settings:

| Setting | Description | Example |
|---|---|---|
| `OPENSEARCH_HOST` | IP or hostname of your Security Onion node | `<your-so-host>` |
| `OPENSEARCH_PORT` | OpenSearch REST API port | `9200` |
| `OPENSEARCH_API_KEY` | Base64-encoded API key from step 2 | `<your-api-key>` |
| `VERIFY_TLS` | `true` for trusted certs, `false` for self-signed | `false` |
| `DATASET_CONTEXT` | Pipe-separated `dataset=description` pairs | see below |
| `ARCHITECTURE_NOTES` | Free-text notes about your SO setup | see below |
| `KNOWN_BENIGN` | Known-benign traffic patterns in your network | see below |

### 4. Discover your actual dataset names

Every Security Onion deployment has different data sources depending on what sensors and integrations are configured. Run this to see exactly what datasets your instance has and how many documents each contains:

```bash
curl -sk \
  -H "Authorization: ApiKey <your-api-key>" \
  -H "Content-Type: application/json" \
  "https://<your-so-host>:<opensearch-port>/_search" -d '{
    "size": 0,
    "aggs": {
      "datasets": { "terms": { "field": "event.dataset", "size": 50 } },
      "modules":  { "terms": { "field": "event.module",  "size": 50 } }
    }
  }' | python3 -m json.tool
```

Use the `key` values from the `datasets` aggregation output to populate your `DATASET_CONTEXT` setting.

### 5. Enable the skill in a workspace

In AnythingLLM, open your workspace → **Agent Configuration** → enable **Security Onion Log Query**.

## Usage

In any AnythingLLM chat using the `@agent` prefix:

```
@agent Show me the last 20 firewall logs from pfsense.log
@agent Search all datasets for IP <an-ip-of-interest> (limit 50)
@agent Are there any SSH login failures in detections.alerts?
@agent Check pfsense.log for blocked traffic on port 443
@agent Search system.auth for failed authentication attempts
@agent Show me the latest IDS alerts from detections.alerts
@agent What datasets are available and what do they contain?
```

## Testing

```bash
# Set your connection details as environment variables
export OPENSEARCH_HOST="<your-so-host>"
export OPENSEARCH_PORT="9200"
export OPENSEARCH_API_KEY="<your-api-key>"

# Run the full automated test suite
node test.js

# Run a single manual test: query, limit, dataset
node test.js "failed" 10 "detections.alerts"
node test.js "*" 20 "pfsense.log"
node test.js "<an-ip-of-interest>" 50 "*"
```

## Customising for your environment

### Adding new dataset → index mappings

If your Security Onion instance has data sources not listed in the default map (e.g., Elastic Agent endpoint data, custom Logstash pipelines, Strelka file analysis), add them to the `datasetIndexMap` object in `handler.js`:

```javascript
"my.custom.dataset": ".ds-logs-my.custom.dataset-default-*",
```

### Configuring dataset descriptions for your LLM

The `DATASET_CONTEXT` setting is injected verbatim into every query result. Tailor it to describe your environment:

```
pfsense.log=OPNsense/pfSense firewall (WAN and LAN interfaces) |
detections.alerts=Suricata IDS alerts and Sigma rule hits |
system.auth=SSH logins to Security Onion nodes |
zeek.notice=Zeek network anomalies from span port
```

### Suppressing known-benign traffic

Use `KNOWN_BENIGN` to prevent the LLM from raising false alarms on traffic that is normal in your environment:

```
port 6881=Fileserver  (expected on this host) |
10.0.0.1=router/gateway (normal) |
fe80::/10=IPv6 link-local neighbour discovery (normal)
```

## Architecture Notes

Security Onion uses three distinct document schemas in OpenSearch:

**1. Standard ECS** (`pfsense.log`, `system.auth`, `zeek.*`): All fields at the top level. `source.ip`, `destination.ip`, `message`, `event.dataset` are directly accessible.

**2. `detections.alerts` schema**: The rule metadata (`rule.name`, `sigma_level`) is at the top level, but all event data (source IP, auth method, process name, etc.) is nested under `event_data{}`. This skill handles both levels transparently.

**3. Rule definition store** (`so-detectionhistory`, `so-detection`): These indices store Suricata and Sigma rule text, not network events. They have **no `source.ip` or `destination.ip` fields**. Searching them for "Metasploit" returns the rule *designed to detect* Metasploit — not evidence that Metasploit was used on your network. This skill explicitly labels these documents to prevent LLM hallucination.

## License

MIT — see [LICENSE](LICENSE)

## Contributing

Pull requests welcome. If you have a Security Onion setup with additional data sources (Elastic Agent endpoint data, Strelka file analysis, Suricata EVE JSON, etc.) and want to contribute index mappings and field extraction for those schemas, please open an issue or PR.
