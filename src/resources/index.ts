/**
 * MCP Resources for WAF Context
 *
 * Resources provide static or dynamic context that AI assistants can reference
 * during conversations. They're useful for:
 * - Documentation and reference material
 * - Configuration templates
 * - Best practices guides
 *
 * Resources are identified by URIs and can be requested by the AI when needed.
 *
 * Learn more: https://spec.modelcontextprotocol.io/specification/server/resources/
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export function registerResources(server: McpServer) {
	/**
	 * WAF Expression Syntax Reference
	 *
	 * Provides comprehensive documentation on Cloudflare's WAF expression
	 * language, enabling the AI to construct valid rule expressions.
	 */
	server.resource(
		"waf://expression-syntax",
		"Cloudflare WAF expression syntax reference for building firewall rules",
		async () => ({
			contents: [
				{
					uri: "waf://expression-syntax",
					mimeType: "text/markdown",
					text: `# Cloudflare WAF Expression Syntax

## Overview
Cloudflare WAF uses a expression language to define rule conditions. Expressions evaluate to true or false and determine whether a rule's action is applied.

## Basic Structure
\`\`\`
(field operator value) and/or (field operator value)
\`\`\`

## Common Fields

### IP and Network
| Field | Description | Example |
|-------|-------------|---------|
| \`ip.src\` | Client IP address | \`ip.src eq 192.168.1.1\` |
| \`ip.src.asnum\` | Client ASN number | \`ip.src.asnum eq 12345\` |
| \`ip.geoip.country\` | Two-letter country code | \`ip.geoip.country eq "US"\` |
| \`ip.geoip.continent\` | Continent code | \`ip.geoip.continent eq "EU"\` |
| \`ip.geoip.is_in_european_union\` | EU membership | \`ip.geoip.is_in_european_union\` |

### HTTP Request
| Field | Description | Example |
|-------|-------------|---------|
| \`http.request.method\` | HTTP method | \`http.request.method eq "POST"\` |
| \`http.request.uri\` | Full URI with query | \`http.request.uri contains "admin"\` |
| \`http.request.uri.path\` | Path only | \`http.request.uri.path eq "/login"\` |
| \`http.request.uri.query\` | Query string | \`http.request.uri.query contains "id="\` |
| \`http.host\` | Host header | \`http.host eq "api.example.com"\` |
| \`http.user_agent\` | User-Agent header | \`http.user_agent contains "bot"\` |
| \`http.referer\` | Referer header | \`http.referer contains "spam.com"\` |
| \`http.request.headers\` | All headers map | \`any(http.request.headers["x-custom"][*], {$ eq "value"})\` |

### Request Body
| Field | Description | Example |
|-------|-------------|---------|
| \`http.request.body.raw\` | Raw body content | \`http.request.body.raw contains "script"\` |
| \`http.request.body.form\` | Form data | \`any(http.request.body.form["field"][*], {$ contains "sql"})\` |

### TLS/SSL
| Field | Description | Example |
|-------|-------------|---------|
| \`ssl\` | Is HTTPS | \`not ssl\` |
| \`cf.tls_client_auth.cert_verified\` | mTLS verified | \`cf.tls_client_auth.cert_verified\` |

### Bot and Threat
| Field | Description | Example |
|-------|-------------|---------|
| \`cf.bot_management.score\` | Bot score (1-99) | \`cf.bot_management.score lt 30\` |
| \`cf.threat_score\` | Threat score (0-100) | \`cf.threat_score gt 50\` |
| \`cf.bot_management.verified_bot\` | Known good bot | \`cf.bot_management.verified_bot\` |

## Operators

### Comparison
| Operator | Description | Example |
|----------|-------------|---------|
| \`eq\` | Equals | \`http.request.method eq "GET"\` |
| \`ne\` | Not equals | \`ip.geoip.country ne "US"\` |
| \`lt\` | Less than | \`cf.threat_score lt 10\` |
| \`le\` | Less than or equal | \`cf.bot_management.score le 30\` |
| \`gt\` | Greater than | \`cf.threat_score gt 50\` |
| \`ge\` | Greater than or equal | \`cf.bot_management.score ge 80\` |

### String Operations
| Operator | Description | Example |
|----------|-------------|---------|
| \`contains\` | Substring match | \`http.user_agent contains "curl"\` |
| \`starts_with\` | Prefix match | \`http.request.uri.path starts_with "/api"\` |
| \`ends_with\` | Suffix match | \`http.request.uri.path ends_with ".php"\` |
| \`matches\` | Regex match | \`http.request.uri.path matches "^/api/v[0-9]+"\` |

### Set Operations
| Operator | Description | Example |
|----------|-------------|---------|
| \`in\` | Value in set | \`ip.geoip.country in {"CN" "RU" "KP"}\` |
| \`not in\` | Value not in set | \`ip.geoip.country not in {"US" "CA"}\` |

### Logical
| Operator | Description | Example |
|----------|-------------|---------|
| \`and\` | Both true | \`(cond1) and (cond2)\` |
| \`or\` | Either true | \`(cond1) or (cond2)\` |
| \`not\` | Negation | \`not http.request.uri.path contains "api"\` |

## Common Patterns

### Block Country
\`\`\`
ip.geoip.country in {"CN" "RU" "KP"}
\`\`\`

### Protect Admin
\`\`\`
http.request.uri.path starts_with "/admin" and not ip.src in {192.168.1.0/24}
\`\`\`

### Block Bad Bots
\`\`\`
cf.bot_management.score lt 30 and not cf.bot_management.verified_bot
\`\`\`

### API Rate Limit Path
\`\`\`
http.request.uri.path starts_with "/api" and http.request.method eq "POST"
\`\`\`

### Block Vulnerability Scanners
\`\`\`
http.user_agent matches ".*(nikto|sqlmap|nmap|masscan).*"
\`\`\`

### Geographic + Path Protection
\`\`\`
(ip.geoip.country ne "US") and (http.request.uri.path contains "/checkout")
\`\`\`

## Best Practices

1. **Use parentheses** for complex expressions to ensure correct evaluation order
2. **Be specific** - narrow expressions reduce false positives
3. **Test with log action** before blocking
4. **Use \`in\` operator** for multiple values instead of chained \`or\`
5. **Combine conditions** - more specific rules are better than broad ones
`,
				},
			],
		}),
	);

	/**
	 * WAF Actions Reference
	 *
	 * Documents available actions and when to use each one.
	 */
	server.resource(
		"waf://actions",
		"Reference guide for WAF rule actions and when to use them",
		async () => ({
			contents: [
				{
					uri: "waf://actions",
					mimeType: "text/markdown",
					text: `# WAF Rule Actions

## Available Actions

### block
Immediately blocks the request and returns a Cloudflare error page.

**Use when:**
- High confidence the traffic is malicious
- Protecting against known attack patterns
- Blocking specific IPs or countries

**Considerations:**
- No opportunity for legitimate users to proceed
- May cause support issues if too aggressive

### managed_challenge
Presents a Cloudflare-managed challenge that selects the appropriate challenge type based on request characteristics.

**Use when:**
- Medium confidence traffic may be malicious
- Want to filter bots while allowing humans
- Protecting forms and login pages

**Considerations:**
- Best balance of security and user experience
- Cloudflare optimizes challenge type automatically
- Recommended over js_challenge in most cases

### js_challenge
Presents a JavaScript challenge that browsers must solve.

**Use when:**
- Want to verify browser capability
- Filtering simple bots and scripts

**Considerations:**
- Blocks non-browser clients (APIs, mobile apps)
- Less sophisticated than managed_challenge
- Consider managed_challenge instead

### challenge (Legacy CAPTCHA)
Presents an interactive challenge to verify the visitor is human.

**Use when:**
- High-value actions (checkout, registration)
- Need strong human verification

**Considerations:**
- Higher friction for users
- May impact conversion rates
- Consider managed_challenge for better UX

### log
Records the request in security events without taking action.

**Use when:**
- Testing new rule expressions
- Monitoring traffic patterns
- Gathering data before blocking

**Considerations:**
- Traffic is not blocked
- Use to validate rules before enabling block action

### skip
Skips all remaining rules or specific rule products.

**Use when:**
- Creating allow-lists for known-good traffic
- Excluding specific paths from WAF inspection
- Allowing trusted IPs to bypass security

**Considerations:**
- Reduces security coverage
- Use sparingly and with specific conditions

## Decision Guide

\`\`\`
Is the traffic definitely malicious?
├── Yes → block
└── No → Is it likely a bot?
    ├── Yes → managed_challenge
    └── No → Is this a new rule?
        ├── Yes → log (test first)
        └── No → Based on risk:
            ├── High risk → managed_challenge
            ├── Medium risk → js_challenge
            └── Low risk → log
\`\`\`

## Action Comparison

| Action | User Impact | Bot Effectiveness | False Positive Risk |
|--------|-------------|-------------------|---------------------|
| block | High | Complete | High |
| managed_challenge | Low | High | Low |
| js_challenge | Medium | High | Medium |
| challenge | Medium-High | Very High | Low |
| log | None | None | None |
| skip | None | None | N/A |
`,
				},
			],
		}),
	);

	/**
	 * Common Attack Patterns
	 *
	 * Reference for identifying and blocking common web attacks.
	 */
	server.resource(
		"waf://attack-patterns",
		"Common web attack patterns and how to detect them with WAF rules",
		async () => ({
			contents: [
				{
					uri: "waf://attack-patterns",
					mimeType: "text/markdown",
					text: `# Common Attack Patterns

## Credential Stuffing

**Indicators:**
- High volume of POST requests to login endpoints
- Many unique IPs with similar patterns
- Failed authentication attempts
- User agents associated with automation tools

**Detection Expression:**
\`\`\`
http.request.uri.path contains "/login" and
http.request.method eq "POST"
\`\`\`

**Recommended Action:** managed_challenge or rate limiting

---

## SQL Injection

**Indicators:**
- Query parameters with SQL keywords
- Unusual characters in input fields
- Error messages indicating database issues

**Detection Expression:**
\`\`\`
http.request.uri.query matches ".*(union|select|insert|delete|update|drop|truncate).*"
\`\`\`

**Note:** Prefer Cloudflare Managed Rules for comprehensive SQLi protection

---

## XSS (Cross-Site Scripting)

**Indicators:**
- Script tags in parameters
- Event handlers in input
- Encoded JavaScript

**Detection Expression:**
\`\`\`
http.request.uri.query matches ".*(<script|javascript:|on\\w+=).*"
\`\`\`

**Note:** Prefer Cloudflare Managed Rules for comprehensive XSS protection

---

## Path Traversal

**Indicators:**
- Requests containing "../"
- Attempts to access system files
- Encoded path sequences

**Detection Expression:**
\`\`\`
http.request.uri.path contains "../" or
http.request.uri.path contains "..%2f" or
http.request.uri.path contains "%2e%2e"
\`\`\`

---

## Vulnerability Scanning

**Indicators:**
- Known scanner user agents
- Rapid requests to many paths
- Requests for common vulnerability paths

**Detection Expression:**
\`\`\`
http.user_agent matches ".*(nikto|sqlmap|nmap|masscan|acunetix|nessus|openvas).*" or
http.request.uri.path matches ".*(\\.git|\\.env|\\.svn|wp-config|phpinfo).*"
\`\`\`

**Recommended Action:** block

---

## DDoS / Volumetric Attacks

**Indicators:**
- Sudden traffic spike
- Single or few ASNs
- Specific path targeted
- Unusual geographic distribution

**Detection Expression:**
\`\`\`
ip.src.asnum eq 12345
\`\`\`
(Replace with attacking ASN)

**Recommended Action:** block or rate limiting

---

## Scraping / Data Harvesting

**Indicators:**
- High request rates to data pages
- Bot-like user agents
- Sequential access patterns
- No JavaScript execution

**Detection Expression:**
\`\`\`
cf.bot_management.score lt 30 and
not cf.bot_management.verified_bot and
http.request.uri.path starts_with "/products"
\`\`\`

**Recommended Action:** managed_challenge

---

## API Abuse

**Indicators:**
- High request rates to API endpoints
- Missing or invalid API keys
- Unusual parameter values
- Automated access patterns

**Detection Expression:**
\`\`\`
http.request.uri.path starts_with "/api" and
not any(http.request.headers["authorization"][*], {$ ne ""})
\`\`\`

**Recommended Action:** block or managed_challenge
`,
				},
			],
		}),
	);

	/**
	 * Rule Templates
	 *
	 * Ready-to-use rule templates for common protection scenarios.
	 */
	server.resource(
		"waf://rule-templates",
		"Ready-to-use WAF rule templates for common protection scenarios",
		async () => ({
			contents: [
				{
					uri: "waf://rule-templates",
					mimeType: "text/markdown",
					text: `# WAF Rule Templates

## Geographic Blocking

### Block Specific Countries
\`\`\`json
{
  "description": "Block traffic from high-risk countries",
  "expression": "ip.geoip.country in {\\"CN\\" \\"RU\\" \\"KP\\"}",
  "action": "block"
}
\`\`\`

### Allow Only Specific Countries
\`\`\`json
{
  "description": "Allow only US and Canada traffic",
  "expression": "ip.geoip.country not in {\\"US\\" \\"CA\\"}",
  "action": "block"
}
\`\`\`

---

## Endpoint Protection

### Protect Admin Panel
\`\`\`json
{
  "description": "Require challenge for admin access",
  "expression": "http.request.uri.path starts_with \\"/admin\\"",
  "action": "managed_challenge"
}
\`\`\`

### Admin Panel - IP Allowlist
\`\`\`json
{
  "description": "Block admin access except from office IPs",
  "expression": "http.request.uri.path starts_with \\"/admin\\" and not ip.src in {192.168.1.0/24 10.0.0.0/8}",
  "action": "block"
}
\`\`\`

### Protect Login Endpoint
\`\`\`json
{
  "description": "Challenge login attempts to prevent credential stuffing",
  "expression": "http.request.uri.path eq \\"/login\\" and http.request.method eq \\"POST\\"",
  "action": "managed_challenge"
}
\`\`\`

---

## Bot Protection

### Block Known Bad Bots
\`\`\`json
{
  "description": "Block requests from known malicious bots",
  "expression": "cf.bot_management.score lt 10 and not cf.bot_management.verified_bot",
  "action": "block"
}
\`\`\`

### Challenge Suspicious Bots
\`\`\`json
{
  "description": "Challenge suspicious but not confirmed bad traffic",
  "expression": "cf.bot_management.score lt 30 and cf.bot_management.score ge 10 and not cf.bot_management.verified_bot",
  "action": "managed_challenge"
}
\`\`\`

### Block Scrapers on Product Pages
\`\`\`json
{
  "description": "Protect product data from scraping",
  "expression": "http.request.uri.path starts_with \\"/products\\" and cf.bot_management.score lt 30",
  "action": "managed_challenge"
}
\`\`\`

---

## API Protection

### Require API Key Header
\`\`\`json
{
  "description": "Block API requests without authorization header",
  "expression": "http.request.uri.path starts_with \\"/api/\\" and not any(http.request.headers[\\"authorization\\"][*], {$ ne \\"\\"})",
  "action": "block"
}
\`\`\`

### Rate Limit API Endpoints
\`\`\`json
{
  "description": "Prepare for rate limiting on API",
  "expression": "http.request.uri.path starts_with \\"/api/\\" and http.request.method eq \\"POST\\"",
  "action": "log"
}
\`\`\`

---

## Security Scanners

### Block Vulnerability Scanners
\`\`\`json
{
  "description": "Block known vulnerability scanning tools",
  "expression": "http.user_agent matches \\".*(nikto|sqlmap|nmap|masscan|acunetix|nessus).*\\"",
  "action": "block"
}
\`\`\`

### Block Suspicious Paths
\`\`\`json
{
  "description": "Block access to sensitive files and paths",
  "expression": "http.request.uri.path matches \\".*(\\\\.git|\\\\.env|\\\\.svn|wp-config\\\\.php|phpinfo|debug).*\\"",
  "action": "block"
}
\`\`\`

---

## Request Filtering

### Block Non-Standard Methods
\`\`\`json
{
  "description": "Allow only standard HTTP methods",
  "expression": "http.request.method not in {\\"GET\\" \\"POST\\" \\"PUT\\" \\"DELETE\\" \\"PATCH\\" \\"HEAD\\" \\"OPTIONS\\"}",
  "action": "block"
}
\`\`\`

### Block Empty User Agents
\`\`\`json
{
  "description": "Block requests with no user agent (likely bots)",
  "expression": "http.user_agent eq \\"\\"",
  "action": "managed_challenge"
}
\`\`\`

---

## Emergency Response

### Block Specific IP
\`\`\`json
{
  "description": "Emergency block for attacking IP",
  "expression": "ip.src eq 1.2.3.4",
  "action": "block"
}
\`\`\`

### Block ASN
\`\`\`json
{
  "description": "Block traffic from specific hosting provider",
  "expression": "ip.src.asnum eq 12345",
  "action": "block"
}
\`\`\`

### Under Attack Mode for Path
\`\`\`json
{
  "description": "Challenge all traffic to under-attack endpoint",
  "expression": "http.request.uri.path starts_with \\"/api/vulnerable\\"",
  "action": "managed_challenge"
}
\`\`\`
`,
				},
			],
		}),
	);
}
