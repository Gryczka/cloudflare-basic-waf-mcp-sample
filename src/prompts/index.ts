/**
 * MCP Prompts for WAF Workflows
 *
 * Prompts are pre-configured conversation templates that guide AI assistants
 * through complex, multi-step workflows. They provide structure and context
 * for common WAF management tasks.
 *
 * Each prompt defines:
 * - A unique name for invocation
 * - A description explaining its purpose
 * - Optional arguments to customize the workflow
 * - A message template that starts the conversation
 *
 * Learn more: https://spec.modelcontextprotocol.io/specification/server/prompts/
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export function registerPrompts(server: McpServer) {
	/**
	 * Security Audit Prompt
	 *
	 * Performs a comprehensive security posture review including:
	 * - Current rule inventory and coverage
	 * - Recent security event analysis
	 * - Gap identification and recommendations
	 *
	 * Use case: Regular security assessments, compliance reviews
	 */
	server.prompt(
		"security_audit",
		"Perform a comprehensive security audit of a zone's WAF configuration, analyzing rules, events, and providing recommendations",
		{
			zoneId: z.string().optional().describe("Zone ID to audit. If not provided, will list zones first."),
			timeRange: z
				.enum(["1h", "6h", "24h", "7d"])
				.optional()
				.describe("Time range for event analysis (default: 24h)"),
		},
		async ({ zoneId, timeRange = "24h" }) => {
			const timeMinutes = {
				"1h": 60,
				"6h": 360,
				"24h": 1440,
				"7d": 10080,
			}[timeRange];

			const zoneContext = zoneId
				? `Analyze zone ID: ${zoneId}`
				: "First, list available zones and ask which one to audit.";

			return {
				messages: [
					{
						role: "user",
						content: {
							type: "text",
							text: `Perform a comprehensive WAF security audit.

${zoneContext}

Please complete these steps:

1. **Rule Inventory**
   - List all custom WAF rules (use list_custom_rules)
   - List managed rulesets deployed (use list_managed_rulesets)
   - Identify any disabled rules that may indicate gaps

2. **Security Event Analysis** (last ${timeRange})
   - Get security events summary (use get_attack_summary with minutes=${timeMinutes})
   - Identify top attacked paths (use get_top_attacked_paths)
   - Analyze attack patterns by source country and action taken

3. **Gap Analysis**
   - Compare current rules against observed attack patterns
   - Identify unprotected endpoints receiving attack traffic
   - Check for overly permissive rules (e.g., log-only on critical paths)

4. **Recommendations**
   - Prioritized list of suggested rule additions
   - Rules that could be tightened or removed
   - Managed rulesets that should be enabled

Format the output as a structured security report with clear sections and actionable items.`,
						},
					},
				],
			};
		},
	);

	/**
	 * Rule Builder Prompt
	 *
	 * Interactive workflow for creating WAF rules based on specific
	 * threat scenarios or protection requirements.
	 *
	 * Use case: Creating rules for new threats, protecting new endpoints
	 */
	server.prompt(
		"rule_builder",
		"Interactive workflow for creating custom WAF rules based on specific protection requirements",
		{
			scenario: z
				.enum([
					"block_country",
					"protect_endpoint",
					"rate_limit",
					"block_user_agent",
					"custom",
				])
				.optional()
				.describe("Protection scenario to implement"),
			zoneId: z.string().optional().describe("Zone ID to create the rule in"),
		},
		async ({ scenario, zoneId }) => {
			const scenarioPrompts: Record<string, string> = {
				block_country: `Create a rule to block traffic from specific countries.
Ask which countries to block and which paths to protect (or all paths).
Consider whether to use "block" action or "managed_challenge" for less aggressive protection.`,

				protect_endpoint: `Create a rule to protect a specific endpoint.
Ask about the endpoint path and what protection is needed:
- Rate limiting threshold
- Geographic restrictions
- Bot protection (challenge)
- Complete blocking of certain patterns`,

				rate_limit: `Create a rate limiting rule.
Ask about:
- Which endpoints to protect
- Request threshold (requests per period)
- What action to take when exceeded (challenge, block)
- Whether to apply globally or per-IP`,

				block_user_agent: `Create a rule to block specific user agents.
Ask about:
- User agent patterns to block (bots, scrapers, specific tools)
- Whether to use exact match or contains
- Action (block vs challenge)`,

				custom: `Help create a custom WAF rule.
Ask the user to describe what they want to protect against, then:
1. Suggest an appropriate expression using Cloudflare's rule language
2. Recommend the right action (block, challenge, log)
3. Explain what the rule will do`,
			};

			const scenarioGuide = scenario
				? scenarioPrompts[scenario]
				: `Ask the user what type of protection they need:
1. Block traffic from specific countries
2. Protect a specific endpoint
3. Add rate limiting
4. Block specific user agents
5. Custom rule (describe the threat)`;

			const zoneContext = zoneId
				? `Working with zone ID: ${zoneId}`
				: "First, list available zones (use list_zones) and ask which zone to protect.";

			return {
				messages: [
					{
						role: "user",
						content: {
							type: "text",
							text: `Help me create a WAF rule.

${zoneContext}

${scenarioGuide}

For any rule creation:
1. First show the proposed rule configuration:
   - Expression (in Cloudflare WAF syntax)
   - Action (block, challenge, js_challenge, managed_challenge, log)
   - Description

2. Explain what traffic the rule will match
3. Ask for confirmation before creating
4. Use create_custom_rule to implement

Cloudflare expression syntax reference:
- ip.src eq 1.2.3.4 (IP match)
- ip.geoip.country eq "US" (country match)
- http.request.uri.path contains "/admin" (path match)
- http.user_agent contains "bot" (user agent match)
- http.request.method eq "POST" (method match)
- Combine with: and, or, not, parentheses

After creating, offer to:
- Create additional related rules
- Review the full ruleset to verify`,
						},
					},
				],
			};
		},
	);

	/**
	 * Incident Response Prompt
	 *
	 * Guided investigation of active attacks with analysis and
	 * immediate mitigation recommendations.
	 *
	 * Use case: Responding to ongoing attacks, investigating anomalies
	 */
	server.prompt(
		"incident_response",
		"Investigate an active attack or security incident with guided analysis and mitigation options",
		{
			zoneId: z.string().optional().describe("Zone ID under attack"),
			symptom: z
				.enum(["high_blocks", "slow_response", "error_spike", "suspicious_traffic", "unknown"])
				.optional()
				.describe("Observed symptom"),
		},
		async ({ zoneId, symptom = "unknown" }) => {
			const symptomContext: Record<string, string> = {
				high_blocks: "The user is seeing an unusual number of blocked requests.",
				slow_response: "The application is responding slowly, possibly due to attack traffic.",
				error_spike: "There's a spike in 4xx/5xx errors that may indicate an attack.",
				suspicious_traffic: "Suspicious traffic patterns have been observed.",
				unknown: "The user suspects an attack but hasn't identified specific symptoms.",
			};

			const zoneContext = zoneId
				? `Investigating zone ID: ${zoneId}`
				: "First, identify which zone is affected (use list_zones).";

			return {
				messages: [
					{
						role: "user",
						content: {
							type: "text",
							text: `Investigate a potential security incident.

${zoneContext}
Context: ${symptomContext[symptom]}

Follow this incident response workflow:

## 1. Immediate Assessment (Priority)
- Get security events from the last 15 minutes (use get_security_events with minutes=15, limit=200)
- Get attack summary (use get_attack_summary with minutes=15)
- Identify top attacked paths (use get_top_attacked_paths with minutes=15)

## 2. Attack Pattern Analysis
Based on the data, determine:
- **Attack Type**: Credential stuffing, DDoS, vulnerability scanning, data scraping, etc.
- **Attack Source**: Single IP, IP range, ASN, geographic region
- **Target**: Specific endpoints, entire site, API endpoints
- **Scale**: Request volume, unique IPs involved

## 3. Current Protection Status
- List current custom rules (use list_custom_rules)
- Identify if existing rules are blocking the attack
- Note any gaps in protection

## 4. Mitigation Recommendations
Provide prioritized options:

**Immediate (can implement now)**
- Specific rule to block the attack pattern
- Enable managed challenge for affected endpoints
- Temporarily increase security level

**Short-term (after immediate threat)**
- Rate limiting rules
- Additional custom rules for similar patterns
- Managed ruleset adjustments

## 5. Offer Implementation
For each recommended mitigation:
- Show the exact rule configuration
- Explain impact on legitimate traffic
- Ask for approval before implementing
- Use create_custom_rule or toggle_rule as appropriate

After mitigation, offer to:
- Monitor the situation (re-run event analysis)
- Document the incident
- Suggest preventive measures`,
						},
					},
				],
			};
		},
	);

	/**
	 * Compliance Check Prompt
	 *
	 * Review WAF configuration against security best practices
	 * and common compliance requirements.
	 *
	 * Use case: Pre-audit preparation, security baseline verification
	 */
	server.prompt(
		"compliance_check",
		"Review WAF configuration against security best practices and compliance requirements",
		{
			zoneId: z.string().optional().describe("Zone ID to check"),
			framework: z
				.enum(["general", "pci", "owasp", "enterprise"])
				.optional()
				.describe("Compliance framework to check against"),
		},
		async ({ zoneId, framework = "general" }) => {
			const frameworkChecks: Record<string, string> = {
				general: `General security best practices:
- OWASP Top 10 protection coverage
- Bot protection enabled
- Rate limiting in place
- Sensitive endpoint protection
- Logging enabled for visibility`,

				pci: `PCI-DSS relevant controls:
- Requirement 6.6: WAF for public-facing web applications
- Protection against known attack types
- Logging and monitoring of security events
- Regular rule review and updates`,

				owasp: `OWASP Top 10 (2021) coverage:
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection (SQL, XSS, Command)
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable Components
- A07: Authentication Failures
- A08: Data Integrity Failures
- A09: Logging Failures
- A10: SSRF`,

				enterprise: `Enterprise security requirements:
- Defense in depth (multiple rule layers)
- Managed ruleset deployment
- Custom rules for business logic
- Geographic restrictions where appropriate
- Rate limiting and bot protection
- Comprehensive logging
- Regular rule review process`,
			};

			const zoneContext = zoneId
				? `Checking zone ID: ${zoneId}`
				: "First, list available zones (use list_zones) and ask which to check.";

			return {
				messages: [
					{
						role: "user",
						content: {
							type: "text",
							text: `Perform a WAF compliance and best practices review.

${zoneContext}

## Framework: ${framework.toUpperCase()}
${frameworkChecks[framework]}

## Review Steps

### 1. Rule Inventory
- List all custom rules (use list_custom_rules)
- List managed rulesets (use list_managed_rulesets)
- List all rulesets across phases (use list_all_rulesets)

### 2. Coverage Analysis
For each check in the framework above:
- Indicate PASS/FAIL/PARTIAL status
- Cite specific rules providing coverage
- Note gaps in protection

### 3. Configuration Quality
Check for:
- Rules with vague descriptions
- Overly broad expressions (may cause false positives)
- Disabled rules that should be enabled
- Log-only rules on critical paths
- Missing rate limiting

### 4. Event Analysis
- Review recent events (use get_security_events with minutes=1440)
- Identify attacks that were blocked (good)
- Identify attacks that only logged (potential gap)

### 5. Compliance Report
Format as a compliance report with:

| Requirement | Status | Evidence | Remediation |
|-------------|--------|----------|-------------|
| ... | PASS/FAIL | Rule ID or gap | Suggested fix |

### 6. Remediation Plan
Provide prioritized recommendations:
1. Critical gaps (immediate fix needed)
2. Important improvements (short-term)
3. Enhancements (ongoing)

Offer to implement high-priority fixes using create_custom_rule.`,
						},
					},
				],
			};
		},
	);

	/**
	 * Rule Optimization Prompt
	 *
	 * Analyze existing rules for performance and effectiveness,
	 * suggesting consolidation and improvements.
	 *
	 * Use case: Rule maintenance, reducing false positives
	 */
	server.prompt(
		"rule_optimization",
		"Analyze and optimize existing WAF rules for better performance and reduced false positives",
		{
			zoneId: z.string().optional().describe("Zone ID to optimize"),
		},
		async ({ zoneId }) => {
			const zoneContext = zoneId
				? `Optimizing zone ID: ${zoneId}`
				: "First, list available zones (use list_zones) and ask which to optimize.";

			return {
				messages: [
					{
						role: "user",
						content: {
							type: "text",
							text: `Analyze and optimize WAF rules.

${zoneContext}

## Analysis Steps

### 1. Current Rule Inventory
- List all custom rules (use list_custom_rules)
- For each rule, note:
  - Expression complexity
  - Action type
  - Enabled status
  - Description quality

### 2. Effectiveness Analysis
- Get security events (use get_security_events with minutes=1440, limit=500)
- Identify which rules are triggering
- Find rules that never trigger (may be redundant)
- Find rules triggering excessively (may need tuning)

### 3. Optimization Opportunities

**Consolidation**
- Rules with similar expressions that could be combined
- Multiple country blocks that could use "in" operator
- Overlapping path protections

**Performance**
- Complex expressions that could be simplified
- Rules that could use more efficient operators
- Order optimization (most-hit rules first)

**False Positive Reduction**
- Rules with high trigger rates on legitimate traffic
- Overly broad expressions
- Missing exclusions for known-good patterns

### 4. Recommendations
For each optimization:
- Current rule(s) affected
- Proposed change
- Expected improvement
- Risk assessment

### 5. Implementation
Offer to:
- Update rules (use update_custom_rule)
- Consolidate rules (delete + create)
- Reorder rules for performance

Always ask for confirmation before making changes.`,
						},
					},
				],
			};
		},
	);
}
