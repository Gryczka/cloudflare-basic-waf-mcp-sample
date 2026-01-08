// WAF Write Tools - Tools for creating and modifying WAF rules
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { CloudflareApi, sanitizeErrorMessage } from "../cloudflare-api";
import { zoneIdSchema, rulesetIdSchema, ruleIdSchema, wafActionSchema } from "../validation";

export function registerWafWriteTools(server: McpServer, getApi: () => CloudflareApi) {
	// Create a new custom WAF rule
	server.tool(
		"create_custom_rule",
		"Create a new custom WAF rule for a zone. Use this to add new security rules based on conditions like IP addresses, countries, user agents, etc.",
		{
			zoneId: zoneIdSchema,
			description: z.string().min(1).max(500).describe("A clear description of what this rule does (e.g., 'Block traffic from country X')"),
			expression: z.string().min(1).max(4096).describe("The firewall expression (e.g., '(ip.geoip.country eq \"CN\")' or '(http.user_agent contains \"bot\")'). See Cloudflare Ruleset Engine docs for syntax."),
			action: wafActionSchema.describe("The action to take when the rule matches"),
			enabled: z.boolean().default(true).describe("Whether the rule should be enabled immediately"),
		},
		async ({ zoneId, description, expression, action, enabled }) => {
			const api = getApi();
			try {
				const result = await api.createCustomRule(zoneId, {
					description,
					expression,
					action,
					enabled,
				});
				return {
					content: [
						{
							type: "text",
							text: `Successfully created custom rule.\n\n${JSON.stringify(result, null, 2)}`,
						},
					],
				};
			} catch (error: any) {
				return {
					content: [
						{
							type: "text",
							text: `Failed to create rule: ${sanitizeErrorMessage(error.message)}`,
						},
					],
				};
			}
		},
	);

	// Update an existing custom rule
	server.tool(
		"update_custom_rule",
		"Update an existing custom WAF rule. You can modify its description, expression, action, or enabled status.",
		{
			zoneId: zoneIdSchema,
			rulesetId: rulesetIdSchema,
			ruleId: ruleIdSchema,
			description: z.string().min(1).max(500).optional().describe("New description for the rule"),
			expression: z.string().min(1).max(4096).optional().describe("New firewall expression"),
			action: wafActionSchema.optional().describe("New action"),
			enabled: z.boolean().optional().describe("Whether the rule should be enabled"),
		},
		async ({ zoneId, rulesetId, ruleId, description, expression, action, enabled }) => {
			const api = getApi();
			try {
				const updates: any = {};
				if (description !== undefined) updates.description = description;
				if (expression !== undefined) updates.expression = expression;
				if (action !== undefined) updates.action = action;
				if (enabled !== undefined) updates.enabled = enabled;

				const result = await api.updateCustomRule(zoneId, rulesetId, ruleId, updates);
				return {
					content: [
						{
							type: "text",
							text: `Successfully updated rule.\n\n${JSON.stringify(result, null, 2)}`,
						},
					],
				};
			} catch (error: any) {
				return {
					content: [
						{
							type: "text",
							text: `Failed to update rule: ${sanitizeErrorMessage(error.message)}`,
						},
					],
				};
			}
		},
	);

	// Delete a custom rule
	server.tool(
		"delete_custom_rule",
		"Delete a custom WAF rule. This action cannot be undone.",
		{
			zoneId: zoneIdSchema,
			rulesetId: rulesetIdSchema,
			ruleId: ruleIdSchema,
		},
		async ({ zoneId, rulesetId, ruleId }) => {
			const api = getApi();
			try {
				await api.deleteCustomRule(zoneId, rulesetId, ruleId);
				return {
					content: [
						{
							type: "text",
							text: `Successfully deleted rule ${ruleId}`,
						},
					],
				};
			} catch (error: any) {
				return {
					content: [
						{
							type: "text",
							text: `Failed to delete rule: ${sanitizeErrorMessage(error.message)}`,
						},
					],
				};
			}
		},
	);

	// Enable/disable a rule quickly
	server.tool(
		"toggle_rule",
		"Quickly enable or disable a WAF rule without changing other settings.",
		{
			zoneId: zoneIdSchema,
			rulesetId: rulesetIdSchema,
			ruleId: ruleIdSchema,
			enabled: z.boolean().describe("Set to true to enable, false to disable"),
		},
		async ({ zoneId, rulesetId, ruleId, enabled }) => {
			const api = getApi();
			try {
				const result = await api.updateCustomRule(zoneId, rulesetId, ruleId, { enabled });
				return {
					content: [
						{
							type: "text",
							text: `Successfully ${enabled ? "enabled" : "disabled"} rule ${ruleId}`,
						},
					],
				};
			} catch (error: any) {
				return {
					content: [
						{
							type: "text",
							text: `Failed to toggle rule: ${sanitizeErrorMessage(error.message)}`,
						},
					],
				};
			}
		},
	);

	// Helper tool to analyze security events and suggest rules
	server.tool(
		"suggest_rule_from_events",
		"Analyze recent security events and suggest a WAF rule to block or challenge similar traffic. This helps create rules based on actual attack patterns.",
		{
			zoneId: zoneIdSchema,
			minutes: z.number().min(1).max(1440).default(60).describe("How many minutes of history to analyze"),
			actionType: z.enum(["block", "challenge", "log"]).default("block").describe("What action the suggested rule should take"),
		},
		async ({ zoneId, minutes, actionType }) => {
			const api = getApi();
			try {
				// Get recent security events
				const endTime = new Date();
				const startTime = new Date(endTime.getTime() - minutes * 60 * 1000);
				const events = await api.getSecurityEvents(
					zoneId,
					startTime.toISOString(),
					endTime.toISOString(),
					100,
				);

				if (events.length === 0) {
					return {
						content: [
							{
								type: "text",
								text: "No security events found in the specified time period. No rule suggestions available.",
							},
						],
					};
				}

				// Analyze patterns
				const countryMap = new Map<string, number>();
				const ipMap = new Map<string, number>();
				const pathMap = new Map<string, number>();
				const sourceMap = new Map<string, number>();

				events.forEach((event) => {
					countryMap.set(event.clientCountryName, (countryMap.get(event.clientCountryName) || 0) + 1);
					ipMap.set(event.clientIP, (ipMap.get(event.clientIP) || 0) + 1);
					pathMap.set(event.clientRequestPath, (pathMap.get(event.clientRequestPath) || 0) + 1);
					sourceMap.set(event.source, (sourceMap.get(event.source) || 0) + 1);
				});

				// Find top offenders
				const topCountry = Array.from(countryMap.entries()).sort((a, b) => b[1] - a[1])[0];
				const topIP = Array.from(ipMap.entries()).sort((a, b) => b[1] - a[1])[0];
				const topPath = Array.from(pathMap.entries()).sort((a, b) => b[1] - a[1])[0];
				const topSource = Array.from(sourceMap.entries()).sort((a, b) => b[1] - a[1])[0];

				let suggestions = `Analyzed ${events.length} security events from the last ${minutes} minutes.\n\n`;
				suggestions += `**Top Attack Patterns:**\n`;
				suggestions += `- Country: ${topCountry[0]} (${topCountry[1]} events)\n`;
				suggestions += `- IP: ${topIP[0]} (${topIP[1]} events)\n`;
				suggestions += `- Path: ${topPath[0]} (${topPath[1]} events)\n`;
				suggestions += `- Source: ${topSource[0]} (${topSource[1]} events)\n\n`;

				suggestions += `**Suggested Rules:**\n\n`;

				// Suggest country-based rule if significant
				if (topCountry[1] > events.length * 0.3) {
					suggestions += `1. **Block traffic from ${topCountry[0]}**\n`;
					suggestions += `   Expression: \`(ip.geoip.country eq "${topCountry[0]}")\`\n`;
					suggestions += `   Action: ${actionType}\n`;
					suggestions += `   Reason: ${Math.round((topCountry[1] / events.length) * 100)}% of attacks from this country\n\n`;
				}

				// Suggest IP-based rule if single IP is problematic
				if (topIP[1] > 5) {
					suggestions += `2. **Block specific IP address**\n`;
					suggestions += `   Expression: \`(ip.src eq ${topIP[0]})\`\n`;
					suggestions += `   Action: ${actionType}\n`;
					suggestions += `   Reason: This IP generated ${topIP[1]} security events\n\n`;
				}

				// Suggest path-based rule if specific path is targeted
				if (topPath[1] > events.length * 0.4) {
					suggestions += `3. **Protect specific path**\n`;
					suggestions += `   Expression: \`(http.request.uri.path eq "${topPath[0]}")\`\n`;
					suggestions += `   Action: ${actionType}\n`;
					suggestions += `   Reason: ${Math.round((topPath[1] / events.length) * 100)}% of attacks target this path\n\n`;
				}

				suggestions += `\nTo create a rule, use the \`create_custom_rule\` tool with the suggested expression.`;

				return {
					content: [
						{
							type: "text",
							text: suggestions,
						},
					],
				};
			} catch (error: any) {
				return {
					content: [
						{
							type: "text",
							text: `Failed to analyze events: ${sanitizeErrorMessage(error.message)}`,
						},
					],
				};
			}
		},
	);
}
