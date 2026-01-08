// WAF Read Tools - Tools for reading WAF configuration and rules
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { CloudflareApi } from "../cloudflare-api";
import { zoneIdSchema, accountIdSchema, rulesetIdSchema } from "../validation";

export function registerWafReadTools(server: McpServer, getApi: () => CloudflareApi) {
	// List all accounts the user has access to
	server.tool(
		"list_accounts",
		"List all Cloudflare accounts the authenticated user has access to",
		{},
		async () => {
			const api = getApi();
			const accounts = await api.listAccounts();
			return {
				content: [
					{
						type: "text",
						text: JSON.stringify(accounts, null, 2),
					},
				],
			};
		},
	);

	// List zones in an account
	server.tool(
		"list_zones",
		"List all zones (domains) in a Cloudflare account. If no accountId is provided, lists zones across all accessible accounts.",
		{
			accountId: accountIdSchema.optional(),
		},
		async ({ accountId }) => {
			const api = getApi();
			const zones = await api.listZones(accountId);
			return {
				content: [
					{
						type: "text",
						text: JSON.stringify(zones, null, 2),
					},
				],
			};
		},
	);

	// Get zone details
	server.tool(
		"get_zone",
		"Get detailed information about a specific zone including its plan and status",
		{
			zoneId: zoneIdSchema,
		},
		async ({ zoneId }) => {
			const api = getApi();
			const zone = await api.getZone(zoneId);
			return {
				content: [
					{
						type: "text",
						text: JSON.stringify(zone, null, 2),
					},
				],
			};
		},
	);

	// List custom WAF rules for a zone
	server.tool(
		"list_custom_rules",
		"List all custom WAF rules for a zone. These are user-created rules in the http_request_firewall_custom phase.",
		{
			zoneId: zoneIdSchema,
		},
		async ({ zoneId }) => {
			const api = getApi();
			try {
				const ruleset = await api.getEntryPointRuleset(zoneId, "http_request_firewall_custom");
				return {
					content: [
						{
							type: "text",
							text: JSON.stringify(ruleset, null, 2),
						},
					],
				};
			} catch (error: any) {
				// If no ruleset exists, return empty
				if (error.message?.includes("404") || error.message?.includes("not found")) {
					return {
						content: [
							{
								type: "text",
								text: JSON.stringify({ rules: [], message: "No custom rules configured for this zone" }, null, 2),
							},
						],
					};
				}
				throw error;
			}
		},
	);

	// List managed rulesets deployed to a zone
	server.tool(
		"list_managed_rulesets",
		"List all managed WAF rulesets deployed to a zone (Cloudflare Managed Rules, OWASP, etc.)",
		{
			zoneId: zoneIdSchema,
		},
		async ({ zoneId }) => {
			const api = getApi();
			try {
				const ruleset = await api.getEntryPointRuleset(zoneId, "http_request_firewall_managed");
				return {
					content: [
						{
							type: "text",
							text: JSON.stringify(ruleset, null, 2),
						},
					],
				};
			} catch (error: any) {
				// If no ruleset exists, return empty
				if (error.message?.includes("404") || error.message?.includes("not found")) {
					return {
						content: [
							{
								type: "text",
								text: JSON.stringify({ rules: [], message: "No managed rulesets deployed to this zone" }, null, 2),
							},
						],
					};
				}
				throw error;
			}
		},
	);

	// Get a specific ruleset with all its rules
	server.tool(
		"get_ruleset",
		"Get a specific ruleset with all its rules. Use this to see the full configuration of a ruleset.",
		{
			zoneId: zoneIdSchema,
			rulesetId: rulesetIdSchema,
		},
		async ({ zoneId, rulesetId }) => {
			const api = getApi();
			const ruleset = await api.getRuleset(zoneId, rulesetId);
			return {
				content: [
					{
						type: "text",
						text: JSON.stringify(ruleset, null, 2),
					},
				],
			};
		},
	);

	// List all rulesets for a zone (all phases)
	server.tool(
		"list_all_rulesets",
		"List all rulesets for a zone across all phases. This gives an overview of all WAF configurations.",
		{
			zoneId: zoneIdSchema,
		},
		async ({ zoneId }) => {
			const api = getApi();
			const rulesets = await api.listRulesets(zoneId);
			return {
				content: [
					{
						type: "text",
						text: JSON.stringify(rulesets, null, 2),
					},
				],
			};
		},
	);

	// Account-level rulesets
	server.tool(
		"list_account_rulesets",
		"List all account-level WAF rulesets. These can be deployed across multiple zones. Enterprise feature.",
		{
			accountId: accountIdSchema,
		},
		async ({ accountId }) => {
			const api = getApi();
			const rulesets = await api.listAccountRulesets(accountId);
			return {
				content: [
					{
						type: "text",
						text: JSON.stringify(rulesets, null, 2),
					},
				],
			};
		},
	);
}
