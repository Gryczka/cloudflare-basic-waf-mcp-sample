// WAF Analytics Tools - Tools for querying security events and analytics
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { CloudflareApi } from "../cloudflare-api";
import { zoneIdSchema } from "../validation";

// Helper to calculate time range
function getTimeRange(minutes: number): { startTime: string; endTime: string } {
	const endTime = new Date();
	const startTime = new Date(endTime.getTime() - minutes * 60 * 1000);
	return {
		startTime: startTime.toISOString(),
		endTime: endTime.toISOString(),
	};
}

export function registerWafAnalyticsTools(server: McpServer, getApi: () => CloudflareApi) {
	// Get recent security events
	server.tool(
		"get_security_events",
		"Get recent WAF security events for a zone. Shows blocked requests, challenges, and other security actions.",
		{
			zoneId: zoneIdSchema,
			minutes: z
				.number()
				.min(1)
				.max(1440)
				.default(60)
				.describe("How many minutes of history to retrieve (1-1440, default 60)."),
			limit: z
				.number()
				.min(1)
				.max(1000)
				.default(100)
				.describe("Maximum number of events to return (1-1000, default 100)."),
		},
		async ({ zoneId, minutes, limit }) => {
			const api = getApi();
			const { startTime, endTime } = getTimeRange(minutes);
			const events = await api.getSecurityEvents(zoneId, startTime, endTime, limit);
			return {
				content: [
					{
						type: "text",
						text: JSON.stringify(
							{
								timeRange: { start: startTime, end: endTime },
								eventCount: events.length,
								events,
							},
							null,
							2,
						),
					},
				],
			};
		},
	);

	// Get security events summary/aggregation
	server.tool(
		"get_attack_summary",
		"Get a summary of security events grouped by action, source, and country. Useful for understanding attack patterns.",
		{
			zoneId: zoneIdSchema,
			minutes: z
				.number()
				.min(1)
				.max(1440)
				.default(60)
				.describe("How many minutes of history to analyze (1-1440, default 60)."),
		},
		async ({ zoneId, minutes }) => {
			const api = getApi();
			const { startTime, endTime } = getTimeRange(minutes);
			const summary = await api.getSecurityEventsSummary(zoneId, startTime, endTime);
			return {
				content: [
					{
						type: "text",
						text: JSON.stringify(
							{
								timeRange: { start: startTime, end: endTime },
								summary,
							},
							null,
							2,
						),
					},
				],
			};
		},
	);

	// Get top attacked paths
	server.tool(
		"get_top_attacked_paths",
		"Get the most frequently attacked URL paths. Useful for identifying which endpoints are being targeted.",
		{
			zoneId: zoneIdSchema,
			minutes: z
				.number()
				.min(1)
				.max(1440)
				.default(60)
				.describe("How many minutes of history to analyze (1-1440, default 60)."),
			limit: z
				.number()
				.min(1)
				.max(100)
				.default(10)
				.describe("Number of top paths to return (1-100, default 10)."),
		},
		async ({ zoneId, minutes, limit }) => {
			const api = getApi();
			const { startTime, endTime } = getTimeRange(minutes);
			const paths = await api.getTopAttackedPaths(zoneId, startTime, endTime, limit);
			return {
				content: [
					{
						type: "text",
						text: JSON.stringify(
							{
								timeRange: { start: startTime, end: endTime },
								topPaths: paths,
							},
							null,
							2,
						),
					},
				],
			};
		},
	);
}
