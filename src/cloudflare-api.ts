// Cloudflare API client for WAF operations

const CF_API_BASE = "https://api.cloudflare.com/client/v4";
const CF_GRAPHQL_URL = "https://api.cloudflare.com/client/v4/graphql";

// Sanitize error messages to avoid leaking sensitive information
export function sanitizeErrorMessage(message: string): string {
	// Remove any potential API keys, tokens, or sensitive data patterns
	let sanitized = message
		// Remove Bearer tokens
		.replace(/Bearer\s+[a-zA-Z0-9_-]+/gi, "Bearer [REDACTED]")
		// Remove API keys (common patterns)
		.replace(/[a-f0-9]{32,}/gi, "[REDACTED_ID]")
		// Remove email addresses
		.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]")
		// Remove IP addresses
		.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, "[REDACTED_IP]");

	// Limit message length to prevent excessive information disclosure
	if (sanitized.length > 200) {
		sanitized = sanitized.substring(0, 200) + "...";
	}

	return sanitized;
}

export interface CloudflareApiError {
	code: number;
	message: string;
}

export interface CloudflareApiResponse<T> {
	success: boolean;
	errors: CloudflareApiError[];
	messages: string[];
	result: T;
	result_info?: {
		page: number;
		per_page: number;
		total_pages: number;
		count: number;
		total_count: number;
	};
}

export interface Account {
	id: string;
	name: string;
	type: string;
	settings?: {
		enforce_twofactor: boolean;
	};
}

export interface Zone {
	id: string;
	name: string;
	status: string;
	paused: boolean;
	type: string;
	account: {
		id: string;
		name: string;
	};
	plan: {
		id: string;
		name: string;
		is_subscribed: boolean;
	};
}

export interface RulesetRule {
	id: string;
	version: string;
	action: string;
	expression: string;
	description: string;
	enabled: boolean;
	action_parameters?: Record<string, unknown>;
	logging?: {
		enabled: boolean;
	};
	last_updated: string;
	ref?: string;
}

export interface Ruleset {
	id: string;
	name: string;
	description: string;
	kind: string;
	version: string;
	phase: string;
	rules: RulesetRule[];
	last_updated: string;
}

export interface SecurityEvent {
	action: string;
	clientAsn: string;
	clientCountryName: string;
	clientIP: string;
	clientRequestPath: string;
	clientRequestQuery: string;
	datetime: string;
	source: string;
	userAgent: string;
	ruleId?: string;
	ruleName?: string;
}

export class CloudflareApi {
	private accessToken: string;

	constructor(accessToken: string) {
		this.accessToken = accessToken;
	}

	private async request<T>(
		endpoint: string,
		options: RequestInit = {},
	): Promise<CloudflareApiResponse<T>> {
		const url = `${CF_API_BASE}${endpoint}`;
		const response = await fetch(url, {
			...options,
			headers: {
				Authorization: `Bearer ${this.accessToken}`,
				"Content-Type": "application/json",
				...options.headers,
			},
		});

		const data = (await response.json()) as CloudflareApiResponse<T>;

		if (!data.success) {
			const errorMessage = data.errors.map((e) => e.message).join(", ");
			throw new Error(`Cloudflare API error: ${sanitizeErrorMessage(errorMessage)}`);
		}

		return data;
	}

	private async graphqlRequest<T>(query: string, variables: Record<string, unknown>): Promise<T> {
		const response = await fetch(CF_GRAPHQL_URL, {
			method: "POST",
			headers: {
				Authorization: `Bearer ${this.accessToken}`,
				"Content-Type": "application/json",
			},
			body: JSON.stringify({ query, variables }),
		});

		const data = (await response.json()) as { data: T; errors?: Array<{ message: string }> };

		if (data.errors && data.errors.length > 0) {
			const errorMessage = data.errors.map((e) => e.message).join(", ");
			throw new Error(`GraphQL error: ${sanitizeErrorMessage(errorMessage)}`);
		}

		return data.data;
	}

	// Account operations
	async listAccounts(): Promise<Account[]> {
		const response = await this.request<Account[]>("/accounts");
		return response.result;
	}

	// Zone operations
	async listZones(accountId?: string): Promise<Zone[]> {
		const params = new URLSearchParams();
		if (accountId) {
			params.set("account.id", accountId);
		}
		const queryString = params.toString();
		const response = await this.request<Zone[]>(`/zones${queryString ? `?${queryString}` : ""}`);
		return response.result;
	}

	async getZone(zoneId: string): Promise<Zone> {
		const response = await this.request<Zone>(`/zones/${encodeURIComponent(zoneId)}`);
		return response.result;
	}

	// Ruleset operations
	async listRulesets(zoneId: string, phase?: string): Promise<Ruleset[]> {
		const params = new URLSearchParams();
		if (phase) {
			params.set("phase", phase);
		}
		const queryString = params.toString();
		const response = await this.request<Ruleset[]>(`/zones/${encodeURIComponent(zoneId)}/rulesets${queryString ? `?${queryString}` : ""}`);
		return response.result;
	}

	async getRuleset(zoneId: string, rulesetId: string): Promise<Ruleset> {
		const response = await this.request<Ruleset>(`/zones/${encodeURIComponent(zoneId)}/rulesets/${encodeURIComponent(rulesetId)}`);
		return response.result;
	}

	async getEntryPointRuleset(zoneId: string, phase: string): Promise<Ruleset> {
		const response = await this.request<Ruleset>(
			`/zones/${encodeURIComponent(zoneId)}/rulesets/phases/${encodeURIComponent(phase)}/entrypoint`,
		);
		return response.result;
	}

	// Account-level rulesets
	async listAccountRulesets(accountId: string, phase?: string): Promise<Ruleset[]> {
		const params = new URLSearchParams();
		if (phase) {
			params.set("phase", phase);
		}
		const queryString = params.toString();
		const response = await this.request<Ruleset[]>(`/accounts/${encodeURIComponent(accountId)}/rulesets${queryString ? `?${queryString}` : ""}`);
		return response.result;
	}

	async getAccountRuleset(accountId: string, rulesetId: string): Promise<Ruleset> {
		const response = await this.request<Ruleset>(`/accounts/${encodeURIComponent(accountId)}/rulesets/${encodeURIComponent(rulesetId)}`);
		return response.result;
	}

	// Security events via GraphQL
	async getSecurityEvents(
		zoneTag: string,
		startTime: string,
		endTime: string,
		limit: number = 100,
	): Promise<SecurityEvent[]> {
		const query = `
			query GetSecurityEvents($zoneTag: string!, $start: Time!, $end: Time!, $limit: Int!) {
				viewer {
					zones(filter: { zoneTag: $zoneTag }) {
						firewallEventsAdaptive(
							filter: { datetime_geq: $start, datetime_leq: $end }
							limit: $limit
							orderBy: [datetime_DESC]
						) {
							action
							clientAsn
							clientCountryName
							clientIP
							clientRequestPath
							clientRequestQuery
							datetime
							source
							userAgent
							ruleId
						}
					}
				}
			}
		`;

		const result = await this.graphqlRequest<{
			viewer: {
				zones: Array<{
					firewallEventsAdaptive: SecurityEvent[];
				}>;
			};
		}>(query, {
			zoneTag,
			start: startTime,
			end: endTime,
			limit,
		});

		return result.viewer.zones[0]?.firewallEventsAdaptive || [];
	}

	async getSecurityEventsSummary(
		zoneTag: string,
		startTime: string,
		endTime: string,
	): Promise<{
		byAction: Array<{ action: string; count: number }>;
		bySource: Array<{ source: string; count: number }>;
		byCountry: Array<{ country: string; count: number }>;
	}> {
		const query = `
			query GetSecuritySummary($zoneTag: string!, $start: Time!, $end: Time!) {
				viewer {
					zones(filter: { zoneTag: $zoneTag }) {
						byAction: firewallEventsAdaptiveGroups(
							filter: { datetime_geq: $start, datetime_leq: $end }
							limit: 20
							orderBy: [count_DESC]
						) {
							count
							dimensions {
								action
							}
						}
						bySource: firewallEventsAdaptiveGroups(
							filter: { datetime_geq: $start, datetime_leq: $end }
							limit: 20
							orderBy: [count_DESC]
						) {
							count
							dimensions {
								source
							}
						}
						byCountry: firewallEventsAdaptiveGroups(
							filter: { datetime_geq: $start, datetime_leq: $end }
							limit: 20
							orderBy: [count_DESC]
						) {
							count
							dimensions {
								clientCountryName
							}
						}
					}
				}
			}
		`;

		const result = await this.graphqlRequest<{
			viewer: {
				zones: Array<{
					byAction: Array<{ count: number; dimensions: { action: string } }>;
					bySource: Array<{ count: number; dimensions: { source: string } }>;
					byCountry: Array<{ count: number; dimensions: { clientCountryName: string } }>;
				}>;
			};
		}>(query, {
			zoneTag,
			start: startTime,
			end: endTime,
		});

		const zone = result.viewer.zones[0];
		return {
			byAction: zone?.byAction.map((item) => ({ action: item.dimensions.action, count: item.count })) || [],
			bySource: zone?.bySource.map((item) => ({ source: item.dimensions.source, count: item.count })) || [],
			byCountry:
				zone?.byCountry.map((item) => ({ country: item.dimensions.clientCountryName, count: item.count })) || [],
		};
	}

	async getTopAttackedPaths(
		zoneTag: string,
		startTime: string,
		endTime: string,
		limit: number = 10,
	): Promise<Array<{ path: string; count: number }>> {
		const query = `
			query GetTopAttackedPaths($zoneTag: string!, $start: Time!, $end: Time!, $limit: Int!) {
				viewer {
					zones(filter: { zoneTag: $zoneTag }) {
						firewallEventsAdaptiveGroups(
							filter: { datetime_geq: $start, datetime_leq: $end }
							limit: $limit
							orderBy: [count_DESC]
						) {
							count
							dimensions {
								clientRequestPath
							}
						}
					}
				}
			}
		`;

		const result = await this.graphqlRequest<{
			viewer: {
				zones: Array<{
					firewallEventsAdaptiveGroups: Array<{
						count: number;
						dimensions: { clientRequestPath: string };
					}>;
				}>;
			};
		}>(query, {
			zoneTag,
			start: startTime,
			end: endTime,
			limit,
		});

		return (
			result.viewer.zones[0]?.firewallEventsAdaptiveGroups.map((item) => ({
				path: item.dimensions.clientRequestPath,
				count: item.count,
			})) || []
		);
	}

	// User info
	async getUserInfo(): Promise<{ id: string; email: string; username?: string }> {
		const response = await this.request<{ id: string; email: string; username?: string }>(
			"/user",
		);
		return response.result;
	}

	// Write operations for WAF rules
	async createCustomRule(
		zoneId: string,
		rule: {
			description: string;
			expression: string;
			action: string;
			enabled: boolean;
		},
	): Promise<RulesetRule> {
		// First, get or create the entry point ruleset
		let rulesetId: string;
		try {
			const ruleset = await this.getEntryPointRuleset(zoneId, "http_request_firewall_custom");
			rulesetId = ruleset.id;
		} catch (error: any) {
			// If ruleset doesn't exist, create it
			if (error.message?.includes("404") || error.message?.includes("not found")) {
				const newRuleset = await this.request<Ruleset>(`/zones/${encodeURIComponent(zoneId)}/rulesets`, {
					method: "POST",
					body: JSON.stringify({
						name: "Custom Firewall Rules",
						kind: "zone",
						phase: "http_request_firewall_custom",
						rules: [],
					}),
				});
				rulesetId = newRuleset.result.id;
			} else {
				throw error;
			}
		}

		// Add the rule to the ruleset
		const response = await this.request<Ruleset>(`/zones/${encodeURIComponent(zoneId)}/rulesets/${encodeURIComponent(rulesetId)}/rules`, {
			method: "POST",
			body: JSON.stringify(rule),
		});

		return response.result.rules[response.result.rules.length - 1];
	}

	async updateCustomRule(
		zoneId: string,
		rulesetId: string,
		ruleId: string,
		updates: {
			description?: string;
			expression?: string;
			action?: string;
			enabled?: boolean;
		},
	): Promise<RulesetRule> {
		const response = await this.request<Ruleset>(
			`/zones/${encodeURIComponent(zoneId)}/rulesets/${encodeURIComponent(rulesetId)}/rules/${encodeURIComponent(ruleId)}`,
			{
				method: "PATCH",
				body: JSON.stringify(updates),
			},
		);

		// Find the updated rule in the response
		const updatedRule = response.result.rules.find((r) => r.id === ruleId);
		if (!updatedRule) {
			throw new Error("Updated rule not found in response");
		}
		return updatedRule;
	}

	async deleteCustomRule(zoneId: string, rulesetId: string, ruleId: string): Promise<void> {
		await this.request<void>(`/zones/${encodeURIComponent(zoneId)}/rulesets/${encodeURIComponent(rulesetId)}/rules/${encodeURIComponent(ruleId)}`, {
			method: "DELETE",
		});
	}
}
