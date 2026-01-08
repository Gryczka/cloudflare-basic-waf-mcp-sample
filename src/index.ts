/**
 * Cloudflare WAF MCP Server
 *
 * A Model Context Protocol (MCP) server for managing Cloudflare WAF rules.
 * This is the main entry point that:
 * - Defines the WafMCP Durable Object class for stateful session handling
 * - Registers all tools, prompts, and resources
 * - Handles HTTP routing for MCP and info endpoints
 *
 * Architecture:
 * - Each authenticated user gets their own Durable Object instance
 * - The Durable Object stores user context (API token, user info)
 * - Tools use the stored token to make authenticated Cloudflare API calls
 *
 * Learn more about MCP: https://modelcontextprotocol.io/
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpAgent } from "agents/mcp";
import { CloudflareApi } from "./cloudflare-api";
import { registerPrompts } from "./prompts";
import { registerResources } from "./resources";
import { registerWafAnalyticsTools } from "./tools/waf-analytics";
import { registerWafReadTools } from "./tools/waf-read";
import { registerWafWriteTools } from "./tools/waf-write";

// User context stored in Durable Object props
type Props = {
	userId: string;
	email: string;
	accessToken: string;
};

export class WafMCP extends McpAgent<Env, Record<string, never>, Props> {
	server = new McpServer({
		name: "Cloudflare WAF MCP Server",
		version: "1.0.0",
	});

	async init() {
		// Create a helper to get the API client with the user's access token
		// This is called by tools to get an authenticated API client
		const getApi = () => new CloudflareApi(this.props!.accessToken);

		// Register MCP Tools
		// Tools are executable actions that the AI can invoke
		// See: https://spec.modelcontextprotocol.io/specification/server/tools/

		// Read tools: accounts, zones, rules, rulesets
		registerWafReadTools(this.server, getApi);

		// Analytics tools: security events, attack summaries
		registerWafAnalyticsTools(this.server, getApi);

		// Write tools: create, update, delete rules + intelligent suggestions
		registerWafWriteTools(this.server, getApi);

		// Register MCP Prompts
		// Prompts are guided workflow templates for complex tasks
		// See: https://spec.modelcontextprotocol.io/specification/server/prompts/
		registerPrompts(this.server);

		// Register MCP Resources
		// Resources provide reference documentation and context
		// See: https://spec.modelcontextprotocol.io/specification/server/resources/
		registerResources(this.server);
	}

	/**
	 * Custom authentication handler for API token mode
	 * This validates the Cloudflare API token and fetches user info
	 */
	async authenticate(token: string): Promise<Props> {
		// Validate token by fetching user info
		const api = new CloudflareApi(token);
		try {
			const userInfo = await api.getUserInfo();
			return {
				userId: userInfo.id,
				email: userInfo.email,
				accessToken: token,
			};
		} catch (error: any) {
			throw new Error(`Invalid Cloudflare API token: ${error.message}`);
		}
	}
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);

		// Handle MCP endpoint
		if (url.pathname === "/mcp" || url.pathname.startsWith("/mcp/")) {
			// Extract API token from Authorization header or environment variable
			const authHeader = request.headers.get("Authorization");
			const envToken = (env as any).CLOUDFLARE_API_TOKEN;

			let props: Props | undefined;

			// Try Authorization header first, then fall back to env token
			let token: string | undefined;
			if (authHeader?.startsWith("Bearer ")) {
				token = authHeader.slice(7);
			} else if (envToken) {
				// Handle both "Bearer xxx" and plain "xxx" formats
				token = envToken.startsWith("Bearer ") ? envToken.slice(7) : envToken;
			}

			if (token) {
				try {
					// Validate token by fetching user info
					const api = new CloudflareApi(token);
					const userInfo = await api.getUserInfo();
					props = {
						userId: userInfo.id,
						email: userInfo.email,
						accessToken: token,
					};
				} catch (error: any) {
					// Token validation failed - continue without props
					console.error("Token validation failed:", error.message);
				}
			}

			const mcpCtx = Object.assign({}, ctx, { props }) as ExecutionContext & { props?: Props };
			return WafMCP.serve("/mcp").fetch(request, env, mcpCtx);
		}

		// Return a simple info page for the root
		if (url.pathname === "/") {
			return new Response(
				`
<!DOCTYPE html>
<html>
<head>
	<title>Cloudflare WAF MCP Server</title>
	<style>
		body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; line-height: 1.6; }
		h1 { color: #f38020; }
		code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
		pre { background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }
	</style>
</head>
<body>
	<h1>Cloudflare WAF MCP Server</h1>
	<p>This is a Model Context Protocol (MCP) server for managing Cloudflare WAF rules and viewing security analytics.</p>

	<h2>Authentication</h2>
	<p>This server uses Cloudflare API token authentication. You'll need to provide your API token when connecting.</p>

	<h3>Creating an API Token</h3>
	<ol>
		<li>Log in to the <a href="https://dash.cloudflare.com">Cloudflare Dashboard</a></li>
		<li>Go to <strong>My Profile → API Tokens</strong></li>
		<li>Click <strong>Create Token</strong></li>
		<li>Use a template or create a custom token with these permissions:
			<ul>
				<li><strong>Account → Account Settings → Read</strong></li>
				<li><strong>Zone → Zone → Read</strong></li>
				<li><strong>Zone → Firewall Services → Edit</strong> (for creating/updating rules)</li>
				<li><strong>Zone → Analytics → Read</strong></li>
				<li><strong>User → User Details → Read</strong></li>
			</ul>
		</li>
		<li>Copy the token (shown only once)</li>
	</ol>

	<h2>Connecting</h2>
	<p>MCP Endpoint: <code>${url.origin}/mcp</code></p>

	<h3>Claude Desktop Configuration</h3>
	<pre>{
  "mcpServers": {
    "cloudflare-waf": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "${url.origin}/mcp"
      ],
      "env": {
        "CLOUDFLARE_API_TOKEN": "your-api-token-here"
      }
    }
  }
}</pre>

	<h2>Available Tools</h2>
	<h3>Read Operations</h3>
	<ul>
		<li><strong>list_accounts</strong> - List Cloudflare accounts</li>
		<li><strong>list_zones</strong> - List zones (domains)</li>
		<li><strong>list_custom_rules</strong> - List custom WAF rules</li>
		<li><strong>list_managed_rulesets</strong> - List managed rulesets</li>
		<li><strong>get_security_events</strong> - Query security events</li>
		<li><strong>get_attack_summary</strong> - Attack pattern summaries</li>
		<li>...and more</li>
	</ul>
	<h3>Write Operations</h3>
	<ul>
		<li><strong>create_custom_rule</strong> - Create new WAF rules</li>
		<li><strong>update_custom_rule</strong> - Update existing rules</li>
		<li><strong>delete_custom_rule</strong> - Delete rules</li>
		<li><strong>toggle_rule</strong> - Quickly enable/disable rules</li>
		<li><strong>suggest_rule_from_events</strong> - AI-powered rule suggestions from attack patterns</li>
	</ul>

	<p><a href="https://github.com/Gryczka/cloudflare-basic-waf-mcp-sample">Documentation</a></p>
</body>
</html>
				`,
				{
					headers: {
						"Content-Type": "text/html; charset=utf-8",
						"X-Content-Type-Options": "nosniff",
						"X-Frame-Options": "DENY",
						"X-XSS-Protection": "1; mode=block",
						"Referrer-Policy": "strict-origin-when-cross-origin",
						"Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'",
					},
				},
			);
		}

		return new Response("Not Found", { status: 404 });
	},
} satisfies ExportedHandler<Env>;
