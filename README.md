# Cloudflare WAF MCP Server

A reference implementation of a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for managing Cloudflare Web Application Firewall (WAF) rules. Built on Cloudflare Workers with Durable Objects for stateful session management.

This project demonstrates how to build MCP servers that give AI assistants secure, authenticated access to cloud infrastructure APIs.

> [!WARNING]
> **Not Production Ready**: This is a reference implementation for educational purposes only. It has not been audited for security vulnerabilities and should not be deployed to production environments without thorough review and hardening.

> [!NOTE]
> **Learning Resource**: This repository serves as an educational example for developers building their own MCP servers. See the [Architecture](#architecture) and [Extending the Server](#extending-the-server) sections for implementation patterns.

## Features

- **Read Operations**: List accounts, zones, rulesets, and security events
- **Write Operations**: Create, update, delete, and toggle WAF rules
- **Analytics**: Query security events, attack summaries, and top attacked paths
- **AI-Powered Suggestions**: Analyze attack patterns and suggest protective rules
- **Built-in Prompts**: Pre-configured workflows for common WAF operations
- **Secure Authentication**: API token-based auth with per-user isolation via Durable Objects

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Claude Desktop / MCP Client                   │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ MCP Protocol (SSE/HTTP)
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Cloudflare Workers Edge                         │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                     WAF MCP Server                             │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │  │
│  │  │   Tools     │  │  Prompts    │  │    Resources        │   │  │
│  │  │ - read ops  │  │ - audit     │  │ - waf://overview    │   │  │
│  │  │ - write ops │  │ - builder   │  │ - waf://guidance    │   │  │
│  │  │ - analytics │  │ - incident  │  │                     │   │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘   │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                │                                     │
│                    ┌───────────┴───────────┐                        │
│                    ▼                       ▼                        │
│  ┌─────────────────────────┐  ┌─────────────────────────────────┐  │
│  │     Durable Object      │  │      Cloudflare API v4          │  │
│  │  (Session & Auth State) │  │  (REST + GraphQL Analytics)     │  │
│  └─────────────────────────┘  └─────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Purpose | Implementation |
|-----------|---------|----------------|
| **MCP Server** | Protocol handling, tool/prompt/resource registration | `src/index.ts` using `@modelcontextprotocol/sdk` |
| **Durable Object** | Per-user session state, token storage | `WafMCP` class extending `McpAgent` |
| **Cloudflare API Client** | REST and GraphQL API calls | `src/cloudflare-api.ts` |
| **Tools** | Executable actions (read/write/analytics) | `src/tools/*.ts` |
| **Prompts** | Guided workflow templates | `src/prompts/index.ts` |
| **Resources** | Static context and documentation | `src/resources/index.ts` |

## Quick Start

### Prerequisites

- Node.js 18+
- A Cloudflare account
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)

### 1. Clone and Install

```bash
git clone https://github.com/gryczka/waf-mcp-server.git
cd waf-mcp-server
npm install
```

### 2. Create a Cloudflare API Token

1. Go to the [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Navigate to **My Profile > API Tokens**
3. Click **Create Token**
4. Create a custom token with these permissions:

| Resource | Permission | Required For |
|----------|------------|--------------|
| Account Settings | Read | Listing accounts |
| Zone | Read | Listing zones and zone details |
| Firewall Services | Edit | Reading and writing WAF rules |
| Analytics | Read | Security events and attack data |
| User Details | Read | Token validation |

### 3. Run Locally

```bash
npm run dev
```

The server starts at `http://localhost:8788`. Visit the root URL to see setup instructions.

### 4. Test with MCP Inspector

```bash
npx @modelcontextprotocol/inspector@latest
```

Enter `http://localhost:8788/mcp` as the endpoint and provide your API token when prompted.

### 5. Connect with Claude Desktop

Add to your Claude Desktop configuration:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "cloudflare-waf": {
      "command": "npx",
      "args": ["mcp-remote", "http://localhost:8788/mcp"]
    }
  }
}
```

### 6. Deploy to Production

```bash
# Set your account ID
export CLOUDFLARE_ACCOUNT_ID="your-account-id"

npm run deploy
```

Then update your Claude Desktop config to use the production URL:
```
https://waf-mcp-server.<your-subdomain>.workers.dev/mcp
```

## Available Tools

### Read Operations

| Tool | Description |
|------|-------------|
| `list_accounts` | List all Cloudflare accounts you have access to |
| `list_zones` | List zones (domains) in an account |
| `get_zone` | Get detailed information about a specific zone |
| `list_custom_rules` | List custom WAF rules for a zone |
| `list_managed_rulesets` | List managed WAF rulesets (OWASP, Cloudflare Managed, etc.) |
| `get_ruleset` | Get a specific ruleset with all its rules |
| `list_all_rulesets` | List all rulesets across all phases |
| `list_account_rulesets` | List account-level rulesets (Enterprise) |

### Write Operations

| Tool | Description |
|------|-------------|
| `create_custom_rule` | Create a new custom WAF rule |
| `update_custom_rule` | Update an existing rule's expression, action, or status |
| `delete_custom_rule` | Delete a custom rule |
| `toggle_rule` | Quickly enable or disable a rule |

### Analytics

| Tool | Description |
|------|-------------|
| `get_security_events` | Query recent security events (blocks, challenges, etc.) |
| `get_attack_summary` | Get aggregated attack data by action, source, and country |
| `get_top_attacked_paths` | Identify the most frequently attacked URL paths |
| `suggest_rule_from_events` | Analyze patterns and suggest protective rules |

## Built-in Prompts

The server includes pre-configured prompts for common WAF workflows. Prompts provide guided, multi-step interactions for complex tasks.

| Prompt | Description | Use Case |
|--------|-------------|----------|
| `security_audit` | Comprehensive security posture review | Regular security assessments |
| `rule_builder` | Interactive rule creation workflow | Creating rules for specific threats |
| `incident_response` | Attack investigation and mitigation | Active incident handling |
| `compliance_check` | Best practices and coverage review | Security compliance audits |

### Using Prompts

In Claude Desktop, you can invoke prompts directly:

```
Use the security_audit prompt to review my zone example.com
```

Or prompts may be suggested contextually based on your conversation.

## Example Conversations

### Security Audit

```
User: Audit the security posture of my main website

Claude: I'll perform a comprehensive security audit of your zone.
[Uses list_custom_rules, list_managed_rulesets, get_security_events]

Security Audit Summary for example.com:

Current Protection:
✓ 12 custom rules active
✓ Cloudflare Managed Ruleset deployed
✓ OWASP Core Ruleset enabled

Recent Activity (24h):
- 1,247 requests blocked
- 89 challenges issued
- Top threat: SQL injection attempts (43%)

Recommendations:
1. Add rate limiting for /api/* endpoints (high traffic, no protection)
2. Enable Bot Management for login pages
3. Consider geo-blocking for countries with no legitimate traffic
```

### Creating a Protective Rule

```
User: Block all traffic from country X to our admin panel

Claude: I'll create a custom WAF rule for that protection.
[Uses create_custom_rule tool]

Created rule successfully:
- Name: Block Country X Admin Access
- Expression: (ip.geoip.country eq "XX") and (http.request.uri.path contains "/admin")
- Action: Block
- Status: Enabled

The rule is now active. All requests from country X to /admin/* paths will be blocked.
Would you like me to also add logging for this rule to monitor blocked attempts?
```

### Incident Response

```
User: We're seeing a spike in 403 errors, investigate

Claude: I'll analyze recent security events to understand the pattern.
[Uses get_security_events, get_attack_summary, get_top_attacked_paths]

Incident Analysis:

Attack Pattern Detected:
- 2,847 requests blocked in the last hour (10x normal)
- Source: 73% from AS12345 (Example Hosting Provider)
- Target: /api/v1/users endpoint
- Signature: Credential stuffing attack (multiple failed auth attempts)

Immediate Actions Available:
1. Create rate limiting rule for /api/v1/users
2. Block the specific ASN temporarily
3. Enable managed challenge for suspicious requests

Shall I implement any of these mitigations?
```

## Project Structure

```
waf-mcp-server/
├── src/
│   ├── index.ts              # Entry point, routing, Durable Object definition
│   ├── cloudflare-api.ts     # Cloudflare API client (REST + GraphQL)
│   ├── validation.ts         # Zod schemas for input validation
│   ├── tools/
│   │   ├── waf-read.ts       # Read operation tools
│   │   ├── waf-write.ts      # Write operation tools
│   │   └── waf-analytics.ts  # Analytics and events tools
│   ├── prompts/
│   │   └── index.ts          # MCP prompts for guided workflows
│   └── resources/
│       └── index.ts          # MCP resources for context
├── docs/
│   ├── architecture.md       # Detailed architecture documentation
│   └── use-cases.md          # Real-world usage examples
├── .github/
│   ├── workflows/ci.yml      # GitHub Actions CI
│   └── ISSUE_TEMPLATE/       # Issue templates
├── wrangler.jsonc            # Cloudflare Workers configuration
├── tsconfig.json             # TypeScript configuration
├── CONTRIBUTING.md           # Contribution guidelines
├── LICENSE                   # Apache 2.0 license
└── package.json
```

## Extending the Server

This project is designed as a learning resource. Here's how to extend it:

### Adding a New Tool

Tools are the primary way MCP servers expose functionality. Each tool has a name, description, input schema, and handler.

```typescript
// src/tools/my-tools.ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { CloudflareApi } from "../cloudflare-api";

export function registerMyTools(server: McpServer, getApi: () => CloudflareApi) {
  server.tool(
    "my_custom_tool",                              // Tool name
    "Description shown to the AI assistant",       // Description
    {
      zoneId: z.string().describe("The zone ID"),  // Input schema with Zod
      option: z.boolean().optional(),
    },
    async ({ zoneId, option }) => {                // Handler function
      const api = getApi();
      const result = await api.someMethod(zoneId);

      return {
        content: [{
          type: "text",
          text: JSON.stringify(result, null, 2)
        }],
      };
    },
  );
}
```

Then register in `src/index.ts`:

```typescript
import { registerMyTools } from "./tools/my-tools";

// In WafMCP.init():
registerMyTools(this.server, getApi);
```

### Adding a New Prompt

Prompts are templates for guided workflows. They can include arguments and return structured conversation starters.

```typescript
// src/prompts/index.ts
server.prompt(
  "my_workflow",
  "Guided workflow for specific task",
  {
    zone: z.string().describe("Zone to analyze"),
    depth: z.enum(["quick", "thorough"]).optional(),
  },
  async ({ zone, depth = "quick" }) => ({
    messages: [
      {
        role: "user",
        content: {
          type: "text",
          text: `Perform a ${depth} analysis of zone ${zone}.
                 Start by listing current rules, then analyze recent events,
                 and provide recommendations.`,
        },
      },
    ],
  }),
);
```

### Adding a New Resource

Resources provide static or dynamic context that the AI can reference.

```typescript
// src/resources/index.ts
server.resource(
  "waf://expression-syntax",
  "Cloudflare WAF expression syntax reference",
  async () => ({
    contents: [{
      uri: "waf://expression-syntax",
      mimeType: "text/markdown",
      text: `# WAF Expression Syntax

## Fields
- \`ip.src\` - Client IP address
- \`http.request.uri.path\` - Request path
- \`http.user_agent\` - User agent string
...`,
    }],
  }),
);
```

## Security Considerations

### Authentication Model

- **Per-user isolation**: Each authenticated user gets their own Durable Object instance
- **Token validation**: API tokens validated against Cloudflare `/user` endpoint before use
- **No stored secrets**: The server itself stores no secrets; users provide their own tokens

### Securing the MCP Endpoint in Production (Recommended)

By default, the `/mcp` endpoint is publicly accessible. While users can only access data their API token permits, you may want to restrict who can connect to your MCP server entirely.

**Cloudflare Access** is the recommended solution for production deployments. It adds identity-based authentication before users can reach your MCP endpoint.

#### Setting Up Cloudflare Access

1. **Navigate to Zero Trust Dashboard**
   - Go to [Cloudflare Zero Trust](https://one.dash.cloudflare.com/)
   - Select your account

2. **Create an Access Application**
   - Go to **Access > Applications**
   - Click **Add an application**
   - Select **Self-hosted**

3. **Configure the Application**
   ```
   Application name: WAF MCP Server
   Session duration: 24 hours (or your preference)

   Application domain:
   - Subdomain: waf-mcp-server (your worker subdomain)
   - Domain: <your-account>.workers.dev
   - Path: /mcp
   ```

4. **Create an Access Policy**

   Define who can access your MCP server:

   | Policy Type | Example Configuration |
   |-------------|----------------------|
   | **Email** | Allow specific emails (`you@company.com`) |
   | **Email Domain** | Allow your organization (`@company.com`) |
   | **GitHub Organization** | Allow org members |
   | **Google Workspace** | Allow workspace users |
   | **Service Token** | For programmatic access |

   Example policy for personal use:
   ```
   Policy name: Personal Access
   Action: Allow

   Include:
   - Selector: Emails
   - Value: your-email@example.com
   ```

5. **Configure MCP Client for Access**

   When connecting through Cloudflare Access, you'll need to authenticate first. For Claude Desktop with `mcp-remote`:

   ```json
   {
     "mcpServers": {
       "cloudflare-waf": {
         "command": "npx",
         "args": [
           "mcp-remote",
           "https://waf-mcp-server.<account>.workers.dev/mcp"
         ]
       }
     }
   }
   ```

   The first connection will open a browser for Access authentication. After authenticating, your session is cached.

   For **Service Token** authentication (headless/automated):

   ```bash
   # Create a service token in Zero Trust > Access > Service Auth
   # Then use the token headers in your client
   CF-Access-Client-Id: <service-token-id>
   CF-Access-Client-Secret: <service-token-secret>
   ```

#### Alternative: Cloudflare Tunnel with Access

For more advanced setups, you can run the MCP server locally and expose it through a Cloudflare Tunnel with Access policies:

```bash
# Install cloudflared
brew install cloudflared  # or appropriate installer

# Create a tunnel
cloudflared tunnel create waf-mcp

# Configure tunnel (in ~/.cloudflared/config.yml)
tunnel: <tunnel-id>
credentials-file: ~/.cloudflared/<tunnel-id>.json
ingress:
  - hostname: waf-mcp.yourdomain.com
    service: http://localhost:8788
  - service: http_status:404

# Run the tunnel
cloudflared tunnel run waf-mcp
```

Then apply Access policies to `waf-mcp.yourdomain.com` in the Zero Trust dashboard.

#### Access + API Token: Defense in Depth

With Cloudflare Access enabled, your MCP server has two layers of authentication:

1. **Cloudflare Access**: Verifies the user's identity before reaching the endpoint
2. **API Token**: Validates the user has Cloudflare API permissions for the requested operations

This provides defense in depth—even if someone bypasses Access, they still need a valid API token to access any data.

### Input Validation

All inputs are validated using Zod schemas with:
- Regex patterns for Cloudflare IDs (32-character hex strings)
- Length limits on string fields
- Enum restrictions for action types

### Error Handling

Error messages are sanitized to prevent information disclosure:
- Bearer tokens are redacted
- Long hex strings (IDs) are redacted
- Email addresses and IPs are redacted
- Messages are truncated to 200 characters

### Security Headers

The info page includes security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Content-Security-Policy`

## Development

### Commands

```bash
npm run dev        # Start local development server (port 8788)
npm run deploy     # Deploy to Cloudflare Workers
npm run type-check # Run TypeScript type checking
npm run cf-typegen # Generate Cloudflare Workers types
```

### Testing Locally

1. Start the dev server: `npm run dev`
2. Use MCP Inspector: `npx @modelcontextprotocol/inspector@latest`
3. Connect to `http://localhost:8788/mcp`
4. Provide your Cloudflare API token when prompted

### Code Style

The project uses Prettier for formatting:

```bash
npx prettier --write .
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Resources

- [Model Context Protocol Specification](https://spec.modelcontextprotocol.io/)
- [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk)
- [Cloudflare WAF Documentation](https://developers.cloudflare.com/waf/)
- [Cloudflare Workers Documentation](https://developers.cloudflare.com/workers/)
- [Cloudflare Ruleset Engine](https://developers.cloudflare.com/ruleset-engine/)

## Related Projects

- [cloudflare/agents](https://github.com/cloudflare/agents) - Build AI agents on Cloudflare
- [cloudflare/mcp-server-cloudflare](https://github.com/cloudflare/mcp-server-cloudflare) - General Cloudflare MCP server
