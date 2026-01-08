# Architecture

This document describes the architecture of the Cloudflare WAF MCP Server, providing insights for developers who want to understand how it works or build similar MCP servers.

## Overview

The WAF MCP Server is a Model Context Protocol (MCP) server that runs on Cloudflare Workers. It provides AI assistants with tools, prompts, and resources for managing Cloudflare WAF rules.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              MCP Client                                   │
│                    (Claude Desktop, Cursor, etc.)                        │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ HTTP + Server-Sent Events
                                    │ (MCP Protocol)
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                        Cloudflare Workers                                 │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │                     Request Handler (fetch)                         │  │
│  │  - Routes /mcp to MCP server                                       │  │
│  │  - Serves info page at /                                           │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                    │                                      │
│                                    ▼                                      │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │                     Durable Object (WafMCP)                         │  │
│  │  - Per-user session management                                     │  │
│  │  - Stores authenticated user context                               │  │
│  │  - Handles MCP protocol messages                                   │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐   │  │
│  │  │    Tools     │  │   Prompts    │  │      Resources         │   │  │
│  │  │  (Actions)   │  │ (Workflows)  │  │ (Reference Material)   │   │  │
│  │  └──────────────┘  └──────────────┘  └────────────────────────┘   │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                    │                                      │
│                                    ▼                                      │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │                     Cloudflare API Client                          │  │
│  │  - REST API for WAF operations                                     │  │
│  │  - GraphQL API for analytics                                       │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                        ┌───────────────────┐
                        │  Cloudflare API   │
                        │  api.cloudflare.com│
                        └───────────────────┘
```

## Components

### 1. Request Handler (`src/index.ts`)

The main entry point that handles incoming HTTP requests and authentication:

```typescript
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);

    if (url.pathname === "/mcp" || url.pathname.startsWith("/mcp/")) {
      // Extract API token from Authorization header or environment variable
      const authHeader = request.headers.get("Authorization");
      const envToken = env.CLOUDFLARE_API_TOKEN;

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

      // Pass props via context to the MCP handler
      const mcpCtx = Object.assign({}, ctx, { props });
      return WafMCP.serve("/mcp").fetch(request, env, mcpCtx);
    }

    // Serve info page at root
    if (url.pathname === "/") {
      return new Response(/* HTML info page */);
    }

    return new Response("Not Found", { status: 404 });
  },
};
```

**Token Sources (in priority order):**
1. `Authorization: Bearer <token>` header
2. `CLOUDFLARE_API_TOKEN` environment variable (from `.dev.vars` or secrets)

### 2. Durable Object (`WafMCP` class)

The Durable Object provides stateful session management:

```typescript
export class WafMCP extends McpAgent<Env, Record<string, never>, Props> {
  // MCP server instance
  server = new McpServer({
    name: "Cloudflare WAF MCP Server",
    version: "1.0.0",
  });

  // Called once when the Durable Object is initialized
  async init() {
    // Create helper to get authenticated API client
    const getApi = () => new CloudflareApi(this.props!.accessToken);

    // Register tools, prompts, and resources
    registerWafReadTools(this.server, getApi);
    registerWafAnalyticsTools(this.server, getApi);
    registerWafWriteTools(this.server, getApi);
    registerPrompts(this.server);
    registerResources(this.server);
  }
}
```

**Why Durable Objects?**

- **Session Persistence**: Maintains user context across multiple requests
- **Isolation**: Each user gets their own Durable Object instance
- **State Management**: Stores authenticated tokens securely (passed via execution context)
- **Consistent Behavior**: Same instance handles all requests for a session

### 3. Cloudflare API Client (`src/cloudflare-api.ts`)

Handles all communication with Cloudflare APIs:

```typescript
export class CloudflareApi {
  private accessToken: string;

  // REST API calls
  private async request<T>(endpoint: string, options?: RequestInit) {
    const response = await fetch(`${CF_API_BASE}${endpoint}`, {
      headers: { Authorization: `Bearer ${this.accessToken}` },
      ...options,
    });
    // Handle response
  }

  // GraphQL API calls (for analytics)
  private async graphqlRequest<T>(query: string, variables: object) {
    // Execute GraphQL query
  }

  // Business methods
  async listZones() { /* ... */ }
  async createCustomRule() { /* ... */ }
  async getSecurityEvents() { /* ... */ }
}
```

**Design Decisions:**

- Separate REST and GraphQL methods for different API styles
- Error sanitization to prevent sensitive data leakage
- URL encoding for all path parameters
- Parameterized GraphQL queries to prevent injection

### 4. Tools (`src/tools/`)

Tools are the primary way MCP servers expose functionality to AI assistants:

```typescript
server.tool(
  "tool_name",           // Unique identifier
  "Description",         // Helps AI understand when to use this tool
  {
    param: z.string(),   // Zod schema for input validation
  },
  async ({ param }) => { // Handler function
    // Execute tool logic
    return {
      content: [{ type: "text", text: result }],
    };
  },
);
```

**Tool Categories:**

| Category | Purpose | Tools |
|----------|---------|-------|
| Read | Retrieve configuration | list_zones, list_custom_rules, etc. |
| Write | Modify configuration | create_custom_rule, update_custom_rule, etc. |
| Analytics | Query security data | get_security_events, get_attack_summary, etc. |

### 5. Prompts (`src/prompts/index.ts`)

Prompts are workflow templates that guide AI assistants through complex tasks:

```typescript
server.prompt(
  "prompt_name",
  "Description of this workflow",
  {
    param: z.string().optional(),
  },
  async ({ param }) => ({
    messages: [
      {
        role: "user",
        content: {
          type: "text",
          text: "Detailed instructions for the AI...",
        },
      },
    ],
  }),
);
```

**Why Prompts?**

- Guide AI through multi-step workflows
- Ensure consistent approach to common tasks
- Provide structure for complex operations
- Reduce need for user to know exact steps

### 6. Resources (`src/resources/index.ts`)

Resources provide reference material the AI can access:

```typescript
server.resource(
  "waf://expression-syntax",
  "WAF expression syntax reference",
  async () => ({
    contents: [{
      uri: "waf://expression-syntax",
      mimeType: "text/markdown",
      text: "# Expression Syntax\n...",
    }],
  }),
);
```

**Resource Types:**

- Expression syntax reference
- Available actions documentation
- Common attack patterns
- Rule templates

## Authentication Flow

```
┌────────┐     ┌─────────────┐     ┌──────────────┐     ┌───────────────┐
│ Client │────▶│ MCP Server  │────▶│   Request    │────▶│ Cloudflare    │
│        │     │             │     │   Handler    │     │ /user endpoint│
└────────┘     └─────────────┘     └──────────────┘     └───────────────┘
     │                                    │                      │
     │     Token from header or env       │                      │
     │◀───────────────────────────────────│                      │
     │                                    │    Validate token    │
     │                                    │─────────────────────▶│
     │                                    │                      │
     │                                    │    User info         │
     │                                    │◀─────────────────────│
     │                                    │                      │
     │         Store in props             │                      │
     │         (userId, email, token)     │                      │
     │                                    │                      │
     │         Session established        │                      │
     │◀───────────────────────────────────│                      │
```

**Key Points:**

1. Token sourced from `Authorization` header or `CLOUDFLARE_API_TOKEN` environment variable
2. Token validated against Cloudflare `/user` endpoint
3. User context stored in Durable Object props via execution context
4. All subsequent tool calls use stored token
5. Each user gets isolated Durable Object instance

## Security Architecture

### Endpoint Protection with Cloudflare Access

For production deployments, we recommend protecting the `/mcp` endpoint with [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/). This adds identity-based authentication before users can reach the MCP server.

```
┌────────────────┐     ┌───────────────────┐     ┌─────────────────┐     ┌─────────────┐
│   MCP Client   │────▶│ Cloudflare Access │────▶│   MCP Server    │────▶│ Cloudflare  │
│                │     │  (Identity Auth)  │     │ (Token Auth)    │     │   API       │
└────────────────┘     └───────────────────┘     └─────────────────┘     └─────────────┘
                              │
                              │ Verify identity via:
                              ├── Email one-time code
                              ├── SSO (Google, GitHub, etc.)
                              ├── Service tokens
                              └── Client certificates
```

**Defense in Depth:**

1. **Layer 1 - Cloudflare Access**: Authenticates the user's identity
2. **Layer 2 - API Token**: Authorizes access to specific Cloudflare resources

Even if Access is bypassed, attackers cannot access any data without a valid Cloudflare API token.

See the [main README](../README.md#securing-the-mcp-endpoint-in-production-recommended) for setup instructions.

### Input Validation

All tool inputs are validated using Zod schemas:

```typescript
// Shared validation schemas
export const cloudflareIdSchema = z
  .string()
  .regex(/^[a-f0-9]{32}$/, "Invalid Cloudflare ID format");

// Used in tools
zoneId: zoneIdSchema,  // Validates format
expression: z.string().max(4096),  // Limits length
action: z.enum(["block", "challenge", ...]),  // Restricts values
```

### Error Sanitization

Errors are sanitized before being returned to clients:

```typescript
function sanitizeErrorMessage(message: string): string {
  return message
    .replace(/Bearer\s+[a-zA-Z0-9_-]+/gi, "Bearer [REDACTED]")
    .replace(/[a-f0-9]{32,}/gi, "[REDACTED_ID]")
    .replace(/[email pattern]/g, "[REDACTED_EMAIL]")
    .substring(0, 200);
}
```

### URL Encoding

All path parameters are encoded to prevent injection:

```typescript
`/zones/${encodeURIComponent(zoneId)}/rulesets/${encodeURIComponent(rulesetId)}`
```

### Security Headers

The info page includes security headers:

```typescript
headers: {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-XSS-Protection": "1; mode=block",
  "Content-Security-Policy": "default-src 'self'",
}
```

## Data Flow

### Tool Execution

```
User Request → MCP Client → MCP Server → Tool Handler → CloudflareApi → Cloudflare API
                                │
                                ├── Validate input (Zod)
                                ├── Get API client (getApi())
                                ├── Make API call
                                ├── Format response
                                └── Return to client
```

### Prompt Execution

```
User invokes prompt → MCP Server returns prompt template → AI follows instructions → AI calls tools
```

## Extending the Architecture

### Adding a New Tool

1. Create handler in appropriate file under `src/tools/`
2. Define Zod schema for inputs
3. Implement logic using CloudflareApi
4. Register in `src/index.ts`

### Adding a New API Method

1. Add method to CloudflareApi class
2. Use proper URL encoding
3. Use parameterized queries for GraphQL
4. Handle errors appropriately

### Adding a New Prompt

1. Add to `src/prompts/index.ts`
2. Define input arguments
3. Create detailed instruction template
4. Reference appropriate tools

## Performance Considerations

- **Durable Objects**: Provide consistent low-latency access to session state
- **Edge Deployment**: Workers run close to users globally
- **Connection Reuse**: HTTP keep-alive for API calls
- **Minimal Dependencies**: Only essential packages included

## Testing Approach

1. **Type Checking**: `npm run type-check` validates TypeScript
2. **Local Development**: `npm run dev` runs local server
3. **MCP Inspector**: Test tools and prompts interactively
4. **Manual Testing**: Verify with real Cloudflare account

## Future Considerations

- **Rate Limiting**: Implement per-user rate limits
- **Audit Logging**: Track all write operations
- **Caching**: Cache read-only data where appropriate
- **Metrics**: Add observability for tool usage
