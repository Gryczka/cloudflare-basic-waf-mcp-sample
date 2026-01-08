/**
 * Input Validation Schemas
 *
 * This module defines Zod schemas for validating MCP tool inputs.
 * Using Zod provides:
 * - Runtime type validation (TypeScript types are compile-time only)
 * - Descriptive error messages for invalid inputs
 * - Schema descriptions that help AI assistants understand parameters
 *
 * Security Benefits:
 * - Prevents path traversal attacks by validating ID formats
 * - Restricts actions to known-safe values
 * - Limits input lengths to prevent abuse
 *
 * Learn more about Zod: https://zod.dev/
 */

import { z } from "zod";

/**
 * Cloudflare ID Format
 *
 * Cloudflare uses 32-character hexadecimal strings for most resource IDs.
 * Examples: zone IDs, account IDs, ruleset IDs, rule IDs
 *
 * This regex ensures:
 * - Exactly 32 characters (no more, no less)
 * - Only lowercase hex characters (a-f, 0-9)
 * - No path traversal characters (../, etc.)
 */
const CLOUDFLARE_ID_REGEX = /^[a-f0-9]{32}$/;

/**
 * Base schema for Cloudflare IDs
 *
 * Used as the foundation for more specific ID schemas.
 * The error message helps users understand the expected format.
 */
export const cloudflareIdSchema = z
	.string()
	.regex(CLOUDFLARE_ID_REGEX, "Invalid Cloudflare ID format (expected 32-character hex string)");

/**
 * Zone ID Schema
 *
 * Zones represent domains in Cloudflare. Each zone has a unique ID
 * that's required for most WAF operations.
 *
 * The .describe() method adds context that helps AI assistants
 * understand how to obtain and use this parameter.
 */
export const zoneIdSchema = cloudflareIdSchema.describe(
	"The zone ID (32-character hex string). Get this from list_zones."
);

/**
 * Account ID Schema
 *
 * Accounts are the top-level container in Cloudflare.
 * Users may have access to multiple accounts.
 */
export const accountIdSchema = cloudflareIdSchema.describe(
	"The account ID (32-character hex string). Get this from list_accounts."
);

/**
 * Ruleset ID Schema
 *
 * Rulesets are collections of rules that apply to a zone.
 * Each phase (e.g., http_request_firewall_custom) has its own ruleset.
 */
export const rulesetIdSchema = cloudflareIdSchema.describe("The ruleset ID (32-character hex string).");

/**
 * Rule ID Schema
 *
 * Individual rules within a ruleset.
 * Each rule has an expression, action, and other properties.
 */
export const ruleIdSchema = cloudflareIdSchema.describe("The rule ID (32-character hex string).");

/**
 * Ruleset Phase Schema
 *
 * Cloudflare processes requests through multiple phases.
 * Each phase has a specific purpose and available features.
 *
 * Key phases for WAF:
 * - http_request_firewall_custom: User-created WAF rules
 * - http_request_firewall_managed: Cloudflare Managed Rules, OWASP, etc.
 * - http_ratelimit: Rate limiting rules
 *
 * Using z.enum() ensures only valid phases are accepted,
 * preventing errors from typos or invalid values.
 */
export const rulesetPhaseSchema = z.enum([
	"http_request_firewall_custom", // Custom WAF rules (most common)
	"http_request_firewall_managed", // Managed rulesets (OWASP, CF Managed)
	"http_ratelimit", // Rate limiting rules
	"http_request_sbfm", // Super Bot Fight Mode
	"http_request_transform", // URL/header transformations
	"http_request_origin", // Origin selection rules
	"http_request_cache_settings", // Cache configuration
	"http_config_settings", // Configuration rules
	"http_request_dynamic_redirect", // Dynamic redirects
	"http_request_redirect", // Static redirects
	"http_response_headers_transform", // Response header modifications
	"http_response_firewall_managed", // Response-phase managed rules
	"http_log_custom_fields", // Custom logging fields
]);

/**
 * WAF Action Schema
 *
 * Defines what happens when a WAF rule matches.
 *
 * Actions from most to least aggressive:
 * - block: Immediately block the request
 * - challenge: Present CAPTCHA challenge
 * - js_challenge: Present JavaScript challenge
 * - managed_challenge: Cloudflare-selected challenge (recommended)
 * - log: Record but don't block (good for testing)
 * - skip: Skip remaining rules (use for allow-lists)
 *
 * Recommendation: Use managed_challenge for most cases,
 * block only for high-confidence malicious traffic.
 */
export const wafActionSchema = z.enum([
	"block", // Immediately block the request
	"challenge", // Present interactive challenge (CAPTCHA)
	"js_challenge", // JavaScript challenge (verifies browser)
	"managed_challenge", // Cloudflare-managed challenge (recommended)
	"log", // Log only, don't block (testing)
	"skip", // Skip remaining rules (allow-lists)
]);
