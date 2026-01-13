/**
 * API mutation detection for curl commands
 *
 * Catches GraphQL mutations and REST API writes to known services:
 * - Linear (api.linear.app) - GraphQL mutation detection
 * - Datadog (api.datadoghq.com) - HTTP method detection
 */

import { extractWords, tokenize } from "../shell/parser.ts";
import { stripWrappers } from "../shell/wrappers.ts";
import type { AnalyzerOptions, SegmentResult } from "../types.ts";

// ============================================================================
// API Endpoint Patterns
// ============================================================================

interface ApiEndpoint {
	name: string;
	patterns: RegExp[];
	analyze: (parsed: ParsedCurl, options: AnalyzerOptions) => SegmentResult;
}

const API_ENDPOINTS: ApiEndpoint[] = [
	{
		name: "linear",
		patterns: [/api\.linear\.app/i],
		analyze: analyzeLinearRequest,
	},
	{
		name: "datadog",
		patterns: [
			/api\.datadoghq\.(com|eu)/i,
			/app\.datadoghq\.(com|eu)\/api/i,
		],
		analyze: analyzeDatadogRequest,
	},
];

// ============================================================================
// Curl Parsing
// ============================================================================

interface ParsedCurl {
	url?: string;
	method: string; // Default to GET, or POST if data present
	data?: string;
	hasFileInput: boolean; // @file or @-
	hasVariableInput: boolean; // $VAR or ${VAR}
}

const CURL_DATA_FLAGS = [
	"-d",
	"--data",
	"--data-raw",
	"--data-binary",
	"--data-urlencode",
	"--data-ascii",
	"--json",
];
const CURL_METHOD_FLAGS = ["-X", "--request"];

/**
 * Parse curl command arguments
 */
function parseCurlCommand(words: string[]): ParsedCurl {
	const result: ParsedCurl = {
		method: "GET",
		hasFileInput: false,
		hasVariableInput: false,
	};

	let i = 1; // Skip "curl"

	while (i < words.length) {
		const word = words[i];
		if (!word) break;

		// Check for method flag
		if (CURL_METHOD_FLAGS.includes(word)) {
			const method = words[i + 1];
			if (method) {
				result.method = method.toUpperCase();
			}
			i += 2;
			continue;
		}

		// Check for data flags
		if (CURL_DATA_FLAGS.includes(word)) {
			const data = words[i + 1];
			if (data) {
				result.data = data;
				// If data is provided without explicit method, it's POST
				if (result.method === "GET") {
					result.method = "POST";
				}
				// Check for file input
				if (data.startsWith("@")) {
					result.hasFileInput = true;
				}
				// Check for variable input
				if (data.includes("$")) {
					result.hasVariableInput = true;
				}
			}
			i += 2;
			continue;
		}

		// Check for --data=value format
		const dataFlagMatch = CURL_DATA_FLAGS.find(
			(flag) => word.startsWith(`${flag}=`) || word.startsWith(`${flag}:`),
		);
		if (dataFlagMatch) {
			const data = word.slice(dataFlagMatch.length + 1);
			result.data = data;
			if (result.method === "GET") {
				result.method = "POST";
			}
			if (data.startsWith("@")) {
				result.hasFileInput = true;
			}
			if (data.includes("$")) {
				result.hasVariableInput = true;
			}
			i += 1;
			continue;
		}

		// Skip other flags with values
		if (
			word.startsWith("-") &&
			!word.startsWith("--") &&
			word.length === 2
		) {
			// Short flag, might have value
			i += 2;
			continue;
		}
		if (word.startsWith("--") && !word.includes("=")) {
			// Long flag without =, might have value
			const nextWord = words[i + 1];
			if (nextWord && !nextWord.startsWith("-")) {
				i += 2;
				continue;
			}
			i += 1;
			continue;
		}

		// URL (positional argument not starting with -)
		if (!word.startsWith("-") && !result.url) {
			result.url = word;
		}

		i += 1;
	}

	return result;
}

// ============================================================================
// GraphQL Detection
// ============================================================================

/**
 * Check if a GraphQL request body contains a mutation
 */
function isGraphQLMutation(body: string): boolean {
	// Normalize whitespace for matching
	const normalized = body.replace(/\s+/g, " ").trim();

	// Pattern 1: JSON format { "query": "mutation..." }
	// Handles: {"query":"mutation CreateIssue($title: String!) { ... }"}
	// Also: {"query":"mutation{...}"} (no space after mutation)
	if (/["']query["']\s*:\s*["']\s*mutation[\s{]/i.test(normalized)) {
		return true;
	}

	// Pattern 2: Raw GraphQL format starting with mutation
	// Handles: mutation { issueCreate(...) { ... } }
	// Also: mutation{ (no space)
	if (/^\s*mutation[\s{]/i.test(normalized)) {
		return true;
	}

	// Pattern 3: Named mutation in JSON
	// Handles: {"query":"mutation","variables":...}
	if (/["']query["']\s*:\s*["']mutation["']/i.test(normalized)) {
		return true;
	}

	return false;
}

/**
 * Check if a GraphQL request body contains a query (read)
 */
function isGraphQLQuery(body: string): boolean {
	const normalized = body.replace(/\s+/g, " ").trim();

	// Pattern 1: JSON format { "query": "query ..." }
	if (/["']query["']\s*:\s*["']\s*query\s/i.test(normalized)) {
		return true;
	}

	// Pattern 2: JSON format { "query": "{ ... }" } (anonymous query)
	if (/["']query["']\s*:\s*["']\s*\{/i.test(normalized)) {
		// Make sure it's not a mutation
		return !isGraphQLMutation(body);
	}

	// Pattern 3: Raw GraphQL starting with query or {
	if (/^\s*(query\s|\{)/i.test(normalized)) {
		return !isGraphQLMutation(body);
	}

	return false;
}

// ============================================================================
// Linear Analysis
// ============================================================================

function analyzeLinearRequest(
	parsed: ParsedCurl,
	options: AnalyzerOptions,
): SegmentResult {
	// If we can't see the data, be cautious
	if (parsed.hasFileInput || parsed.hasVariableInput) {
		const decision =
			options.paranoid || options.paranoidApi ? "deny" : "warn";
		return {
			decision,
			rule: "api-linear-unanalyzable",
			category: "api",
			reason:
				"Linear API request with file/variable input cannot be fully analyzed.",
			matchedTokens: ["curl", "api.linear.app"],
			confidence: "low",
		};
	}

	// No data = likely a GET or health check
	if (!parsed.data) {
		return { decision: "allow" };
	}

	// Check if it's a mutation
	if (isGraphQLMutation(parsed.data)) {
		const decision =
			options.paranoid || options.paranoidApi ? "deny" : "warn";
		return {
			decision,
			rule: "api-linear-mutation",
			category: "api",
			reason: "Linear GraphQL mutation detected (creates/modifies data).",
			matchedTokens: ["curl", "api.linear.app", "mutation"],
			confidence: "high",
		};
	}

	// It's a query (read)
	if (isGraphQLQuery(parsed.data)) {
		return { decision: "allow" };
	}

	// Can't determine - warn in paranoid mode
	if (options.paranoid || options.paranoidApi) {
		return {
			decision: "warn",
			rule: "api-linear-unknown",
			category: "api",
			reason: "Linear API request type could not be determined.",
			matchedTokens: ["curl", "api.linear.app"],
			confidence: "low",
		};
	}

	return { decision: "allow" };
}

// ============================================================================
// Datadog Analysis
// ============================================================================

function analyzeDatadogRequest(
	parsed: ParsedCurl,
	options: AnalyzerOptions,
): SegmentResult {
	// DELETE is always destructive
	if (parsed.method === "DELETE") {
		return {
			decision: "deny",
			rule: "api-datadog-delete",
			category: "api",
			reason: "Datadog API DELETE request (destructive operation).",
			matchedTokens: ["curl", "api.datadoghq", "DELETE"],
			confidence: "high",
		};
	}

	// GET is always safe
	if (parsed.method === "GET") {
		return { decision: "allow" };
	}

	// POST/PUT/PATCH are mutations
	if (["POST", "PUT", "PATCH"].includes(parsed.method)) {
		const decision =
			options.paranoid || options.paranoidApi ? "deny" : "warn";
		return {
			decision,
			rule: `api-datadog-${parsed.method.toLowerCase()}`,
			category: "api",
			reason: `Datadog API ${parsed.method} request (modifies data).`,
			matchedTokens: ["curl", "api.datadoghq", parsed.method],
			confidence: "high",
		};
	}

	// Unknown method - allow by default
	return { decision: "allow" };
}

// ============================================================================
// Main Entry Point
// ============================================================================

/**
 * Analyze a curl command for API mutations
 */
export function analyzeApiCommand(
	command: string,
	options: AnalyzerOptions = {},
): SegmentResult {
	const tokens = tokenize(command);
	const { tokens: strippedTokens } = stripWrappers(tokens);
	const words = extractWords(strippedTokens);

	// First word should be "curl"
	if (words[0] !== "curl" || words.length < 2) {
		return { decision: "allow" };
	}

	// Parse curl arguments
	const parsed = parseCurlCommand(words);

	// No URL found
	if (!parsed.url) {
		return { decision: "allow" };
	}

	// Check against known API endpoints
	for (const endpoint of API_ENDPOINTS) {
		const matches = endpoint.patterns.some((pattern) =>
			pattern.test(parsed.url || ""),
		);
		if (matches) {
			return endpoint.analyze(parsed, options);
		}
	}

	// Unknown API - allow (no false positives)
	return { decision: "allow" };
}
