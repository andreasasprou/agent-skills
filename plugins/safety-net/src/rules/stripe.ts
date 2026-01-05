/**
 * Stripe CLI destructive command rules
 * Uses verb-based classification for generalizability
 */

import { extractWords, tokenize } from "../shell/parser.ts";
import { stripWrappers } from "../shell/wrappers.ts";
import type { AnalyzerOptions, SegmentResult } from "../types.ts";

/** Verbs that delete or remove data */
const DESTRUCTIVE_VERBS = ["delete", "cancel", "void", "remove", "archive"];

/** Verbs that move money */
const MONEY_VERBS = ["refund", "capture", "pay", "payout", "transfer"];

/** Resources that involve money movement */
const MONEY_RESOURCES = [
	"charges",
	"payment_intents",
	"invoices",
	"refunds",
	"payouts",
	"transfers",
];

/** Verbs that modify data */
const WRITE_VERBS = ["create", "update", "confirm", "send", "resend", "post"];

/** Verbs that only read data */
const READ_VERBS = ["get", "list", "retrieve", "search"];

/** Commands that are always safe */
const SAFE_COMMANDS = ["listen", "logs", "login", "logout", "help", "version", "status", "config"];

/** Flags that bypass confirmation prompts */
const BYPASS_FLAGS = ["--confirm", "--yes", "-y", "--force", "-f"];

type VerbType = "destructive" | "money" | "write" | "read" | "safe" | "unknown";

/**
 * Check if command is in live mode via --live flag or live API key
 */
function isLiveMode(args: string[]): boolean {
	// Check for --live flag
	if (args.includes("--live")) return true;

	// Check for live API key in --api-key or -k flag
	for (let i = 0; i < args.length; i++) {
		const arg = args[i];
		if (arg === "--api-key" || arg === "-k") {
			const key = args[i + 1];
			if (key && (key.startsWith("sk_live_") || key.startsWith("rk_live_"))) {
				return true;
			}
		}
		// Also check for --api-key=sk_live_xxx format
		if (arg?.startsWith("--api-key=")) {
			const key = arg.slice("--api-key=".length);
			if (key.startsWith("sk_live_") || key.startsWith("rk_live_")) {
				return true;
			}
		}
	}

	return false;
}

/**
 * Check for bypass/auto-confirm flags
 */
function hasBypassFlag(args: string[]): boolean {
	return args.some((arg) => BYPASS_FLAGS.includes(arg));
}

/**
 * Extract the action verb from a Stripe command
 * Handles both: `stripe <resource> <action>` and `stripe <verb> /<path>`
 */
function extractVerb(words: string[]): { verb: string; resource?: string } {
	// words[0] is "stripe"
	if (words.length < 2) return { verb: "" };

	const first = words[1];
	const second = words[2];

	// Check if it's a top-level verb/command: stripe get/post/delete /path
	// Also includes safe commands like trigger, listen, logs, etc.
	if (
		READ_VERBS.includes(first) ||
		first === "post" ||
		first === "delete" ||
		SAFE_COMMANDS.includes(first) ||
		first === "trigger"
	) {
		return { verb: first, resource: second };
	}

	// Otherwise it's: stripe <resource> <action>
	// e.g., stripe customers delete, stripe refunds create
	if (second) {
		return { verb: second, resource: first };
	}

	// Single word after stripe (could be a safe command)
	return { verb: first };
}

/**
 * Classify the verb type
 */
function classifyVerb(verb: string, resource?: string): VerbType {
	if (!verb) return "unknown";

	// Safe commands
	if (SAFE_COMMANDS.includes(verb)) return "safe";

	// Read-only
	if (READ_VERBS.includes(verb)) return "read";

	// Destructive
	if (DESTRUCTIVE_VERBS.includes(verb)) return "destructive";

	// Money-moving verb
	if (MONEY_VERBS.includes(verb)) return "money";

	// Money-moving resource with write verb
	if (resource && MONEY_RESOURCES.includes(resource)) {
		if (WRITE_VERBS.includes(verb) || verb === "post") {
			return "money";
		}
	}

	// General write
	if (WRITE_VERBS.includes(verb)) return "write";

	return "unknown";
}

/**
 * Apply the decision matrix based on verb type, live mode, and bypass flags
 */
function getDecision(
	verbType: VerbType,
	isLive: boolean,
	hasBypass: boolean,
	paranoid: boolean,
): "allow" | "warn" | "deny" {
	// Read-only and safe commands are always allowed
	if (verbType === "read" || verbType === "safe") {
		return "allow";
	}

	// Unknown verbs: warn in live mode, allow otherwise
	if (verbType === "unknown") {
		if (isLive) return paranoid ? "deny" : "warn";
		return "allow";
	}

	// Destructive and money-moving: deny in live, warn in test
	if (verbType === "destructive" || verbType === "money") {
		if (isLive) return "deny";
		return paranoid ? "deny" : "warn";
	}

	// Write operations: deny if live+bypass, warn if live, allow in test
	if (verbType === "write") {
		if (isLive && hasBypass) return "deny";
		if (isLive) return paranoid ? "deny" : "warn";
		return "allow";
	}

	return "allow";
}

/**
 * Build reason message
 */
function buildReason(
	verb: string,
	resource: string | undefined,
	verbType: VerbType,
	isLive: boolean,
	hasBypass: boolean,
): string {
	const modeStr = isLive ? "live mode" : "test mode";
	const bypassStr = hasBypass ? " with confirmation bypass" : "";
	const resourceStr = resource ? ` on ${resource}` : "";

	switch (verbType) {
		case "destructive":
			return `stripe ${verb}${resourceStr} is a destructive operation in ${modeStr}${bypassStr}.`;
		case "money":
			return `stripe ${verb}${resourceStr} involves money movement in ${modeStr}${bypassStr}.`;
		case "write":
			return `stripe ${verb}${resourceStr} modifies data in ${modeStr}${bypassStr}.`;
		default:
			return `stripe ${verb}${resourceStr} in ${modeStr}${bypassStr}.`;
	}
}

/**
 * Analyze a Stripe CLI command for destructive operations
 */
export function analyzeStripeCommand(
	command: string,
	options: AnalyzerOptions = {},
): SegmentResult {
	const tokens = tokenize(command);
	const { tokens: strippedTokens } = stripWrappers(tokens);
	const words = extractWords(strippedTokens);

	// First word should be "stripe"
	if (words[0] !== "stripe" || words.length < 2) {
		return { decision: "allow" };
	}

	const args = words.slice(1);
	const { verb, resource } = extractVerb(words);

	// Special case: stripe trigger in live mode should warn
	if (verb === "trigger" && isLiveMode(args)) {
		const decision = options.paranoid || options.paranoidStripe ? "deny" : "warn";
		return {
			decision,
			rule: "stripe-trigger-live",
			category: "stripe",
			reason: "stripe trigger in live mode may affect production systems.",
			matchedTokens: ["stripe", "trigger", "--live"],
			confidence: "high",
		};
	}

	const verbType = classifyVerb(verb, resource);
	const isLive = isLiveMode(args);
	const hasBypass = hasBypassFlag(args);
	const paranoid = options.paranoid || options.paranoidStripe || false;

	const decision = getDecision(verbType, isLive, hasBypass, paranoid);

	if (decision === "allow") {
		return { decision: "allow" };
	}

	const matchedTokens = ["stripe", verb];
	if (resource) matchedTokens.push(resource);
	if (isLive) matchedTokens.push("--live");
	if (hasBypass) matchedTokens.push("--confirm");

	return {
		decision,
		rule: `stripe-${verbType}${isLive ? "-live" : ""}`,
		category: "stripe",
		reason: buildReason(verb, resource, verbType, isLive, hasBypass),
		matchedTokens,
		confidence: "high",
	};
}
