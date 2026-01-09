/**
 * AWS CLI verb-based command classification
 *
 * Instead of maintaining explicit allowlists, we classify by verb prefix:
 * - READ verbs (describe, get, list, head) → allow
 * - MUTATION verbs (create, update, modify, etc.) → warn
 * - DESTRUCTIVE verbs (delete, terminate, purge) → deny
 * - Unknown verbs → warn (default closed)
 */

import { extractWords, tokenize } from "../shell/parser.ts";
import { stripWrappers } from "../shell/wrappers.ts";
import type { AnalyzerOptions, SegmentResult } from "../types.ts";

// ============================================================================
// Verb Classification
// ============================================================================

/** Read-only verbs - no side effects */
const READ_VERBS = ["describe", "get", "list", "head", "filter", "query", "scan"];

/** Exact subcommands that are read-only despite verb extraction */
const READ_EXACT = ["batch-get-item", "transact-get-items"];

/** Mutation verbs - have side effects but are reversible */
const MUTATION_VERBS = [
	// Create/modify
	"create",
	"put",
	"update",
	"modify",
	"set",
	"import",
	"run",
	"execute",
	"deploy",
	"invoke",
	"send",
	"publish",
	"start",
	"stop",
	"reboot",
	"pause",
	"resume",
	// Associations (reversible)
	"attach",
	"detach",
	"associate",
	"disassociate",
	"enable",
	"disable",
	"register",
	"deregister",
	"authorize",
	"revoke",
	"add",
	"remove",
	"allocate",
	"release",
	"grant",
	"rotate",
	"reset",
	"tag",
	"untag",
	"subscribe",
	"unsubscribe",
	"copy",
	"restore",
	"request",
	"accept",
	"reject",
	"change",
	"cancel", // Often protective: cancel-key-deletion, cancel-spot-instance-requests
];

/** Exact subcommands that are mutations */
const MUTATION_EXACT = ["batch-write-item", "transact-write-items"];

/** Destructive verbs - data loss or resource destruction */
const DESTRUCTIVE_VERBS = ["delete", "terminate", "purge"];

/** Exact subcommands that are destructive despite verb extraction */
const DESTRUCTIVE_EXACT = ["schedule-key-deletion", "force-delete-stack"];

/** Flags that escalate severity (skip safety checks) */
const BYPASS_FLAGS = [
	"--skip-final-snapshot",
	"--force",
	"--force-delete",
	"--yes",
];

// ============================================================================
// Global Options Parsing
// ============================================================================

/** Global options that consume a following value */
const GLOBAL_VALUE_OPTIONS = [
	"--profile",
	"--region",
	"--output",
	"--query",
	"--endpoint-url",
	"--cli-input-json",
	"--cli-input-yaml",
	"--ca-bundle",
	"--cli-connect-timeout",
	"--cli-read-timeout",
	"--color",
];

/** Global options that are flags (no value) */
const GLOBAL_FLAG_OPTIONS = ["--debug", "--no-verify-ssl", "--no-paginate"];

/**
 * Skip global options to find service and subcommand
 * Handles: aws --profile prod --region us-east-1 ec2 describe-instances
 */
function skipGlobalOptions(words: string[]): {
	service: string | undefined;
	subcommand: string | undefined;
	args: string[];
} {
	let i = 1; // Skip "aws"

	// Skip global options
	while (i < words.length) {
		const word = words[i];
		if (!word) break;

		// Check if it's a global option that takes a value
		if (GLOBAL_VALUE_OPTIONS.includes(word)) {
			i += 2; // Skip option and its value
			continue;
		}

		// Check if it's a global flag option
		if (GLOBAL_FLAG_OPTIONS.includes(word)) {
			i += 1;
			continue;
		}

		// Check for --option=value format
		if (
			word.startsWith("--") &&
			word.includes("=") &&
			GLOBAL_VALUE_OPTIONS.some((opt) => word.startsWith(`${opt}=`))
		) {
			i += 1;
			continue;
		}

		// Not a global option, must be service
		break;
	}

	return {
		service: words[i],
		subcommand: words[i + 1],
		args: words.slice(i + 2),
	};
}

// ============================================================================
// Verb Classification
// ============================================================================

type VerbClass = "read" | "mutation" | "destructive";

/**
 * Extract the verb prefix from a subcommand
 * Examples: terminate-instances → terminate, delete-db-instance → delete
 */
function extractVerb(subcommand: string): string {
	return subcommand.split("-")[0] || subcommand;
}

/**
 * Classify a subcommand as read, mutation, or destructive
 * Order: exact matches first, then verb prefix, then default to mutation
 */
function classifySubcommand(subcommand: string): VerbClass {
	// 1. Check exact matches first (highest priority)
	if (DESTRUCTIVE_EXACT.includes(subcommand)) return "destructive";
	if (MUTATION_EXACT.includes(subcommand)) return "mutation";
	if (READ_EXACT.includes(subcommand)) return "read";

	// 2. Extract verb prefix and match
	const verb = extractVerb(subcommand);

	if (DESTRUCTIVE_VERBS.includes(verb)) return "destructive";
	if (READ_VERBS.includes(verb)) return "read";
	if (MUTATION_VERBS.includes(verb)) return "mutation";

	// 3. Default to mutation for unknown verbs (never allow on ambiguity)
	return "mutation";
}

// ============================================================================
// S3 High-Level Commands
// ============================================================================

type S3Direction = "upload" | "download" | "s3-to-s3" | "unknown";

/**
 * Determine the direction of an S3 cp/sync operation
 * - s3:// to local = download (read-like)
 * - local to s3:// = upload (mutation)
 * - s3:// to s3:// = s3-to-s3 (mutation)
 */
function analyzeS3Direction(args: string[]): S3Direction {
	// Find source and destination (first two non-flag arguments)
	const paths: string[] = [];
	for (const arg of args) {
		if (!arg.startsWith("-") && !arg.startsWith("--")) {
			paths.push(arg);
			if (paths.length === 2) break;
		}
	}

	if (paths.length < 2) return "unknown";

	const [source, dest] = paths;
	const sourceIsS3 = source?.startsWith("s3://");
	const destIsS3 = dest?.startsWith("s3://");

	if (sourceIsS3 && destIsS3) return "s3-to-s3";
	if (sourceIsS3 && !destIsS3) return "download";
	if (!sourceIsS3 && destIsS3) return "upload";

	return "unknown";
}

/**
 * Handle S3 high-level commands (s3 cp, s3 sync, s3 rm, etc.)
 * These don't follow the standard verb-subcommand pattern
 */
function analyzeS3HighLevel(
	subcommand: string,
	args: string[],
	options: AnalyzerOptions,
): SegmentResult | null {
	// s3 ls is always safe
	if (subcommand === "ls") {
		return { decision: "allow" };
	}

	// s3 cp and s3 sync with direction awareness
	if (subcommand === "cp" || subcommand === "sync") {
		const direction = analyzeS3Direction(args);

		// Download from S3 to local is read-like
		if (direction === "download") {
			return { decision: "allow" };
		}

		// Check for --delete flag (only dangerous if destination is S3)
		if (subcommand === "sync" && args.includes("--delete")) {
			if (direction !== "download") {
				return {
					decision: "deny",
					rule: "aws-s3-sync-delete",
					category: "aws",
					reason: "aws s3 sync --delete removes objects not present in source.",
					matchedTokens: ["aws", "s3", "sync", "--delete"],
					confidence: "high",
				};
			}
		}

		// Upload or s3-to-s3 = mutation
		const decision =
			options.paranoid || options.paranoidAws ? "deny" : "warn";
		return {
			decision,
			rule: `aws-s3-${subcommand}`,
			category: "aws",
			reason: `aws s3 ${subcommand} modifies S3 objects.`,
			matchedTokens: ["aws", "s3", subcommand],
			confidence: "high",
		};
	}

	// s3 rm - always a delete operation
	if (subcommand === "rm") {
		const hasRecursive = args.includes("--recursive") || args.includes("-r");
		if (hasRecursive) {
			return {
				decision: "deny",
				rule: "aws-s3-rm-recursive",
				category: "aws",
				reason: "aws s3 rm --recursive bulk deletes S3 objects.",
				matchedTokens: ["aws", "s3", "rm", "--recursive"],
				confidence: "high",
			};
		}
		const decision =
			options.paranoid || options.paranoidAws ? "deny" : "warn";
		return {
			decision,
			rule: "aws-s3-rm",
			category: "aws",
			reason: "aws s3 rm deletes S3 objects.",
			matchedTokens: ["aws", "s3", "rm"],
			confidence: "high",
		};
	}

	// s3 rb - remove bucket
	if (subcommand === "rb") {
		if (args.includes("--force")) {
			return {
				decision: "deny",
				rule: "aws-s3-rb-force",
				category: "aws",
				reason: "aws s3 rb --force removes bucket and ALL contents.",
				matchedTokens: ["aws", "s3", "rb", "--force"],
				confidence: "high",
			};
		}
		const decision =
			options.paranoid || options.paranoidAws ? "deny" : "warn";
		return {
			decision,
			rule: "aws-s3-rb",
			category: "aws",
			reason: "aws s3 rb removes S3 bucket.",
			matchedTokens: ["aws", "s3", "rb"],
			confidence: "high",
		};
	}

	// s3 mb (make bucket) - mutation
	if (subcommand === "mb") {
		const decision =
			options.paranoid || options.paranoidAws ? "deny" : "warn";
		return {
			decision,
			rule: "aws-s3-mb",
			category: "aws",
			reason: "aws s3 mb creates S3 bucket.",
			matchedTokens: ["aws", "s3", "mb"],
			confidence: "high",
		};
	}

	// s3 mv - mutation (deletes source after copy)
	if (subcommand === "mv") {
		const decision =
			options.paranoid || options.paranoidAws ? "deny" : "warn";
		return {
			decision,
			rule: "aws-s3-mv",
			category: "aws",
			reason: "aws s3 mv moves objects (deletes source after copy).",
			matchedTokens: ["aws", "s3", "mv"],
			confidence: "high",
		};
	}

	return null; // Not handled, fall through to generic classification
}

// ============================================================================
// Dry Run Detection
// ============================================================================

/**
 * Check for --dry-run flag (safe escape hatch)
 * Must not be accompanied by --no-dry-run
 */
function hasDryRun(args: string[]): boolean {
	const hasDry = args.includes("--dry-run") || args.includes("--dryrun");
	const hasNoDry = args.includes("--no-dry-run") || args.includes("--no-dryrun");
	return hasDry && !hasNoDry;
}

/**
 * Check for bypass flags that escalate severity
 */
function hasBypassFlag(args: string[]): boolean {
	return BYPASS_FLAGS.some((flag) => args.includes(flag));
}

// ============================================================================
// Route53 Special Case
// ============================================================================

/**
 * Check for Route53 change-resource-record-sets with DELETE action
 */
function checkRoute53Delete(command: string): boolean {
	return (
		command.includes("DELETE") ||
		command.includes('"Action":"DELETE"') ||
		command.includes("'Action':'DELETE'") ||
		command.includes('"Action": "DELETE"')
	);
}

// ============================================================================
// Main Entry Point
// ============================================================================

/**
 * Analyze an AWS CLI command for destructive operations
 */
export function analyzeAwsCommand(
	command: string,
	options: AnalyzerOptions = {},
): SegmentResult {
	const tokens = tokenize(command);
	const { tokens: strippedTokens } = stripWrappers(tokens);
	const words = extractWords(strippedTokens);

	// First word should be "aws"
	if (words[0] !== "aws" || words.length < 2) {
		return { decision: "allow" };
	}

	// Parse service, subcommand, and args (skipping global options)
	const { service, subcommand, args } = skipGlobalOptions(words);

	if (!service || !subcommand) {
		// Not enough info to classify - default to allow for help commands
		// aws, aws help, aws --version, etc.
		return { decision: "allow" };
	}

	// Check for --dry-run early (escape hatch)
	const isDryRun = hasDryRun(args);

	// S3 high-level commands have special handling
	if (service === "s3") {
		const s3Result = analyzeS3HighLevel(subcommand, args, options);
		if (s3Result) {
			// Downgrade severity if dry-run
			if (isDryRun) {
				if (s3Result.decision === "deny") {
					return { ...s3Result, decision: "warn" };
				}
				if (s3Result.decision === "warn") {
					return { decision: "allow" };
				}
			}
			return s3Result;
		}
	}

	// Route53 special case: check for DELETE in JSON payload
	if (service === "route53" && subcommand === "change-resource-record-sets") {
		if (checkRoute53Delete(command)) {
			const decision =
				options.paranoid || options.paranoidAws ? "deny" : "warn";
			return {
				decision: isDryRun ? "allow" : decision,
				rule: "aws-route53-delete-record",
				category: "aws",
				reason:
					"aws route53 change-resource-record-sets with DELETE removes DNS records.",
				matchedTokens: [
					"aws",
					"route53",
					"change-resource-record-sets",
					"DELETE",
				],
				confidence: "medium",
			};
		}
	}

	// Classify the subcommand by verb
	const verbClass = classifySubcommand(subcommand);

	// Allow read-only operations
	if (verbClass === "read") {
		return { decision: "allow" };
	}

	// Check for bypass flags that escalate severity
	const hasBypass = hasBypassFlag(args);

	// Determine base severity
	let decision: "warn" | "deny";
	if (verbClass === "destructive") {
		decision = "deny";
	} else {
		// mutation - warn by default, escalate in paranoid mode or with bypass flags
		decision =
			options.paranoid || options.paranoidAws || hasBypass ? "deny" : "warn";
	}

	// Downgrade severity if dry-run
	if (isDryRun) {
		if (decision === "deny") {
			decision = "warn";
		} else {
			return { decision: "allow" };
		}
	}

	return {
		decision,
		rule: `aws-${service}-${subcommand}`,
		category: "aws",
		reason: `aws ${service} ${subcommand} is a ${verbClass} operation.`,
		matchedTokens: ["aws", service, subcommand],
		confidence: "high",
	};
}
