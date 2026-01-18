/**
 * Google Cloud CLI (gcloud, gsutil) destructive command rules
 */

import { extractWords, tokenize } from "../shell/parser.ts";
import { stripWrappers } from "../shell/wrappers.ts";
import type { AnalyzerOptions, SegmentResult } from "../types.ts";

/**
 * Check for --quiet or -q flag (suppresses confirmation)
 */
function hasQuietFlag(args: string[]): boolean {
	return args.includes("--quiet") || args.includes("-q");
}

/**
 * Check for --force or -f flag
 */
function hasForceFlag(args: string[]): boolean {
	return args.includes("--force") || args.includes("-f");
}

/**
 * Check for -r or -R (recursive) flag
 */
function hasRecursiveFlag(args: string[]): boolean {
	return args.includes("-r") || args.includes("-R") || args.includes("-m");
}

// ============================================================================
// gcloud command analysis
// ============================================================================

/**
 * Catastrophic gcloud commands (always deny)
 */
const GCLOUD_CATASTROPHIC: Record<string, string> = {
	"projects delete": "gcloud projects delete removes an ENTIRE project and ALL resources within it.",
	"organizations delete": "gcloud organizations delete removes an organization.",
};

/**
 * Destructive gcloud commands (deny by default)
 */
const GCLOUD_DESTRUCTIVE: Record<string, string> = {
	"compute instances delete": "gcloud compute instances delete permanently destroys VM instances.",
	"compute disks delete": "gcloud compute disks delete permanently destroys disks and data.",
	"sql instances delete": "gcloud sql instances delete destroys Cloud SQL instances.",
	"container clusters delete": "gcloud container clusters delete removes GKE clusters.",
	"functions delete": "gcloud functions delete removes Cloud Functions.",
	"pubsub topics delete": "gcloud pubsub topics delete removes Pub/Sub topics.",
	"pubsub subscriptions delete": "gcloud pubsub subscriptions delete removes subscriptions.",
	"firestore databases delete": "gcloud firestore databases delete removes Firestore databases.",
	"spanner instances delete": "gcloud spanner instances delete removes Spanner instances.",
	"spanner databases delete": "gcloud spanner databases delete removes Spanner databases.",
	"run services delete": "gcloud run services delete removes Cloud Run services.",
	"app services delete": "gcloud app services delete removes App Engine services.",
	"secrets delete": "gcloud secrets delete removes secrets from Secret Manager.",
	"kms keys destroy": "gcloud kms keys destroy destroys cryptographic keys.",
	"kms keyrings delete": "gcloud kms keyrings delete removes key rings.",
	"bigtable instances delete": "gcloud bigtable instances delete removes Bigtable instances.",
	"redis instances delete": "gcloud redis instances delete removes Memorystore Redis instances.",
};

/**
 * Analyze gcloud command
 */
function analyzeGcloudCommand(
	words: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const args = words.slice(1);
	const hasQuiet = hasQuietFlag(args);

	// Build command path for matching
	const commandParts: string[] = [];
	for (const arg of args) {
		if (arg.startsWith("-")) break;
		commandParts.push(arg);
	}

	// Check for catastrophic commands
	for (const [pattern, reason] of Object.entries(GCLOUD_CATASTROPHIC)) {
		if (commandParts.join(" ").startsWith(pattern)) {
			return {
				decision: "deny",
				rule: `gcloud-${pattern.replace(/ /g, "-")}`,
				category: "gcloud",
				reason: `${reason} ${hasQuiet ? "(--quiet bypasses confirmation)" : ""}`,
				matchedTokens: ["gcloud", ...pattern.split(" ")],
				confidence: "high",
			};
		}
	}

	// Check for destructive commands
	for (const [pattern, reason] of Object.entries(GCLOUD_DESTRUCTIVE)) {
		if (commandParts.join(" ").startsWith(pattern)) {
			const decision = hasQuiet || options.paranoid ? "deny" : "warn";
			return {
				decision,
				rule: `gcloud-${pattern.replace(/ /g, "-")}`,
				category: "gcloud",
				reason,
				matchedTokens: ["gcloud", ...pattern.split(" ")],
				confidence: "high",
			};
		}
	}

	// Generic delete detection
	if (commandParts.includes("delete") || commandParts.includes("destroy")) {
		const decision = hasQuiet || options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "gcloud-delete-generic",
			category: "gcloud",
			reason: `gcloud ${commandParts.join(" ")} is a destructive operation.`,
			matchedTokens: ["gcloud", ...commandParts.slice(0, 3)],
			confidence: "medium",
		};
	}

	return { decision: "allow" };
}

// ============================================================================
// gsutil command analysis
// ============================================================================

/**
 * Analyze gsutil rm command
 */
function analyzeGsutilRm(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const hasRecursive = hasRecursiveFlag(args);
	const hasForce = hasForceFlag(args);

	// gsutil rm -r is bulk delete
	if (hasRecursive) {
		return {
			decision: "deny",
			rule: "gsutil-rm-recursive",
			category: "gcloud",
			reason: "gsutil rm -r recursively deletes objects in GCS (bulk data loss).",
			matchedTokens: ["gsutil", "rm", "-r"],
			confidence: "high",
		};
	}

	// gsutil rm -f (force)
	if (hasForce) {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "gsutil-rm-force",
			category: "gcloud",
			reason: "gsutil rm -f ignores errors and continues deleting.",
			matchedTokens: ["gsutil", "rm", "-f"],
			confidence: "high",
		};
	}

	// Regular gsutil rm
	const decision = options.paranoid ? "deny" : "warn";
	return {
		decision,
		rule: "gsutil-rm",
		category: "gcloud",
		reason: "gsutil rm deletes GCS objects.",
		matchedTokens: ["gsutil", "rm"],
		confidence: "high",
	};
}

/**
 * Analyze gsutil rb (remove bucket) command
 */
function analyzeGsutilRb(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const hasForce = hasForceFlag(args);

	// gsutil rb -f removes bucket even if not empty
	if (hasForce) {
		return {
			decision: "deny",
			rule: "gsutil-rb-force",
			category: "gcloud",
			reason: "gsutil rb -f removes bucket and ALL contents.",
			matchedTokens: ["gsutil", "rb", "-f"],
			confidence: "high",
		};
	}

	return {
		decision: options.paranoid ? "deny" : "warn",
		rule: "gsutil-rb",
		category: "gcloud",
		reason: "gsutil rb removes GCS bucket.",
		matchedTokens: ["gsutil", "rb"],
		confidence: "high",
	};
}

/**
 * Analyze gsutil rsync command
 */
function analyzeGsutilRsync(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	// -d flag deletes files at destination not in source
	const hasDelete = args.includes("-d");

	if (hasDelete) {
		return {
			decision: "deny",
			rule: "gsutil-rsync-delete",
			category: "gcloud",
			reason: "gsutil rsync -d deletes files at destination not present in source.",
			matchedTokens: ["gsutil", "rsync", "-d"],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze gsutil command
 */
function analyzeGsutil(
	words: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const subcommand = words[1];
	const args = words.slice(2);

	switch (subcommand) {
		case "rm":
			return analyzeGsutilRm(args, options);
		case "rb":
			return analyzeGsutilRb(args, options);
		case "rsync":
			return analyzeGsutilRsync(args, options);
		default:
			return { decision: "allow" };
	}
}

/**
 * Analyze a Google Cloud command for destructive operations
 */
export function analyzeGcloudCommand(
	command: string,
	options: AnalyzerOptions = {},
): SegmentResult {
	const tokens = tokenize(command);
	const { tokens: strippedTokens } = stripWrappers(tokens);
	const words = extractWords(strippedTokens);

	if (words.length < 2) {
		return { decision: "allow" };
	}

	const cmd = words[0];

	switch (cmd) {
		case "gcloud":
			return analyzeGcloudCommand(words, options);
		case "gsutil":
			return analyzeGsutil(words, options);
		default:
			return { decision: "allow" };
	}
}
