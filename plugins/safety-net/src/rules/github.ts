/**
 * GitHub CLI (gh) destructive command rules
 */

import { extractWords, tokenize } from "../shell/parser.ts";
import { stripWrappers } from "../shell/wrappers.ts";
import type { AnalyzerOptions, SegmentResult } from "../types.ts";

/**
 * Check for --yes or -y flag (bypasses confirmation)
 */
function hasYesFlag(args: string[]): boolean {
	return args.includes("--yes") || args.includes("-y");
}

/**
 * Check for --force or -f flag
 */
function hasForceFlag(args: string[]): boolean {
	return args.includes("--force") || args.includes("-f");
}

// ============================================================================
// Repository Commands
// ============================================================================

/**
 * Analyze gh repo commands
 */
function analyzeGhRepo(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const subcommand = args[0];
	const subArgs = args.slice(1);

	// gh repo delete
	if (subcommand === "delete") {
		const hasYes = hasYesFlag(subArgs);
		return {
			decision: "deny",
			rule: "gh-repo-delete",
			category: "github",
			reason: `gh repo delete permanently removes a GitHub repository.${hasYes ? " (--yes bypasses confirmation)" : ""}`,
			matchedTokens: ["gh", "repo", "delete"],
			confidence: "high",
		};
	}

	// gh repo archive
	if (subcommand === "archive") {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "gh-repo-archive",
			category: "github",
			reason: "gh repo archive makes a repository read-only.",
			matchedTokens: ["gh", "repo", "archive"],
			confidence: "high",
		};
	}

	// gh repo rename
	if (subcommand === "rename") {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "gh-repo-rename",
			category: "github",
			reason: "gh repo rename changes the repository name (may break links).",
			matchedTokens: ["gh", "repo", "rename"],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

// ============================================================================
// Release Commands
// ============================================================================

/**
 * Analyze gh release commands
 */
function analyzeGhRelease(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const subcommand = args[0];
	const subArgs = args.slice(1);

	// gh release delete
	if (subcommand === "delete") {
		const hasYes = hasYesFlag(subArgs);
		const decision = hasYes || options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "gh-release-delete",
			category: "github",
			reason: "gh release delete removes a release and its assets.",
			matchedTokens: ["gh", "release", "delete"],
			confidence: "high",
		};
	}

	// gh release delete-asset
	if (subcommand === "delete-asset") {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "gh-release-delete-asset",
			category: "github",
			reason: "gh release delete-asset removes release assets.",
			matchedTokens: ["gh", "release", "delete-asset"],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

// ============================================================================
// Secret Commands
// ============================================================================

/**
 * Analyze gh secret commands
 */
function analyzeGhSecret(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const subcommand = args[0];

	// gh secret delete
	if (subcommand === "delete" || subcommand === "remove") {
		return {
			decision: options.paranoid ? "deny" : "warn",
			rule: "gh-secret-delete",
			category: "github",
			reason: "gh secret delete removes repository/org secrets.",
			matchedTokens: ["gh", "secret", subcommand],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

// ============================================================================
// Variable Commands
// ============================================================================

/**
 * Analyze gh variable commands
 */
function analyzeGhVariable(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const subcommand = args[0];

	// gh variable delete
	if (subcommand === "delete" || subcommand === "remove") {
		return {
			decision: options.paranoid ? "deny" : "warn",
			rule: "gh-variable-delete",
			category: "github",
			reason: "gh variable delete removes repository/org variables.",
			matchedTokens: ["gh", "variable", subcommand],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

// ============================================================================
// SSH Key Commands
// ============================================================================

/**
 * Analyze gh ssh-key commands
 */
function analyzeGhSshKey(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const subcommand = args[0];

	// gh ssh-key delete
	if (subcommand === "delete") {
		return {
			decision: options.paranoid ? "deny" : "warn",
			rule: "gh-ssh-key-delete",
			category: "github",
			reason: "gh ssh-key delete removes SSH keys from your GitHub account.",
			matchedTokens: ["gh", "ssh-key", "delete"],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

// ============================================================================
// GPG Key Commands
// ============================================================================

/**
 * Analyze gh gpg-key commands
 */
function analyzeGhGpgKey(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const subcommand = args[0];

	// gh gpg-key delete
	if (subcommand === "delete") {
		return {
			decision: options.paranoid ? "deny" : "warn",
			rule: "gh-gpg-key-delete",
			category: "github",
			reason: "gh gpg-key delete removes GPG keys from your GitHub account.",
			matchedTokens: ["gh", "gpg-key", "delete"],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

// ============================================================================
// Issue/PR Commands
// ============================================================================

/**
 * Analyze gh issue commands
 */
function analyzeGhIssue(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const subcommand = args[0];

	// gh issue delete
	if (subcommand === "delete") {
		return {
			decision: options.paranoid ? "deny" : "warn",
			rule: "gh-issue-delete",
			category: "github",
			reason: "gh issue delete permanently removes an issue.",
			matchedTokens: ["gh", "issue", "delete"],
			confidence: "high",
		};
	}

	// gh issue close (warn only)
	if (subcommand === "close") {
		return {
			decision: "warn",
			rule: "gh-issue-close",
			category: "github",
			reason: "gh issue close will close the issue.",
			matchedTokens: ["gh", "issue", "close"],
			confidence: "medium",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze gh pr commands
 */
function analyzeGhPr(args: string[], options: AnalyzerOptions): SegmentResult {
	const subcommand = args[0];
	const subArgs = args.slice(1);

	// gh pr close
	if (subcommand === "close") {
		const hasDelete = subArgs.includes("--delete-branch") || subArgs.includes("-d");
		if (hasDelete) {
			return {
				decision: options.paranoid ? "deny" : "warn",
				rule: "gh-pr-close-delete",
				category: "github",
				reason: "gh pr close --delete-branch closes the PR and deletes its branch.",
				matchedTokens: ["gh", "pr", "close", "--delete-branch"],
				confidence: "high",
			};
		}
	}

	// gh pr merge with delete
	if (subcommand === "merge") {
		const hasDelete = subArgs.includes("--delete-branch") || subArgs.includes("-d");
		const hasAdmin = subArgs.includes("--admin");

		if (hasAdmin) {
			return {
				decision: options.paranoid ? "deny" : "warn",
				rule: "gh-pr-merge-admin",
				category: "github",
				reason: "gh pr merge --admin bypasses branch protection rules.",
				matchedTokens: ["gh", "pr", "merge", "--admin"],
				confidence: "high",
			};
		}

		if (hasDelete) {
			return {
				decision: "warn",
				rule: "gh-pr-merge-delete",
				category: "github",
				reason: "gh pr merge --delete-branch merges and deletes the source branch.",
				matchedTokens: ["gh", "pr", "merge", "--delete-branch"],
				confidence: "medium",
			};
		}
	}

	return { decision: "allow" };
}

// ============================================================================
// API Commands
// ============================================================================

/**
 * Analyze gh api commands
 */
function analyzeGhApi(args: string[], options: AnalyzerOptions): SegmentResult {
	// Check for DELETE method
	const methodIdx = args.findIndex((a) => a === "-X" || a === "--method");
	let method = "GET";
	if (methodIdx !== -1 && args[methodIdx + 1]) {
		method = args[methodIdx + 1].toUpperCase();
	}

	// Extract endpoint
	const endpoint = args.find((a) => !a.startsWith("-") && a.includes("/"));

	if (method === "DELETE") {
		return {
			decision: options.paranoid ? "deny" : "warn",
			rule: "gh-api-delete",
			category: "github",
			reason: `gh api DELETE ${endpoint || "endpoint"} is a destructive operation.`,
			matchedTokens: ["gh", "api", "-X", "DELETE"],
			confidence: "high",
		};
	}

	// POST/PUT/PATCH to sensitive endpoints
	if (["POST", "PUT", "PATCH"].includes(method)) {
		// Check for sensitive endpoints
		const sensitivePatterns = [
			/\/repos\/[^/]+\/[^/]+\/delete/,
			/\/repos\/[^/]+\/[^/]+\/actions\/secrets/,
			/\/orgs\/[^/]+\/actions\/secrets/,
			/\/repos\/[^/]+\/[^/]+\/hooks/,
			/\/repos\/[^/]+\/[^/]+\/keys/,
		];

		if (endpoint && sensitivePatterns.some((p) => p.test(endpoint))) {
			return {
				decision: options.paranoid ? "deny" : "warn",
				rule: "gh-api-sensitive",
				category: "github",
				reason: `gh api ${method} to sensitive endpoint ${endpoint}.`,
				matchedTokens: ["gh", "api", "-X", method],
				confidence: "medium",
			};
		}
	}

	return { decision: "allow" };
}

// ============================================================================
// Workflow Commands
// ============================================================================

/**
 * Analyze gh workflow commands
 */
function analyzeGhWorkflow(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const subcommand = args[0];

	// gh workflow disable
	if (subcommand === "disable") {
		return {
			decision: options.paranoid ? "deny" : "warn",
			rule: "gh-workflow-disable",
			category: "github",
			reason: "gh workflow disable stops a workflow from running.",
			matchedTokens: ["gh", "workflow", "disable"],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

// ============================================================================
// Run Commands
// ============================================================================

/**
 * Analyze gh run commands
 */
function analyzeGhRun(args: string[], options: AnalyzerOptions): SegmentResult {
	const subcommand = args[0];

	// gh run cancel
	if (subcommand === "cancel") {
		return {
			decision: options.paranoid ? "deny" : "warn",
			rule: "gh-run-cancel",
			category: "github",
			reason: "gh run cancel terminates a running workflow.",
			matchedTokens: ["gh", "run", "cancel"],
			confidence: "medium",
		};
	}

	// gh run delete
	if (subcommand === "delete") {
		return {
			decision: options.paranoid ? "deny" : "warn",
			rule: "gh-run-delete",
			category: "github",
			reason: "gh run delete removes workflow run logs.",
			matchedTokens: ["gh", "run", "delete"],
			confidence: "medium",
		};
	}

	return { decision: "allow" };
}

// ============================================================================
// Main Entry Point
// ============================================================================

/**
 * Analyze a GitHub CLI command for destructive operations
 */
export function analyzeGithubCommand(
	command: string,
	options: AnalyzerOptions = {},
): SegmentResult {
	const tokens = tokenize(command);
	const { tokens: strippedTokens } = stripWrappers(tokens);
	const words = extractWords(strippedTokens);

	// First word should be "gh"
	if (words[0] !== "gh" || words.length < 2) {
		return { decision: "allow" };
	}

	const subcommand = words[1];
	const args = words.slice(2);

	switch (subcommand) {
		case "repo":
			return analyzeGhRepo(args, options);
		case "release":
			return analyzeGhRelease(args, options);
		case "secret":
			return analyzeGhSecret(args, options);
		case "variable":
			return analyzeGhVariable(args, options);
		case "ssh-key":
			return analyzeGhSshKey(args, options);
		case "gpg-key":
			return analyzeGhGpgKey(args, options);
		case "issue":
			return analyzeGhIssue(args, options);
		case "pr":
			return analyzeGhPr(args, options);
		case "api":
			return analyzeGhApi(args, options);
		case "workflow":
			return analyzeGhWorkflow(args, options);
		case "run":
			return analyzeGhRun(args, options);
		default:
			return { decision: "allow" };
	}
}
