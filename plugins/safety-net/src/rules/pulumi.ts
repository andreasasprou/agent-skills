/**
 * Pulumi CLI destructive command rules
 */

import { extractWords, tokenize } from "../shell/parser.ts";
import { stripWrappers } from "../shell/wrappers.ts";
import type { AnalyzerOptions, SegmentResult } from "../types.ts";

/**
 * Pulumi destructive operations
 * Format: { subcommand: { reason, severity, subSubcommand? } }
 */
interface PulumiOp {
	reason: string;
	severity: "deny" | "warn";
	/** If set, only matches when this sub-subcommand follows */
	subSubcommand?: string;
}

const PULUMI_DESTRUCTIVE_OPS: Record<string, PulumiOp | Record<string, PulumiOp>> = {
	// Direct destructive commands
	destroy: {
		reason: "destroys all resources in the stack",
		severity: "deny",
	},
	cancel: {
		reason: "cancels running update, may leave state inconsistent",
		severity: "warn",
	},

	// Stack operations
	stack: {
		rm: {
			reason: "removes the stack",
			severity: "warn",
		},
	},

	// State operations
	state: {
		delete: {
			reason: "removes resource from state",
			severity: "warn",
		},
	},

	// Deploy operations (warn when auto-approved)
	up: {
		reason: "deploys changes without interactive confirmation",
		severity: "warn",
	},
	refresh: {
		reason: "refreshes state without interactive confirmation",
		severity: "warn",
	},
};

/**
 * Check for --preview flag (makes command safe)
 */
function hasPreviewFlag(args: string[]): boolean {
	return args.includes("--preview");
}

/**
 * Check for auto-approve flags (--yes or -y)
 */
function hasAutoApproveFlag(args: string[]): boolean {
	return args.includes("--yes") || args.includes("-y");
}

/**
 * Check for --force flag
 */
function hasForceFlag(args: string[]): boolean {
	return args.includes("--force") || args.includes("-f");
}

/**
 * Analyze a Pulumi CLI command for destructive operations
 */
export function analyzePulumiCommand(
	command: string,
	options: AnalyzerOptions = {},
): SegmentResult {
	const tokens = tokenize(command);
	const { tokens: strippedTokens } = stripWrappers(tokens);
	const words = extractWords(strippedTokens);

	// First word should be "pulumi"
	if (words[0] !== "pulumi" || words.length < 2) {
		return { decision: "allow" };
	}

	const subcommand = words[1];
	const subSubcommand = words[2];
	const args = words.slice(2);

	// pulumi destroy
	if (subcommand === "destroy") {
		// --preview makes it safe
		if (hasPreviewFlag(args)) {
			return { decision: "allow" };
		}

		return {
			decision: "deny",
			rule: "pulumi-destroy",
			category: "pulumi",
			reason: "pulumi destroy destroys all resources in the stack.",
			matchedTokens: ["pulumi", "destroy"],
			confidence: "high",
		};
	}

	// pulumi cancel
	if (subcommand === "cancel") {
		const decision = options.paranoid || options.paranoidPulumi ? "deny" : "warn";
		return {
			decision,
			rule: "pulumi-cancel",
			category: "pulumi",
			reason: "pulumi cancel may leave state inconsistent.",
			matchedTokens: ["pulumi", "cancel"],
			confidence: "high",
		};
	}

	// pulumi stack rm
	if (subcommand === "stack" && subSubcommand === "rm") {
		const stackArgs = words.slice(3);

		// --force or --yes makes it worse
		if (hasForceFlag(stackArgs) || hasAutoApproveFlag(stackArgs)) {
			return {
				decision: "deny",
				rule: "pulumi-stack-rm-force",
				category: "pulumi",
				reason: "pulumi stack rm with --force/--yes removes stack without confirmation.",
				matchedTokens: ["pulumi", "stack", "rm", "--force"],
				confidence: "high",
			};
		}

		// Regular stack rm still prompts
		const decision = options.paranoid || options.paranoidPulumi ? "deny" : "warn";
		return {
			decision,
			rule: "pulumi-stack-rm",
			category: "pulumi",
			reason: "pulumi stack rm removes the stack.",
			matchedTokens: ["pulumi", "stack", "rm"],
			confidence: "high",
		};
	}

	// pulumi state delete
	if (subcommand === "state" && subSubcommand === "delete") {
		const decision = options.paranoid || options.paranoidPulumi ? "deny" : "warn";
		return {
			decision,
			rule: "pulumi-state-delete",
			category: "pulumi",
			reason: "pulumi state delete removes resource from state.",
			matchedTokens: ["pulumi", "state", "delete"],
			confidence: "high",
		};
	}

	// pulumi up --yes (auto-approve)
	if (subcommand === "up" && hasAutoApproveFlag(args)) {
		const decision = options.paranoid || options.paranoidPulumi ? "deny" : "warn";
		return {
			decision,
			rule: "pulumi-up-yes",
			category: "pulumi",
			reason: "pulumi up --yes deploys changes without interactive confirmation.",
			matchedTokens: ["pulumi", "up", "--yes"],
			confidence: "high",
		};
	}

	// pulumi refresh --yes (auto-approve)
	if (subcommand === "refresh" && hasAutoApproveFlag(args)) {
		const decision = options.paranoid || options.paranoidPulumi ? "deny" : "warn";
		return {
			decision,
			rule: "pulumi-refresh-yes",
			category: "pulumi",
			reason: "pulumi refresh --yes refreshes state without interactive confirmation.",
			matchedTokens: ["pulumi", "refresh", "--yes"],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}
