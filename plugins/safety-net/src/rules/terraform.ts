/**
 * Terraform CLI destructive command rules
 */

import { extractWords, tokenize } from "../shell/parser.ts";
import { stripWrappers } from "../shell/wrappers.ts";
import type { AnalyzerOptions, SegmentResult } from "../types.ts";

/**
 * Check for auto-approve flag
 */
function hasAutoApprove(args: string[]): boolean {
	return args.includes("-auto-approve") || args.includes("--auto-approve");
}

/**
 * Check for -destroy flag in plan
 */
function hasDestroyFlag(args: string[]): boolean {
	return args.includes("-destroy") || args.includes("--destroy");
}

/**
 * Analyze terraform destroy command
 */
function analyzeTerraformDestroy(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const autoApprove = hasAutoApprove(args);

	if (autoApprove) {
		return {
			decision: "deny",
			rule: "terraform-destroy-auto-approve",
			category: "terraform",
			reason:
				"terraform destroy -auto-approve destroys ALL infrastructure without confirmation.",
			matchedTokens: ["terraform", "destroy", "-auto-approve"],
			confidence: "high",
		};
	}

	// Even with confirmation, destroy is very dangerous
	return {
		decision: "deny",
		rule: "terraform-destroy",
		category: "terraform",
		reason:
			"terraform destroy removes ALL managed infrastructure. Use with extreme caution.",
		matchedTokens: ["terraform", "destroy"],
		confidence: "high",
	};
}

/**
 * Analyze terraform apply command
 */
function analyzeTerraformApply(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const autoApprove = hasAutoApprove(args);
	const hasDestroy = hasDestroyFlag(args);

	// terraform apply -destroy is equivalent to destroy
	if (hasDestroy) {
		if (autoApprove) {
			return {
				decision: "deny",
				rule: "terraform-apply-destroy-auto-approve",
				category: "terraform",
				reason:
					"terraform apply -destroy -auto-approve destroys infrastructure without confirmation.",
				matchedTokens: ["terraform", "apply", "-destroy", "-auto-approve"],
				confidence: "high",
			};
		}

		return {
			decision: "deny",
			rule: "terraform-apply-destroy",
			category: "terraform",
			reason: "terraform apply -destroy removes all managed infrastructure.",
			matchedTokens: ["terraform", "apply", "-destroy"],
			confidence: "high",
		};
	}

	// Auto-approve without destroy is still risky
	if (autoApprove) {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "terraform-apply-auto-approve",
			category: "terraform",
			reason:
				"terraform apply -auto-approve modifies infrastructure without confirmation.",
			matchedTokens: ["terraform", "apply", "-auto-approve"],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze terraform plan command
 */
function analyzeTerraformPlan(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const hasDestroy = hasDestroyFlag(args);

	// terraform plan -destroy shows what would be destroyed
	if (hasDestroy) {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "terraform-plan-destroy",
			category: "terraform",
			reason:
				"terraform plan -destroy shows destruction plan. Be careful not to apply it.",
			matchedTokens: ["terraform", "plan", "-destroy"],
			confidence: "medium",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze terraform taint command
 */
function analyzeTerraformTaint(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const decision = options.paranoid ? "deny" : "warn";
	return {
		decision,
		rule: "terraform-taint",
		category: "terraform",
		reason:
			"terraform taint marks resource for destruction and recreation on next apply.",
		matchedTokens: ["terraform", "taint"],
		confidence: "high",
	};
}

/**
 * Analyze terraform untaint command
 */
function analyzeTerraformUntaint(
	_args: string[],
	_options: AnalyzerOptions,
): SegmentResult {
	return { decision: "allow" }; // Untaint is generally safe
}

/**
 * Analyze terraform state commands
 */
function analyzeTerraformState(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const stateSubcommand = args[0];

	// terraform state rm - removes resource from state (becomes unmanaged)
	if (stateSubcommand === "rm") {
		return {
			decision: options.paranoid ? "deny" : "warn",
			rule: "terraform-state-rm",
			category: "terraform",
			reason:
				"terraform state rm removes resource from state. Resource becomes unmanaged and may cause drift.",
			matchedTokens: ["terraform", "state", "rm"],
			confidence: "high",
		};
	}

	// terraform state mv - moves resource (may cause recreation)
	if (stateSubcommand === "mv") {
		return {
			decision: options.paranoid ? "deny" : "warn",
			rule: "terraform-state-mv",
			category: "terraform",
			reason:
				"terraform state mv moves resources. Incorrect moves may cause resource recreation.",
			matchedTokens: ["terraform", "state", "mv"],
			confidence: "high",
		};
	}

	// terraform state replace-provider - changes provider
	if (stateSubcommand === "replace-provider") {
		return {
			decision: options.paranoid ? "deny" : "warn",
			rule: "terraform-state-replace-provider",
			category: "terraform",
			reason:
				"terraform state replace-provider changes the provider for resources in state.",
			matchedTokens: ["terraform", "state", "replace-provider"],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze terraform import command
 */
function analyzeTerraformImport(
	_args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const decision = options.paranoid ? "deny" : "warn";
	return {
		decision,
		rule: "terraform-import",
		category: "terraform",
		reason:
			"terraform import brings existing resources under Terraform management. Ensure correct resource address.",
		matchedTokens: ["terraform", "import"],
		confidence: "medium",
	};
}

/**
 * Analyze terraform force-unlock command
 */
function analyzeTerraformForceUnlock(
	_args: string[],
	_options: AnalyzerOptions,
): SegmentResult {
	return {
		decision: "deny",
		rule: "terraform-force-unlock",
		category: "terraform",
		reason:
			"terraform force-unlock removes state lock. Only use if you are certain no other operation is running.",
		matchedTokens: ["terraform", "force-unlock"],
		confidence: "high",
	};
}

/**
 * Analyze terraform workspace commands
 */
function analyzeTerraformWorkspace(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const workspaceSubcommand = args[0];

	// terraform workspace delete
	if (workspaceSubcommand === "delete") {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "terraform-workspace-delete",
			category: "terraform",
			reason:
				"terraform workspace delete removes workspace. Ensure resources are destroyed first.",
			matchedTokens: ["terraform", "workspace", "delete"],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze terraform refresh command
 */
function analyzeTerraformRefresh(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const autoApprove = hasAutoApprove(args);

	if (autoApprove) {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "terraform-refresh-auto-approve",
			category: "terraform",
			reason:
				"terraform refresh updates state from infrastructure. Changes may be unexpected.",
			matchedTokens: ["terraform", "refresh"],
			confidence: "medium",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze a Terraform command for destructive operations
 */
export function analyzeTerraformCommand(
	command: string,
	options: AnalyzerOptions = {},
): SegmentResult {
	const tokens = tokenize(command);
	const { tokens: strippedTokens } = stripWrappers(tokens);
	const words = extractWords(strippedTokens);

	// First word should be "terraform"
	if (words[0] !== "terraform" || words.length < 2) {
		return { decision: "allow" };
	}

	const subcommand = words[1];
	const args = words.slice(2);

	switch (subcommand) {
		case "destroy":
			return analyzeTerraformDestroy(args, options);
		case "apply":
			return analyzeTerraformApply(args, options);
		case "plan":
			return analyzeTerraformPlan(args, options);
		case "taint":
			return analyzeTerraformTaint(args, options);
		case "untaint":
			return analyzeTerraformUntaint(args, options);
		case "state":
			return analyzeTerraformState(args, options);
		case "import":
			return analyzeTerraformImport(args, options);
		case "force-unlock":
			return analyzeTerraformForceUnlock(args, options);
		case "workspace":
			return analyzeTerraformWorkspace(args, options);
		case "refresh":
			return analyzeTerraformRefresh(args, options);
		default:
			return { decision: "allow" };
	}
}
