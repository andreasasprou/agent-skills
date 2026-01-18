/**
 * Command analyzer orchestrator
 * Coordinates rule checking across all categories
 */

import { loadConfig, mergeConfig } from "./config.ts";
import { analyzeAwsCommand } from "./rules/aws.ts";
import { analyzeFilesystemCommand } from "./rules/filesystem.ts";
import { analyzeGitCommand } from "./rules/git.ts";
import { analyzePulumiCommand } from "./rules/pulumi.ts";
import { analyzeStripeCommand } from "./rules/stripe.ts";
import { analyzeSystemCommand } from "./rules/system.ts";
import { analyzeApiCommand } from "./rules/api.ts";
import { analyzeDockerCommand } from "./rules/docker.ts";
import { analyzeKubernetesCommand } from "./rules/kubernetes.ts";
import { analyzeTerraformCommand } from "./rules/terraform.ts";
import { analyzeGcloudCommand } from "./rules/gcloud.ts";
import { analyzeAzureCommand } from "./rules/azure.ts";
import { analyzeDatabaseCommand } from "./rules/database.ts";
import { analyzeGithubCommand } from "./rules/github.ts";
import { tokenize } from "./shell/parser.ts";
import { hasUnparseableConstructs, splitCommand } from "./shell/splitter.ts";
import {
	extractNestedCommands,
	getEffectiveCommand,
} from "./shell/wrappers.ts";
import type {
	AnalysisResult,
	AnalyzerOptions,
	Decision,
	SegmentResult,
} from "./types.ts";
import { truncateCommand } from "./utils.ts";

/**
 * Commands handled by each analyzer
 */
const SYSTEM_COMMANDS = [
	"kill",
	"killall",
	"pkill",
	"dd",
	"mkfs",
	"mkfs.ext4",
	"mkfs.ext3",
	"mkfs.xfs",
	"mkfs.btrfs",
	"mkfs.vfat",
	"mkfs.ntfs",
	"fdisk",
	"parted",
	"gdisk",
	"cfdisk",
	"chmod",
	"chown",
	"chgrp",
	"systemctl",
	"launchctl",
	"service",
	"reboot",
	"shutdown",
	"halt",
	"poweroff",
	"init",
];

const DOCKER_COMMANDS = ["docker", "docker-compose", "podman"];
const KUBERNETES_COMMANDS = ["kubectl", "helm"];
const DATABASE_COMMANDS = [
	"psql",
	"dropdb",
	"mysql",
	"mysqladmin",
	"mongo",
	"mongosh",
	"mongorestore",
	"redis-cli",
];

/**
 * Analyze a single command segment
 */
function analyzeSegment(
	segment: string,
	options: AnalyzerOptions,
): SegmentResult {
	const { command: cmdName } = getEffectiveCommand(segment);

	// Skip disabled rule sets
	if (!options.disableGit && cmdName === "git") {
		const result = analyzeGitCommand(segment, options);
		if (result.decision !== "allow") return result;
	}

	if (
		!options.disableRm &&
		(cmdName === "rm" ||
			cmdName === "find" ||
			cmdName === "xargs" ||
			cmdName === "parallel")
	) {
		const result = analyzeFilesystemCommand(segment, options);
		if (result.decision !== "allow") return result;
	}

	if (!options.disableAws && cmdName === "aws") {
		const result = analyzeAwsCommand(segment, options);
		if (result.decision !== "allow") return result;
	}

	if (!options.disablePulumi && cmdName === "pulumi") {
		const result = analyzePulumiCommand(segment, options);
		if (result.decision !== "allow") return result;
	}

	if (!options.disableStripe && cmdName === "stripe") {
		const result = analyzeStripeCommand(segment, options);
		if (result.decision !== "allow") return result;
	}

	if (!options.disableSystem && SYSTEM_COMMANDS.includes(cmdName)) {
		const result = analyzeSystemCommand(segment, options);
		if (result.decision !== "allow") return result;
	}

	if (!options.disableApi && cmdName === "curl") {
		const result = analyzeApiCommand(segment, options);
		if (result.decision !== "allow") return result;
	}

	// New rule categories
	if (!options.disableDocker && DOCKER_COMMANDS.includes(cmdName)) {
		const result = analyzeDockerCommand(segment, options);
		if (result.decision !== "allow") return result;
	}

	if (!options.disableKubernetes && KUBERNETES_COMMANDS.includes(cmdName)) {
		const result = analyzeKubernetesCommand(segment, options);
		if (result.decision !== "allow") return result;
	}

	if (!options.disableTerraform && cmdName === "terraform") {
		const result = analyzeTerraformCommand(segment, options);
		if (result.decision !== "allow") return result;
	}

	if (!options.disableGcloud && (cmdName === "gcloud" || cmdName === "gsutil")) {
		const result = analyzeGcloudCommand(segment, options);
		if (result.decision !== "allow") return result;
	}

	if (!options.disableAzure && cmdName === "az") {
		const result = analyzeAzureCommand(segment, options);
		if (result.decision !== "allow") return result;
	}

	if (!options.disableDatabase && DATABASE_COMMANDS.includes(cmdName)) {
		const result = analyzeDatabaseCommand(segment, options);
		if (result.decision !== "allow") return result;
	}

	if (!options.disableGithub && cmdName === "gh") {
		const result = analyzeGithubCommand(segment, options);
		if (result.decision !== "allow") return result;
	}

	return { decision: "allow" };
}

/**
 * Recursively analyze nested commands
 */
function analyzeNested(
	segment: string,
	options: AnalyzerOptions,
	depth: number,
): SegmentResult[] {
	const maxDepth = options.maxRecursionDepth ?? 4;
	if (depth >= maxDepth) {
		return [];
	}

	const tokens = tokenize(segment);
	const nested = extractNestedCommands(tokens);
	const results: SegmentResult[] = [];

	for (const n of nested) {
		// Analyze the nested command
		const result = analyzeSegment(n.command, options);
		if (result.decision !== "allow") {
			// Add context about the wrapper
			result.reason = `[via ${n.wrapper}] ${result.reason || ""}`;
			results.push(result);
		}

		// Recursively check for deeper nesting (shell wrappers)
		if (n.type === "shell") {
			const deepResults = analyzeNested(n.command, options, depth + 1);
			results.push(...deepResults);
		}
	}

	return results;
}

/**
 * Aggregate decisions from multiple segments
 * Rules:
 * 1. Any deny → final is deny
 * 2. Strict mode + unparseable → deny
 * 3. Any warn → final is warn
 * 4. Otherwise → allow
 */
function aggregateDecisions(
	segments: SegmentResult[],
	hasUnparseable: boolean,
	options: AnalyzerOptions,
): Decision {
	// Check for any denies
	if (segments.some((s) => s.decision === "deny")) {
		return "deny";
	}

	// Strict mode: unparseable → deny
	if (options.strict && hasUnparseable) {
		return "deny";
	}

	// Check for any warns
	if (segments.some((s) => s.decision === "warn")) {
		return "warn";
	}

	// Unparseable without strict mode is a warning
	if (hasUnparseable) {
		return "warn";
	}

	return "allow";
}

/**
 * Build a human-readable reason from segment results
 */
function buildReason(segments: SegmentResult[], decision: Decision): string {
	const issues = segments.filter((s) => s.decision !== "allow");

	if (issues.length === 0) {
		return decision === "allow"
			? "Command appears safe."
			: "Unable to fully analyze command.";
	}

	const reasons = issues.map((s) => {
		const prefix = s.decision === "deny" ? "🚫" : "⚠️";
		return `${prefix} ${s.reason || s.rule || "Unknown issue"}`;
	});

	return reasons.join("\n");
}

/**
 * Main entry point: analyze a command for destructive operations
 */
export function analyzeCommand(
	command: string,
	options: AnalyzerOptions = {},
): AnalysisResult {
	// Merge with environment config
	const config = loadConfig();
	const mergedOptions = mergeConfig(options, config);

	// Check for unparseable constructs
	const unparseable = hasUnparseableConstructs(command);

	// Split into segments
	const commandSegments = splitCommand(command);
	const maxSegments = mergedOptions.maxSegments ?? 64;

	// Analyze each segment
	const allResults: SegmentResult[] = [];
	let segmentCount = 0;

	for (const seg of commandSegments) {
		if (segmentCount >= maxSegments) {
			allResults.push({
				decision: mergedOptions.strict ? "deny" : "warn",
				rule: "too-many-segments",
				reason: `Command has more than ${maxSegments} segments.`,
				confidence: "low",
			});
			break;
		}

		// Analyze the segment itself
		const result = analyzeSegment(seg.command, mergedOptions);
		if (result.decision !== "allow") {
			allResults.push(result);
		}

		// Analyze nested commands
		const nestedResults = analyzeNested(seg.command, mergedOptions, 0);
		allResults.push(...nestedResults);

		segmentCount++;
	}

	// Add unparseable warning if needed
	if (unparseable) {
		allResults.push({
			decision: mergedOptions.strict ? "deny" : "warn",
			rule: "unparseable-construct",
			reason:
				"Command contains constructs that cannot be fully analyzed (heredocs, process substitution, etc.).",
			confidence: "low",
		});
	}

	// Aggregate final decision
	let finalDecision = aggregateDecisions(
		allResults,
		unparseable,
		mergedOptions,
	);

	// Apply modifiers
	if (mergedOptions.warnOnly && finalDecision === "deny") {
		finalDecision = "warn";
	}

	if (mergedOptions.bypass) {
		finalDecision = "allow";
	}

	const reason = buildReason(allResults, finalDecision);

	return {
		decision: finalDecision,
		segments: allResults,
		reason,
		command,
		truncatedCommand: truncateCommand(command),
	};
}

// Re-export types
export type { AnalysisResult, SegmentResult, AnalyzerOptions };
