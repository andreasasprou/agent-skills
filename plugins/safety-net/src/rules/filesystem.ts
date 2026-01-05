/**
 * Filesystem destructive command rules
 * Handles rm -rf, find -delete, and related operations
 */

import { extractWords, tokenize } from "../shell/parser.ts";
import { extractNestedCommands, stripWrappers } from "../shell/wrappers.ts";
import type { AnalyzerOptions, SegmentResult } from "../types.ts";
import { isDangerousPath, isSystemPath, isUnderSafeRoot } from "../utils.ts";

/**
 * Check if rm command has recursive and force flags
 */
function hasRecursiveForce(args: string[]): boolean {
	let hasRecursive = false;
	let hasForce = false;

	for (const arg of args) {
		if (arg.startsWith("-") && !arg.startsWith("--")) {
			// Combined flags like -rf, -fr, -rfv
			if (arg.includes("r") || arg.includes("R")) hasRecursive = true;
			if (arg.includes("f")) hasForce = true;
		} else {
			if (arg === "--recursive" || arg === "-r" || arg === "-R")
				hasRecursive = true;
			if (arg === "--force" || arg === "-f") hasForce = true;
		}
	}

	return hasRecursive && hasForce;
}

/**
 * Check if rm command has --no-preserve-root
 */
function hasNoPreserveRoot(args: string[]): boolean {
	return args.includes("--no-preserve-root");
}

/**
 * Extract target paths from rm arguments
 */
function extractRmTargets(args: string[]): string[] {
	const targets: string[] = [];
	let skipNext = false;

	for (const arg of args) {
		if (skipNext) {
			skipNext = false;
			continue;
		}

		// Skip options that take arguments
		if (arg === "--interactive" || arg === "-i" || arg === "-I") {
			continue;
		}

		// Skip option arguments
		if (arg.startsWith("-")) {
			// Some options like --preserve-root don't need skipping
			continue;
		}

		targets.push(arg);
	}

	return targets;
}

/**
 * Analyze an rm command
 */
function analyzeRmCommand(
	words: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const args = words.slice(1);

	// Check for interactive mode (safer)
	if (
		args.includes("-i") ||
		args.includes("-I") ||
		args.includes("--interactive")
	) {
		return { decision: "allow" };
	}

	const isRecursiveForce = hasRecursiveForce(args);
	const noPreserveRoot = hasNoPreserveRoot(args);
	const targets = extractRmTargets(args);

	// --no-preserve-root is always dangerous
	if (noPreserveRoot) {
		return {
			decision: "deny",
			rule: "rm-no-preserve-root",
			category: "filesystem",
			reason: "rm --no-preserve-root explicitly bypasses root protection.",
			matchedTokens: ["rm", "--no-preserve-root"],
			confidence: "high",
		};
	}

	// No targets is suspicious
	if (targets.length === 0 && isRecursiveForce) {
		return {
			decision: "warn",
			rule: "rm-rf-no-target",
			category: "filesystem",
			reason: "rm -rf with no target path specified.",
			matchedTokens: ["rm", "-rf"],
			confidence: "medium",
		};
	}

	// Check each target
	for (const target of targets) {
		// Catastrophic targets
		if (isDangerousPath(target, options.cwd)) {
			return {
				decision: "deny",
				rule: "rm-catastrophic-target",
				category: "filesystem",
				reason: `rm targeting '${target}' would delete critical files/directories.`,
				matchedTokens: ["rm", target],
				confidence: "high",
			};
		}

		// System paths
		if (isSystemPath(target) && isRecursiveForce) {
			return {
				decision: "deny",
				rule: "rm-system-path",
				category: "filesystem",
				reason: `rm -rf targeting system path '${target}'.`,
				matchedTokens: ["rm", "-rf", target],
				confidence: "high",
			};
		}

		// Paranoid mode checks
		if ((options.paranoid || options.paranoidRm) && isRecursiveForce) {
			// Allow temp roots
			if (
				options.tempRoots &&
				isUnderSafeRoot(target, options.tempRoots, options.cwd)
			) {
				continue;
			}

			return {
				decision: "deny",
				rule: "rm-rf-paranoid",
				category: "filesystem",
				reason: `rm -rf '${target}' blocked in paranoid mode.`,
				matchedTokens: ["rm", "-rf", target],
				confidence: "high",
			};
		}
	}

	// Default: warn for rm -rf, allow for regular rm
	if (isRecursiveForce) {
		return {
			decision: "warn",
			rule: "rm-rf",
			category: "filesystem",
			reason: `rm -rf can permanently delete files. Targets: ${targets.join(", ") || "(none)"}`,
			matchedTokens: ["rm", "-rf", ...targets],
			confidence: "medium",
		};
	}

	return { decision: "allow" };
}

/**
 * Check if a path is extremely dangerous for find -delete
 * More lenient than isDangerousPath since find has filter criteria
 */
function isFindDangerousPath(path: string): boolean {
	// Only truly catastrophic root paths
	const catastrophic = ["/", "$HOME", "~"];
	return catastrophic.includes(path);
}

/**
 * Analyze a find command for -delete or -exec rm
 */
function analyzeFindCommand(
	words: string[],
	_options: AnalyzerOptions,
): SegmentResult {
	const args = words.slice(1);

	// Check for -delete
	if (args.includes("-delete")) {
		// Find the search path (usually first non-option arg)
		const searchPath = args.find((a) => !a.startsWith("-") && a !== "-delete");

		// Only deny for truly catastrophic paths (/, ~, $HOME)
		// For find, "." is acceptable since find has filter criteria
		if (searchPath && isFindDangerousPath(searchPath)) {
			return {
				decision: "deny",
				rule: "find-delete-dangerous",
				category: "filesystem",
				reason: `find -delete on dangerous path '${searchPath}'.`,
				matchedTokens: ["find", "-delete", searchPath],
				confidence: "high",
			};
		}

		return {
			decision: "warn",
			rule: "find-delete",
			category: "filesystem",
			reason: "find -delete permanently removes matched files.",
			matchedTokens: ["find", "-delete"],
			confidence: "high",
		};
	}

	// -exec with rm is handled by nested command extraction
	return { decision: "allow" };
}

/**
 * Analyze an xargs or parallel command
 */
function analyzeXargsCommand(
	words: string[],
	command: string,
	options: AnalyzerOptions,
): SegmentResult {
	// Extract the nested command
	const tokens = tokenize(command);
	const nested = extractNestedCommands(tokens);

	for (const n of nested) {
		if (n.type === "xargs" && n.command.includes("rm")) {
			// Check if it's rm -rf
			const rmWords = n.command.split(/\s+/);
			if (rmWords[0] === "rm" && hasRecursiveForce(rmWords.slice(1))) {
				return {
					decision: options.paranoid || options.paranoidRm ? "deny" : "warn",
					rule: "xargs-rm-rf",
					category: "filesystem",
					reason: "xargs/parallel feeding input to rm -rf is dangerous.",
					matchedTokens: [words[0] || "xargs", "rm", "-rf"],
					confidence: "high",
				};
			}
		}
	}

	return { decision: "allow" };
}

/**
 * Analyze a filesystem command for destructive operations
 */
export function analyzeFilesystemCommand(
	command: string,
	options: AnalyzerOptions = {},
): SegmentResult {
	const tokens = tokenize(command);
	const { tokens: strippedTokens } = stripWrappers(tokens);
	const words = extractWords(strippedTokens);

	if (words.length === 0) {
		return { decision: "allow" };
	}

	const cmd = words[0];

	switch (cmd) {
		case "rm":
			return analyzeRmCommand(words, options);

		case "find":
			return analyzeFindCommand(words, options);

		case "xargs":
		case "parallel":
			return analyzeXargsCommand(words, command, options);

		default:
			return { decision: "allow" };
	}
}
