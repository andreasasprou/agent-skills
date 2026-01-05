/**
 * Git destructive command rules
 */

import { extractWords, tokenize } from "../shell/parser.ts";
import { stripWrappers } from "../shell/wrappers.ts";
import type { AnalyzerOptions, SegmentResult } from "../types.ts";

/** Check if command has safety flags that make it non-destructive */
function hasSafetyFlags(args: string[]): boolean {
	const safeFlags = [
		"--dry-run",
		"-n",
		"--porcelain",
		"--help",
		"-h",
		"--version",
	];
	return args.some((arg) => safeFlags.includes(arg));
}

/** Check if a git push is using force without lease */
function isUnsafeForce(args: string[]): boolean {
	const hasForce = args.some(
		(arg) => arg === "--force" || arg === "-f" || arg.startsWith("--force="),
	);
	const hasLease = args.some(
		(arg) =>
			arg === "--force-with-lease" || arg.startsWith("--force-with-lease="),
	);
	return hasForce && !hasLease;
}

/** Check if args contain a path separator indicating file targeting */
function hasPathArg(args: string[], afterDoubleDash = false): boolean {
	const ddIndex = args.indexOf("--");
	const searchArgs =
		afterDoubleDash && ddIndex >= 0 ? args.slice(ddIndex + 1) : args;
	return searchArgs.some((arg) => !arg.startsWith("-"));
}

/**
 * Analyze a git command for destructive operations
 */
export function analyzeGitCommand(
	command: string,
	_options: AnalyzerOptions = {},
): SegmentResult {
	const tokens = tokenize(command);
	const { tokens: strippedTokens } = stripWrappers(tokens);
	const words = extractWords(strippedTokens);

	// First word should be "git"
	if (words[0] !== "git" || words.length < 2) {
		return { decision: "allow" };
	}

	const subcommand = words[1];
	const args = words.slice(2);

	// Skip if safety flags present
	if (hasSafetyFlags(args)) {
		return { decision: "allow" };
	}

	// git checkout -- <path> or git checkout <ref> -- <path>
	if (subcommand === "checkout") {
		const hasDash = args.includes("--");
		const hasForce = args.includes("-f") || args.includes("--force");

		if (hasDash || hasForce) {
			return {
				decision: "warn",
				rule: "git-checkout-discard",
				category: "git",
				reason:
					"git checkout can discard uncommitted changes. Use 'git stash' first if needed.",
				matchedTokens: ["git", "checkout", hasDash ? "--" : "-f"],
				confidence: "high",
			};
		}
	}

	// git reset --hard or --merge
	if (subcommand === "reset") {
		const hasHard = args.includes("--hard");
		const hasMerge = args.includes("--merge");

		if (hasHard || hasMerge) {
			return {
				decision: "deny",
				rule: "git-reset-hard",
				category: "git",
				reason: `git reset ${hasHard ? "--hard" : "--merge"} destroys uncommitted changes permanently.`,
				matchedTokens: ["git", "reset", hasHard ? "--hard" : "--merge"],
				confidence: "high",
			};
		}
	}

	// git clean -f (force required to actually delete)
	if (subcommand === "clean") {
		const hasForce =
			args.includes("-f") ||
			args.includes("--force") ||
			args.some((a) => /^-[a-zA-Z]*f/.test(a));

		if (hasForce) {
			return {
				decision: "deny",
				rule: "git-clean-force",
				category: "git",
				reason: "git clean -f permanently removes untracked files.",
				matchedTokens: ["git", "clean", "-f"],
				confidence: "high",
			};
		}
	}

	// git push --force (without --force-with-lease)
	if (subcommand === "push") {
		if (isUnsafeForce(args)) {
			return {
				decision: "deny",
				rule: "git-push-force",
				category: "git",
				reason:
					"git push --force can destroy remote history. Use --force-with-lease instead.",
				matchedTokens: ["git", "push", "--force"],
				confidence: "high",
			};
		}
	}

	// git branch -D (force delete)
	if (subcommand === "branch") {
		const hasForceDelete =
			args.includes("-D") ||
			(args.includes("-d") && args.includes("-f")) ||
			(args.includes("--delete") && args.includes("--force"));

		if (hasForceDelete) {
			return {
				decision: "warn",
				rule: "git-branch-force-delete",
				category: "git",
				reason:
					"git branch -D force-deletes without checking if branch is merged.",
				matchedTokens: ["git", "branch", "-D"],
				confidence: "high",
			};
		}
	}

	// git stash drop or clear
	if (subcommand === "stash") {
		if (args.includes("drop")) {
			return {
				decision: "warn",
				rule: "git-stash-drop",
				category: "git",
				reason: "git stash drop permanently deletes a stashed change.",
				matchedTokens: ["git", "stash", "drop"],
				confidence: "high",
			};
		}
		if (args.includes("clear")) {
			return {
				decision: "deny",
				rule: "git-stash-clear",
				category: "git",
				reason: "git stash clear permanently deletes ALL stashed changes.",
				matchedTokens: ["git", "stash", "clear"],
				confidence: "high",
			};
		}
	}

	// git restore (without --staged discards working tree changes)
	if (subcommand === "restore") {
		const hasStaged = args.includes("--staged") || args.includes("-S");
		const hasWorktree = args.includes("--worktree") || args.includes("-W");

		// If restoring worktree (explicitly or by default when not --staged only)
		if (!hasStaged || hasWorktree) {
			if (hasPathArg(args)) {
				return {
					decision: "warn",
					rule: "git-restore-worktree",
					category: "git",
					reason: "git restore discards uncommitted changes to working tree.",
					matchedTokens: ["git", "restore"],
					confidence: "medium",
				};
			}
		}
	}

	// git switch -f
	if (subcommand === "switch") {
		const hasForce =
			args.includes("-f") ||
			args.includes("--force") ||
			args.includes("--discard-changes");

		if (hasForce) {
			return {
				decision: "warn",
				rule: "git-switch-force",
				category: "git",
				reason: "git switch -f discards local changes when switching branches.",
				matchedTokens: ["git", "switch", "-f"],
				confidence: "high",
			};
		}
	}

	// git worktree remove --force
	if (subcommand === "worktree" && args.includes("remove")) {
		if (args.includes("--force") || args.includes("-f")) {
			return {
				decision: "warn",
				rule: "git-worktree-remove-force",
				category: "git",
				reason:
					"git worktree remove --force can delete worktree files with uncommitted changes.",
				matchedTokens: ["git", "worktree", "remove", "--force"],
				confidence: "high",
			};
		}
	}

	// git rebase (history rewrite - warn by default)
	if (subcommand === "rebase") {
		// Allow abort/continue/skip
		if (
			args.includes("--abort") ||
			args.includes("--continue") ||
			args.includes("--skip")
		) {
			return { decision: "allow" };
		}
		return {
			decision: "warn",
			rule: "git-rebase",
			category: "git",
			reason:
				"git rebase rewrites commit history. Ensure you understand the implications.",
			matchedTokens: ["git", "rebase"],
			confidence: "medium",
		};
	}

	// git filter-repo / filter-branch (history rewrite)
	if (subcommand === "filter-repo" || subcommand === "filter-branch") {
		return {
			decision: "warn",
			rule: "git-filter-history",
			category: "git",
			reason: `git ${subcommand} rewrites repository history. This is dangerous for shared repositories.`,
			matchedTokens: ["git", subcommand],
			confidence: "high",
		};
	}

	// git reflog expire
	if (subcommand === "reflog" && args.includes("expire")) {
		return {
			decision: "warn",
			rule: "git-reflog-expire",
			category: "git",
			reason: "git reflog expire can remove recovery data for lost commits.",
			matchedTokens: ["git", "reflog", "expire"],
			confidence: "high",
		};
	}

	// git gc --prune=now
	if (subcommand === "gc") {
		const hasPruneNow = args.some(
			(arg) => arg === "--prune=now" || arg === "--prune=all",
		);
		if (hasPruneNow) {
			return {
				decision: "warn",
				rule: "git-gc-prune",
				category: "git",
				reason:
					"git gc --prune=now immediately removes unreachable objects, reducing recovery options.",
				matchedTokens: ["git", "gc", "--prune=now"],
				confidence: "high",
			};
		}
	}

	return { decision: "allow" };
}
