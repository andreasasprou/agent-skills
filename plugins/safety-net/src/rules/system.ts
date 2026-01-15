/**
 * System/process command rules
 * Handles kill, killall, pkill and related dangerous operations
 */

import { extractWords, tokenize } from "../shell/parser.ts";
import { stripWrappers } from "../shell/wrappers.ts";
import type { AnalyzerOptions, SegmentResult } from "../types.ts";

/** Critical PIDs that should never be killed */
const CRITICAL_PIDS = ["1", "0"];

/** Critical process names that should never be killed */
const CRITICAL_PROCESSES = [
	"init",
	"systemd",
	"launchd",
	"kernel",
	"kthreadd",
	"sshd",
	"dockerd",
];

/**
 * Check if kill command has SIGKILL (-9 or -KILL)
 */
function hasSigkill(args: string[]): boolean {
	for (const arg of args) {
		if (arg === "-9" || arg === "-KILL" || arg === "-SIGKILL") {
			return true;
		}
		// Handle -s 9 or -s KILL format
		if (arg === "-s") {
			const idx = args.indexOf(arg);
			const nextArg = args[idx + 1];
			if (nextArg === "9" || nextArg === "KILL" || nextArg === "SIGKILL") {
				return true;
			}
		}
		// Handle --signal=9 format
		if (arg.startsWith("--signal=")) {
			const sig = arg.slice("--signal=".length);
			if (sig === "9" || sig === "KILL" || sig === "SIGKILL") {
				return true;
			}
		}
	}
	return false;
}

/**
 * Extract PIDs from kill arguments
 */
function extractPids(args: string[]): string[] {
	const pids: string[] = [];
	let skipNext = false;

	for (let i = 0; i < args.length; i++) {
		if (skipNext) {
			skipNext = false;
			continue;
		}

		const arg = args[i];

		// Skip signal specifications
		if (arg === "-s" || arg === "-n") {
			skipNext = true;
			continue;
		}

		// Skip options
		if (arg?.startsWith("-")) {
			continue;
		}

		// Remaining args are PIDs or process names
		if (arg) {
			pids.push(arg);
		}
	}

	return pids;
}

/**
 * Analyze a kill command
 */
function analyzeKillCommand(
	words: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const args = words.slice(1);
	const isSigkill = hasSigkill(args);
	const pids = extractPids(args);

	// Check for critical PIDs
	for (const pid of pids) {
		if (CRITICAL_PIDS.includes(pid)) {
			return {
				decision: "deny",
				rule: "kill-critical-pid",
				category: "system",
				reason: `kill targeting critical PID ${pid} (init/kernel).`,
				matchedTokens: ["kill", pid],
				confidence: "high",
			};
		}
	}

	// SIGKILL (-9) is dangerous - processes can't clean up
	if (isSigkill) {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "kill-sigkill",
			category: "system",
			reason: "kill -9 (SIGKILL) forcefully terminates without cleanup.",
			matchedTokens: ["kill", "-9", ...pids],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze killall/pkill commands (mass process termination)
 */
function analyzeKillallCommand(
	words: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const cmd = words[0];
	const args = words.slice(1);
	const isSigkill = hasSigkill(args);
	const targets = extractPids(args); // For killall/pkill these are process names/patterns

	// Check for critical process names
	for (const target of targets) {
		const lowerTarget = target?.toLowerCase();
		if (lowerTarget && CRITICAL_PROCESSES.some((p) => lowerTarget.includes(p))) {
			return {
				decision: "deny",
				rule: `${cmd}-critical-process`,
				category: "system",
				reason: `${cmd} targeting critical process '${target}'.`,
				matchedTokens: [cmd || "killall", target],
				confidence: "high",
			};
		}
	}

	// Mass kill with SIGKILL is very dangerous
	if (isSigkill) {
		return {
			decision: options.paranoid ? "deny" : "warn",
			rule: `${cmd}-sigkill`,
			category: "system",
			reason: `${cmd} -9 forcefully terminates multiple processes without cleanup.`,
			matchedTokens: [cmd || "killall", "-9", ...targets],
			confidence: "high",
		};
	}

	// Even without SIGKILL, mass killing is potentially dangerous
	if (targets.length > 0) {
		return {
			decision: "warn",
			rule: `${cmd}-mass`,
			category: "system",
			reason: `${cmd} terminates all processes matching '${targets.join(", ")}'.`,
			matchedTokens: [cmd || "killall", ...targets],
			confidence: "medium",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze shutdown/reboot/halt/poweroff commands
 */
function analyzePowerCommand(
	words: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const cmd = words[0];
	const args = words.slice(1);

	// Check for cancel flag (safe)
	if (args.includes("-c") || args.includes("--cancel")) {
		return { decision: "allow" };
	}

	// Check for --help or similar
	if (args.includes("--help") || args.includes("-h")) {
		return { decision: "allow" };
	}

	// Power commands are always dangerous
	return {
		decision: "deny",
		rule: `${cmd}-power`,
		category: "system",
		reason: `${cmd} will shut down or restart the system.`,
		matchedTokens: [cmd || "shutdown", ...args.filter((a) => !a.startsWith("-"))],
		confidence: "high",
	};
}

/**
 * Analyze init command (init 0, init 6, etc.)
 */
function analyzeInitCommand(
	words: string[],
	_options: AnalyzerOptions,
): SegmentResult {
	const args = words.slice(1);

	// init 0 = shutdown, init 6 = reboot
	const dangerousRunlevels = ["0", "6"];
	const hasDangerousRunlevel = args.some((arg) => dangerousRunlevels.includes(arg));

	if (hasDangerousRunlevel) {
		const runlevel = args.find((arg) => dangerousRunlevels.includes(arg));
		const action = runlevel === "0" ? "shutdown" : "reboot";
		return {
			decision: "deny",
			rule: `init-${action}`,
			category: "system",
			reason: `init ${runlevel} will ${action} the system.`,
			matchedTokens: ["init", runlevel || "0"],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze a system/process command for dangerous operations
 */
export function analyzeSystemCommand(
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
		case "kill":
			return analyzeKillCommand(words, options);

		case "killall":
		case "pkill":
			return analyzeKillallCommand(words, options);

		case "shutdown":
		case "reboot":
		case "halt":
		case "poweroff":
			return analyzePowerCommand(words, options);

		case "init":
			return analyzeInitCommand(words, options);

		default:
			return { decision: "allow" };
	}
}
