/**
 * System/process command rules
 * Handles kill, killall, pkill, disk operations, permissions, and services
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

/** Critical system directories */
const CRITICAL_SYSTEM_DIRS = [
	"/",
	"/bin",
	"/sbin",
	"/usr",
	"/usr/bin",
	"/usr/sbin",
	"/etc",
	"/var",
	"/lib",
	"/lib64",
	"/boot",
	"/root",
	"/System",
	"/Library",
	"/Applications",
];

/** Critical services that should not be stopped */
const CRITICAL_SERVICES = [
	"sshd",
	"ssh",
	"networking",
	"network",
	"NetworkManager",
	"systemd-journald",
	"systemd-logind",
	"dbus",
	"docker",
	"containerd",
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

// ============================================================================
// Disk Operations
// ============================================================================

/**
 * Check if a target is a block device
 */
function isBlockDevice(target: string): boolean {
	return (
		target.startsWith("/dev/sd") ||
		target.startsWith("/dev/hd") ||
		target.startsWith("/dev/nvme") ||
		target.startsWith("/dev/vd") ||
		target.startsWith("/dev/xvd") ||
		target.startsWith("/dev/disk") ||
		target.startsWith("/dev/mmcblk") ||
		target === "/dev/null" // This is actually safe, but let's be careful
	);
}

/**
 * Analyze dd command (disk duplicate)
 */
function analyzeDdCommand(
	words: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const args = words.slice(1);

	// Extract of= target
	let outputTarget: string | undefined;
	for (const arg of args) {
		if (arg.startsWith("of=")) {
			outputTarget = arg.slice(3);
			break;
		}
	}

	// dd to a block device is extremely dangerous
	if (outputTarget && isBlockDevice(outputTarget)) {
		return {
			decision: "deny",
			rule: "dd-to-device",
			category: "system",
			reason: `dd writing to block device ${outputTarget} can destroy disk data.`,
			matchedTokens: ["dd", `of=${outputTarget}`],
			confidence: "high",
		};
	}

	// dd to system paths
	if (outputTarget && CRITICAL_SYSTEM_DIRS.some((dir) => outputTarget?.startsWith(dir + "/"))) {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "dd-to-system-path",
			category: "system",
			reason: `dd writing to system path ${outputTarget} may damage the system.`,
			matchedTokens: ["dd", `of=${outputTarget}`],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze mkfs command (make filesystem)
 */
function analyzeMkfsCommand(
	words: string[],
	_options: AnalyzerOptions,
): SegmentResult {
	// mkfs is always dangerous - it formats disks
	return {
		decision: "deny",
		rule: "mkfs",
		category: "system",
		reason: "mkfs formats a disk, destroying ALL existing data.",
		matchedTokens: words.slice(0, 2),
		confidence: "high",
	};
}

/**
 * Analyze fdisk/parted command (partition management)
 */
function analyzePartitionCommand(
	words: string[],
	_options: AnalyzerOptions,
): SegmentResult {
	const cmd = words[0];

	return {
		decision: "deny",
		rule: `${cmd}-partition`,
		category: "system",
		reason: `${cmd} modifies disk partition table. Incorrect use can cause data loss.`,
		matchedTokens: words.slice(0, 2),
		confidence: "high",
	};
}

// ============================================================================
// Permission Operations
// ============================================================================

/**
 * Check for recursive flag
 */
function hasRecursiveFlag(args: string[]): boolean {
	return args.includes("-R") || args.includes("--recursive");
}

/**
 * Check if chmod mode is dangerous (world-writable)
 */
function isDangerousChmodMode(mode: string): boolean {
	// 777, 776, 766, etc. - world or group writable
	if (/^[0-7]?[67][67][67]$/.test(mode)) return true;

	// Symbolic: a+w, o+w
	if (/[ao]\+w/.test(mode)) return true;

	return false;
}

/**
 * Check if target is a critical system path
 */
function isCriticalPath(target: string): boolean {
	return CRITICAL_SYSTEM_DIRS.some(
		(dir) => target === dir || target.startsWith(dir + "/"),
	);
}

/**
 * Analyze chmod command
 */
function analyzeChmodCommand(
	words: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const args = words.slice(1);
	const hasRecursive = hasRecursiveFlag(args);

	// Extract mode and target
	const nonFlagArgs = args.filter((a) => !a.startsWith("-"));
	const mode = nonFlagArgs[0];
	const target = nonFlagArgs[1];

	// chmod 777 or similar world-writable modes
	if (mode && isDangerousChmodMode(mode)) {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "chmod-world-writable",
			category: "system",
			reason: `chmod ${mode} makes files world-writable (security risk).`,
			matchedTokens: ["chmod", mode],
			confidence: "high",
		};
	}

	// Recursive chmod on critical paths
	if (hasRecursive && target && isCriticalPath(target)) {
		return {
			decision: "deny",
			rule: "chmod-recursive-system",
			category: "system",
			reason: `chmod -R on system path ${target} can break the system.`,
			matchedTokens: ["chmod", "-R", target],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze chown command
 */
function analyzeChownCommand(
	words: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const args = words.slice(1);
	const hasRecursive = hasRecursiveFlag(args);

	// Extract target
	const nonFlagArgs = args.filter((a) => !a.startsWith("-"));
	const target = nonFlagArgs[1]; // Second non-flag arg is typically the path

	// Recursive chown on critical paths
	if (hasRecursive && target && isCriticalPath(target)) {
		return {
			decision: "deny",
			rule: "chown-recursive-system",
			category: "system",
			reason: `chown -R on system path ${target} can break the system.`,
			matchedTokens: ["chown", "-R", target],
			confidence: "high",
		};
	}

	// chown on root
	const owner = nonFlagArgs[0];
	if (target === "/" || (hasRecursive && isCriticalPath(target || ""))) {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "chown-system-path",
			category: "system",
			reason: `chown ${owner} on ${target} affects system file ownership.`,
			matchedTokens: ["chown", owner || "", target || ""],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

// ============================================================================
// Service Operations
// ============================================================================

/**
 * Analyze systemctl command
 */
function analyzeSystemctlCommand(
	words: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const args = words.slice(1);
	const action = args[0];
	const service = args[1];

	// Dangerous actions
	const dangerousActions = ["stop", "disable", "mask", "kill"];

	if (action && dangerousActions.includes(action)) {
		// Check if it's a critical service
		if (service && CRITICAL_SERVICES.some((s) => service.includes(s))) {
			return {
				decision: "deny",
				rule: `systemctl-${action}-critical`,
				category: "system",
				reason: `systemctl ${action} ${service} would affect a critical system service.`,
				matchedTokens: ["systemctl", action, service],
				confidence: "high",
			};
		}

		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: `systemctl-${action}`,
			category: "system",
			reason: `systemctl ${action} ${service || "service"} stops or disables a service.`,
			matchedTokens: ["systemctl", action],
			confidence: "medium",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze launchctl command (macOS)
 */
function analyzeLaunchctlCommand(
	words: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const args = words.slice(1);
	const action = args[0];

	const dangerousActions = ["unload", "stop", "remove", "bootout"];

	if (action && dangerousActions.includes(action)) {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: `launchctl-${action}`,
			category: "system",
			reason: `launchctl ${action} stops or removes a service.`,
			matchedTokens: ["launchctl", action],
			confidence: "medium",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze reboot/shutdown/halt/poweroff command
 */
function analyzePowerCommand(
	words: string[],
	_options: AnalyzerOptions,
): SegmentResult {
	const cmd = words[0];

	return {
		decision: "deny",
		rule: `${cmd}-system`,
		category: "system",
		reason: `${cmd} will ${cmd === "reboot" ? "restart" : "shut down"} the system.`,
		matchedTokens: [cmd || "shutdown"],
		confidence: "high",
	};
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
		// Process management
		case "kill":
			return analyzeKillCommand(words, options);
		case "killall":
		case "pkill":
			return analyzeKillallCommand(words, options);

		// Disk operations
		case "dd":
			return analyzeDdCommand(words, options);
		case "mkfs":
		case "mkfs.ext4":
		case "mkfs.ext3":
		case "mkfs.xfs":
		case "mkfs.btrfs":
		case "mkfs.vfat":
		case "mkfs.ntfs":
			return analyzeMkfsCommand(words, options);
		case "fdisk":
		case "parted":
		case "gdisk":
		case "cfdisk":
			return analyzePartitionCommand(words, options);

		// Permission operations
		case "chmod":
			return analyzeChmodCommand(words, options);
		case "chown":
		case "chgrp":
			return analyzeChownCommand(words, options);

		// Service operations
		case "systemctl":
			return analyzeSystemctlCommand(words, options);
		case "launchctl":
			return analyzeLaunchctlCommand(words, options);
		case "service":
			// service <name> stop
			if (words[2] === "stop" || words[2] === "restart") {
				const decision = options.paranoid ? "deny" : "warn";
				return {
					decision,
					rule: `service-${words[2]}`,
					category: "system",
					reason: `service ${words[1]} ${words[2]} affects a system service.`,
					matchedTokens: words.slice(0, 3),
					confidence: "medium",
				};
			}
			return { decision: "allow" };

		// Power operations
		case "reboot":
		case "shutdown":
		case "halt":
		case "poweroff":
		case "init":
			return analyzePowerCommand(words, options);

		default:
			return { decision: "allow" };
	}
}
