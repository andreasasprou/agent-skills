/**
 * Docker/container destructive command rules
 * Covers docker, docker-compose, and podman
 */

import { extractWords, tokenize } from "../shell/parser.ts";
import { stripWrappers } from "../shell/wrappers.ts";
import type { AnalyzerOptions, SegmentResult } from "../types.ts";

/**
 * Check if command has force flag
 */
function hasForceFlag(args: string[]): boolean {
	return args.some(
		(arg) =>
			arg === "-f" ||
			arg === "--force" ||
			(arg.startsWith("-") && !arg.startsWith("--") && arg.includes("f")),
	);
}

/**
 * Check if command has all flag (affects all containers/images)
 */
function hasAllFlag(args: string[]): boolean {
	return args.some((arg) => arg === "-a" || arg === "--all" || arg === "-all");
}

/**
 * Check if command includes volumes flag
 */
function hasVolumesFlag(args: string[]): boolean {
	return args.some(
		(arg) => arg === "-v" || arg === "--volumes" || arg === "--rmi",
	);
}

/**
 * Analyze docker system commands
 */
function analyzeDockerSystem(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const subcommand = args[0];

	// docker system prune - removes unused data
	if (subcommand === "prune") {
		const hasAll = hasAllFlag(args);
		const hasVolumes = hasVolumesFlag(args);

		if (hasAll || hasVolumes) {
			return {
				decision: "deny",
				rule: "docker-system-prune-aggressive",
				category: "docker",
				reason: `docker system prune ${hasAll ? "-a" : ""} ${hasVolumes ? "--volumes" : ""} removes ALL unused data including volumes.`,
				matchedTokens: ["docker", "system", "prune"],
				confidence: "high",
			};
		}

		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "docker-system-prune",
			category: "docker",
			reason:
				"docker system prune removes unused containers, networks, and images.",
			matchedTokens: ["docker", "system", "prune"],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze docker volume commands
 */
function analyzeDockerVolume(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const subcommand = args[0];

	// docker volume prune
	if (subcommand === "prune") {
		const hasAll = hasAllFlag(args);
		return {
			decision: "deny",
			rule: "docker-volume-prune",
			category: "docker",
			reason: `docker volume prune removes ${hasAll ? "ALL" : "unused"} volumes (permanent data loss).`,
			matchedTokens: ["docker", "volume", "prune"],
			confidence: "high",
		};
	}

	// docker volume rm
	if (subcommand === "rm" || subcommand === "remove") {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "docker-volume-rm",
			category: "docker",
			reason: "docker volume rm permanently deletes volume data.",
			matchedTokens: ["docker", "volume", "rm"],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze docker container commands
 */
function analyzeDockerContainer(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const subcommand = args[0];

	// docker container prune
	if (subcommand === "prune") {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "docker-container-prune",
			category: "docker",
			reason: "docker container prune removes all stopped containers.",
			matchedTokens: ["docker", "container", "prune"],
			confidence: "high",
		};
	}

	// docker container rm -f
	if (subcommand === "rm" || subcommand === "remove") {
		if (hasForceFlag(args.slice(1))) {
			const decision = options.paranoid ? "deny" : "warn";
			return {
				decision,
				rule: "docker-container-rm-force",
				category: "docker",
				reason:
					"docker container rm -f forcibly removes running containers (potential data loss).",
				matchedTokens: ["docker", "container", "rm", "-f"],
				confidence: "high",
			};
		}
	}

	return { decision: "allow" };
}

/**
 * Analyze docker image commands
 */
function analyzeDockerImage(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const subcommand = args[0];

	// docker image prune
	if (subcommand === "prune") {
		const hasAll = hasAllFlag(args);
		if (hasAll) {
			return {
				decision: options.paranoid ? "deny" : "warn",
				rule: "docker-image-prune-all",
				category: "docker",
				reason: "docker image prune -a removes ALL unused images.",
				matchedTokens: ["docker", "image", "prune", "-a"],
				confidence: "high",
			};
		}
	}

	return { decision: "allow" };
}

/**
 * Analyze docker network commands
 */
function analyzeDockerNetwork(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const subcommand = args[0];

	// docker network prune
	if (subcommand === "prune") {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "docker-network-prune",
			category: "docker",
			reason: "docker network prune removes all unused networks.",
			matchedTokens: ["docker", "network", "prune"],
			confidence: "high",
		};
	}

	// docker network rm
	if (subcommand === "rm" || subcommand === "remove") {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "docker-network-rm",
			category: "docker",
			reason: "docker network rm removes networks.",
			matchedTokens: ["docker", "network", "rm"],
			confidence: "medium",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze top-level docker commands (rm, rmi, stop, kill)
 */
function analyzeDockerTopLevel(
	words: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const subcommand = words[1];
	const args = words.slice(2);

	// docker rm -f (shorthand for container rm)
	if (subcommand === "rm") {
		if (hasForceFlag(args)) {
			const decision = options.paranoid ? "deny" : "warn";
			return {
				decision,
				rule: "docker-rm-force",
				category: "docker",
				reason:
					"docker rm -f forcibly removes running containers (potential data loss).",
				matchedTokens: ["docker", "rm", "-f"],
				confidence: "high",
			};
		}
	}

	// docker rmi -f (force remove images)
	if (subcommand === "rmi") {
		if (hasForceFlag(args)) {
			const decision = options.paranoid ? "deny" : "warn";
			return {
				decision,
				rule: "docker-rmi-force",
				category: "docker",
				reason:
					"docker rmi -f forcibly removes images even if in use by containers.",
				matchedTokens: ["docker", "rmi", "-f"],
				confidence: "high",
			};
		}
	}

	// docker stop with $(docker ps -q) pattern - stops all containers
	if (subcommand === "stop" || subcommand === "kill") {
		// Check if args contain a subshell that lists all containers
		const fullCommand = words.join(" ");
		if (
			fullCommand.includes("$(docker ps") ||
			fullCommand.includes("`docker ps")
		) {
			return {
				decision: options.paranoid ? "deny" : "warn",
				rule: `docker-${subcommand}-all`,
				category: "docker",
				reason: `docker ${subcommand} targeting all containers disrupts all services.`,
				matchedTokens: ["docker", subcommand, "$(docker ps...)"],
				confidence: "high",
			};
		}
	}

	return { decision: "allow" };
}

/**
 * Analyze docker-compose commands
 */
function analyzeDockerCompose(
	words: string[],
	options: AnalyzerOptions,
): SegmentResult {
	// Find the actual subcommand (skip docker-compose or docker compose)
	let startIdx = 1;
	if (words[0] === "docker" && words[1] === "compose") {
		startIdx = 2;
	}

	const subcommand = words[startIdx];
	const args = words.slice(startIdx + 1);

	// docker-compose down
	if (subcommand === "down") {
		const hasVolumes =
			args.includes("-v") ||
			args.includes("--volumes") ||
			args.includes("--rmi");
		const hasRmiAll = args.includes("--rmi") && args.includes("all");

		if (hasVolumes) {
			return {
				decision: "deny",
				rule: "docker-compose-down-volumes",
				category: "docker",
				reason:
					"docker-compose down -v removes volumes (permanent data loss).",
				matchedTokens: ["docker-compose", "down", "-v"],
				confidence: "high",
			};
		}

		if (hasRmiAll) {
			return {
				decision: options.paranoid ? "deny" : "warn",
				rule: "docker-compose-down-rmi",
				category: "docker",
				reason: "docker-compose down --rmi all removes all images.",
				matchedTokens: ["docker-compose", "down", "--rmi"],
				confidence: "high",
			};
		}

		// Regular down is relatively safe
		return { decision: "allow" };
	}

	// docker-compose rm
	if (subcommand === "rm") {
		const hasForce = hasForceFlag(args);
		const hasVolumes = args.includes("-v") || args.includes("--volumes");

		if (hasVolumes) {
			return {
				decision: "deny",
				rule: "docker-compose-rm-volumes",
				category: "docker",
				reason:
					"docker-compose rm -v removes containers and volumes (data loss).",
				matchedTokens: ["docker-compose", "rm", "-v"],
				confidence: "high",
			};
		}

		if (hasForce) {
			const decision = options.paranoid ? "deny" : "warn";
			return {
				decision,
				rule: "docker-compose-rm-force",
				category: "docker",
				reason: "docker-compose rm -f removes containers without confirmation.",
				matchedTokens: ["docker-compose", "rm", "-f"],
				confidence: "high",
			};
		}
	}

	return { decision: "allow" };
}

/**
 * Analyze a Docker/container command for destructive operations
 */
export function analyzeDockerCommand(
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

	// docker-compose (hyphenated form)
	if (cmd === "docker-compose") {
		return analyzeDockerCompose(words, options);
	}

	// docker or podman
	if (cmd === "docker" || cmd === "podman") {
		const subcommand = words[1];
		const subArgs = words.slice(2);

		// docker compose (space form)
		if (subcommand === "compose") {
			return analyzeDockerCompose(words, options);
		}

		// Sub-command based routing
		switch (subcommand) {
			case "system":
				return analyzeDockerSystem(subArgs, options);
			case "volume":
				return analyzeDockerVolume(subArgs, options);
			case "container":
				return analyzeDockerContainer(subArgs, options);
			case "image":
				return analyzeDockerImage(subArgs, options);
			case "network":
				return analyzeDockerNetwork(subArgs, options);
			default:
				return analyzeDockerTopLevel(words, options);
		}
	}

	return { decision: "allow" };
}
