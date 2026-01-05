/**
 * Wrapper stripping and nested command extraction
 * Handles sudo, env, command, and various interpreter wrappers
 */

import type { ParsedToken } from "../types.ts";
import { extractWords, tokenize } from "./parser.ts";

/** Prefixes that should be stripped to get to the actual command */
const STRIP_PREFIXES = [
	"sudo",
	"env",
	"command",
	"builtin",
	"exec",
	"nohup",
	"nice",
	"ionice",
	"time",
	"strace",
	"ltrace",
];

/** Commands that take a positional argument before the actual command */
const COMMANDS_WITH_POSITIONAL_ARG: Record<string, number> = {
	timeout: 1, // timeout DURATION COMMAND
	nice: 0, // nice can take -n NUM but we handle that with options
	ionice: 0, // ionice can take -c CLASS but we handle that with options
};

/** Shell wrappers that execute a command string */
const SHELL_WRAPPERS: Record<string, string[]> = {
	sh: ["-c"],
	bash: ["-c", "-lc"],
	zsh: ["-c", "-lc"],
	dash: ["-c"],
	ksh: ["-c"],
	fish: ["-c"],
};

/** Interpreter wrappers that execute inline code */
const INTERPRETER_WRAPPERS: Record<string, string[]> = {
	python: ["-c"],
	python3: ["-c"],
	node: ["-e", "--eval"],
	ruby: ["-e"],
	perl: ["-e"],
	php: ["-r"],
};

/** Result of wrapper stripping */
export interface StrippedCommand {
	tokens: ParsedToken[];
	strippedPrefixes: string[];
	envVars: Map<string, string>;
}

/** Result of nested command extraction */
export interface ExtractedCommand {
	command: string;
	wrapper: string;
	type: "shell" | "interpreter" | "xargs" | "find-exec";
}

/**
 * Strip wrapper prefixes from tokens
 * Returns the stripped tokens and what was removed
 */
export function stripWrappers(tokens: ParsedToken[]): StrippedCommand {
	const strippedPrefixes: string[] = [];
	const envVars = new Map<string, string>();
	let idx = 0;

	// First, collect any env var assignments
	while (idx < tokens.length && tokens[idx]?.type === "env") {
		const token = tokens[idx];
		const eqIdx = token.value.indexOf("=");
		if (eqIdx > 0) {
			envVars.set(token.value.slice(0, eqIdx), token.value.slice(eqIdx + 1));
		}
		idx++;
	}

	// Then strip wrapper prefixes
	while (idx < tokens.length) {
		const token = tokens[idx];
		if (token?.type !== "word") break;

		const cmd = token.value.toLowerCase();

		// Check if it's a strippable prefix
		if (STRIP_PREFIXES.includes(cmd)) {
			strippedPrefixes.push(token.value);
			idx++;

			// Skip any options for these commands
			while (idx < tokens.length && tokens[idx]?.value.startsWith("-")) {
				idx++;
			}
			continue;
		}

		// Handle commands with positional arguments (e.g., timeout DURATION CMD)
		if (cmd in COMMANDS_WITH_POSITIONAL_ARG) {
			strippedPrefixes.push(token.value);
			idx++;

			// Skip options
			while (idx < tokens.length && tokens[idx]?.value.startsWith("-")) {
				idx++;
			}

			// Skip the required positional arguments
			const numArgs = COMMANDS_WITH_POSITIONAL_ARG[cmd] ?? 0;
			for (let i = 0; i < numArgs && idx < tokens.length; i++) {
				if (!tokens[idx]?.value.startsWith("-")) {
					idx++;
				}
			}
			continue;
		}

		// env with VAR=value handling
		if (cmd === "env" || token.type === "env") {
			strippedPrefixes.push(token.value);
			idx++;
			// Skip VAR=value pairs and options
			while (idx < tokens.length) {
				const next = tokens[idx];
				if (
					next?.type === "env" ||
					next?.value.includes("=") ||
					next?.value.startsWith("-")
				) {
					idx++;
				} else {
					break;
				}
			}
			continue;
		}

		break;
	}

	return {
		tokens: tokens.slice(idx),
		strippedPrefixes,
		envVars,
	};
}

/**
 * Extract nested commands from shell/interpreter wrappers
 */
export function extractNestedCommands(
	tokens: ParsedToken[],
): ExtractedCommand[] {
	const extracted: ExtractedCommand[] = [];
	const words = extractWords(tokens);

	if (words.length < 2) return extracted;

	const cmd = words[0]?.toLowerCase() || "";

	// Check for shell wrappers: sh -c "command"
	if (cmd in SHELL_WRAPPERS) {
		const flags = SHELL_WRAPPERS[cmd];
		for (let i = 1; i < words.length; i++) {
			const word = words[i];
			if (word && flags?.includes(word)) {
				// Next argument is the command to execute
				const nestedCmd = words[i + 1];
				if (nestedCmd) {
					extracted.push({
						command: nestedCmd,
						wrapper: `${cmd} ${word}`,
						type: "shell",
					});
				}
			}
		}
	}

	// Check for interpreter wrappers: python -c "code"
	if (cmd in INTERPRETER_WRAPPERS) {
		const flags = INTERPRETER_WRAPPERS[cmd];
		for (let i = 1; i < words.length; i++) {
			const word = words[i];
			if (word && flags?.includes(word)) {
				const code = words[i + 1];
				if (code) {
					extracted.push({
						command: code,
						wrapper: `${cmd} ${word}`,
						type: "interpreter",
					});
				}
			}
		}
	}

	// Check for xargs: xargs rm -rf
	if (cmd === "xargs") {
		// Everything after xargs (and its options) is the command
		let startIdx = 1;
		while (startIdx < words.length && words[startIdx]?.startsWith("-")) {
			startIdx++;
		}
		if (startIdx < words.length) {
			const xargsCmd = words.slice(startIdx).join(" ");
			if (xargsCmd) {
				extracted.push({
					command: xargsCmd,
					wrapper: "xargs",
					type: "xargs",
				});
			}
		}
	}

	// Check for parallel: parallel rm -rf
	if (cmd === "parallel") {
		let startIdx = 1;
		// Skip parallel options (they can be complex, but we try)
		while (startIdx < words.length && words[startIdx]?.startsWith("-")) {
			const opt = words[startIdx];
			// Some parallel options take arguments
			if (
				opt === "-j" ||
				opt === "--jobs" ||
				opt === "-S" ||
				opt === "--sshlogin"
			) {
				startIdx += 2;
			} else {
				startIdx++;
			}
		}
		if (startIdx < words.length) {
			// Handle ::: separator
			const colonIdx = words.indexOf(":::", startIdx);
			const endIdx = colonIdx > startIdx ? colonIdx : words.length;
			const parallelCmd = words.slice(startIdx, endIdx).join(" ");
			if (parallelCmd) {
				extracted.push({
					command: parallelCmd,
					wrapper: "parallel",
					type: "xargs",
				});
			}
		}
	}

	// Check for find -exec: find . -exec rm -rf {} \;
	if (cmd === "find") {
		for (let i = 1; i < words.length; i++) {
			const word = words[i];
			if (
				word === "-exec" ||
				word === "-execdir" ||
				word === "-ok" ||
				word === "-okdir"
			) {
				// Collect until {} \; or {} +
				const execCmd: string[] = [];
				for (let j = i + 1; j < words.length; j++) {
					const w = words[j];
					if (w === ";" || w === "\\;" || w === "+") break;
					if (w) execCmd.push(w);
				}
				if (execCmd.length > 0) {
					// Remove {} placeholders for analysis
					const cleanedCmd = execCmd.filter((w) => w !== "{}").join(" ");
					if (cleanedCmd) {
						extracted.push({
							command: cleanedCmd,
							wrapper: `find ${word}`,
							type: "find-exec",
						});
					}
				}
			}
		}
	}

	return extracted;
}

/**
 * Get the effective command and arguments after stripping wrappers
 */
export function getEffectiveCommand(command: string): {
	command: string;
	args: string[];
	envVars: Map<string, string>;
	nested: ExtractedCommand[];
} {
	const tokens = tokenize(command);
	const stripped = stripWrappers(tokens);
	const words = extractWords(stripped.tokens);
	const nested = extractNestedCommands(tokens);

	return {
		command: words[0] || "",
		args: words.slice(1),
		envVars: stripped.envVars,
		nested,
	};
}
