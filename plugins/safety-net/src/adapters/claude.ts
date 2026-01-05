/**
 * Claude Code PreToolUse adapter
 * Reads hook input from stdin and outputs hook response to stdout
 */

import { analyzeCommand } from "../analyzer.ts";
import { auditAsync } from "../audit.ts";
import type {
	AnalysisResult,
	ClaudeHookInput,
	ClaudeHookOutput,
} from "../types.ts";

/**
 * Map internal decision to Claude hook output
 */
function mapDecision(result: AnalysisResult): ClaudeHookOutput {
	switch (result.decision) {
		case "deny":
			return {
				hookSpecificOutput: {
					hookEventName: "PreToolUse",
					permissionDecision: "deny",
					permissionDecisionReason: `BLOCKED by Safety Net\n\n${result.reason}`,
				},
			};

		case "warn":
			return {
				hookSpecificOutput: {
					hookEventName: "PreToolUse",
					permissionDecision: "ask",
					permissionDecisionReason: result.reason,
				},
				systemMessage: `⚠️ Safety Net Warning:\n${result.reason}`,
			};
		default:
			return {
				hookSpecificOutput: {
					hookEventName: "PreToolUse",
					permissionDecision: "allow",
				},
			};
	}
}

/**
 * Process a Claude Code PreToolUse hook
 */
export async function processClaudeHook(
	input: ClaudeHookInput,
): Promise<ClaudeHookOutput> {
	// Only process Bash tool
	if (input.tool_name !== "Bash") {
		return {
			hookSpecificOutput: {
				hookEventName: "PreToolUse",
				permissionDecision: "allow",
			},
		};
	}

	const command = input.tool_input.command;
	if (!command || typeof command !== "string") {
		return {
			hookSpecificOutput: {
				hookEventName: "PreToolUse",
				permissionDecision: "allow",
			},
		};
	}

	// Analyze the command
	const result = analyzeCommand(command, {
		cwd: input.cwd,
	});

	// Fire-and-forget audit logging
	auditAsync(result, input.session_id, input.cwd);

	return mapDecision(result);
}

/**
 * Read JSON from stdin
 */
async function readStdin(): Promise<string> {
	const chunks: Buffer[] = [];

	for await (const chunk of process.stdin) {
		chunks.push(chunk);
	}

	return Buffer.concat(chunks).toString("utf-8");
}

/**
 * Main entry point for Claude Code adapter
 * Reads from stdin, processes, writes to stdout
 */
export async function runClaudeAdapter(): Promise<void> {
	try {
		const inputStr = await readStdin();

		if (!inputStr.trim()) {
			// No input, allow by default
			console.log(
				JSON.stringify({
					hookSpecificOutput: {
						hookEventName: "PreToolUse",
						permissionDecision: "allow",
					},
				}),
			);
			return;
		}

		const input = JSON.parse(inputStr) as ClaudeHookInput;
		const output = await processClaudeHook(input);

		console.log(JSON.stringify(output));
	} catch (error) {
		// On error, output to stderr and exit with code 2 (blocking error)
		console.error(`[safety-net] Error: ${error}`);
		process.exit(2);
	}
}
