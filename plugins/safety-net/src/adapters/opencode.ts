/**
 * OpenCode plugin adapter
 * Provides hooks for permission.ask and tool.execute.before
 */

import { type AnalyzerOptions, analyzeCommand } from "../analyzer.ts";
import { auditAsync } from "../audit.ts";

/** OpenCode permission request */
interface OpenCodePermission {
	type: string;
	pattern: string;
	sessionID?: string;
}

/** OpenCode permission output */
interface OpenCodePermissionOutput {
	status: "allow" | "deny" | "ask";
}

/** OpenCode tool input */
interface OpenCodeToolInput {
	tool: string;
}

/** OpenCode tool output */
interface OpenCodeToolOutput {
	args: {
		command?: string;
		[key: string]: unknown;
	};
}

/** OpenCode plugin context */
interface OpenCodeContext {
	directory?: string;
}

/**
 * Create an OpenCode plugin instance
 * Usage in ~/.config/opencode/plugins/safety-net.ts:
 *
 * import { createOpenCodePlugin } from "safety-net/adapters/opencode";
 * export const SafetyNet = createOpenCodePlugin;
 */
export function createOpenCodePlugin(context: OpenCodeContext) {
	const options: AnalyzerOptions = {
		cwd: context.directory,
	};

	return {
		/**
		 * Intercept permission requests
		 * This is the primary hook for bash commands
		 */
		"permission.ask": async (
			permission: OpenCodePermission,
			output: OpenCodePermissionOutput,
		): Promise<void> => {
			if (permission.type !== "bash") {
				return;
			}

			const result = analyzeCommand(permission.pattern, options);

			// Fire-and-forget audit
			auditAsync(result, permission.sessionID, context.directory);

			switch (result.decision) {
				case "deny":
					output.status = "deny";
					break;
				case "warn":
					output.status = "ask";
					break;
				default:
					output.status = "allow";
					break;
			}
		},

		/**
		 * Fallback hook for tools that bypass permission system
		 * Throws to block execution
		 */
		"tool.execute.before": async (
			input: OpenCodeToolInput,
			output: OpenCodeToolOutput,
		): Promise<void> => {
			if (input.tool !== "bash" && input.tool !== "shell") {
				return;
			}

			const command = output.args.command;
			if (!command || typeof command !== "string") {
				return;
			}

			const result = analyzeCommand(command, options);

			// Fire-and-forget audit
			auditAsync(result, undefined, context.directory);

			if (result.decision === "deny") {
				throw new Error(`BLOCKED by Safety Net\n\n${result.reason}`);
			}
		},
	};
}

// Default export for OpenCode plugin discovery
export const SafetyNet = createOpenCodePlugin;
