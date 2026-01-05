/**
 * Safety Net - Block destructive commands across Claude Code and OpenCode
 *
 * Main entry point and CLI
 */

import { runClaudeAdapter } from "./adapters/claude.ts";
import { analyzeCommand } from "./analyzer.ts";

export { processClaudeHook } from "./adapters/claude.ts";
export { createOpenCodePlugin, SafetyNet } from "./adapters/opencode.ts";
// Re-export main API
export { analyzeCommand } from "./analyzer.ts";
export type {
	AnalysisResult,
	AnalyzerOptions,
	Decision,
	SegmentResult,
} from "./types.ts";

/**
 * CLI entry point
 * Detects mode from arguments or environment
 */
export async function main(): Promise<void> {
	const args = process.argv.slice(2);

	// Direct command analysis mode: safety-net "command"
	if (args.length > 0 && !args[0]?.startsWith("-")) {
		const command = args.join(" ");
		const result = analyzeCommand(command, {
			cwd: process.cwd(),
		});

		// Output result as JSON
		console.log(JSON.stringify(result, null, 2));

		// Exit with code based on decision
		if (result.decision === "deny") {
			process.exit(1);
		}
		return;
	}

	// Help mode
	if (args.includes("-h") || args.includes("--help")) {
		printHelp();
		return;
	}

	// Version mode
	if (args.includes("-v") || args.includes("--version")) {
		console.log("safety-net 0.1.0");
		return;
	}

	// Default: Claude Code hook mode (read from stdin)
	await runClaudeAdapter();
}

function printHelp(): void {
	console.log(`
Safety Net - Block destructive commands across Claude Code and OpenCode

USAGE:
  safety-net [OPTIONS] [COMMAND]

MODES:
  safety-net                    Claude Code hook mode (reads JSON from stdin)
  safety-net "rm -rf /"         Direct analysis mode (analyzes command)

OPTIONS:
  -h, --help                    Show this help message
  -v, --version                 Show version

ENVIRONMENT VARIABLES:
  SAFETY_NET_STRICT=1           Deny unparseable commands (fail closed)
  SAFETY_NET_PARANOID=1         Block all non-temp deletions
  SAFETY_NET_PARANOID_RM=1      Paranoid mode for rm only
  SAFETY_NET_PARANOID_AWS=1     Paranoid mode for AWS only
  SAFETY_NET_DISABLE_GIT=1      Skip git rules
  SAFETY_NET_DISABLE_RM=1       Skip rm/filesystem rules
  SAFETY_NET_DISABLE_AWS=1      Skip AWS rules
  SAFETY_NET_TEMP_ROOTS=/tmp    Comma-separated safe directories
  SAFETY_NET_BYPASS=1           Allow blocked commands (audited)
  SAFETY_NET_WARN_ONLY=1        Never deny, only warn

SETUP (Claude Code):
  Add to ~/.claude/settings.json:
  {
    "hooks": {
      "PreToolUse": [{
        "matcher": "Bash",
        "hooks": [{
          "type": "command",
          "command": "~/.local/bin/safety-net"
        }]
      }]
    }
  }

SETUP (OpenCode):
  Create ~/.config/opencode/plugins/safety-net.ts:
  import { SafetyNet } from "safety-net";
  export { SafetyNet };

DOCUMENTATION:
  https://github.com/your-org/safety-net
`);
}

// Run if this is the main module
if (import.meta.main) {
	main().catch((error) => {
		console.error("[safety-net] Fatal error:", error);
		process.exit(2);
	});
}
