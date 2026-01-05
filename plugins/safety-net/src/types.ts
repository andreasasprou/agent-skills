/**
 * Core types for Safety Net
 */

/** Decision levels for command analysis */
export type Decision = "allow" | "warn" | "deny";

/** Categories of rules */
export type RuleCategory = "git" | "filesystem" | "aws";

/** Result of analyzing a single command segment */
export interface SegmentResult {
	decision: Decision;
	rule?: string;
	category?: RuleCategory;
	reason?: string;
	matchedTokens?: string[];
	confidence?: "high" | "medium" | "low";
}

/** Result of analyzing a complete command (may have multiple segments) */
export interface AnalysisResult {
	decision: Decision;
	segments: SegmentResult[];
	reason: string;
	command: string;
	truncatedCommand?: string;
}

/** Options for command analysis */
export interface AnalyzerOptions {
	cwd?: string;
	strict?: boolean;
	paranoid?: boolean;
	paranoidRm?: boolean;
	paranoidAws?: boolean;
	disableGit?: boolean;
	disableRm?: boolean;
	disableAws?: boolean;
	tempRoots?: string[];
	maxRecursionDepth?: number;
	maxSegments?: number;
	bypass?: boolean;
	warnOnly?: boolean;
}

/** Claude Code PreToolUse input format */
export interface ClaudeHookInput {
	session_id: string;
	transcript_path?: string;
	cwd: string;
	permission_mode?: "default" | "plan" | "acceptEdits" | "bypassPermissions";
	hook_event_name: string;
	tool_name: string;
	tool_input: {
		command?: string;
		[key: string]: unknown;
	};
	tool_use_id?: string;
}

/** Claude Code PreToolUse output format */
export interface ClaudeHookOutput {
	hookSpecificOutput?: {
		hookEventName: string;
		permissionDecision: "allow" | "deny" | "ask";
		permissionDecisionReason?: string;
		updatedInput?: Record<string, unknown>;
	};
	continue?: boolean;
	stopReason?: string;
	suppressOutput?: boolean;
	systemMessage?: string;
}

/** Audit log entry */
export interface AuditEntry {
	timestamp: string;
	sessionId?: string;
	cwd?: string;
	command: string;
	truncatedCommand?: string;
	decision: Decision;
	reason: string;
	segments: SegmentResult[];
}

/** Parsed command token */
export interface ParsedToken {
	type: "word" | "operator" | "redirect" | "env";
	value: string;
	quoted?: boolean;
}

/** Command segment from splitting */
export interface CommandSegment {
	command: string;
	operator?: string;
	tokens?: ParsedToken[];
}

/** Rule definition */
export interface Rule {
	id: string;
	category: RuleCategory;
	pattern: RegExp | ((tokens: string[], command: string) => boolean);
	decision: Decision;
	reason: string;
	confidence?: "high" | "medium" | "low";
}
