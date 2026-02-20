/**
 * Shell command splitter
 * Splits commands by &&, ||, ;, |, and &
 */

import type { CommandSegment } from "../types.ts";

/** Operators that separate commands */
const OPERATORS = ["&&", "||", ";", "|", "&"] as const;
type Operator = (typeof OPERATORS)[number];

/** State for the splitter */
interface SplitterState {
	segments: CommandSegment[];
	current: string;
	inSingleQuote: boolean;
	inDoubleQuote: boolean;
	inBacktick: boolean;
	escapeNext: boolean;
	parenDepth: number;
	braceDepth: number;
}

/**
 * Split a shell command into segments by operators
 * Handles quoted strings, escapes, and nested constructs
 */
export function splitCommand(command: string): CommandSegment[] {
	const state: SplitterState = {
		segments: [],
		current: "",
		inSingleQuote: false,
		inDoubleQuote: false,
		inBacktick: false,
		escapeNext: false,
		parenDepth: 0,
		braceDepth: 0,
	};

	for (let i = 0; i < command.length; i++) {
		const char = command[i];
		const nextChar = command[i + 1];

		// Handle escape sequences
		if (state.escapeNext) {
			state.current += char;
			state.escapeNext = false;
			continue;
		}

		if (char === "\\" && !state.inSingleQuote) {
			state.escapeNext = true;
			state.current += char;
			continue;
		}

		// Handle quotes
		if (char === "'" && !state.inDoubleQuote && !state.inBacktick) {
			state.inSingleQuote = !state.inSingleQuote;
			state.current += char;
			continue;
		}

		if (char === '"' && !state.inSingleQuote && !state.inBacktick) {
			state.inDoubleQuote = !state.inDoubleQuote;
			state.current += char;
			continue;
		}

		if (char === "`" && !state.inSingleQuote) {
			state.inBacktick = !state.inBacktick;
			state.current += char;
			continue;
		}

		// If inside quotes, just add the character
		if (state.inSingleQuote || state.inDoubleQuote || state.inBacktick) {
			state.current += char;
			continue;
		}

		// Handle nested constructs
		if (char === "(" || char === "{") {
			if (char === "(") state.parenDepth++;
			else state.braceDepth++;
			state.current += char;
			continue;
		}

		if (char === ")" || char === "}") {
			if (char === ")") state.parenDepth = Math.max(0, state.parenDepth - 1);
			else state.braceDepth = Math.max(0, state.braceDepth - 1);
			state.current += char;
			continue;
		}

		// If inside nested constructs, just add the character
		if (state.parenDepth > 0 || state.braceDepth > 0) {
			state.current += char;
			continue;
		}

		// Check for two-character operators
		const twoChar = char + (nextChar || "");
		if (twoChar === "&&" || twoChar === "||") {
			pushSegment(state, twoChar as Operator);
			i++; // Skip next character
			continue;
		}

		// Check for single-character operators
		if (char === ";" || char === "|" || char === "&") {
			pushSegment(state, char as Operator);
			continue;
		}

		state.current += char;
	}

	// Push any remaining content
	if (state.current.trim()) {
		state.segments.push({
			command: state.current.trim(),
		});
	}

	return state.segments;
}

/** Push current segment and start a new one */
function pushSegment(state: SplitterState, operator: Operator): void {
	if (state.current.trim()) {
		state.segments.push({
			command: state.current.trim(),
			operator,
		});
	}
	state.current = "";
}

/**
 * Check if a command appears to have unparseable constructs
 * Used to determine if we should fail-open or fail-closed
 */
export function hasUnparseableConstructs(command: string): boolean {
	// Heredocs: <<EOF, <<-EOF, <<'EOF', <<-'EOF', <<"EOF"
	// BUT exclude safe patterns that use heredocs for stdin input:
	// - $(cat <<EOF) - safe string generation for commit messages/PR bodies
	// - agent-browser eval --stdin <<EOF - browser automation JS evaluation
	if (/<<-?['"]?\w+/.test(command)) {
		const isCatHeredoc = /\$\(cat\s+<</.test(command);
		const isStdinHeredoc = /--stdin\s+<</.test(command);
		if (!isCatHeredoc && !isStdinHeredoc) {
			return true;
		}
	}

	// Process substitution: <(cmd) is common, >(cmd) is rare
	// Only check for <( to avoid false positives on TypeScript generics like Array<T>()
	// where >() appears after closing the generic type
	if (/<\(/.test(command)) return true;

	// Arithmetic expansion
	if (/\$\(\(/.test(command)) return true;

	return false;
}

/**
 * Extract the base command (first word) from a command string
 */
export function extractBaseCommand(command: string): string | null {
	const trimmed = command.trim();
	if (!trimmed) return null;

	// Simple extraction: first word
	const match = trimmed.match(/^([^\s]+)/);
	return match?.[1] || null;
}
