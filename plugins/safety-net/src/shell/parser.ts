/**
 * Shell command parser (shlex-like tokenization)
 * Tokenizes a single command into words, handling quotes and escapes
 */

import type { ParsedToken } from "../types.ts";

/** State for the tokenizer */
interface TokenizerState {
	tokens: ParsedToken[];
	current: string;
	inSingleQuote: boolean;
	inDoubleQuote: boolean;
	escapeNext: boolean;
	currentQuoted: boolean;
}

/**
 * Tokenize a shell command into words
 * Handles single quotes, double quotes, and escape sequences
 */
export function tokenize(command: string): ParsedToken[] {
	const state: TokenizerState = {
		tokens: [],
		current: "",
		inSingleQuote: false,
		inDoubleQuote: false,
		escapeNext: false,
		currentQuoted: false,
	};

	for (let i = 0; i < command.length; i++) {
		const char = command[i];

		// Handle escape sequences
		if (state.escapeNext) {
			state.current += char;
			state.escapeNext = false;
			continue;
		}

		// Backslash escapes (except in single quotes)
		if (char === "\\" && !state.inSingleQuote) {
			state.escapeNext = true;
			continue;
		}

		// Single quote handling (no escapes inside)
		if (char === "'" && !state.inDoubleQuote) {
			state.inSingleQuote = !state.inSingleQuote;
			state.currentQuoted = true;
			continue;
		}

		// Double quote handling
		if (char === '"' && !state.inSingleQuote) {
			state.inDoubleQuote = !state.inDoubleQuote;
			state.currentQuoted = true;
			continue;
		}

		// If inside quotes, just add the character
		if (state.inSingleQuote || state.inDoubleQuote) {
			state.current += char;
			continue;
		}

		// Whitespace splits tokens (outside quotes)
		if (/\s/.test(char)) {
			pushToken(state);
			continue;
		}

		// Handle redirections and operators as separate tokens
		if (char === ">" || char === "<") {
			pushToken(state);
			// Check for >> or << or <<< or 2> etc
			let op = char;
			while (
				command[i + 1] === ">" ||
				command[i + 1] === "<" ||
				/\d/.test(command[i + 1] || "")
			) {
				i++;
				op += command[i];
			}
			// Check for >&N or <&N
			if (command[i + 1] === "&") {
				i++;
				op += "&";
				if (/\d/.test(command[i + 1] || "")) {
					i++;
					op += command[i];
				}
			}
			state.tokens.push({ type: "redirect", value: op });
			continue;
		}

		state.current += char;
	}

	// Push any remaining token
	pushToken(state);

	return state.tokens;
}

/** Push current token if non-empty */
function pushToken(state: TokenizerState): void {
	if (state.current) {
		// Check if it's an environment variable assignment
		const isEnvAssignment = /^[A-Za-z_][A-Za-z0-9_]*=/.test(state.current);
		state.tokens.push({
			type: isEnvAssignment ? "env" : "word",
			value: state.current,
			quoted: state.currentQuoted,
		});
	}
	state.current = "";
	state.currentQuoted = false;
}

/**
 * Extract just the word values from tokens
 * Useful for rule matching
 */
export function extractWords(tokens: ParsedToken[]): string[] {
	return tokens.filter((t) => t.type === "word").map((t) => t.value);
}

/**
 * Extract environment variables from tokens
 */
export function extractEnvVars(tokens: ParsedToken[]): Map<string, string> {
	const env = new Map<string, string>();
	for (const token of tokens) {
		if (token.type === "env") {
			const eqIdx = token.value.indexOf("=");
			if (eqIdx > 0) {
				env.set(token.value.slice(0, eqIdx), token.value.slice(eqIdx + 1));
			}
		}
	}
	return env;
}

/**
 * Get the command name (first non-env word)
 */
export function getCommandName(tokens: ParsedToken[]): string | null {
	for (const token of tokens) {
		if (token.type === "word") {
			return token.value;
		}
	}
	return null;
}

/**
 * Get command arguments (all words after the command name)
 */
export function getCommandArgs(tokens: ParsedToken[]): string[] {
	const words = extractWords(tokens);
	return words.slice(1);
}
