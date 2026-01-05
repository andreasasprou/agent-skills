/**
 * Utility functions for Safety Net
 */

import { homedir } from "node:os";
import { normalize, resolve } from "node:path";

/** Patterns for secret detection */
const SECRET_PATTERNS = [
	// API keys and tokens
	/(?:api[_-]?key|apikey|api[_-]?token)[\s]*[=:]\s*["']?([A-Za-z0-9_-]{16,})["']?/gi,
	/(?:auth[_-]?token|access[_-]?token|bearer)[\s]*[=:]\s*["']?([A-Za-z0-9_-]{16,})["']?/gi,
	// AWS credentials
	/(?:aws[_-]?(?:access[_-]?key|secret|session))[\s]*[=:]\s*["']?([A-Za-z0-9/+=]{16,})["']?/gi,
	/AKIA[A-Z0-9]{16}/g,
	// GitHub tokens
	/gh[pousr]_[A-Za-z0-9_]{36,}/g,
	/github[_-]?(?:token|pat)[\s]*[=:]\s*["']?([A-Za-z0-9_-]{36,})["']?/gi,
	// Generic passwords
	/(?:password|passwd|pwd|secret)[\s]*[=:]\s*["']?([^\s"']{8,})["']?/gi,
	// Private keys
	/-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g,
];

/** Redact secrets from a string */
export function redactSecrets(input: string): string {
	let result = input;
	for (const pattern of SECRET_PATTERNS) {
		// Reset lastIndex for global patterns
		pattern.lastIndex = 0;
		result = result.replace(pattern, (match) => {
			// Keep first 4 chars, redact rest
			const visible = Math.min(4, Math.floor(match.length / 4));
			return `${match.slice(0, visible)}[REDACTED]`;
		});
	}
	return result;
}

/** Truncate a command for logging */
export function truncateCommand(command: string, maxLength = 200): string {
	if (command.length <= maxLength) return command;
	return `${command.slice(0, maxLength)}... [truncated]`;
}

/** Normalize and resolve a path */
export function normalizePath(path: string, cwd?: string): string {
	// Expand ~ to home directory
	if (path.startsWith("~")) {
		path = path.replace(/^~/, homedir());
	}
	// Resolve relative paths
	if (cwd && !path.startsWith("/")) {
		path = resolve(cwd, path);
	}
	return normalize(path);
}

/** Check if a path is under a safe root */
export function isUnderSafeRoot(
	path: string,
	safeRoots: string[],
	cwd?: string,
): boolean {
	const normalizedPath = normalizePath(path, cwd);
	return safeRoots.some((root) => {
		const normalizedRoot = normalizePath(root, cwd);
		return (
			normalizedPath.startsWith(`${normalizedRoot}/`) ||
			normalizedPath === normalizedRoot
		);
	});
}

/** Check if a path is a dangerous target */
export function isDangerousPath(path: string, cwd?: string): boolean {
	const normalized = normalizePath(path, cwd);
	const home = homedir();

	// Exact matches for catastrophic targets
	const catastrophicPaths = ["/", home, ".", ".."];
	if (
		catastrophicPaths.includes(path) ||
		catastrophicPaths.includes(normalized)
	) {
		return true;
	}

	// Path is ~ or $HOME
	if (path === "~" || path === "$HOME") {
		return true;
	}

	// Empty path or looks like an option
	if (!path || path.startsWith("-")) {
		return true;
	}

	return false;
}

/** Check if a path looks like it's targeting system directories */
export function isSystemPath(path: string): boolean {
	const systemPrefixes = [
		"/bin",
		"/sbin",
		"/usr",
		"/etc",
		"/var",
		"/lib",
		"/boot",
		"/dev",
		"/proc",
		"/sys",
		"/root",
		"/System",
		"/Library",
		"/Applications", // macOS
		"/Windows",
		"/Program Files", // Windows (via WSL)
	];
	const normalized = normalizePath(path);
	return systemPrefixes.some(
		(prefix) => normalized === prefix || normalized.startsWith(`${prefix}/`),
	);
}

/** Generate a unique session ID */
export function generateSessionId(): string {
	return `${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
}

/** Sanitize a filename for safe use in paths */
export function sanitizeFilename(name: string): string {
	// Remove or replace unsafe characters
	return name
		.replace(/[/\\:*?"<>|]/g, "_")
		.replace(/\.\./g, "_")
		.slice(0, 100);
}
