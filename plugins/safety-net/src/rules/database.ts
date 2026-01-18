/**
 * Database destructive command rules
 * Covers PostgreSQL, MySQL, MongoDB, Redis, and SQLite
 */

import { extractWords, tokenize } from "../shell/parser.ts";
import { stripWrappers } from "../shell/wrappers.ts";
import type { AnalyzerOptions, SegmentResult } from "../types.ts";

// ============================================================================
// SQL Pattern Detection (PostgreSQL, MySQL, SQLite)
// ============================================================================

/**
 * Dangerous SQL patterns
 */
const DANGEROUS_SQL_PATTERNS = [
	{
		pattern: /\bDROP\s+DATABASE\b/i,
		rule: "sql-drop-database",
		reason: "DROP DATABASE permanently deletes the entire database.",
		severity: "critical" as const,
	},
	{
		pattern: /\bDROP\s+TABLE\b/i,
		rule: "sql-drop-table",
		reason: "DROP TABLE permanently deletes a table and all its data.",
		severity: "critical" as const,
	},
	{
		pattern: /\bDROP\s+SCHEMA\b/i,
		rule: "sql-drop-schema",
		reason: "DROP SCHEMA removes a schema and all objects within it.",
		severity: "critical" as const,
	},
	{
		pattern: /\bTRUNCATE\s+(?:TABLE\s+)?\w/i,
		rule: "sql-truncate",
		reason: "TRUNCATE TABLE deletes all rows from the table.",
		severity: "critical" as const,
	},
	{
		// DELETE without WHERE
		pattern: /\bDELETE\s+FROM\s+\w+\s*(?:;|$)/i,
		rule: "sql-delete-all",
		reason: "DELETE without WHERE clause removes ALL rows from the table.",
		severity: "critical" as const,
	},
	{
		// UPDATE without WHERE
		pattern: /\bUPDATE\s+\w+\s+SET\s+[^;]+(?:;|$)/i,
		matchExclude: /\bWHERE\b/i, // Only match if no WHERE
		rule: "sql-update-all",
		reason: "UPDATE without WHERE clause modifies ALL rows in the table.",
		severity: "high" as const,
	},
	{
		pattern: /\bALTER\s+TABLE\s+\w+\s+DROP\s+(?:COLUMN|CONSTRAINT)\b/i,
		rule: "sql-alter-drop",
		reason: "ALTER TABLE DROP removes columns or constraints.",
		severity: "high" as const,
	},
];

/**
 * Check if a string contains dangerous SQL
 */
function containsDangerousSQL(
	sql: string,
	options: AnalyzerOptions,
): SegmentResult | null {
	for (const { pattern, rule, reason, severity, matchExclude } of DANGEROUS_SQL_PATTERNS as Array<{
		pattern: RegExp;
		rule: string;
		reason: string;
		severity: "critical" | "high";
		matchExclude?: RegExp;
	}>) {
		if (pattern.test(sql)) {
			// Check exclusion pattern
			if (matchExclude && matchExclude.test(sql)) {
				continue;
			}

			const decision =
				severity === "critical" || options.paranoid ? "deny" : "warn";
			return {
				decision,
				rule,
				category: "database",
				reason,
				matchedTokens: [rule.replace("sql-", "").toUpperCase()],
				confidence: "high",
			};
		}
	}
	return null;
}

// ============================================================================
// PostgreSQL (psql, dropdb)
// ============================================================================

/**
 * Analyze psql command
 */
function analyzePsql(
	words: string[],
	command: string,
	options: AnalyzerOptions,
): SegmentResult {
	const args = words.slice(1);

	// Check for -c or --command with SQL
	for (let i = 0; i < args.length; i++) {
		const arg = args[i];
		if (arg === "-c" || arg === "--command") {
			const sqlCommand = args[i + 1];
			if (sqlCommand) {
				const result = containsDangerousSQL(sqlCommand, options);
				if (result) return result;
			}
		}
	}

	// Check for -f or --file (running from file - can't analyze content)
	if (args.includes("-f") || args.includes("--file")) {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "psql-file-execution",
			category: "database",
			reason:
				"psql -f executes SQL from file. Content cannot be analyzed for safety.",
			matchedTokens: ["psql", "-f"],
			confidence: "low",
		};
	}

	// Check for piped input (psql < file or echo | psql)
	if (command.includes("|") || command.includes("<")) {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "psql-piped-input",
			category: "database",
			reason:
				"psql with piped input. Content cannot be analyzed for safety.",
			matchedTokens: ["psql", "|"],
			confidence: "low",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze dropdb command
 */
function analyzeDropdb(
	_words: string[],
	_options: AnalyzerOptions,
): SegmentResult {
	return {
		decision: "deny",
		rule: "dropdb",
		category: "database",
		reason: "dropdb permanently deletes the entire PostgreSQL database.",
		matchedTokens: ["dropdb"],
		confidence: "high",
	};
}

// ============================================================================
// MySQL (mysql, mysqladmin)
// ============================================================================

/**
 * Analyze mysql command
 */
function analyzeMysql(
	words: string[],
	command: string,
	options: AnalyzerOptions,
): SegmentResult {
	const args = words.slice(1);

	// Check for -e or --execute with SQL
	for (let i = 0; i < args.length; i++) {
		const arg = args[i];
		if (arg === "-e" || arg === "--execute") {
			const sqlCommand = args[i + 1];
			if (sqlCommand) {
				const result = containsDangerousSQL(sqlCommand, options);
				if (result) return result;
			}
		}
	}

	// Check for piped input
	if (command.includes("|") || command.includes("<")) {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "mysql-piped-input",
			category: "database",
			reason:
				"mysql with piped input. Content cannot be analyzed for safety.",
			matchedTokens: ["mysql", "|"],
			confidence: "low",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze mysqladmin command
 */
function analyzeMysqladmin(
	words: string[],
	_options: AnalyzerOptions,
): SegmentResult {
	const args = words.slice(1);

	// mysqladmin drop <db>
	if (args.includes("drop")) {
		return {
			decision: "deny",
			rule: "mysqladmin-drop",
			category: "database",
			reason: "mysqladmin drop permanently deletes the MySQL database.",
			matchedTokens: ["mysqladmin", "drop"],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

// ============================================================================
// MongoDB (mongo, mongosh)
// ============================================================================

/**
 * Dangerous MongoDB patterns
 */
const MONGO_DANGEROUS_PATTERNS = [
	{
		pattern: /\.dropDatabase\s*\(\s*\)/,
		rule: "mongo-drop-database",
		reason: "dropDatabase() permanently deletes the entire MongoDB database.",
	},
	{
		pattern: /\.drop\s*\(\s*\)/,
		rule: "mongo-drop-collection",
		reason: "drop() permanently deletes a MongoDB collection.",
	},
	{
		pattern: /\.dropCollection\s*\(/,
		rule: "mongo-drop-collection",
		reason: "dropCollection() permanently deletes a MongoDB collection.",
	},
	{
		pattern: /\.deleteMany\s*\(\s*\{\s*\}\s*\)/,
		rule: "mongo-delete-all",
		reason: "deleteMany({}) deletes ALL documents in the collection.",
	},
	{
		pattern: /\.remove\s*\(\s*\{\s*\}\s*\)/,
		rule: "mongo-remove-all",
		reason: "remove({}) deletes ALL documents in the collection.",
	},
];

/**
 * Analyze mongo/mongosh command
 */
function analyzeMongo(
	words: string[],
	command: string,
	options: AnalyzerOptions,
): SegmentResult {
	const args = words.slice(1);

	// Check for --eval with JavaScript
	for (let i = 0; i < args.length; i++) {
		const arg = args[i];
		if (arg === "--eval") {
			const jsCode = args[i + 1] || "";
			for (const { pattern, rule, reason } of MONGO_DANGEROUS_PATTERNS) {
				if (pattern.test(jsCode)) {
					return {
						decision: "deny",
						rule,
						category: "database",
						reason,
						matchedTokens: [words[0] || "mongo", "--eval"],
						confidence: "high",
					};
				}
			}
		}
	}

	// Check full command for patterns (heredocs, piped input)
	for (const { pattern, rule, reason } of MONGO_DANGEROUS_PATTERNS) {
		if (pattern.test(command)) {
			return {
				decision: "deny",
				rule,
				category: "database",
				reason,
				matchedTokens: [words[0] || "mongo"],
				confidence: "high",
			};
		}
	}

	// Piped input warning
	if (command.includes("|") || command.includes("<")) {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "mongo-piped-input",
			category: "database",
			reason:
				"mongo/mongosh with piped input. Content cannot be fully analyzed.",
			matchedTokens: [words[0] || "mongo", "|"],
			confidence: "low",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze mongorestore command
 */
function analyzeMongorestore(
	words: string[],
	_options: AnalyzerOptions,
): SegmentResult {
	const args = words.slice(1);

	// --drop deletes existing data before restoring
	if (args.includes("--drop")) {
		return {
			decision: "deny",
			rule: "mongorestore-drop",
			category: "database",
			reason:
				"mongorestore --drop deletes existing collections before restoring.",
			matchedTokens: ["mongorestore", "--drop"],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

// ============================================================================
// Redis (redis-cli)
// ============================================================================

/**
 * Dangerous Redis commands
 */
const REDIS_DANGEROUS = [
	{
		command: "FLUSHALL",
		rule: "redis-flushall",
		reason: "FLUSHALL deletes ALL keys in ALL Redis databases.",
		severity: "critical" as const,
	},
	{
		command: "FLUSHDB",
		rule: "redis-flushdb",
		reason: "FLUSHDB deletes ALL keys in the current database.",
		severity: "critical" as const,
	},
	{
		command: "DEBUG SEGFAULT",
		rule: "redis-debug-crash",
		reason: "DEBUG SEGFAULT crashes the Redis server.",
		severity: "critical" as const,
	},
	{
		command: "DEBUG CRASH",
		rule: "redis-debug-crash",
		reason: "DEBUG CRASH crashes the Redis server.",
		severity: "critical" as const,
	},
	{
		command: "SHUTDOWN",
		rule: "redis-shutdown",
		reason: "SHUTDOWN stops the Redis server.",
		severity: "high" as const,
	},
	{
		command: "CONFIG SET",
		rule: "redis-config-set",
		reason: "CONFIG SET modifies Redis server configuration.",
		severity: "high" as const,
	},
	{
		command: "DEBUG SLEEP",
		rule: "redis-debug-sleep",
		reason: "DEBUG SLEEP blocks the Redis server.",
		severity: "high" as const,
	},
];

/**
 * Analyze redis-cli command
 */
function analyzeRedisCli(
	words: string[],
	command: string,
	options: AnalyzerOptions,
): SegmentResult {
	// Check for dangerous commands in args
	const upperCommand = command.toUpperCase();

	for (const { command: cmd, rule, reason, severity } of REDIS_DANGEROUS) {
		if (upperCommand.includes(cmd)) {
			const decision =
				severity === "critical" || options.paranoid ? "deny" : "warn";
			return {
				decision,
				rule,
				category: "database",
				reason,
				matchedTokens: ["redis-cli", cmd],
				confidence: "high",
			};
		}
	}

	// Check for piped input
	if (command.includes("|") || command.includes("<")) {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "redis-piped-input",
			category: "database",
			reason:
				"redis-cli with piped input. Content cannot be analyzed for safety.",
			matchedTokens: ["redis-cli", "|"],
			confidence: "low",
		};
	}

	return { decision: "allow" };
}

// ============================================================================
// Main Entry Point
// ============================================================================

/**
 * Analyze a database command for destructive operations
 */
export function analyzeDatabaseCommand(
	command: string,
	options: AnalyzerOptions = {},
): SegmentResult {
	const tokens = tokenize(command);
	const { tokens: strippedTokens } = stripWrappers(tokens);
	const words = extractWords(strippedTokens);

	if (words.length < 1) {
		return { decision: "allow" };
	}

	const cmd = words[0];

	switch (cmd) {
		case "psql":
			return analyzePsql(words, command, options);
		case "dropdb":
			return analyzeDropdb(words, options);
		case "mysql":
			return analyzeMysql(words, command, options);
		case "mysqladmin":
			return analyzeMysqladmin(words, options);
		case "mongo":
		case "mongosh":
			return analyzeMongo(words, command, options);
		case "mongorestore":
			return analyzeMongorestore(words, options);
		case "redis-cli":
			return analyzeRedisCli(words, command, options);
		default:
			return { decision: "allow" };
	}
}
