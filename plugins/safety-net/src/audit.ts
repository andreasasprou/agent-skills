/**
 * Audit logging for Safety Net
 * Logs warn and deny decisions to ~/.safety-net/logs/
 */

import { appendFile, mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import type { AnalysisResult, AuditEntry } from "./types.ts";
import { redactSecrets, sanitizeFilename } from "./utils.ts";

/** Base directory for audit logs */
const AUDIT_DIR = join(homedir(), ".safety-net", "logs");

/** Ensure audit directory exists with proper permissions */
async function ensureAuditDir(): Promise<void> {
	try {
		await mkdir(AUDIT_DIR, { recursive: true, mode: 0o700 });
	} catch (error) {
		// Ignore if already exists
		if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
			throw error;
		}
	}
}

/**
 * Write an audit entry (fire-and-forget async)
 * Only logs warn and deny decisions
 */
export async function writeAuditLog(
	result: AnalysisResult,
	sessionId?: string,
	cwd?: string,
): Promise<void> {
	// Only log non-allow decisions
	if (result.decision === "allow") {
		return;
	}

	try {
		await ensureAuditDir();

		// Sanitize session ID for filename
		const safeSessionId = sessionId ? sanitizeFilename(sessionId) : "unknown";
		const logFile = join(AUDIT_DIR, `${safeSessionId}.jsonl`);

		const entry: AuditEntry = {
			timestamp: new Date().toISOString(),
			sessionId,
			cwd,
			command: redactSecrets(result.command),
			truncatedCommand: result.truncatedCommand
				? redactSecrets(result.truncatedCommand)
				: undefined,
			decision: result.decision,
			reason: result.reason,
			segments: result.segments.map((s) => ({
				...s,
				matchedTokens: s.matchedTokens?.map((t) => redactSecrets(t)),
			})),
		};

		const line = `${JSON.stringify(entry)}\n`;

		// Append with secure permissions
		await appendFile(logFile, line, { mode: 0o600 });
	} catch (error) {
		// Log errors to stderr but don't fail the main operation
		console.error("[safety-net] Audit log error:", error);
	}
}

/**
 * Fire-and-forget audit logging
 * Returns immediately, logging happens in background
 */
export function auditAsync(
	result: AnalysisResult,
	sessionId?: string,
	cwd?: string,
): void {
	// Fire and forget - don't await
	writeAuditLog(result, sessionId, cwd).catch((error) => {
		console.error("[safety-net] Async audit error:", error);
	});
}

/**
 * Get the path to the audit log directory
 */
export function getAuditDir(): string {
	return AUDIT_DIR;
}

/**
 * Get the path to a session's audit log file
 */
export function getAuditLogPath(sessionId: string): string {
	return join(AUDIT_DIR, `${sanitizeFilename(sessionId)}.jsonl`);
}
