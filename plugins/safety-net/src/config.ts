/**
 * Configuration system for Safety Net
 * Reads from environment variables and provides defaults
 */

import type { AnalyzerOptions } from "./types.ts";

/** Default temp roots that are considered safe for deletion */
const DEFAULT_TEMP_ROOTS = [
	"/tmp",
	"/var/tmp",
	"/private/tmp",
	"/private/var/tmp",
	process.env.TMPDIR,
].filter(Boolean) as string[];

/** Parse a boolean environment variable */
function parseBoolEnv(value: string | undefined): boolean {
	return value === "1" || value?.toLowerCase() === "true";
}

/** Parse a comma-separated list environment variable */
function parseListEnv(value: string | undefined): string[] | undefined {
	if (!value) return undefined;
	return value
		.split(",")
		.map((s) => s.trim())
		.filter(Boolean);
}

/** Parse an integer environment variable with default */
function parseIntEnv(value: string | undefined, defaultValue: number): number {
	if (!value) return defaultValue;
	const parsed = Number.parseInt(value, 10);
	return Number.isNaN(parsed) ? defaultValue : parsed;
}

/** Load configuration from environment variables */
export function loadConfig(): AnalyzerOptions {
	return {
		strict: parseBoolEnv(process.env.SAFETY_NET_STRICT),
		paranoid: parseBoolEnv(process.env.SAFETY_NET_PARANOID),
		paranoidRm: parseBoolEnv(process.env.SAFETY_NET_PARANOID_RM),
		paranoidAws: parseBoolEnv(process.env.SAFETY_NET_PARANOID_AWS),
		disableGit: parseBoolEnv(process.env.SAFETY_NET_DISABLE_GIT),
		disableRm: parseBoolEnv(process.env.SAFETY_NET_DISABLE_RM),
		disableAws: parseBoolEnv(process.env.SAFETY_NET_DISABLE_AWS),
		disablePulumi: parseBoolEnv(process.env.SAFETY_NET_DISABLE_PULUMI),
		paranoidPulumi: parseBoolEnv(process.env.SAFETY_NET_PARANOID_PULUMI),
		disableStripe: parseBoolEnv(process.env.SAFETY_NET_DISABLE_STRIPE),
		paranoidStripe: parseBoolEnv(process.env.SAFETY_NET_PARANOID_STRIPE),
		tempRoots:
			parseListEnv(process.env.SAFETY_NET_TEMP_ROOTS) ?? DEFAULT_TEMP_ROOTS,
		maxRecursionDepth: parseIntEnv(
			process.env.SAFETY_NET_MAX_RECURSION_DEPTH,
			4,
		),
		maxSegments: parseIntEnv(process.env.SAFETY_NET_MAX_SEGMENTS, 64),
		bypass: parseBoolEnv(process.env.SAFETY_NET_BYPASS),
		warnOnly: parseBoolEnv(process.env.SAFETY_NET_WARN_ONLY),
	};
}

/** Merge options with config, giving priority to explicit options */
export function mergeConfig(
	options: AnalyzerOptions,
	config: AnalyzerOptions,
): AnalyzerOptions {
	return {
		cwd: options.cwd ?? config.cwd,
		strict: options.strict ?? config.strict,
		paranoid: options.paranoid ?? config.paranoid,
		paranoidRm: options.paranoidRm ?? config.paranoidRm,
		paranoidAws: options.paranoidAws ?? config.paranoidAws,
		disableGit: options.disableGit ?? config.disableGit,
		disableRm: options.disableRm ?? config.disableRm,
		disableAws: options.disableAws ?? config.disableAws,
		disablePulumi: options.disablePulumi ?? config.disablePulumi,
		paranoidPulumi: options.paranoidPulumi ?? config.paranoidPulumi,
		disableStripe: options.disableStripe ?? config.disableStripe,
		paranoidStripe: options.paranoidStripe ?? config.paranoidStripe,
		tempRoots: options.tempRoots ?? config.tempRoots,
		maxRecursionDepth: options.maxRecursionDepth ?? config.maxRecursionDepth,
		maxSegments: options.maxSegments ?? config.maxSegments,
		bypass: options.bypass ?? config.bypass,
		warnOnly: options.warnOnly ?? config.warnOnly,
	};
}

export { DEFAULT_TEMP_ROOTS };
