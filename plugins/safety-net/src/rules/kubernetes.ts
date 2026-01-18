/**
 * Kubernetes CLI destructive command rules
 * Covers kubectl, helm, and kustomize
 */

import { extractWords, tokenize } from "../shell/parser.ts";
import { stripWrappers } from "../shell/wrappers.ts";
import type { AnalyzerOptions, SegmentResult } from "../types.ts";

/**
 * Critical namespaces that should be protected
 */
const CRITICAL_NAMESPACES = [
	"kube-system",
	"kube-public",
	"kube-node-lease",
	"default",
];

/**
 * Resource types that are particularly dangerous to delete
 */
const CRITICAL_RESOURCES = [
	"namespace",
	"namespaces",
	"ns",
	"node",
	"nodes",
	"persistentvolume",
	"persistentvolumes",
	"pv",
	"persistentvolumeclaim",
	"persistentvolumeclaims",
	"pvc",
	"secret",
	"secrets",
	"configmap",
	"configmaps",
	"cm",
];

/**
 * Check for --all flag
 */
function hasAllFlag(args: string[]): boolean {
	return args.includes("--all") || args.includes("-A");
}

/**
 * Check for --all-namespaces flag
 */
function hasAllNamespaces(args: string[]): boolean {
	return args.includes("--all-namespaces") || args.includes("-A");
}

/**
 * Check for --force flag
 */
function hasForceFlag(args: string[]): boolean {
	return args.includes("--force");
}

/**
 * Check for --grace-period=0 flag
 */
function hasNoGracePeriod(args: string[]): boolean {
	return args.some(
		(arg) => arg === "--grace-period=0" || arg === "--grace-period 0",
	);
}

/**
 * Check for dry-run flag
 */
function hasDryRun(args: string[]): boolean {
	return args.some(
		(arg) =>
			arg === "--dry-run" ||
			arg.startsWith("--dry-run=") ||
			arg === "--server-dry-run",
	);
}

/**
 * Extract namespace from -n or --namespace flag
 */
function extractNamespace(args: string[]): string | undefined {
	for (let i = 0; i < args.length; i++) {
		const arg = args[i];
		if (arg === "-n" || arg === "--namespace") {
			return args[i + 1];
		}
		if (arg?.startsWith("--namespace=")) {
			return arg.slice("--namespace=".length);
		}
		if (arg?.startsWith("-n=")) {
			return arg.slice("-n=".length);
		}
	}
	return undefined;
}

/**
 * Analyze kubectl delete command
 */
function analyzeKubectlDelete(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const hasAll = hasAllFlag(args);
	const hasAllNs = hasAllNamespaces(args);
	const hasForce = hasForceFlag(args);
	const noGrace = hasNoGracePeriod(args);
	const namespace = extractNamespace(args);

	if (hasDryRun(args)) {
		return { decision: "allow" };
	}

	// kubectl delete with -A (all namespaces) is extremely dangerous
	if (hasAllNs) {
		return {
			decision: "deny",
			rule: "kubectl-delete-all-namespaces",
			category: "kubernetes",
			reason:
				"kubectl delete --all-namespaces affects ALL namespaces (catastrophic).",
			matchedTokens: ["kubectl", "delete", "-A"],
			confidence: "high",
		};
	}

	// Check for namespace deletion
	const resourceTypes = args.filter(
		(a) =>
			!a.startsWith("-") &&
			a !== "delete" &&
			!a.includes("/") &&
			!a.includes("="),
	);
	const firstResource = resourceTypes[0]?.toLowerCase();

	if (
		firstResource === "namespace" ||
		firstResource === "namespaces" ||
		firstResource === "ns"
	) {
		const nsName = resourceTypes[1];
		if (nsName && CRITICAL_NAMESPACES.includes(nsName)) {
			return {
				decision: "deny",
				rule: "kubectl-delete-critical-namespace",
				category: "kubernetes",
				reason: `kubectl delete namespace ${nsName} removes a critical system namespace.`,
				matchedTokens: ["kubectl", "delete", "namespace", nsName],
				confidence: "high",
			};
		}

		return {
			decision: "deny",
			rule: "kubectl-delete-namespace",
			category: "kubernetes",
			reason:
				"kubectl delete namespace removes the namespace and ALL resources within it.",
			matchedTokens: ["kubectl", "delete", "namespace"],
			confidence: "high",
		};
	}

	// kubectl delete --all deletes all resources of that type
	if (hasAll) {
		return {
			decision: "deny",
			rule: "kubectl-delete-all",
			category: "kubernetes",
			reason: "kubectl delete --all removes ALL resources of the specified type.",
			matchedTokens: ["kubectl", "delete", "--all"],
			confidence: "high",
		};
	}

	// Force delete without grace period - dangerous
	if (hasForce && noGrace) {
		return {
			decision: "deny",
			rule: "kubectl-delete-force-immediate",
			category: "kubernetes",
			reason:
				"kubectl delete --force --grace-period=0 immediately removes resources without graceful shutdown.",
			matchedTokens: ["kubectl", "delete", "--force", "--grace-period=0"],
			confidence: "high",
		};
	}

	// Deleting critical resources
	if (firstResource && CRITICAL_RESOURCES.includes(firstResource)) {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: `kubectl-delete-${firstResource}`,
			category: "kubernetes",
			reason: `kubectl delete ${firstResource} removes critical resource (potential data loss).`,
			matchedTokens: ["kubectl", "delete", firstResource],
			confidence: "high",
		};
	}

	// General delete warning
	const decision = options.paranoid ? "deny" : "warn";
	return {
		decision,
		rule: "kubectl-delete",
		category: "kubernetes",
		reason: "kubectl delete removes Kubernetes resources.",
		matchedTokens: ["kubectl", "delete", ...resourceTypes.slice(0, 2)],
		confidence: "medium",
	};
}

/**
 * Analyze kubectl drain command
 */
function analyzeKubectlDrain(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const hasForce = hasForceFlag(args);
	const hasIgnoreDaemonsets = args.includes("--ignore-daemonsets");
	const hasDeleteLocalData =
		args.includes("--delete-local-data") ||
		args.includes("--delete-emptydir-data");

	if (hasDryRun(args)) {
		return { decision: "allow" };
	}

	if (hasDeleteLocalData) {
		return {
			decision: "deny",
			rule: "kubectl-drain-delete-data",
			category: "kubernetes",
			reason:
				"kubectl drain --delete-local-data evicts pods and deletes their local data.",
			matchedTokens: ["kubectl", "drain", "--delete-local-data"],
			confidence: "high",
		};
	}

	if (hasForce) {
		return {
			decision: "deny",
			rule: "kubectl-drain-force",
			category: "kubernetes",
			reason:
				"kubectl drain --force evicts pods even if they are not managed by a controller.",
			matchedTokens: ["kubectl", "drain", "--force"],
			confidence: "high",
		};
	}

	const decision = options.paranoid ? "deny" : "warn";
	return {
		decision,
		rule: "kubectl-drain",
		category: "kubernetes",
		reason: "kubectl drain evicts all pods from a node.",
		matchedTokens: ["kubectl", "drain"],
		confidence: "high",
	};
}

/**
 * Analyze kubectl cordon command
 */
function analyzeKubectlCordon(
	_args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const decision = options.paranoid ? "deny" : "warn";
	return {
		decision,
		rule: "kubectl-cordon",
		category: "kubernetes",
		reason:
			"kubectl cordon marks node as unschedulable (prevents new pods from being scheduled).",
		matchedTokens: ["kubectl", "cordon"],
		confidence: "high",
	};
}

/**
 * Analyze kubectl taint command
 */
function analyzeKubectlTaint(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const command = args.join(" ");

	// NoExecute taints evict existing pods
	if (command.includes("NoExecute")) {
		return {
			decision: options.paranoid ? "deny" : "warn",
			rule: "kubectl-taint-noexecute",
			category: "kubernetes",
			reason: "kubectl taint with NoExecute effect evicts existing pods.",
			matchedTokens: ["kubectl", "taint", "NoExecute"],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze kubectl scale command
 */
function analyzeKubectlScale(
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	// Check for --replicas=0
	const replicasZero = args.some(
		(arg) => arg === "--replicas=0" || arg === "--replicas 0",
	);

	if (hasDryRun(args)) {
		return { decision: "allow" };
	}

	if (replicasZero) {
		return {
			decision: options.paranoid ? "deny" : "warn",
			rule: "kubectl-scale-zero",
			category: "kubernetes",
			reason:
				"kubectl scale --replicas=0 stops all pods of the workload (service outage).",
			matchedTokens: ["kubectl", "scale", "--replicas=0"],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

/**
 * Analyze kubectl apply/replace with -k (kustomize)
 */
function analyzeKubectlKustomize(
	subcommand: string,
	args: string[],
	options: AnalyzerOptions,
): SegmentResult {
	if (hasDryRun(args)) {
		return { decision: "allow" };
	}

	// kubectl delete -k is very dangerous
	if (subcommand === "delete") {
		return {
			decision: "deny",
			rule: "kubectl-delete-kustomize",
			category: "kubernetes",
			reason:
				"kubectl delete -k removes all resources defined in kustomization.",
			matchedTokens: ["kubectl", "delete", "-k"],
			confidence: "high",
		};
	}

	return { decision: "allow" };
}

/**
 * Main kubectl command analyzer
 */
function analyzeKubectl(
	words: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const subcommand = words[1];
	const args = words.slice(2);

	// Check for -k flag (kustomize)
	if (args.includes("-k") || args.includes("--kustomize")) {
		return analyzeKubectlKustomize(subcommand, args, options);
	}

	switch (subcommand) {
		case "delete":
			return analyzeKubectlDelete(args, options);
		case "drain":
			return analyzeKubectlDrain(args, options);
		case "cordon":
			return analyzeKubectlCordon(args, options);
		case "taint":
			return analyzeKubectlTaint(args, options);
		case "scale":
			return analyzeKubectlScale(args, options);
		default:
			return { decision: "allow" };
	}
}

/**
 * Analyze helm commands
 */
function analyzeHelm(
	words: string[],
	options: AnalyzerOptions,
): SegmentResult {
	const subcommand = words[1];
	const args = words.slice(2);

	// Check for --dry-run
	if (args.includes("--dry-run")) {
		return { decision: "allow" };
	}

	// helm uninstall / helm delete
	if (subcommand === "uninstall" || subcommand === "delete") {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "helm-uninstall",
			category: "kubernetes",
			reason: "helm uninstall removes the release and all its resources.",
			matchedTokens: ["helm", subcommand],
			confidence: "high",
		};
	}

	// helm rollback
	if (subcommand === "rollback") {
		const decision = options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "helm-rollback",
			category: "kubernetes",
			reason: "helm rollback reverts to a previous release version.",
			matchedTokens: ["helm", "rollback"],
			confidence: "medium",
		};
	}

	// helm upgrade --force
	if (subcommand === "upgrade") {
		if (args.includes("--force")) {
			return {
				decision: options.paranoid ? "deny" : "warn",
				rule: "helm-upgrade-force",
				category: "kubernetes",
				reason:
					"helm upgrade --force deletes and recreates resources (potential downtime).",
				matchedTokens: ["helm", "upgrade", "--force"],
				confidence: "high",
			};
		}

		// --reset-values discards previously set values
		if (args.includes("--reset-values")) {
			return {
				decision: options.paranoid ? "deny" : "warn",
				rule: "helm-upgrade-reset-values",
				category: "kubernetes",
				reason:
					"helm upgrade --reset-values discards all previously set values.",
				matchedTokens: ["helm", "upgrade", "--reset-values"],
				confidence: "high",
			};
		}
	}

	return { decision: "allow" };
}

/**
 * Analyze a Kubernetes command for destructive operations
 */
export function analyzeKubernetesCommand(
	command: string,
	options: AnalyzerOptions = {},
): SegmentResult {
	const tokens = tokenize(command);
	const { tokens: strippedTokens } = stripWrappers(tokens);
	const words = extractWords(strippedTokens);

	if (words.length < 2) {
		return { decision: "allow" };
	}

	const cmd = words[0];

	switch (cmd) {
		case "kubectl":
			return analyzeKubectl(words, options);
		case "helm":
			return analyzeHelm(words, options);
		default:
			return { decision: "allow" };
	}
}
