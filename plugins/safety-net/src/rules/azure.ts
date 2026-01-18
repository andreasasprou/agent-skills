/**
 * Azure CLI (az) destructive command rules
 */

import { extractWords, tokenize } from "../shell/parser.ts";
import { stripWrappers } from "../shell/wrappers.ts";
import type { AnalyzerOptions, SegmentResult } from "../types.ts";

/**
 * Check for --yes or -y flag (bypasses confirmation)
 */
function hasYesFlag(args: string[]): boolean {
	return args.includes("--yes") || args.includes("-y");
}

/**
 * Check for --force flag
 */
function hasForceFlag(args: string[]): boolean {
	return args.includes("--force") || args.includes("--force-string");
}

/**
 * Check for --no-wait flag
 */
function hasNoWaitFlag(args: string[]): boolean {
	return args.includes("--no-wait");
}

/**
 * Catastrophic Azure commands (always deny)
 */
const AZURE_CATASTROPHIC: Record<string, string> = {
	"group delete": "az group delete removes the ENTIRE resource group and ALL resources within it.",
	"account clear": "az account clear removes all subscriptions from the CLI.",
};

/**
 * Destructive Azure commands (deny with --yes, warn otherwise)
 */
const AZURE_DESTRUCTIVE: Record<string, string> = {
	// Compute
	"vm delete": "az vm delete permanently destroys virtual machines.",
	"vmss delete": "az vmss delete destroys VM scale sets.",
	"disk delete": "az disk delete destroys managed disks and data.",
	"snapshot delete": "az snapshot delete removes disk snapshots.",
	"image delete": "az image delete removes VM images.",

	// Storage
	"storage account delete": "az storage account delete destroys storage account and ALL data.",
	"storage container delete": "az storage container delete removes blob containers.",
	"storage blob delete": "az storage blob delete removes blobs.",
	"storage blob delete-batch": "az storage blob delete-batch bulk deletes blobs.",
	"storage share delete": "az storage share delete removes file shares.",
	"storage table delete": "az storage table delete removes tables.",
	"storage queue delete": "az storage queue delete removes queues.",

	// Databases
	"sql server delete": "az sql server delete destroys SQL servers.",
	"sql db delete": "az sql db delete destroys SQL databases.",
	"cosmosdb delete": "az cosmosdb delete destroys Cosmos DB accounts.",
	"mysql server delete": "az mysql server delete destroys MySQL servers.",
	"postgres server delete": "az postgres server delete destroys PostgreSQL servers.",
	"redis delete": "az redis delete destroys Redis caches.",

	// Kubernetes
	"aks delete": "az aks delete removes AKS clusters.",
	"aks nodepool delete": "az aks nodepool delete removes node pools.",

	// App Services
	"webapp delete": "az webapp delete removes web apps.",
	"functionapp delete": "az functionapp delete removes function apps.",
	"appservice plan delete": "az appservice plan delete removes App Service plans.",

	// Networking
	"network vnet delete": "az network vnet delete removes virtual networks.",
	"network nsg delete": "az network nsg delete removes network security groups.",
	"network lb delete": "az network lb delete removes load balancers.",
	"network public-ip delete": "az network public-ip delete removes public IPs.",
	"network application-gateway delete": "az network application-gateway delete removes app gateways.",

	// Security
	"keyvault delete": "az keyvault delete removes Key Vaults.",
	"keyvault secret delete": "az keyvault secret delete removes secrets.",
	"keyvault key delete": "az keyvault key delete removes keys.",
	"keyvault certificate delete": "az keyvault certificate delete removes certificates.",

	// Container Registry
	"acr delete": "az acr delete removes container registries.",
	"acr repository delete": "az acr repository delete removes repositories.",

	// Service Bus
	"servicebus namespace delete": "az servicebus namespace delete removes Service Bus namespaces.",
	"servicebus queue delete": "az servicebus queue delete removes queues.",
	"servicebus topic delete": "az servicebus topic delete removes topics.",

	// Event Hub
	"eventhubs namespace delete": "az eventhubs namespace delete removes Event Hub namespaces.",
	"eventhubs eventhub delete": "az eventhubs eventhub delete removes Event Hubs.",
};

/**
 * Build command path from args
 */
function buildCommandPath(args: string[]): string[] {
	const parts: string[] = [];
	for (const arg of args) {
		if (arg.startsWith("-")) break;
		parts.push(arg);
	}
	return parts;
}

/**
 * Analyze an Azure CLI command for destructive operations
 */
export function analyzeAzureCommand(
	command: string,
	options: AnalyzerOptions = {},
): SegmentResult {
	const tokens = tokenize(command);
	const { tokens: strippedTokens } = stripWrappers(tokens);
	const words = extractWords(strippedTokens);

	// First word should be "az"
	if (words[0] !== "az" || words.length < 2) {
		return { decision: "allow" };
	}

	const args = words.slice(1);
	const hasYes = hasYesFlag(args);
	const hasForce = hasForceFlag(args);
	const hasNoWait = hasNoWaitFlag(args);

	// Build command path for matching
	const commandParts = buildCommandPath(args);
	const commandPath = commandParts.join(" ");

	// Check for catastrophic commands
	for (const [pattern, reason] of Object.entries(AZURE_CATASTROPHIC)) {
		if (commandPath.startsWith(pattern)) {
			return {
				decision: "deny",
				rule: `azure-${pattern.replace(/ /g, "-")}`,
				category: "azure",
				reason: `${reason}${hasYes ? " (--yes bypasses confirmation)" : ""}`,
				matchedTokens: ["az", ...pattern.split(" ")],
				confidence: "high",
			};
		}
	}

	// Check for destructive commands
	for (const [pattern, reason] of Object.entries(AZURE_DESTRUCTIVE)) {
		if (commandPath.startsWith(pattern)) {
			// --yes or --force + --no-wait escalates severity
			const isAggressive = hasYes || (hasForce && hasNoWait);
			const decision = isAggressive || options.paranoid ? "deny" : "warn";

			return {
				decision,
				rule: `azure-${pattern.replace(/ /g, "-")}`,
				category: "azure",
				reason,
				matchedTokens: ["az", ...pattern.split(" ")],
				confidence: "high",
			};
		}
	}

	// Generic delete detection
	if (commandParts.includes("delete") || commandParts.includes("purge")) {
		const decision = hasYes || options.paranoid ? "deny" : "warn";
		return {
			decision,
			rule: "azure-delete-generic",
			category: "azure",
			reason: `az ${commandPath} is a destructive operation.`,
			matchedTokens: ["az", ...commandParts.slice(0, 3)],
			confidence: "medium",
		};
	}

	return { decision: "allow" };
}
