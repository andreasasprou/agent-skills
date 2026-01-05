/**
 * AWS CLI destructive command rules
 */

import { extractWords, tokenize } from "../shell/parser.ts";
import { stripWrappers } from "../shell/wrappers.ts";
import type { AnalyzerOptions, SegmentResult } from "../types.ts";

/**
 * AWS destructive operations by service
 * Format: { service: { subcommand: { reason, severity } } }
 */
const AWS_DESTRUCTIVE_OPS: Record<
	string,
	Record<string, { reason: string; severity: "deny" | "warn" }>
> = {
	// S3 operations
	s3: {
		rm: { reason: "deletes S3 objects", severity: "warn" },
		rb: { reason: "removes S3 bucket", severity: "warn" },
	},
	s3api: {
		"delete-object": { reason: "deletes S3 object", severity: "warn" },
		"delete-objects": { reason: "bulk deletes S3 objects", severity: "warn" },
		"delete-bucket": { reason: "deletes S3 bucket", severity: "warn" },
	},

	// EC2 operations
	ec2: {
		"terminate-instances": {
			reason: "terminates EC2 instances",
			severity: "deny",
		},
		"delete-volume": { reason: "deletes EBS volume", severity: "deny" },
		"delete-snapshot": { reason: "deletes EBS snapshot", severity: "warn" },
		"delete-security-group": {
			reason: "deletes security group",
			severity: "warn",
		},
		"delete-key-pair": { reason: "deletes key pair", severity: "warn" },
		"delete-vpc": { reason: "deletes VPC", severity: "deny" },
		"delete-subnet": { reason: "deletes subnet", severity: "warn" },
		"delete-internet-gateway": {
			reason: "deletes internet gateway",
			severity: "warn",
		},
		"delete-nat-gateway": { reason: "deletes NAT gateway", severity: "warn" },
	},

	// RDS operations
	rds: {
		"delete-db-instance": {
			reason: "deletes RDS database instance",
			severity: "deny",
		},
		"delete-db-cluster": { reason: "deletes RDS cluster", severity: "deny" },
		"delete-db-snapshot": { reason: "deletes RDS snapshot", severity: "warn" },
		"delete-db-cluster-snapshot": {
			reason: "deletes RDS cluster snapshot",
			severity: "warn",
		},
	},

	// IAM operations
	iam: {
		"delete-user": { reason: "deletes IAM user", severity: "deny" },
		"delete-role": { reason: "deletes IAM role", severity: "deny" },
		"delete-policy": { reason: "deletes IAM policy", severity: "warn" },
		"delete-group": { reason: "deletes IAM group", severity: "warn" },
		"delete-access-key": { reason: "deletes access key", severity: "warn" },
	},

	// Lambda operations
	lambda: {
		"delete-function": { reason: "deletes Lambda function", severity: "deny" },
		"delete-layer-version": {
			reason: "deletes Lambda layer version",
			severity: "warn",
		},
	},

	// CloudFormation operations
	cloudformation: {
		"delete-stack": {
			reason: "deletes entire CloudFormation stack",
			severity: "deny",
		},
		"delete-stack-set": {
			reason: "deletes CloudFormation stack set",
			severity: "deny",
		},
	},

	// DynamoDB operations
	dynamodb: {
		"delete-table": { reason: "deletes DynamoDB table", severity: "deny" },
		"delete-backup": { reason: "deletes DynamoDB backup", severity: "warn" },
	},

	// KMS operations
	kms: {
		"schedule-key-deletion": {
			reason: "schedules KMS key for deletion",
			severity: "deny",
		},
		"delete-alias": { reason: "deletes KMS alias", severity: "warn" },
	},

	// Route53 operations
	route53: {
		"delete-hosted-zone": {
			reason: "deletes DNS hosted zone",
			severity: "deny",
		},
	},

	// Secrets Manager operations
	secretsmanager: {
		"delete-secret": { reason: "deletes secret", severity: "warn" },
	},

	// CloudWatch Logs operations
	logs: {
		"delete-log-group": { reason: "deletes log group", severity: "warn" },
		"delete-log-stream": { reason: "deletes log stream", severity: "warn" },
	},

	// ECS operations
	ecs: {
		"delete-cluster": { reason: "deletes ECS cluster", severity: "deny" },
		"delete-service": { reason: "deletes ECS service", severity: "warn" },
		"deregister-task-definition": {
			reason: "deregisters task definition",
			severity: "warn",
		},
	},

	// EKS operations
	eks: {
		"delete-cluster": { reason: "deletes EKS cluster", severity: "deny" },
		"delete-nodegroup": { reason: "deletes EKS node group", severity: "warn" },
	},

	// ElastiCache operations
	elasticache: {
		"delete-cache-cluster": {
			reason: "deletes ElastiCache cluster",
			severity: "deny",
		},
		"delete-replication-group": {
			reason: "deletes ElastiCache replication group",
			severity: "deny",
		},
	},

	// SNS operations
	sns: {
		"delete-topic": { reason: "deletes SNS topic", severity: "warn" },
	},

	// SQS operations
	sqs: {
		"delete-queue": { reason: "deletes SQS queue", severity: "warn" },
		"purge-queue": {
			reason: "purges all messages from SQS queue",
			severity: "warn",
		},
	},

	// Cognito operations
	"cognito-idp": {
		"delete-user-pool": {
			reason: "deletes Cognito user pool",
			severity: "deny",
		},
	},

	// API Gateway operations
	apigateway: {
		"delete-rest-api": {
			reason: "deletes API Gateway REST API",
			severity: "deny",
		},
	},
	apigatewayv2: {
		"delete-api": {
			reason: "deletes API Gateway HTTP/WebSocket API",
			severity: "deny",
		},
	},
};

/**
 * Special handling for S3 sync with --delete
 */
function checkS3SyncDelete(args: string[]): boolean {
	return args.includes("--delete");
}

/**
 * Check for --dry-run flag
 */
function hasDryRun(args: string[]): boolean {
	return args.includes("--dry-run") || args.includes("--dryrun");
}

/**
 * Check for recursive/force modifiers that make operations more dangerous
 */
function hasRecursiveModifier(args: string[]): boolean {
	return args.includes("--recursive") || args.includes("-r");
}

/**
 * Check for force/skip-final-snapshot modifiers
 */
function hasSkipSnapshot(args: string[]): boolean {
	return (
		args.includes("--skip-final-snapshot") ||
		args.includes("--force") ||
		args.includes("--force-delete")
	);
}

/**
 * Analyze an AWS CLI command for destructive operations
 */
export function analyzeAwsCommand(
	command: string,
	options: AnalyzerOptions = {},
): SegmentResult {
	const tokens = tokenize(command);
	const { tokens: strippedTokens } = stripWrappers(tokens);
	const words = extractWords(strippedTokens);

	// First word should be "aws"
	if (words[0] !== "aws" || words.length < 3) {
		return { decision: "allow" };
	}

	const service = words[1];
	const subcommand = words[2];
	const args = words.slice(3);

	// Skip if dry-run
	if (hasDryRun(args)) {
		return { decision: "allow" };
	}

	// Special case: s3 sync --delete
	if (service === "s3" && subcommand === "sync" && checkS3SyncDelete(args)) {
		const decision = options.paranoid || options.paranoidAws ? "deny" : "warn";
		return {
			decision,
			rule: "aws-s3-sync-delete",
			category: "aws",
			reason: "aws s3 sync --delete removes objects not present in source.",
			matchedTokens: ["aws", "s3", "sync", "--delete"],
			confidence: "high",
		};
	}

	// Special case: s3 rm --recursive
	if (service === "s3" && subcommand === "rm" && hasRecursiveModifier(args)) {
		const decision = options.paranoid || options.paranoidAws ? "deny" : "warn";
		return {
			decision,
			rule: "aws-s3-rm-recursive",
			category: "aws",
			reason: "aws s3 rm --recursive bulk deletes S3 objects.",
			matchedTokens: ["aws", "s3", "rm", "--recursive"],
			confidence: "high",
		};
	}

	// Special case: s3 rb --force
	if (service === "s3" && subcommand === "rb" && args.includes("--force")) {
		return {
			decision: "deny",
			rule: "aws-s3-rb-force",
			category: "aws",
			reason: "aws s3 rb --force removes bucket and ALL contents.",
			matchedTokens: ["aws", "s3", "rb", "--force"],
			confidence: "high",
		};
	}

	// Special case: route53 change-resource-record-sets with DELETE
	if (service === "route53" && subcommand === "change-resource-record-sets") {
		// Check if command contains DELETE action (in JSON payload)
		if (
			command.includes("DELETE") ||
			command.includes('"Action":"DELETE"') ||
			command.includes("'Action':'DELETE'")
		) {
			return {
				decision: "warn",
				rule: "aws-route53-delete-record",
				category: "aws",
				reason:
					"aws route53 change-resource-record-sets with DELETE removes DNS records.",
				matchedTokens: [
					"aws",
					"route53",
					"change-resource-record-sets",
					"DELETE",
				],
				confidence: "medium",
			};
		}
	}

	// Look up in destructive operations table
	const serviceOps = AWS_DESTRUCTIVE_OPS[service || ""];
	if (serviceOps && subcommand) {
		const opInfo = serviceOps[subcommand];
		if (opInfo) {
			let severity = opInfo.severity;

			// Escalate to deny in paranoid mode
			if ((options.paranoid || options.paranoidAws) && severity === "warn") {
				severity = "deny";
			}

			// Escalate if skipping final snapshot (RDS)
			if (service === "rds" && hasSkipSnapshot(args)) {
				severity = "deny";
			}

			return {
				decision: severity,
				rule: `aws-${service}-${subcommand}`,
				category: "aws",
				reason: `aws ${service} ${subcommand} ${opInfo.reason}.`,
				matchedTokens: ["aws", service, subcommand],
				confidence: "high",
			};
		}
	}

	return { decision: "allow" };
}
