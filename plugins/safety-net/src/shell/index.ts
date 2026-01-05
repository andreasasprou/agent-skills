/**
 * Shell parsing module exports
 */

export {
	extractEnvVars,
	extractWords,
	getCommandArgs,
	getCommandName,
	tokenize,
} from "./parser.ts";
export {
	extractBaseCommand,
	hasUnparseableConstructs,
	splitCommand,
} from "./splitter.ts";
export {
	type ExtractedCommand,
	extractNestedCommands,
	getEffectiveCommand,
	type StrippedCommand,
	stripWrappers,
} from "./wrappers.ts";
