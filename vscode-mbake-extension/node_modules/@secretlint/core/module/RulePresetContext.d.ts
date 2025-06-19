import { SecretLintCoreConfigRulePreset, SecretlintCoreSharedOptions, SecretLintRuleLocaleTag, SecretLintRulePresetContext, SecretLintSourceCode } from "@secretlint/types";
import { RunningEvents } from "./RunningEvents.js";
import { ContextEvents } from "./RuleContext.js";
/**
 * Create a context for Rule Preset
 */
export declare const createRulePresetContext: ({ configRulePreset, sourceCode, runningEvents, contextEvents, sharedOptions, locale, }: {
    configRulePreset: SecretLintCoreConfigRulePreset;
    sourceCode: SecretLintSourceCode;
    contextEvents: ContextEvents;
    runningEvents: RunningEvents;
    sharedOptions: SecretlintCoreSharedOptions;
    locale: SecretLintRuleLocaleTag;
}) => SecretLintRulePresetContext;
//# sourceMappingURL=RulePresetContext.d.ts.map