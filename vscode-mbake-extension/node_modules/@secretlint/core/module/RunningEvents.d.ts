import { SecretLintCoreConfigRule, SecretLintCoreConfigRulePreset, SecretLintRuleContext, SecretLintRulePresetContext, SecretLintSourceCode } from "@secretlint/types";
import { AllowMessage } from "./messages/filter-message-id.js";
export type RunningEvents = {
    collectAllowMessageIds(): AllowMessage[];
    /**
     * register rule to Core
     * In this function, the rule's option is frozen.
     * @param descriptorRule
     * @param context
     */
    registerRule({ descriptorRule, context, }: {
        descriptorRule: SecretLintCoreConfigRule;
        context: SecretLintRuleContext;
    }): void;
    registerRulePreset({ descriptorRulePreset, context, }: {
        descriptorRulePreset: SecretLintCoreConfigRulePreset;
        context: SecretLintRulePresetContext;
    }): void;
    isRegistered(ruleId: string): boolean;
    runLint(options: {
        sourceCode: SecretLintSourceCode;
    }): Promise<Array<void>>;
};
export declare const createRunningEvents: () => RunningEvents;
//# sourceMappingURL=RunningEvents.d.ts.map