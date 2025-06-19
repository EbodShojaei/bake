import { SecretLintCoreIgnoreMessage, SecretLintCoreResultMessage, SecretlintCoreSharedOptions, SecretLintRuleContext, SecretLintRuleCreator, SecretLintRuleLocaleTag, SecretLintRuleSeverityLevel, SecretLintSourceCode } from "@secretlint/types";
type Handler<T> = (descriptor: T) => void;
export type ContextEvents = {
    report(descriptor: SecretLintCoreResultMessage): void;
    onReport(handler: Handler<SecretLintCoreResultMessage>): () => void;
    ignore(descriptor: SecretLintCoreIgnoreMessage): void;
    onIgnore(handler: Handler<SecretLintCoreIgnoreMessage>): () => void;
};
export declare const createContextEvents: () => ContextEvents;
export type CreateRuleContextOptions = {
    ruleId: string;
    /**
     * If the rule is in preset, pass rule preset's id as ruleParentId
     */
    ruleParentId?: string;
    meta: SecretLintRuleCreator["meta"];
    severity?: SecretLintRuleSeverityLevel;
    sourceCode: SecretLintSourceCode;
    contextEvents: ContextEvents;
    sharedOptions: SecretlintCoreSharedOptions;
    locale: SecretLintRuleLocaleTag;
};
export declare const createRuleContext: ({ ruleId, ruleParentId, meta, severity, sourceCode, contextEvents, sharedOptions, locale, }: CreateRuleContextOptions) => SecretLintRuleContext;
export {};
//# sourceMappingURL=RuleContext.d.ts.map