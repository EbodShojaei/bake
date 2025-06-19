import { SecretLintRuleContext, SecretLintCoreConfigRule, SecretLintSourceCode } from "@secretlint/types";
import { AllowMessage } from "./messages/filter-message-id.js";
export type SecretLintRuleOptions = {
    context: SecretLintRuleContext;
    descriptorRule: SecretLintCoreConfigRule;
};
export declare class SecretLintRule {
    private ruleReportHandle;
    private ruleCreator;
    private descriptorRule;
    constructor({ descriptorRule, context }: SecretLintRuleOptions);
    allowMessageIds(): AllowMessage[];
    supportSourceCode(sourceCode: SecretLintSourceCode): boolean;
    file(source: SecretLintSourceCode): Promise<any>;
}
//# sourceMappingURL=SecretLintRuleImpl.d.ts.map