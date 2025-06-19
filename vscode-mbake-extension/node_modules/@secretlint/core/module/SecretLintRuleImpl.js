export class SecretLintRule {
    ruleReportHandle;
    ruleCreator;
    descriptorRule;
    constructor({ descriptorRule, context }) {
        this.descriptorRule = descriptorRule;
        this.ruleCreator = descriptorRule.rule;
        // normalize rule options
        const ruleCreatorOptions = descriptorRule.options || {};
        this.ruleReportHandle = this.ruleCreator.create(context, ruleCreatorOptions);
    }
    allowMessageIds() {
        if (!this.descriptorRule.allowMessageIds) {
            return [];
        }
        const ruleId = this.ruleCreator.meta.id;
        return this.descriptorRule.allowMessageIds.map((allowMessageId) => {
            return {
                messageId: allowMessageId,
                ruleId,
            };
        });
    }
    supportSourceCode(sourceCode) {
        const contentType = sourceCode.contentType;
        if (contentType === "unknown") {
            return true;
        }
        if (this.ruleCreator.meta.supportedContentTypes.includes("all")) {
            return true;
        }
        return this.ruleCreator.meta.supportedContentTypes.includes(contentType);
    }
    async file(source) {
        const file = this.ruleReportHandle.file;
        if (!file) {
            return;
        }
        return file(source);
    }
}
//# sourceMappingURL=SecretLintRuleImpl.js.map