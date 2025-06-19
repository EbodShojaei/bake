import { SecretLintCoreIgnoreMessage, SecretLintCoreResultMessage } from "@secretlint/types";
export type filterIgnoredMessagesOptions = {
    reportedMessages: SecretLintCoreResultMessage[];
    ignoredMessages: SecretLintCoreIgnoreMessage[];
};
/**
 * filter messages by ignore messages
 */
export declare function filterIgnoredMessages(options: filterIgnoredMessagesOptions): SecretLintCoreResultMessage[];
//# sourceMappingURL=filter-ignored-process.d.ts.map