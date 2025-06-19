import { SecretLintCoreIgnoreMessage, SecretLintCoreResultMessage } from "@secretlint/types";
export type cleanupMessagesOptions = {
    reportedMessages: SecretLintCoreResultMessage[];
    ignoredMessages: SecretLintCoreIgnoreMessage[];
    allowMessageIds: {
        ruleId: string;
        messageId: string;
    }[];
    maskSecrets: boolean;
};
/**
 * Post cleanup messages
 * - filter ignored range
 * - filter disabled message
 * - [masSecrets] mask secrets message
 * - filter duplicated messages
 * - sort messages by range
 * @param options
 */
export declare const cleanupMessages: (options: cleanupMessagesOptions) => SecretLintCoreResultMessage[];
//# sourceMappingURL=index.d.ts.map