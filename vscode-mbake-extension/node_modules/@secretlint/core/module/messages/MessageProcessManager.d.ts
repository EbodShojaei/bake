import { SecretLintCoreResultMessage, SecretLintCoreIgnoreMessage } from "@secretlint/types";
export type SecretLintAllMessages = SecretLintCoreResultMessage | SecretLintCoreIgnoreMessage;
export type SecretLintMessageProcessor = (messages: Array<SecretLintAllMessages>) => Array<SecretLintAllMessages>;
export declare const createMessageProcessor: (processors: SecretLintMessageProcessor[]) => {
    /**
     * process `messages` with registered processes
     */
    process<R extends SecretLintAllMessages>(messages: Array<SecretLintAllMessages>): R[];
};
//# sourceMappingURL=MessageProcessManager.d.ts.map