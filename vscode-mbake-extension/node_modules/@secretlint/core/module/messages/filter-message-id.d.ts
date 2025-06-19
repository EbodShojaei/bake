import { SecretLintCoreResultMessage } from "@secretlint/types";
export type AllowMessage = {
    ruleId: string;
    messageId: string;
};
export declare const filterByAllowMessageIds: (messages: SecretLintCoreResultMessage[], allowMessageIds: AllowMessage[]) => SecretLintCoreResultMessage[];
//# sourceMappingURL=filter-message-id.d.ts.map