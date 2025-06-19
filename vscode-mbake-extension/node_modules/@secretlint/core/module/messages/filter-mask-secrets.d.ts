import { SecretLintAllMessages } from "./MessageProcessManager.js";
export type AllowMessage = {
    ruleId: string;
    messageId: string;
};
export declare const filterMaskSecretsData: (messages?: SecretLintAllMessages[]) => SecretLintAllMessages[];
//# sourceMappingURL=filter-mask-secrets.d.ts.map