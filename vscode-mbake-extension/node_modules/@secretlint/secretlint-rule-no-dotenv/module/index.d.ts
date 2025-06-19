import type { SecretLintRuleCreator } from "@secretlint/types";
export type Options = {
    /**
     * List of .env file names to allow
     * @example [".env.local", ".env.test"]
     */
    allowFileNames?: string[];
};
export declare const messages: {
    FOUND_DOTENV_FILE: {
        en: () => string;
        ja: () => string;
    };
};
export declare const creator: SecretLintRuleCreator<Options>;
//# sourceMappingURL=index.d.ts.map