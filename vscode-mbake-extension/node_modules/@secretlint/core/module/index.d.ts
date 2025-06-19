import type { SecretLintCoreConfig, SecretLintCoreResult, SecretLintRawSource, SecretLintRuleLocaleTag } from "@secretlint/types";
export type SecretLintSourceOptions = {
    /**
     * Lint target source
     */
    source: SecretLintRawSource;
    options: {
        /**
         * local for translate
         * Default: "en"
         */
        locale?: SecretLintRuleLocaleTag;
        /**
         * If this is true, mask all message's data values
         * Replace data value with "****" strings
         * Default: false
         */
        maskSecrets?: boolean;
        /**
         * config present secretlintrc object
         */
        config: SecretLintCoreConfig;
        /**
         * If pass the `source` come from non-physical file such as stdin, you can set `noPhysicFilePath` to true.
         * This option affect to `context.getSourceFilePath()`.
         * If pass `noPhysicFilePath: true`, `context.getSourceFilePath()` return `undefined`.
         */
        noPhysicFilePath?: boolean;
    };
};
export declare const lintSource: ({ source, options }: SecretLintSourceOptions) => Promise<SecretLintCoreResult>;
//# sourceMappingURL=index.d.ts.map