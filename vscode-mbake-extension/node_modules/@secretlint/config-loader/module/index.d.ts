import { SecretLintConfigDescriptor, SecretLintCoreConfig, SecretLintRuleModule, SecretLintUnionRuleCreator } from "@secretlint/types";
import { AggregationError } from "./AggregationError.js";
export declare function importSecretlintCreator(moduleExports?: SecretLintRuleModule | Record<string, unknown>): SecretLintUnionRuleCreator;
export type SecretLintConfigLoaderOptions = {
    cwd?: string;
    configFilePath?: string;
    /**
     * node_modules directory path
     * Default: undefined
     */
    node_moduleDir?: string;
    /**
     * This definitions replace id to rule module
     * It is useful for replacing specific ruleId with specific rule module.
     * Main use-case is tester.
     */
    testReplaceDefinitions?: {
        id: string;
        rule: SecretLintUnionRuleCreator;
    }[];
};
export type SecretLintConfigLoaderResult = {
    ok: true;
    /**
     * Full config object
     */
    config: SecretLintCoreConfig;
    /**
     * Partial config file represent
     */
    configDescriptor: SecretLintConfigDescriptor;
    configFilePath: string;
};
export type SecretLintConfigLoaderRawResult = {
    ok: true;
    configFilePath: string;
    configDescriptor: SecretLintConfigDescriptor;
};
export type SecretLintLoadPackagesFromRawConfigOptions = {
    /**
     * Loaded config object
     */
    configDescriptor: SecretLintConfigDescriptor;
    /**
     * node_modules directory path
     * Default: undefined
     */
    node_moduleDir?: string;
    /**
     * This definitions replace id to rule module
     * It is useful for replacing specific ruleId with specific rule module.
     * Main use-case is tester.
     */
    testReplaceDefinitions?: {
        id: string;
        rule: SecretLintUnionRuleCreator;
    }[];
};
export type SecretLintLoadPackagesFromRawConfigResult = {
    ok: true;
    config: SecretLintCoreConfig;
};
/**
 * Load packages in RawConfig and return loaded config object
 * @param options
 */
export declare const loadPackagesFromConfigDescriptor: (options: SecretLintLoadPackagesFromRawConfigOptions) => Promise<SecretLintLoadPackagesFromRawConfigResult>;
/**
 *  Load config file and return config object that is loaded rule instance.
 * @param options
 */
export declare const loadConfig: (options: SecretLintConfigLoaderOptions) => Promise<SecretLintConfigLoaderResult>;
/**
 *  Load config file and return config object that is not loaded rule instance
 *  It is just JSON present for config file. Raw data
 * @param options
 */
export declare const loadConfigDescriptor: (options: SecretLintConfigLoaderOptions) => Promise<SecretLintConfigLoaderRawResult>;
export type validateConfigResult = {
    ok: true;
} | {
    ok: false;
    error: AggregationError | Error;
};
export declare const validateConfig: (options: SecretLintConfigLoaderOptions) => Promise<validateConfigResult>;
//# sourceMappingURL=index.d.ts.map