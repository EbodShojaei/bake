import type { SecretLintConfigDescriptor, SecretLintCoreConfig } from "@secretlint/types";
import { AggregationError } from "./AggregationError.js";
/**
 * value should be SecretLintCoreConfig
 * @param configDescriptor
 */
export declare const validateConfigDescriptor: (configDescriptor: SecretLintConfigDescriptor) => {
    ok: true;
} | {
    ok: false;
    error: Error | AggregationError;
};
export type validateConfigOption = {
    config: SecretLintCoreConfig;
};
/**
 * validate config after loading config.
 * It is additional check
 * please pass validateRawConfig before it.
 * @param value
 */
export declare const validateConfigWithDescriptor: ({ config, }: validateConfigOption) => {
    ok: true;
} | {
    ok: false;
    error: Error;
};
//# sourceMappingURL=validator.d.ts.map