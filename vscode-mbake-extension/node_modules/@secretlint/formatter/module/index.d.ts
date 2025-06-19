import { SecretLintCoreResult } from "@secretlint/types";
import { FormatterConfig } from "./types.js";
export interface SecretLintFormatterConfig {
    /**
     * Using Formatter name
     */
    formatterName: string;
    /**
     * Output color
     * Default: true
     */
    color?: boolean;
    /**
     * If terminalLink is true, some formatter will output that includes clickable click
     * Support Terminal: https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda
     * Default: false
     */
    terminalLink?: boolean;
}
export declare function loadFormatter(formatterConfig: SecretLintFormatterConfig): Promise<{
    format: (results: SecretLintCoreResult[]) => string;
}>;
export declare function secretlintCreateFormatter(formatterConfig: FormatterConfig): Promise<{
    format: (results: SecretLintCoreResult[]) => string;
}>;
export interface SecretLintFormatterDetail {
    name: string;
}
export declare function getFormatterList(): SecretLintFormatterDetail[];
export declare function secretlintGetFormatterList(): SecretLintFormatterDetail[];
//# sourceMappingURL=index.d.ts.map