import { SecretLintEngineOptions } from "@secretlint/node";
/**
 * Lint files
 */
export type SecretLintFileOptions = {
    cwd: string;
    filePathOrGlobList: string[];
    outputFilePath?: string;
    ignoreFilePath?: string;
};
/**
 * Lint text from stdin
 */
export type SecretLintStdinOptions = {
    cwd: string;
    stdinContent: string;
    stdinFileName: string;
    outputFilePath?: string;
    ignoreFilePath?: string;
};
export type SecretLintOptions = SecretLintFileOptions | SecretLintStdinOptions;
export declare const runSecretLint: ({ cliOptions, engineOptions, }: {
    cliOptions: SecretLintOptions;
    engineOptions: SecretLintEngineOptions;
}) => Promise<{
    exitStatus: number;
    stdout: string | null;
    stderr: Error | null;
}>;
//# sourceMappingURL=index.d.ts.map