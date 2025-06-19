import { SecretLintConfigDescriptor } from "@secretlint/types";
/**
 * create config descriptor from rule names
 */
export declare const createConfigDescriptor: ({ ruleNames }: {
    ruleNames: string[];
}) => SecretLintConfigDescriptor;
export type CreateConfigFileOption = {
    packageJSON: any;
};
/**
 * Create Config Object from package.json
 */
export declare const createConfig: (options: CreateConfigFileOption) => SecretLintConfigDescriptor;
//# sourceMappingURL=index.d.ts.map