/**
 * This class aim to resolve secretlint's package name and get the module path.
 *
 * Define
 *
 * - `package` is npm package
 * - `module` is package's main module
 *
 * ## Support
 *
 * - secretlint-rule-*
 * - secretlint-preset-*
 * - secretlint-plugin-*
 * - secretlint-config-*
 */
export declare class SecretLintModuleResolver {
    private baseDirectory;
    constructor(config: {
        baseDirectory?: string;
    });
    /**
     * Take package name, and return path to module.
     * @param {string} packageName
     * @returns {string} return path to module
     */
    resolveRulePackageName(packageName: string): string;
    /**
     * Take package name, and return path to module.
     * @param {string} packageName
     * @returns {string} return path to module
     */
    resolveFilterRulePackageName(packageName: string): string;
    /**
     * Take package name, and return path to module.
     * @param {string} packageName
     * @returns {string} return path to module
     */
    resolvePluginPackageName(packageName: string): string;
    /**
     * Take package name, and return path to module.
     * @param {string} packageName
     * The user must specify preset- prefix to these `packageName`.
     * @returns {string} return path to module
     */
    resolvePresetPackageName(packageName: string): string;
    /**
     * Take Config package name, and return path to module.
     * @param {string} packageName
     * @returns {string} return path to module
     */
    resolveConfigPackageName(packageName: string): string;
}
//# sourceMappingURL=SecretLintModuleResolver.d.ts.map