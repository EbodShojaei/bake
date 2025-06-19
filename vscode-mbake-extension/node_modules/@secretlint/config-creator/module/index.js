/**
 * get package names from package.json
 */
const getSecretLintPackageNames = (packageJSON) => {
    const dependencies = packageJSON.dependencies || {};
    const devDependencies = packageJSON.devDependencies || {};
    const mergedDependencies = {
        ...dependencies,
        ...devDependencies,
    };
    const pkgNames = Object.keys(mergedDependencies);
    return pkgNames.filter((pkgName) => {
        // secretlint-rule- or @scope/secretlint-rule
        return pkgName.startsWith("secretlint-rule-") || pkgName.includes("/secretlint-rule-");
    });
};
/**
 * create config descriptor from rule names
 */
export const createConfigDescriptor = ({ ruleNames }) => {
    return {
        rules: ruleNames.map((name) => {
            return {
                id: name,
            };
        }),
    };
};
/**
 * Create Config Object from package.json
 */
export const createConfig = (options) => {
    const ruleNames = getSecretLintPackageNames(options.packageJSON);
    return createConfigDescriptor({ ruleNames: ruleNames });
};
//# sourceMappingURL=index.js.map