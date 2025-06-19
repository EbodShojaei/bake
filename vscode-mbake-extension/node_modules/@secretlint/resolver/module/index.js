import { createRequire } from "node:module";
import * as url from "node:url";
import path from "node:path";
import fs from "node:fs";
const require = createRequire(import.meta.url);
const resolveHooks = [];
const importHooks = [];
/**
 * Register Resolver Hook
 * Hook can return resolved URL
 * if hooks pass through, it should return `undefined` instead of object
 * @param hook
 */
export const registerResolveHook = (hook) => {
    resolveHooks.push(hook);
};
/**
 * Try to resolve package name
 * if `packageName` is found, return resolved absolute path.
 * if `packageName` is not found, return `undefined`
 * @param packageName
 * @param context
 */
export const tryResolve = (packageName, context) => {
    try {
        for (const hook of resolveHooks) {
            const result = hook(packageName, context);
            // Skip if hook return undefined from hook
            if (!result) {
                continue;
            }
            if (result?.url) {
                return result.url;
            }
        }
        // TODO: import.meta.resolve is not supported in Node.js 18
        // We will change to import.meta.resolve(packageName)
        return require.resolve(packageName);
    }
    catch {
        return undefined;
    }
};
/**
 * Register Import Hook
 * @param hook
 */
export const registerImportHook = (hook) => {
    importHooks.push(hook);
};
// Windows's path require to convert file://
// https://github.com/secretlint/secretlint/issues/205
const convertToFileUrl = (filePath) => {
    if (filePath.startsWith("file://")) {
        return filePath;
    }
    return url.pathToFileURL(filePath).href;
};
/**
 * dynamic import() with hooks
 * @param specifier file path or package name
 * @param context
 */
export const dynamicImport = async (specifier, context) => {
    for (const hook of importHooks) {
        const result = await hook(specifier, context);
        if (result) {
            return result;
        }
    }
    // if the `specifier` is not absolute path, it should be package name
    if (!path.isAbsolute(specifier)) {
        return {
            exports: await import(specifier),
        };
    }
    return {
        exports: await import(convertToFileUrl(specifier)),
    };
};
/**
 * Clear all hooks
 */
export const clearHooks = () => {
    resolveHooks.length = 0;
    importHooks.length = 0;
};
/**
 * get package.json content from startDir
 * @param cwd
 * @returns package.json content
 */
export const getPackageJson = (cwd) => {
    try {
        const startDir = path.dirname(url.fileURLToPath(cwd));
        const packageJsonPath = findPackageJson(startDir);
        if (packageJsonPath) {
            return require(packageJsonPath);
        }
        return undefined;
    }
    catch (error) {
        // ignore error
        return undefined;
    }
};
/**
 * search package.json from startDir
 * @param startDir
 * @returns
 */
const findPackageJson = (startDir) => {
    let currentDir = startDir;
    while (true) {
        const packageJsonPath = path.join(currentDir, "package.json");
        if (fs.existsSync(packageJsonPath)) {
            return packageJsonPath;
        }
        const parentDir = path.resolve(currentDir, "..");
        if (parentDir === currentDir) {
            return "";
        }
        currentDir = parentDir;
    }
};
//# sourceMappingURL=index.js.map