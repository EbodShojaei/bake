import { lintSource } from "@secretlint/core";
import { loadConfig, loadPackagesFromConfigDescriptor } from "@secretlint/config-loader";
import { createRawSource } from "@secretlint/source-creator";
import { loadFormatter } from "@secretlint/formatter";
import os from "node:os";
import path from "node:path";
import { secretLintProfiler } from "@secretlint/profiler";
import pMap from "p-map";
import debug0 from "debug";
const debug = debug0("@secretlint/node");
const isConfigFileJSON = (v) => {
    return "configFileJSON" in v && v.configFileJSON !== undefined;
};
const lintFile = async ({ filePath, config, options, }) => {
    const rawSource = await createRawSource(filePath);
    return lintSource({
        source: rawSource,
        options: {
            ...options,
            config: config,
        },
    });
};
const hasErrorMessage = (result) => {
    return result.messages.length > 0;
};
const executeOnContent = async ({ content, filePath, config, options, }) => {
    debug("executeOnContent content: %s", `${content.slice(0, 24)}...`);
    debug("executeOnContent filePath: %s", filePath);
    const result = await lintSource({
        source: {
            filePath: filePath,
            content: content,
            ext: path.extname(filePath),
            contentType: "text",
        },
        options: {
            ...options,
            config,
        },
    });
    debug("executeOnContent result: %o", result);
    secretLintProfiler.mark({
        type: "@node>format::start",
    });
    const formatter = await loadFormatter({
        color: options.color ?? true,
        formatterName: options.formatter,
        terminalLink: options.terminalLink ?? false,
    });
    const output = formatter.format([result]);
    secretLintProfiler.mark({
        type: "@node>format::end",
    });
    return {
        ok: !hasErrorMessage(result),
        output: output,
    };
};
const executeOnFiles = async ({ filePathList, config, options, }) => {
    const mapper = async (filePath) => {
        debug("executeOnFiles file: %s", filePath);
        const result = await lintFile({ filePath: filePath, config: config, options: options });
        debug("executeOnFiles result: %o", result);
        return result;
    };
    const results = await pMap(filePathList, mapper, {
        // Avoid: EMFILE: too many open files, uv_cwd
        // https://github.com/secretlint/secretlint/issues/72
        concurrency: os.cpus().length,
    });
    debug("executeOnFiles result counts: %s", results.length);
    secretLintProfiler.mark({
        type: "@node>format::start",
    });
    const formatter = await loadFormatter({
        color: options.color ?? true,
        formatterName: options.formatter,
        terminalLink: options.terminalLink ?? false,
    });
    const output = formatter.format(results);
    secretLintProfiler.mark({
        type: "@node>format::end",
    });
    const hasErrorAtLeastOne = results.some((result) => {
        return hasErrorMessage(result);
    });
    return {
        ok: !hasErrorAtLeastOne,
        output: output,
    };
};
/**
 * Create SecretLint Engine and return the instance.
 * The engine load config file(.secretlintrc) automatically
 * @param options
 */
export const createEngine = async (options) => {
    secretLintProfiler.mark({
        type: "@node>load-config::start",
    });
    const loadedResult = await (async () => {
        if (isConfigFileJSON(options)) {
            debug("Load ConfigFileJSON: %s", options.configFileJSON);
            return loadPackagesFromConfigDescriptor({
                configDescriptor: options.configFileJSON,
            });
        }
        const loadConfigResult = await loadConfig({
            cwd: options.cwd,
            configFilePath: options.configFilePath,
        });
        debug("Loaded ConfigFilePath: %s", loadConfigResult.configFilePath);
        return loadConfigResult;
    })();
    secretLintProfiler.mark({
        type: "@node>load-config::end",
    });
    if (!loadedResult.ok) {
        throw new Error("Fail to load secretlint config");
    }
    debug("Config: %O", loadedResult.config);
    return {
        /**
         * Lint a content and return the formatted results
         * @param content
         * @param filePath
         */
        executeOnContent: ({ content, filePath }) => {
            debug("executeOnContent content: %s", content);
            debug("executeOnContent filePath: %s", filePath);
            secretLintProfiler.mark({
                type: "@node>execute::start",
            });
            return executeOnContent({
                content,
                filePath,
                config: loadedResult.config,
                options: options,
            }).finally(() => {
                secretLintProfiler.mark({
                    type: "@node>execute::end",
                });
            });
        },
        /**
         * Lint files and return the formatted results
         * @param filePathList
         */
        executeOnFiles: ({ filePathList }) => {
            debug("executeOnFiles file counts: %s", filePathList.length);
            secretLintProfiler.mark({
                type: "@node>execute::start",
            });
            return executeOnFiles({
                filePathList,
                config: loadedResult.config,
                options: options,
            }).finally(() => {
                secretLintProfiler.mark({
                    type: "@node>execute::end",
                });
            });
        },
    };
};
//# sourceMappingURL=index.js.map