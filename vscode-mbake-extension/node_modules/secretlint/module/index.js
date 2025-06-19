import fs from "node:fs";
import { createEngine } from "@secretlint/node";
import { searchFiles } from "./search.js";
const lintFileOrText = async ({ cliOptions, engineOptions, }) => {
    const engine = await createEngine(engineOptions);
    if ("filePathOrGlobList" in cliOptions) {
        const { ok, items } = await searchFiles(cliOptions.filePathOrGlobList, {
            cwd: cliOptions.cwd,
            ignoreFilePath: cliOptions.ignoreFilePath,
        });
        if (!ok) {
            throw new Error("Not found target files");
        }
        return engine.executeOnFiles({
            filePathList: items,
        });
    }
    else if ("stdinFileName" in cliOptions) {
        return engine.executeOnContent({
            content: cliOptions.stdinContent,
            filePath: cliOptions.stdinFileName,
        });
    }
    throw new Error("Unexpected cliOptions", {
        cause: {
            cliOptions: cliOptions,
        },
    });
};
export const runSecretLint = async ({ cliOptions, engineOptions, }) => {
    const { ok, output } = await lintFileOrText({
        cliOptions,
        engineOptions,
    });
    // TODO: if has error, this should be stderr
    const outputFilePath = cliOptions.outputFilePath;
    if (outputFilePath !== undefined) {
        fs.writeFileSync(outputFilePath, output, "utf-8");
        // Return empty to console with exit code 0
        // because output is success
        return {
            exitStatus: 0,
            stdout: null,
            stderr: null,
        };
    }
    return {
        exitStatus: ok ? 0 : 1,
        stdout: output,
        stderr: null,
    };
};
//# sourceMappingURL=index.js.map