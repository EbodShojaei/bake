"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.prettyPrintLintResult = exports.getRuleNameFromRuleId = exports.lintText = exports.lintFiles = void 0;
const chalk_1 = __importDefault(require("chalk"));
const secret_lint_types_1 = require("./typings/secret-lint-types");
const util_1 = require("./util");
const secretsScanningRules = [
    {
        id: "@secretlint/secretlint-rule-preset-recommend",
        rules: [
            {
                id: "@secretlint/secretlint-rule-basicauth",
                allowMessageIds: ["BasicAuth"]
            },
            {
                id: "@secretlint/secretlint-rule-privatekey",
                options: {
                    allows: [
                        // Allow all keys which do not start and end with the BEGIN/END PRIVATE KEY and has at least 50 characters in between
                        // https://github.com/microsoft/vscode-vsce/issues/1147
                        "/^(?![\\s\\S]*-----BEGIN .*PRIVATE KEY-----[A-Za-z0-9+/=\\r\\n]{50,}-----END .*PRIVATE KEY-----)[\\s\\S]*$/"
                    ]
                }
            }, {
                id: "@secretlint/secretlint-rule-npm",
                options: {
                    allows: [
                        // An npm token has the prefix npm_ followed by 36 Base62 characters (30 random + 6-character checksum), totaling 40 characters.
                        // https://github.com/microsoft/vscode-vsce/issues/1153
                        "/^(?!(?:npm_[0-9A-Za-z]{36})$).+$/"
                    ]
                }
            }
        ]
    }
];
const dotEnvRules = [
    {
        id: "@secretlint/secretlint-rule-no-dotenv"
    }
];
// Helper function to dynamically import the createEngine function
async function getEngine(scanSecrets, scanDotEnv) {
    // Use a raw dynamic import that will not be transformed
    // This is necessary because @secretlint/node is an ESM module
    const secretlintModule = await eval('import("@secretlint/node")');
    const rules = [];
    if (scanSecrets) {
        rules.push(...secretsScanningRules);
    }
    if (scanDotEnv) {
        rules.push(...dotEnvRules);
    }
    const lintOptions = {
        configFileJSON: { rules: rules },
        formatter: "@secretlint/secretlint-formatter-sarif",
        color: true,
        maskSecrets: false
    };
    const engine = await secretlintModule.createEngine(lintOptions);
    return engine;
}
async function lintFiles(filePaths, scanSecrets, scanDotEnv) {
    const engine = await getEngine(scanSecrets, scanDotEnv);
    let engineResult;
    try {
        engineResult = await engine.executeOnFiles({
            filePathList: filePaths
        });
    }
    catch (error) {
        util_1.log.error('Error occurred while scanning secrets (files):', error);
        process.exit(1);
    }
    return parseResult(engineResult);
}
exports.lintFiles = lintFiles;
async function lintText(content, fileName, scanSecrets, scanDotEnv) {
    const engine = await getEngine(scanSecrets, scanDotEnv);
    let engineResult;
    try {
        engineResult = await engine.executeOnContent({
            content,
            filePath: fileName
        });
    }
    catch (error) {
        util_1.log.error('Error occurred while scanning secrets (content):', error);
        process.exit(1);
    }
    return parseResult(engineResult);
}
exports.lintText = lintText;
function parseResult(result) {
    const output = secret_lint_types_1.Convert.toSecretLintOutput(result.output);
    const results = output.runs.at(0)?.results ?? [];
    return { ok: result.ok, results };
}
function getRuleNameFromRuleId(ruleId) {
    const parts = ruleId.split('-rule-');
    return parts[parts.length - 1];
}
exports.getRuleNameFromRuleId = getRuleNameFromRuleId;
function prettyPrintLintResult(result) {
    if (!result.message.text) {
        return JSON.stringify(result);
    }
    const text = result.message.text;
    const titleColor = result.level === undefined || result.level === secret_lint_types_1.Level.Error ? chalk_1.default.bold.red : chalk_1.default.bold.yellow;
    const title = text.length > 54 ? text.slice(0, 50) + '...' : text;
    const ruleName = result.ruleId ? getRuleNameFromRuleId(result.ruleId) : 'unknown';
    let output = `\t${titleColor(title)} [${ruleName}]\n`;
    if (result.locations) {
        result.locations.forEach(location => {
            output += `\t${prettyPrintLocation(location)}\n`;
        });
    }
    return output;
}
exports.prettyPrintLintResult = prettyPrintLintResult;
function prettyPrintLocation(location) {
    if (!location.physicalLocation) {
        return JSON.stringify(location);
    }
    const uri = location.physicalLocation.artifactLocation?.uri;
    if (!uri) {
        return JSON.stringify(location);
    }
    let output = uri;
    const region = location.physicalLocation.region;
    const regionStringified = region ? prettyPrintRegion(region) : undefined;
    if (regionStringified) {
        output += `#${regionStringified}`;
    }
    return output;
}
function prettyPrintRegion(region) {
    const startPosition = prettyPrintPosition(region.startLine, region.startColumn);
    const endPosition = prettyPrintPosition(region.endLine, region.endColumn);
    if (!startPosition) {
        return undefined;
    }
    let output = startPosition;
    if (endPosition && startPosition !== endPosition) {
        output += `-${endPosition}`;
    }
    return output;
}
function prettyPrintPosition(line, column) {
    if (line === undefined) {
        return undefined;
    }
    let output = line.toString();
    if (column !== undefined) {
        output += `:${column}`;
    }
    return output;
}
//# sourceMappingURL=secretLint.js.map