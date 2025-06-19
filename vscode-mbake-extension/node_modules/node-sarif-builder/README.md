# node-sarif-builder

[![Version](https://img.shields.io/npm/v/node-sarif-builder.svg)](https://npmjs.org/package/node-sarif-builder)
[![Downloads/week](https://img.shields.io/npm/dw/node-sarif-builder.svg)](https://npmjs.org/package/node-sarif-builder)
[![Downloads/total](https://img.shields.io/npm/dt/node-sarif-builder.svg)](https://npmjs.org/package/node-sarif-builder)
[![Test](https://github.com/nvuillam/node-sarif-builder/workflows/Test/badge.svg?branch=main)](https://github.com/nvuillam/node-sarif-builder/actions?query=workflow%3ATest+branch%3Amain)
<!-- [![codecov](https://codecov.io/gh/nvuillam/node-sarif-builder/branch/master/graph/badge.svg)](https://codecov.io/gh/nvuillam/node-sarif-builder) -->
[![Mega-Linter](https://github.com/nvuillam/node-sarif-builder/workflows/MegaLinter/badge.svg?branch=main)](https://megalinter.github.io/)
[![GitHub contributors](https://img.shields.io/github/contributors/nvuillam/node-sarif-builder.svg)](https://github.com/nvuillam/node-sarif-builder/graphs/contributors/)
[![GitHub stars](https://img.shields.io/github/stars/nvuillam/node-sarif-builder?label=stars&maxAge=3600)](https://github.com/nvuillam/node-sarif-builder/stargazers/)
[![License](https://img.shields.io/npm/l/node-sarif-builder.svg)](https://github.com/nvuillam/node-sarif-builder/blob/master/package.json)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)

## Introduction

Until today, every SAST tool (not exhaustive list available at <https://analysis-tools.dev/>) is using its own custom output format.

In order to **unify SAST tools output format**, more and more tools and services are implementing [**SARIF format**](https://sarifweb.azurewebsites.net/) ([example](https://github.com/microsoft/sarif-tutorials/blob/main/samples/1-Introduction/simple-example.sarif))

SARIF logs can be:
- **Uploaded to DevOps tools**, like [Github](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning), [Azure DevOps](https://github.com/microsoft/sarif-azuredevops-extension) to show issues directly in their web UI <!-- markdown-link-check-disable-line -->
- **Visualized in IDEs**, like [Visual Studio Code](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer), [Visual Studio](https://marketplace.visualstudio.com/items?itemName=WDGIS.MicrosoftSarifViewer), [Jetbrains editors](https://plugins.jetbrains.com/plugin/16938-qodana)
- **Aggregated by multi-language linters**, like [MegaLinter](https://oxsecurity.github.io/megalinter/latest/)

Example of linters that can output logs in SARIF format:

- bandit (python)
- checkov (terraform)
- checkstyle (java)
- cfn-lint (AWS CloudFormation)
- codeql (multi-language)
- devskim (security)
- eslint (javascript,typescript,json)
- gitleaks (security)
- ktlint (Kotlin)
- hadolint (Dockerfile)
- MegaLinter (linters orchestrator)
- psalm (php)
- semgrep (multi-language)
- revive (Go)
- tflint (terraform)
- terrascan (terrasform)
- trivy (security)
- and many more...

If you are a **maintainer** of any **javascript/typescript based** SAST tool, but also IaC tool, or **any type of tool that can return a list of errors with a level of severity**, you can either:

- read the whole [OASIS Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html) and implement it
- **simply use this library** to add SARIF as additional output format, so your tool will be natively compliant with any of SARIF-compliant tools !

## Installation

- with npm

```shell
npm install node-sarif-builder
```

- with yarn

```shell
yarn add node-sarif-builder
```

## Use

With node-sarif-builder, you can generate complex SARIF format with simple methods

___

- Start by importing module

```javascript
const { SarifBuilder, SarifRunBuilder, SarifResultBuilder, SarifRuleBuilder } = require("node-sarif-builder");
```

___

- Create and init **SarifBuilder** and **SarifRunBuilder** objects

```javascript
// SARIF builder
const sarifBuilder = new SarifBuilder();
// SARIF Run builder
const sarifRunBuilder = new SarifRunBuilder().initSimple({
    toolDriverName: "npm-groovy-lint",                           // Name of your analyzer tool
    toolDriverVersion: "9.0.5",                                  // Version of your analyzer tool
    url: "https://nvuillam.github.io/npm-groovy-lint/"           // Url of your analyzer tool
});
```

___

- Add all rules that can be found in your results (recommended but optional)

```javascript
// Add SARIF rules
for (const rule of rules) {                           // rules from your linter in any format
    const sarifRuleBuiler = new SarifRuleBuilder().initSimple({
        ruleId: rule.id,                              // ex: "no-any"
        shortDescriptionText: rule.description,       // ex: "Do not use any in your code !"
        helpUri: rule.docUrl                          // ex: "http://my.linter.com/rules/no-any"
    });
    sarifRunBuilder.addRule(sarifRuleBuiler);
}
```

___

- For each found issue, create a SarifResultBuilder and add it to the SarifRunBuilder object

```javascript
// Add results
for (const issue of issues) { // issues from your linter in any format
    const sarifResultBuilder = new SarifResultBuilder();
    const sarifResultInit = {
         // Transcode to a SARIF level:  can be "warning" or "error" or "note"
        level: issue.severity === "info" ? "note" : issue.severity,
        messageText: err.msg,                                     // Ex: "any is forbidden !"
        ruleId: err.rule,                                         // Ex: "no-any"
        fileUri: process.env.SARIF_URI_ABSOLUTE                   // Ex: src/myfile.ts
            ? "file:///" + fileNm.replace(/\\/g, "/")
            : path.relative(process.cwd(), fileNm)
    };
    // When possible, provide location of the issue in the source code
    if (issue.range) {
        sarifResultInit.startLine = issue.range.start.line;        // any integer >= 1 (optional)
        sarifResultInit.startColumn = issue.range.start.character; // any integer >= 1 (optional)
        sarifResultInit.endLine = issue.range.end.line;            // any integer >= 1 (optional)
        sarifResultInit.endColumn = issue.range.end.character;     // any integer >= 1 (optional)
    }
    // Init sarifResultBuilder
    sarifResultBuilder.initSimple(sarifResultInit); 
    // Add result to sarifRunBuilder
    sarifRunBuilder.addResult(sarifResultBuilder);
}
```

___

- Add run to sarifBuilder then generate JSON SARIF output file

```javascript
    sarifBuilder.addRun(sarifRunBuilder);
    const sarifJsonString = sarifBuilder.buildSarifJsonString({ indent: false }); // indent:true if you like
    fs.writeFileSync(outputSarifFile,sarifJsonString);
    // const sarifObj = sarifBuilder.buildSarifOutput();                          // You could also just get the Sarif log as an object and not a string
```

## Full example

- Working in [npm-groovy-lint](https://github.com/nvuillam/npm-groovy-lint)

```javascript
function buildSarifResult(lintResult) {
    // SARIF builder
    const sarifBuilder = new SarifBuilder();
    // SARIF Run builder
    const sarifRunBuilder = new SarifRunBuilder().initSimple({
        toolDriverName: "npm-groovy-lint",
        toolDriverVersion: "9.0.5", 
        url: "https://nvuillam.github.io/npm-groovy-lint/"
    });
    // SARIF rules
    for (const ruleId of Object.keys(lintResult.rules || {})) {
        const rule = lintResult.rules[ruleId];
        const sarifRuleBuiler = new SarifRuleBuilder().initSimple({
            ruleId: ruleId,
            shortDescriptionText: rule.description,
            helpUri: rule.docUrl
        });
        sarifRunBuilder.addRule(sarifRuleBuiler);
    }
    // Add SARIF results (individual errors)
    for (const fileNm of Object.keys(lintResult.files)) {
        const fileErrors = lintResult.files[fileNm].errors;
        for (const err of fileErrors) {
            const sarifResultBuilder = new SarifResultBuilder();
            const sarifResultInit = {
                level: err.severity === "info" ? "note" : err.severity, // Other values can be "warning" or "error"
                messageText: err.msg,
                ruleId: err.rule,
                fileUri: process.env.SARIF_URI_ABSOLUTE
                    ? "file:///" + fileNm.replace(/\\/g, "/")
                    : path.relative(process.cwd(), fileNm)
            };
            if (err.range) {
                sarifResultInit.startLine = fixLine(err.range.start.line);
                sarifResultInit.startColumn = fixCol(err.range.start.character);
                sarifResultInit.endLine = fixLine(err.range.end.line);
                sarifResultInit.endColumn = fixCol(err.range.end.character);
            }
            sarifResultBuilder.initSimple(sarifResultInit);
            sarifRunBuilder.addResult(sarifResultBuilder);
        }
    }
    sarifBuilder.addRun(sarifRunBuilder);
    return sarifBuilder.buildSarifJsonString({ indent: false });
}

function fixLine(val) {
    if (val === null) {
        return undefined;
    }
    return val === 0 ? 1 : val;
}

function fixCol(val) {
    if (val === null) {
        return undefined;
    }
    return val === 0 ? 1 : val + 1;
}
```

## Test

You can confirm that your generated SARIF logs are valid on <https://sarifweb.azurewebsites.net/Validation>
