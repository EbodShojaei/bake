import { SecretLintSourceCodeImpl } from "./SecretLintSourceCodeImpl.js";
import { createContextEvents, createRuleContext } from "./RuleContext.js";
import { createRunningEvents } from "./RunningEvents.js";
import { secretLintProfiler } from "@secretlint/profiler";
import { createRulePresetContext } from "./RulePresetContext.js";
import { cleanupMessages } from "./messages/index.js";
import debug0 from "debug";
const debug = debug0("@secretlint/core");
export const lintSource = ({ source, options }) => {
    secretLintProfiler.mark({
        type: "@core>lint::start",
        id: source.filePath,
    });
    debug(`source filePath: %O`, source.filePath);
    debug(`options: %O`, options);
    const rules = options.config.rules;
    const locale = options.locale ?? "en";
    const maskSecrets = options.maskSecrets ?? false;
    const contextEvents = createContextEvents();
    const runningEvents = createRunningEvents();
    const reportedMessages = [];
    const ignoredMessages = [];
    // setup
    contextEvents.onReport((message) => {
        reportedMessages.push(message);
    });
    contextEvents.onIgnore((message) => {
        ignoredMessages.push(message);
    });
    // Create a SourceCode for linting
    const sourceCode = new SecretLintSourceCodeImpl({
        content: source.content,
        filePath: source.filePath,
        physicalFilePath: options.noPhysicFilePath ? undefined : source.filePath,
        ext: source.ext || "",
        contentType: source.contentType,
    });
    secretLintProfiler.mark({
        type: "@core>setup-rules::start",
    });
    rules.forEach((rule) => {
        secretLintProfiler.mark({
            type: "@core>setup-rule::start",
            id: rule.rule.meta.id,
        });
        registerRule({
            sourceCode,
            config: options.config,
            descriptorRule: rule,
            contextEvents,
            runningEvents,
            locale,
        });
        secretLintProfiler.mark({
            type: "@core>setup-rule::end",
            id: rule.rule.meta.id,
        });
    });
    secretLintProfiler.mark({
        type: "@core>setup-rules::end",
    });
    // start to run
    return runningEvents
        .runLint({
        sourceCode,
    })
        .then(() => {
        return {
            filePath: source.filePath,
            // binary content should be skipped
            sourceContent: source.contentType === "text" ? source.content : undefined,
            sourceContentType: source.contentType,
            messages: cleanupMessages({
                reportedMessages,
                ignoredMessages,
                allowMessageIds: runningEvents.collectAllowMessageIds(),
                maskSecrets,
            }),
        };
    })
        .finally(() => {
        secretLintProfiler.mark({
            type: "@core>lint::end",
            id: source.filePath,
        });
    });
};
const isRulePreset = (ruleDescriptor) => {
    return ruleDescriptor.rule.meta.type === "preset";
};
const isRule = (ruleDescriptor) => {
    return ruleDescriptor.rule.meta.type === "scanner";
};
/**
 * Rule Processing
 */
const registerRule = ({ sourceCode, config, descriptorRule, contextEvents, runningEvents, locale, }) => {
    const ruleId = descriptorRule.id;
    // Do not register disabled rule
    if (descriptorRule.disabled) {
        debug("Skip registerRule %s, because it is disabled", ruleId);
        return;
    }
    debug("registerRule %s", ruleId);
    // sharedOptions is {} by default
    // sharedOptions is shared between presets and rules
    const sharedOptionsWithDefault = config.sharedOptions ?? {};
    // If option is not defined Options is {} by default
    if (isRulePreset(descriptorRule)) {
        const context = createRulePresetContext({
            configRulePreset: descriptorRule,
            sourceCode,
            contextEvents: contextEvents,
            runningEvents: runningEvents,
            sharedOptions: sharedOptionsWithDefault,
            locale: locale,
        });
        runningEvents.registerRulePreset({
            descriptorRulePreset: descriptorRule,
            context,
        });
        return;
    }
    else if (isRule(descriptorRule)) {
        const context = createRuleContext({
            ruleId: ruleId,
            severity: descriptorRule.severity,
            meta: descriptorRule.rule.meta,
            sourceCode,
            contextEvents: contextEvents,
            sharedOptions: sharedOptionsWithDefault,
            locale: locale,
        });
        runningEvents.registerRule({
            descriptorRule: descriptorRule,
            context,
        });
        return;
    }
    throw new Error(`Unknown descriptor type: ${descriptorRule}`);
};
//# sourceMappingURL=index.js.map