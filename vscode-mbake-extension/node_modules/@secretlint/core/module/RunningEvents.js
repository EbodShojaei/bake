import { PromiseEventEmitter } from "./helper/promise-event-emitter.js";
import { SecretLintRule } from "./SecretLintRuleImpl.js";
import { secretLintProfiler } from "@secretlint/profiler";
export const createRunningEvents = () => {
    const contextEvents = new PromiseEventEmitter();
    const registerSet = new Set();
    const LINT_HANDLE = Symbol("lint:start");
    const rules = [];
    return {
        collectAllowMessageIds() {
            const allowMessageIds = [];
            rules.forEach((rule) => {
                allowMessageIds.push(...rule.allowMessageIds());
            });
            return allowMessageIds;
        },
        /**
         * Start to run linting
         * @param options
         */
        runLint(options) {
            return contextEvents.emit(LINT_HANDLE, options);
        },
        registerRule({ descriptorRule, context, }) {
            if (registerSet.has(descriptorRule.id)) {
                // TODO: more trivial implementation
                throw new Error(`rule.id:${descriptorRule.id} is already registered.
                
Duplicated rule.id is something wrong in .secretlintrc.                
`);
            }
            registerSet.add(descriptorRule.id);
            const rule = new SecretLintRule({
                descriptorRule: descriptorRule,
                context,
            });
            rules.push(rule);
            contextEvents.on(LINT_HANDLE, async ({ sourceCode }) => {
                // TODO: add more handler
                // Call O￿￿rder?
                // - file
                secretLintProfiler.mark({
                    type: "@core>rule-handler::start",
                    id: descriptorRule.rule.meta.id,
                });
                // if this rule support the content type
                if (rule.supportSourceCode(sourceCode)) {
                    await rule.file(sourceCode);
                }
                secretLintProfiler.mark({
                    type: "@core>rule-handler::end",
                    id: descriptorRule.rule.meta.id,
                });
            });
        },
        registerRulePreset({ descriptorRulePreset, context, }) {
            // Normalized Rule Preset Options
            const rulePresetCreatorOptions = descriptorRulePreset.options || [];
            // Internally, RulePreset#register call `registerRule`
            descriptorRulePreset.rule.create(context, rulePresetCreatorOptions);
        },
        isRegistered(ruleId) {
            return registerSet.has(ruleId);
        },
    };
};
//# sourceMappingURL=RunningEvents.js.map