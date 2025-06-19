import { createRuleContext } from "./RuleContext.js";
/**
 * Create a context for Rule Preset
 */
export const createRulePresetContext = ({ configRulePreset, sourceCode, runningEvents, contextEvents, sharedOptions, locale, }) => {
    const presetRules = configRulePreset.rules || [];
    if (!Array.isArray(presetRules)) {
        console.error(`${configRulePreset.id}:PresetRules is invalid format`, presetRules);
        throw new Error("preset's rules should be an array of rule definitions");
    }
    return {
        sharedOptions,
        registerRule(rule, defaultValue) {
            const descriptorRule = presetRules.find((descriptorRule) => {
                return descriptorRule.id === rule.meta.id;
            });
            // Use undefined instead of {}
            // Default value will be handled by RunningEvents#registerRule
            const descriptorRuleOptions = descriptorRule ? descriptorRule.options : undefined;
            const descriptorRuleDisabled = descriptorRule ? descriptorRule.disabled : undefined;
            const descriptorRuleSeverity = descriptorRule ? descriptorRule.severity : undefined;
            const descriptorAllowMessageIds = descriptorRule ? descriptorRule.allowMessageIds : undefined;
            const context = createRuleContext({
                // rule id is a single rule in a preset
                ruleId: rule.meta.id,
                // parent rule id is rule preset id
                ruleParentId: configRulePreset.id,
                meta: rule.meta,
                severity: descriptorRuleSeverity,
                sourceCode,
                contextEvents: contextEvents,
                sharedOptions: sharedOptions,
                locale,
            });
            const defaultValueOfPreset = defaultValue ? defaultValue : {};
            runningEvents.registerRule({
                descriptorRule: {
                    // options and disabled ...
                    ...defaultValueOfPreset,
                    // Prefer to use user setting
                    // User can override preset setting
                    ...descriptorRule,
                    id: rule.meta.id,
                    options: descriptorRuleOptions,
                    rule,
                    disabled: descriptorRuleDisabled,
                    allowMessageIds: descriptorAllowMessageIds,
                    severity: descriptorRuleSeverity,
                },
                context,
            });
        },
    };
};
//# sourceMappingURL=RulePresetContext.js.map