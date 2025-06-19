import { AggregationError } from "./AggregationError.js";
import { validateSecretLintConfigDescriptor_, validateSecretLintConfigDescriptorRule_, validateSecretLintConfigDescriptorRulePreset_, } from "./descriptor-types.validator.js";
function invariant(condition, message) {
    if (condition) {
        return;
    }
    throw new Error(message);
}
const isPreset = (value) => {
    return "rules" in value; // TODO: it is loose detection
};
/**
 * value should be SecretLintCoreConfig
 * @param configDescriptor
 */
export const validateConfigDescriptor = (configDescriptor) => {
    const errors = [];
    if (!Array.isArray(configDescriptor.rules)) {
        return {
            ok: false,
            error: new Error(`secretlintrc should have required 'rules' property.
            
{
    "rules": [
        {
            "id": "secretlint-rule-example"
        }
    ]
}
`),
        };
    }
    // Validate Descriptor
    try {
        validateSecretLintConfigDescriptor_(configDescriptor);
    }
    catch (error) {
        // SecretLintConfigDescriptor -> secretlintrc
        const errorMessage = error instanceof Error
            ? error.message.replace(/SecretLintConfigDescriptor_/g, "secretlintrc")
            : String(error);
        errors.push(new Error(errorMessage));
    }
    for (const ruleOrPreset of configDescriptor.rules) {
        // validate as preset
        // TODO: This condition can not detect preset if `{ id: "preset" }` only pattern
        if (isPreset(ruleOrPreset)) {
            const rulePreset = ruleOrPreset;
            try {
                validateSecretLintConfigDescriptorRulePreset_(rulePreset);
            }
            catch (error) {
                const errorMessage = error instanceof Error
                    ? error.message.replace(/SecretLintConfigDescriptorRulePreset_/g, ruleOrPreset.id)
                    : String(error);
                errors.push(new Error(errorMessage));
            }
            if ("allowMessageIds" in ruleOrPreset) {
                errors.push(new Error(`Can not set "allowMessageIds" option to preset(${rulePreset.id}) `));
            }
            if ("severity" in ruleOrPreset) {
                errors.push(new Error(`Can not set "severity" option to preset(${rulePreset.id})`));
            }
        }
        else {
            const rule = ruleOrPreset;
            try {
                validateSecretLintConfigDescriptorRule_(rule);
            }
            catch (error) {
                const errorMessage = error instanceof Error
                    ? error.message.replace(/SecretLintConfigDescriptorRule_/g, ruleOrPreset.id)
                    : String(error);
                errors.push(new Error(errorMessage));
            }
        }
    }
    return {
        ok: errors.length === 0,
        error: new AggregationError(errors, "Secretlint Configuration Error"),
    };
};
/**
 * validate config after loading config.
 * It is additional check
 * please pass validateRawConfig before it.
 * @param value
 */
export const validateConfigWithDescriptor = ({ config, }) => {
    const errors = [];
    // Descriptor check using loaded config
    // Rule Check
    for (const ruleOrPreset of config.rules) {
        if (isPreset(ruleOrPreset)) {
            // Validate preset
            const preset = ruleOrPreset;
            const ruleConfigs = preset?.rules ?? [];
            invariant(Array.isArray(preset.rule.rules), "preset should have `rules` property");
            invariant(typeof preset.rule.meta === "object", "preset should have `meta` property");
            invariant(typeof preset.rule.create === "function", "preset should have `create` function");
            // ## Detect unknown id - the preset does not have the id
            const actualRuleIdsForPreset = preset.rule.rules.map((rule) => rule.meta.id);
            ruleConfigs?.forEach((ruleCreatorOption) => {
                const existRule = actualRuleIdsForPreset.includes(ruleCreatorOption.id);
                if (!existRule) {
                    errors.push(new Error(`Does not exist id: "${ruleCreatorOption.id}" in the preset(${preset.id}).

Following config is invalid because the preset(${preset.id}) does not have id: "${ruleCreatorOption.id}".

${JSON.stringify(ruleCreatorOption)}
`));
                }
            });
        }
        else {
            // Validate rule
            const rule = ruleOrPreset;
            invariant(typeof rule.rule.meta === "object", "rule should have `meta` property");
            invariant(typeof rule.rule.create === "function", "rule should have `create` function");
            // `allowMessageIds` validation
            if (Array.isArray(rule.allowMessageIds)) {
                const messageIds = Object.keys(rule.rule.messages);
                rule.allowMessageIds.forEach((allowMessageId) => {
                    if (!messageIds.includes(allowMessageId)) {
                        errors.push(new Error(`Doe not found allowMessageIds: ${allowMessageId} in the rule(${rule.id})

Following config is invalid because the rule(${rule.id}) does not have messageId: "${allowMessageId}".

${JSON.stringify({ allowMessageIds: rule.allowMessageIds })}
`));
                    }
                });
            }
        }
    }
    return {
        ok: errors.length === 0,
        error: new AggregationError(errors, "Secretlint Configuration Error"),
    };
};
//# sourceMappingURL=validator.js.map