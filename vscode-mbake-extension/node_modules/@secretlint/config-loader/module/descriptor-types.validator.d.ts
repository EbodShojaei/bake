import * as apiTypes from './descriptor-types.js';
export declare const SCHEMA: {
    $schema: string;
    definitions: {
        SecretLintConfigDescriptor_: {
            $ref: string;
        };
        SecretLintConfigDescriptor: {
            type: string;
            properties: {
                sharedOptions: {
                    $ref: string;
                };
                rules: {
                    type: string;
                    items: {
                        anyOf: {
                            $ref: string;
                        }[];
                    };
                };
            };
            required: string[];
            description: string;
        };
        SecretlintCoreSharedOptions: {
            type: string;
            description: string;
        };
        SecretLintConfigDescriptorRule: {
            type: string;
            properties: {
                id: {
                    type: string;
                    description: string;
                };
                options: {
                    $ref: string;
                    description: string;
                };
                disabled: {
                    type: string;
                    description: string;
                };
                allowMessageIds: {
                    type: string;
                    items: {
                        type: string;
                    };
                    description: string;
                };
                severity: {
                    $ref: string;
                    description: string;
                };
            };
            required: string[];
        };
        SecretLintRuleCreatorOptions: {
            type: string;
        };
        SecretLintRuleSeverityLevel: {
            type: string;
            enum: string[];
            description: string;
        };
        SecretLintConfigDescriptorRulePreset: {
            type: string;
            properties: {
                id: {
                    type: string;
                    description: string;
                };
                options: {
                    $ref: string;
                    description: string;
                };
                disabled: {
                    type: string;
                    description: string;
                };
                rules: {
                    type: string;
                    items: {
                        $ref: string;
                    };
                    description: string;
                };
            };
            required: string[];
        };
        SecretLintRulePresetCreatorOptions: {
            type: string;
        };
        SecretLintConfigDescriptorRule_: {
            $ref: string;
        };
        SecretLintConfigDescriptorRulePreset_: {
            $ref: string;
        };
    };
};
export declare function validateSecretLintConfigDescriptor_(payload: unknown): apiTypes.SecretLintConfigDescriptor_;
export declare function isSecretLintConfigDescriptor_(payload: unknown): payload is apiTypes.SecretLintConfigDescriptor_;
export declare function validateSecretLintConfigDescriptorRule_(payload: unknown): apiTypes.SecretLintConfigDescriptorRule_;
export declare function isSecretLintConfigDescriptorRule_(payload: unknown): payload is apiTypes.SecretLintConfigDescriptorRule_;
export declare function validateSecretLintConfigDescriptorRulePreset_(payload: unknown): apiTypes.SecretLintConfigDescriptorRulePreset_;
export declare function isSecretLintConfigDescriptorRulePreset_(payload: unknown): payload is apiTypes.SecretLintConfigDescriptorRulePreset_;
//# sourceMappingURL=descriptor-types.validator.d.ts.map