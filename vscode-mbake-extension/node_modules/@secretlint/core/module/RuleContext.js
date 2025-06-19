import { EventEmitter } from "./helper/promise-event-emitter.js";
import { createTranslator } from "./helper/SecretLintRuleMessageTranslator.js";
export const createContextEvents = () => {
    const contextEvents = new EventEmitter();
    const REPORT_SYMBOL = Symbol("report");
    const IGNORE_SYMBOL = Symbol("ignore");
    return {
        report(descriptor) {
            contextEvents.emit(REPORT_SYMBOL, descriptor);
        },
        onReport(handler) {
            const listener = (descriptor) => {
                handler(descriptor);
            };
            contextEvents.on(REPORT_SYMBOL, listener);
            return () => {
                contextEvents.off(REPORT_SYMBOL, listener);
            };
        },
        ignore(descriptor) {
            contextEvents.emit(IGNORE_SYMBOL, descriptor);
        },
        onIgnore(handler) {
            const listener = (descriptor) => {
                handler(descriptor);
            };
            contextEvents.on(IGNORE_SYMBOL, listener);
            return () => {
                contextEvents.off(IGNORE_SYMBOL, listener);
            };
        },
    };
};
export const createRuleContext = ({ ruleId, ruleParentId, meta, severity, sourceCode, contextEvents, sharedOptions, locale, }) => {
    return {
        sharedOptions: sharedOptions,
        createTranslator: (messages) => {
            return createTranslator(messages, {
                defaultLocale: locale,
            });
        },
        ignore(descriptor) {
            const { message } = descriptor.message;
            contextEvents.ignore({
                type: "ignore",
                ruleId: ruleId,
                ruleParentId,
                range: descriptor.range,
                targetRuleId: descriptor.targetRuleId,
                loc: sourceCode.rangeToLocation(descriptor.range),
                message: message,
            });
        },
        report(descriptor) {
            const { message, messageId, data } = descriptor.message;
            // Default severity level is "error"
            const severityLevel = severity ?? "error";
            if (ruleParentId) {
                contextEvents.report({
                    ...descriptor,
                    type: "message",
                    ruleId: ruleId,
                    ruleParentId,
                    loc: sourceCode.rangeToLocation(descriptor.range),
                    severity: severityLevel,
                    message,
                    messageId,
                    docsUrl: meta.docs?.url ? `${meta.docs.url}#${messageId}` : undefined,
                    data,
                });
            }
            else {
                contextEvents.report({
                    ...descriptor,
                    type: "message",
                    ruleId: ruleId,
                    loc: sourceCode.rangeToLocation(descriptor.range),
                    severity: severityLevel,
                    message,
                    messageId,
                    docsUrl: meta.docs?.url ? `${meta.docs.url}#${messageId}` : undefined,
                    data,
                });
            }
        },
    };
};
//# sourceMappingURL=RuleContext.js.map