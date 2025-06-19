/**
 * the `index` is in the `range` and return true.
 * @param {Number} index
 * @param {Number[]} range
 * @returns {boolean}
 */
const isContainedRange = (index, range) => {
    const [start, end] = range;
    return start <= index && index <= end;
};
/**
 * filter messages by ignore messages
 */
export function filterIgnoredMessages(options) {
    const reportedMessages = options.reportedMessages;
    const ignoreMessages = options.ignoredMessages;
    // if match, reject the message
    return reportedMessages.filter((message) => {
        return !ignoreMessages.some((ignoreMessage) => {
            const isInIgnoringRange = isContainedRange(message.range[0], ignoreMessage.range) &&
                isContainedRange(message.range[1], ignoreMessage.range);
            if (isInIgnoringRange && ignoreMessage.targetRuleId) {
                // "*" is wildcard that match any rule
                if (ignoreMessage.targetRuleId === "*") {
                    return true;
                }
                // compare normalized key path
                return message.ruleId === ignoreMessage.targetRuleId;
            }
            return isInIgnoringRange;
        });
    });
}
//# sourceMappingURL=filter-ignored-process.js.map