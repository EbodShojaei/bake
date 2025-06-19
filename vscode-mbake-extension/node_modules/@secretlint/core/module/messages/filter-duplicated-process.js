/**
 * equal message
 */
const isEqualMessage = (aMessage, bMessage) => {
    return (aMessage.range[0] === bMessage.range[0] &&
        aMessage.range[1] === bMessage.range[1] &&
        "severity" in aMessage &&
        "severity" in bMessage &&
        aMessage.severity === bMessage.severity &&
        aMessage.message === bMessage.message);
};
/**
 * filter duplicated messages
 */
export function filterDuplicatedMessages(messages = []) {
    return messages.filter((message, index) => {
        const restMessages = messages.slice(index + 1);
        return !restMessages.some((restMessage) => {
            return isEqualMessage(message, restMessage);
        });
    });
}
//# sourceMappingURL=filter-duplicated-process.js.map