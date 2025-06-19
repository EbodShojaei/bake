export const filterByAllowMessageIds = (messages, allowMessageIds) => {
    const disabledSet = new Set(allowMessageIds.map((allowMessage) => {
        return `${allowMessage.ruleId}--${allowMessage.messageId}`;
    }));
    return messages.filter((message) => {
        return !disabledSet.has(`${message.ruleId}--${message.messageId}`);
    });
};
//# sourceMappingURL=filter-message-id.js.map