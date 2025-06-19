export const createMessageProcessor = (processors) => {
    return {
        /**
         * process `messages` with registered processes
         */
        process(messages) {
            const originalMessages = messages;
            if (processors.length === 0) {
                throw new Error("processors should be > 0");
            }
            return processors.reduce((messages, filter) => {
                return filter(messages);
            }, originalMessages);
        },
    };
};
//# sourceMappingURL=MessageProcessManager.js.map