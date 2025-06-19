/**
 * Default locale that is also fallback locale.
 */
const DEFAULT_LOCAL = "en";
const formatMessage = (messageHandler, props) => {
    if (typeof props !== "object" || props === null) {
        return messageHandler();
    }
    return messageHandler(props);
};
const getMatchedLocaleMessage = (locale, locales) => {
    const localKeys = Object.keys(locales);
    const matchLocale = localKeys.find((key) => {
        return key === locale;
    });
    if (matchLocale) {
        return matchLocale;
    }
    const [lang] = locale.split("-");
    if (!lang) {
        return DEFAULT_LOCAL;
    }
    // en-US => en
    const fallbackMatchLocal = localKeys.find((key) => {
        return key === lang;
    });
    if (fallbackMatchLocal) {
        return fallbackMatchLocal;
    }
    return DEFAULT_LOCAL;
};
export const createTranslator = (messages, options) => {
    return (messageId, props) => {
        const messageHandler = messages[messageId];
        if (!messageHandler) {
            throw new Error(`messages:${String(messageId)} is missing in messages.`);
        }
        // if messages is string, use it.
        if (typeof messageHandler === "function") {
            if (typeof messageId !== "string") {
                throw new Error(`message's key:${String(messageId)} should be string`);
            }
            return {
                message: formatMessage(messageHandler, props),
                messageId: messageId,
                data: props,
            };
        }
        // if messages is object, pick message that is matched locale from messages.
        const defaultLocal = options && options.defaultLocale ? options.defaultLocale : DEFAULT_LOCAL;
        const locale = getMatchedLocaleMessage(defaultLocal, messageHandler);
        const localizedMessage = messageHandler[locale];
        if (!localizedMessage) {
            if (messageHandler[DEFAULT_LOCAL]) {
                throw new Error(`messages${String(messageId)}.${locale} is missing in messages.`);
            }
            throw new Error(`message's key:${String(messageId)}.${DEFAULT_LOCAL} should be defined in messages.`);
        }
        if (typeof messageId !== "string") {
            throw new Error(`message's key:${String(messageId)}.${DEFAULT_LOCAL} should be string`);
        }
        return {
            message: formatMessage(localizedMessage, props),
            messageId: messageId,
            data: props,
        };
    };
};
//# sourceMappingURL=SecretLintRuleMessageTranslator.js.map