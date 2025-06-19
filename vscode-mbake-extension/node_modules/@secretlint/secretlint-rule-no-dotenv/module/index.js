import path from "node:path";
const FILE_NAME_DOTENV = ".env";
export const messages = {
    FOUND_DOTENV_FILE: {
        en: () => "found .env file",
        ja: () => ".env ファイルがみつかりました",
    },
};
const isDotenvFile = (filePath, options) => {
    const { name, ext } = path.parse(filePath);
    const fileName = `${name}${ext}`;
    if (options.allowFileNames?.includes(fileName)) {
        return false;
    }
    return fileName === FILE_NAME_DOTENV;
};
export const creator = {
    messages,
    meta: {
        id: "@secretlint/secretlint-rule-no-dotenv",
        recommended: true,
        type: "scanner",
        supportedContentTypes: ["text"],
        docs: {
            url: "https://github.com/secretlint/secretlint/blob/master/packages/%40secretlint/secretlint-rule-no-dotenv/README.md",
        },
    },
    create(context, options) {
        const t = context.createTranslator(messages);
        return {
            file(source) {
                if (!source.filePath) {
                    return;
                }
                if (isDotenvFile(source.filePath, options || {})) {
                    context.report({
                        message: t("FOUND_DOTENV_FILE"),
                        range: [0, source.content.length],
                    });
                }
            },
        };
    },
};
//# sourceMappingURL=index.js.map