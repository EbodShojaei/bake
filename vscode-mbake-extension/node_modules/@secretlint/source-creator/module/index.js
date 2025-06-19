import fs from "node:fs/promises";
import path from "node:path";
import { isBinary, isText } from "istextorbinary";
const detectContentType = (filePath, content) => {
    if (isBinary(filePath, content)) {
        return "binary";
    }
    else if (isText(filePath, content)) {
        return "text";
    }
    else {
        return "unknown";
    }
};
export const createRawSource = async (filePath) => {
    const content = await fs.readFile(filePath);
    const contentType = detectContentType(filePath, content);
    return {
        filePath,
        content: content.toString(),
        ext: path.extname(filePath),
        contentType,
    };
};
//# sourceMappingURL=index.js.map