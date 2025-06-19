import { StructuredSource } from "structured-source";
import { invariant } from "./helper/invariant.js";
/**
 * This class represent of source code.
 */
export class SecretLintSourceCodeImpl {
    hasBOM;
    content;
    filePath;
    physicalFilePath;
    contentType;
    ext;
    structuredSource;
    constructor({ content = "", ext, filePath, physicalFilePath, contentType, }) {
        invariant(ext || filePath, "should be set either of fileExt or filePath.");
        this.hasBOM = content.charCodeAt(0) === 0xfeff;
        this.content = this.hasBOM ? content.slice(1) : content;
        this.structuredSource = new StructuredSource(this.content);
        this.filePath = filePath;
        this.physicalFilePath = physicalFilePath;
        this.contentType = contentType;
        this.ext = ext;
    }
    /**
     * get file path
     * This return `undefined` if the source code is created without file path.
     * For example, use core API to create a source code directly.
     *
     * You can use this path to detect file type.
     * However, if you want to read the file content, use `getPhysicalFilePath` instead.
     * @returns {string|undefined}
     */
    getFilePath() {
        return this.filePath;
    }
    /**
     * get physical file path
     * This return `undefined` if the source code is not related to file.
     * For example, the source code is given from the stdin.
     *
     * You can use this path to read the file content.
     */
    getPhysicalFilePath() {
        return this.physicalFilePath;
    }
    /**
     * @param {SecretLintSourceNodeLocation} loc - location indicator.
     * @return {[ number, number ]} range.
     */
    locationToRange(loc) {
        return this.structuredSource.locationToRange(loc);
    }
    /**
     * @param {[ number, number ]} range - pair of indice.
     * @return {SecretLintSourceNodeLocation} location.
     */
    rangeToLocation(range) {
        const location = this.structuredSource.rangeToLocation(range);
        // Note: unwrap class instance to get plain object
        return {
            start: {
                line: location.start.line,
                column: location.start.column,
            },
            end: {
                line: location.end.line,
                column: location.end.column,
            },
        };
    }
    /**
     * @param {Position} pos - position indicator.
     * @return {number} index.
     */
    positionToIndex(pos) {
        return this.structuredSource.positionToIndex(pos);
    }
    /**
     * @param {number} index - index to the source code.
     * @return {Position} position.
     */
    indexToPosition(index) {
        const position = this.structuredSource.indexToPosition(index);
        // Note: unwrap class instance to get plain object
        return {
            line: position.line,
            column: position.column,
        };
    }
}
//# sourceMappingURL=SecretLintSourceCodeImpl.js.map