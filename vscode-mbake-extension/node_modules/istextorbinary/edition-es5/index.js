"use strict";
/* eslint no-use-before-define:0 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __values = (this && this.__values) || function(o) {
    var s = typeof Symbol === "function" && Symbol.iterator, m = s && o[s], i = 0;
    if (m) return m.call(o);
    if (o && typeof o.length === "number") return {
        next: function () {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
    throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getEncoding = exports.isBinary = exports.isText = void 0;
var pathUtil = __importStar(require("path"));
var textextensions_1 = __importDefault(require("textextensions"));
var binaryextensions_1 = __importDefault(require("binaryextensions"));
/**
 * Determine if the filename and/or buffer is text.
 * Determined by extension checks first (if filename is available), otherwise if unknown extension or no filename, will perform a slower buffer encoding detection.
 * This order is done, as extension checks are quicker, and also because encoding checks cannot guarantee accuracy for chars between utf8 and utf16.
 * The extension checks are performed using the resources https://github.com/bevry/textextensions and https://github.com/bevry/binaryextensions
 * @param filename The filename for the file/buffer if available
 * @param buffer The buffer for the file if available
 * @returns Will be `null` if neither `filename` nor `buffer` were provided. Otherwise will be a boolean value with the detection result.
 */
function isText(filename, buffer) {
    var e_1, _a;
    // Test extensions
    if (filename) {
        // Extract filename
        var parts = pathUtil.basename(filename).split('.').reverse();
        try {
            // Cycle extensions
            for (var parts_1 = __values(parts), parts_1_1 = parts_1.next(); !parts_1_1.done; parts_1_1 = parts_1.next()) {
                var extension = parts_1_1.value;
                if (textextensions_1.default.indexOf(extension) !== -1) {
                    return true;
                }
                if (binaryextensions_1.default.indexOf(extension) !== -1) {
                    return false;
                }
            }
        }
        catch (e_1_1) { e_1 = { error: e_1_1 }; }
        finally {
            try {
                if (parts_1_1 && !parts_1_1.done && (_a = parts_1.return)) _a.call(parts_1);
            }
            finally { if (e_1) throw e_1.error; }
        }
    }
    // Fallback to encoding if extension check was not enough
    if (buffer) {
        return getEncoding(buffer) === 'utf8';
    }
    // No buffer was provided
    return null;
}
exports.isText = isText;
/**
 * Determine if the filename and/or buffer is binary.
 * Determined by extension checks first (if filename is available), otherwise if unknown extension or no filename, will perform a slower buffer encoding detection.
 * This order is done, as extension checks are quicker, and also because encoding checks cannot guarantee accuracy for chars between utf8 and utf16.
 * The extension checks are performed using the resources https://github.com/bevry/textextensions and https://github.com/bevry/binaryextensions
 * @param filename The filename for the file/buffer if available
 * @param buffer The buffer for the file if available
 * @returns Will be `null` if neither `filename` nor `buffer` were provided. Otherwise will be a boolean value with the detection result.
 */
function isBinary(filename, buffer) {
    var text = isText(filename, buffer);
    if (text == null)
        return null;
    return !text;
}
exports.isBinary = isBinary;
/**
 * Get the encoding of a buffer.
 * Checks the start, middle, and end of the buffer for characters that are unrecognized within UTF8 encoding.
 * History has shown that inspection at all three locations is necessary.
 * @returns Will be `null` if `buffer` was not provided. Otherwise will be either `'utf8'` or `'binary'`
 */
function getEncoding(buffer, opts) {
    var _a, _b;
    // Check
    if (!buffer)
        return null;
    // Prepare
    var textEncoding = 'utf8';
    var binaryEncoding = 'binary';
    var chunkLength = (_a = opts === null || opts === void 0 ? void 0 : opts.chunkLength) !== null && _a !== void 0 ? _a : 24;
    var chunkBegin = (_b = opts === null || opts === void 0 ? void 0 : opts.chunkBegin) !== null && _b !== void 0 ? _b : 0;
    // Discover
    if ((opts === null || opts === void 0 ? void 0 : opts.chunkBegin) == null) {
        // Start
        var encoding = getEncoding(buffer, { chunkLength: chunkLength, chunkBegin: chunkBegin });
        if (encoding === textEncoding) {
            // Middle
            chunkBegin = Math.max(0, Math.floor(buffer.length / 2) - chunkLength);
            encoding = getEncoding(buffer, {
                chunkLength: chunkLength,
                chunkBegin: chunkBegin,
            });
            if (encoding === textEncoding) {
                // End
                chunkBegin = Math.max(0, buffer.length - chunkLength);
                encoding = getEncoding(buffer, {
                    chunkLength: chunkLength,
                    chunkBegin: chunkBegin,
                });
            }
        }
        // Return
        return encoding;
    }
    else {
        // Extract
        chunkBegin = getChunkBegin(buffer, chunkBegin);
        if (chunkBegin === -1) {
            return binaryEncoding;
        }
        var chunkEnd = getChunkEnd(buffer, Math.min(buffer.length, chunkBegin + chunkLength));
        if (chunkEnd > buffer.length) {
            return binaryEncoding;
        }
        var contentChunkUTF8 = buffer.toString(textEncoding, chunkBegin, chunkEnd);
        // Detect encoding
        for (var i = 0; i < contentChunkUTF8.length; ++i) {
            var charCode = contentChunkUTF8.charCodeAt(i);
            if (charCode === 65533 || charCode <= 8) {
                // 8 and below are control characters (e.g. backspace, null, eof, etc.)
                // 65533 is the unknown character
                // console.log(charCode, contentChunkUTF8[i])
                return binaryEncoding;
            }
        }
        // Return
        return textEncoding;
    }
}
exports.getEncoding = getEncoding;
// ====================================
// The functions below are created to handle multibyte utf8 characters.
// To understand how the encoding works, check this article: https://en.wikipedia.org/wiki/UTF-8#Encoding
// @todo add documentation for these
function getChunkBegin(buf, chunkBegin) {
    // If it's the beginning, just return.
    if (chunkBegin === 0) {
        return 0;
    }
    if (!isLaterByteOfUtf8(buf[chunkBegin])) {
        return chunkBegin;
    }
    var begin = chunkBegin - 3;
    if (begin >= 0) {
        if (isFirstByteOf4ByteChar(buf[begin])) {
            return begin;
        }
    }
    begin = chunkBegin - 2;
    if (begin >= 0) {
        if (isFirstByteOf4ByteChar(buf[begin]) ||
            isFirstByteOf3ByteChar(buf[begin])) {
            return begin;
        }
    }
    begin = chunkBegin - 1;
    if (begin >= 0) {
        // Is it a 4-byte, 3-byte utf8 character?
        if (isFirstByteOf4ByteChar(buf[begin]) ||
            isFirstByteOf3ByteChar(buf[begin]) ||
            isFirstByteOf2ByteChar(buf[begin])) {
            return begin;
        }
    }
    return -1;
}
function getChunkEnd(buf, chunkEnd) {
    // If it's the end, just return.
    if (chunkEnd === buf.length) {
        return chunkEnd;
    }
    var index = chunkEnd - 3;
    if (index >= 0) {
        if (isFirstByteOf4ByteChar(buf[index])) {
            return chunkEnd + 1;
        }
    }
    index = chunkEnd - 2;
    if (index >= 0) {
        if (isFirstByteOf4ByteChar(buf[index])) {
            return chunkEnd + 2;
        }
        if (isFirstByteOf3ByteChar(buf[index])) {
            return chunkEnd + 1;
        }
    }
    index = chunkEnd - 1;
    if (index >= 0) {
        if (isFirstByteOf4ByteChar(buf[index])) {
            return chunkEnd + 3;
        }
        if (isFirstByteOf3ByteChar(buf[index])) {
            return chunkEnd + 2;
        }
        if (isFirstByteOf2ByteChar(buf[index])) {
            return chunkEnd + 1;
        }
    }
    return chunkEnd;
}
function isFirstByteOf4ByteChar(byte) {
    // eslint-disable-next-line no-bitwise
    return byte >> 3 === 30; // 11110xxx?
}
function isFirstByteOf3ByteChar(byte) {
    // eslint-disable-next-line no-bitwise
    return byte >> 4 === 14; // 1110xxxx?
}
function isFirstByteOf2ByteChar(byte) {
    // eslint-disable-next-line no-bitwise
    return byte >> 5 === 6; // 110xxxxx?
}
function isLaterByteOfUtf8(byte) {
    // eslint-disable-next-line no-bitwise
    return byte >> 6 === 2; // 10xxxxxx?
}
