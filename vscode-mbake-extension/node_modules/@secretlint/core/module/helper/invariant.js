/**
 * Test if condition is truthy.
 * @param {any} expression to be evaluated
 * @param {string} error message to be shown
 * @returns {void}
 * @throws
 */
export function invariant(condition, message) {
    if (!condition)
        throw new Error(message);
}
//# sourceMappingURL=invariant.js.map