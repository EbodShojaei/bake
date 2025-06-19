export const isAggregationError = (error) => {
    return error instanceof AggregationError;
};
export class AggregationError extends Error {
    errors;
    constructor(errors, message) {
        // join error operated ----
        const joinedErrorMessage = errors.map((error) => error.message).join("\n\n----\n\n");
        super(message + "\n\n----\n\n" + joinedErrorMessage);
        this.errors = errors;
    }
}
//# sourceMappingURL=AggregationError.js.map