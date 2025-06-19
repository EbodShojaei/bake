export declare const isAggregationError: (error: Error) => error is AggregationError;
export declare class AggregationError extends Error {
    errors: Error[];
    constructor(errors: Error[], message: string);
}
//# sourceMappingURL=AggregationError.d.ts.map