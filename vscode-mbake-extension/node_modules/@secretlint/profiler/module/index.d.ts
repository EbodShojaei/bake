import perf_hooks from "node:perf_hooks";
type Performance = typeof perf_hooks.performance | typeof performance;
export type SecretLintProfilerMarker = {
    type: "secretlint>cli::start";
} | {
    type: "secretlint>cli::end";
} | {
    type: "@config-loader>load-packages::start";
} | {
    type: "@config-loader>load-packages::end";
} | {
    type: "@config-loader>load-config-file::start";
} | {
    type: "@config-loader>load-config-file::end";
} | {
    type: "@config-loader>resolve-module::start";
    id: string;
} | {
    type: "@config-loader>resolve-module::end";
    id: string;
} | {
    type: "@config-loader>resolve-modules::start";
} | {
    type: "@config-loader>resolve-modules::end";
} | {
    type: "@node>load-config::start";
} | {
    type: "@node>load-config::end";
} | {
    type: "@node>execute::start";
} | {
    type: "@node>execute::end";
} | {
    type: "@node>format::start";
} | {
    type: "@node>format::end";
} | {
    type: "@core>lint::start";
    id: string;
} | {
    type: "@core>lint::end";
    id: string;
} | {
    type: "@core>setup-rules::start";
} | {
    type: "@core>setup-rules::end";
} | {
    type: "@core>setup-rule::start";
    id: string;
} | {
    type: "@core>setup-rule::end";
    id: string;
} | {
    type: "@core>rule-handler::start";
    id: string;
} | {
    type: "@core>rule-handler::end";
    id: string;
};
export type Constructor<I> = {
    new (...args: any[]): I;
};
export type LimitedPerformanceObserver = Constructor<{
    /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/PerformanceObserver/disconnect) */
    disconnect(): void;
    /** [MDN Reference](https://developer.mozilla.org/docs/Web/API/PerformanceObserver/observe) */
    observe(options?: any): void;
}>;
export type SecretLintProfilerOptions = {
    perf: Performance;
    PerformanceObserver: LimitedPerformanceObserver;
};
export declare class SecretLintProfiler {
    private perf;
    private entries;
    private measures;
    private executionPromises;
    constructor(options: SecretLintProfilerOptions);
    mark(marker: SecretLintProfilerMarker): void;
    private waifForExecutionPromises;
    getEntries(): Promise<PerformanceEntry[]>;
    getMeasures(): Promise<PerformanceEntry[]>;
}
export {};
//# sourceMappingURL=index.d.ts.map